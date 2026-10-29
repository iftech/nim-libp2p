# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Experimental Waggle dissemination with application-defined object semantics.

{.push raises: [], gcsafe.}

import std/[sequtils, tables, sets, hashes]
import chronos, chronicles
import ./protocol, ./waggle/[messages, shard, state]
import ../switch, ../crypto/rng, ../muxers/muxer, ../multistream
import ../stream/connection
import ../peerid
from ../utils/future import trackFut
import ../results as lpresults

export lpresults

export protocol, messages, shard, connection, chronicles

logScope:
  topics = "libp2p waggle"

const
  WaggleCodec* = "/waggle/1.0"
  WaggleInvalidDataCause* = "Invalid Waggle data"

type
  TopicId* = seq[byte]
  ConnectionId* = uint64
  ValidatedTopic = distinct TopicId

  PiecesHandler* = proc(peer: PeerId, topicId: TopicId, msg: ObjectPieces) {.
    async: (raises: [CancelledError]), gcsafe
  .}

  SubscriptionAttempt* = object
    ## Immediate admission only; receivers may still be negotiating.
    added*: bool
    blockedConnections*: seq[ConnectionId]

  TopicConfig* = object
    publishFanout*: int
    forwardFanout*: int
    gossipFanout*: int

  WaggleEventKind* {.pure.} = enum
    Received
    Subscribed
    Unsubscribed
    InvalidData
    FullQueue
    StreamFailed

  WaggleEvent* = object
    kind*: WaggleEventKind
    peerId*: PeerId
    connectionId*: ConnectionId
    topicId*: TopicId
    message*: ObjectPieces
    reason*: string

  WaggleEventHandler* = proc(event: WaggleEvent) {.gcsafe, raises: [].}

  ReceiverFailure = tuple[kind: WaggleEventKind, reason: string]

  WaggleConnection = ref object
    id: ConnectionId
    muxer: Muxer
    queued: int
    queuedBytes: int
    opening: int
    readers: Table[TopicId, Future[Opt[ReceiverFailure]]]
    notifyingFailures: HashSet[TopicId]

  TopicSession = ref object
    stream: Stream
    topicId: TopicId
    receiving: bool
    ready: bool
    lock: AsyncLock
    link: WaggleConnection
    queue: AsyncQueue[ObjectPieces]
    queued: int
    queuedBytes: int
    writer: Future[void]

  Waggle* = ref object of LPProtocol
    streams: seq[TopicSession]
    maxMessageSize: int
    maxTopicSize: int
    maxStreams: int
    maxStreamsPerPeer: int
    stopping: bool
    links: seq[WaggleConnection]
    registeredMuxers: HashSet[Muxer]
    nextConnectionId: ConnectionId
    topics: HashSet[TopicId]
    topicConfigs: Table[TopicId, TopicConfig]
    defaultTopicConfig: TopicConfig
    topicWhitelist: Opt[HashSet[TopicId]]
    maxTopics: int
    maxQueued: int
    maxQueuedBytes: int
    maxCachedObjects: int
    state: WaggleState
    random: Rng
    onEvent: WaggleEventHandler
    tasks: seq[Future[void]]
    manager: ConnManager
    connHandler: ConnEventHandler

proc hash(muxer: Muxer): Hash =
  hash(cast[pointer](muxer))

proc notify(
    p: Waggle,
    kind: WaggleEventKind,
    link: WaggleConnection,
    topicId: TopicId,
    msg = ObjectPieces(),
    reason = "",
) =
  if p.onEvent == nil or link == nil:
    return
  let failure =
    kind in {
      WaggleEventKind.StreamFailed, WaggleEventKind.InvalidData,
      WaggleEventKind.FullQueue,
    }
  if failure:
    # An immediate retry at capacity must not recursively notify the same failure.
    if topicId in link.notifyingFailures:
      return
    link.notifyingFailures.incl(topicId)
  defer:
    if failure:
      link.notifyingFailures.excl(topicId)
  p.onEvent(
    WaggleEvent(
      kind: kind,
      peerId: link.muxer.connection.peerId,
      connectionId: link.id,
      topicId: topicId,
      message: msg,
      reason: reason,
    )
  )

proc findConnection(p: Waggle, stream: Stream): WaggleConnection =
  if p.links.len == 0:
    return nil
  var current = stream
  while current != nil:
    for link in p.links:
      if current == link.muxer.connection:
        return link
    let wrapped = current.getWrapped()
    if wrapped == current:
      break
    current = wrapped

proc beginWriter(p: Waggle, session: TopicSession)
proc writeSession(
  p: Waggle, target: TopicSession, msg: ObjectPieces
): Future[LPResult[bool]] {.async: (raises: [CancelledError]).}

proc pendingSlots(p: Waggle, peer: PeerId): tuple[total, perPeer: int] =
  var slots = (total: 0, perPeer: 0)
  for link in p.links:
    slots.total += link.opening
    if link.muxer.connection.peerId == peer:
      slots.perPeer += link.opening
  return slots

proc admit(p: Waggle, stream: Stream, receiving: bool): LPResult[TopicSession] =
  if p.stopping:
    return err("Waggle has stopped")
  let pending = p.pendingSlots(stream.peerId)
  if p.streams.len + pending.total >= p.maxStreams or
      p.streams.countIt(it.stream.peerId == stream.peerId) + pending.perPeer >=
      p.maxStreamsPerPeer:
    return err("Waggle stream limit reached")
  let session = TopicSession(
    stream: stream,
    receiving: receiving,
    lock: newAsyncLock(),
    link: p.findConnection(stream),
  )
  p.streams.add(session)
  return ok(session)

proc updateLink(session: TopicSession, p: Waggle) =
  if session.link == nil:
    session.link = p.findConnection(session.stream)

proc validateTopic(
    p: Waggle, session: TopicSession, topicId: TopicId
): LPResult[ValidatedTopic] =
  if topicId.len > p.maxTopicSize:
    return err("Waggle topic exceeds maximum length")
  for other in p.streams:
    if other != session and other.ready and other.receiving == session.receiving and
        other.stream.peerId == session.stream.peerId and
        (other.link == session.link or other.link == nil or session.link == nil) and
        other.topicId == topicId:
      return err("Duplicate Waggle topic stream")
  return ok(ValidatedTopic(topicId))

proc setTopic(session: TopicSession, topicId: ValidatedTopic) =
  session.topicId = TopicId(topicId)
  session.ready = true

proc forget(p: Waggle, session: TopicSession) =
  p.streams.keepItIf(it != session)

proc invalidSubscription(
    p: Waggle, stream: Stream, session: TopicSession, reason: string
) =
  let link =
    if session == nil:
      p.findConnection(stream)
    else:
      session.link
  let topicId =
    if session == nil:
      @[]
    else:
      session.topicId
  trace "Invalid Waggle subscription", peer = stream.peerId, err = reason
  p.notify(WaggleEventKind.InvalidData, link, topicId, reason = reason)

proc new*(
    T: typedesc[Waggle],
    maxMessageSize: int = 65536,
    maxTopicSize: int = 1024,
    maxStreams: int = 128,
    maxStreamsPerPeer: int = 16,
    maxCachedObjects: int = 100,
    maxTopics: int = 64,
    maxQueued: int = 5000,
    maxQueuedBytes: int = 4 * 1024 * 1024,
    defaultTopicConfig =
      TopicConfig(publishFanout: 50, forwardFanout: 50, gossipFanout: 50),
    topicWhitelist = Opt.none(HashSet[TopicId]),
    onEvent: WaggleEventHandler = nil,
    rng: Rng = nil,
    switch: Switch = nil,
): T =
  ## Queue limits apply per connection across topics, excluding the active write.
  ## If rng is nil, create a generator seeded from system entropy. Inject a seeded
  ## generator for reproducible peer selection, or share the switch generator.
  doAssert maxMessageSize > 0 and maxTopicSize >= 0
  doAssert maxStreams > 0 and maxStreamsPerPeer > 0
  doAssert maxCachedObjects > 0 and maxTopics > 0 and maxQueued > 0
  doAssert maxQueuedBytes > 0
  doAssert defaultTopicConfig.publishFanout > 0 and defaultTopicConfig.forwardFanout > 0 and
    defaultTopicConfig.gossipFanout >= 0
  let random =
    if rng == nil:
      newRng()
    else:
      rng
  doAssert random != nil
  let p = T(
    random: random,
    maxCachedObjects: maxCachedObjects,
    maxTopics: maxTopics,
    maxQueued: maxQueued,
    maxQueuedBytes: maxQueuedBytes,
    defaultTopicConfig: defaultTopicConfig,
    topicWhitelist: topicWhitelist,
    onEvent: onEvent,
    state: WaggleState.new(maxCachedObjects, maxTopics),
    maxMessageSize: maxMessageSize,
    maxTopicSize: maxTopicSize,
    maxStreams: maxStreams,
    maxStreamsPerPeer: maxStreamsPerPeer,
  )
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    var session: TopicSession
    try:
      session = p.admit(stream, receiving = false).valueOr:
        p.invalidSubscription(stream, session, $error)
        return
      let subscription = TopicSubscription.decode(await stream.readLp(p.maxMessageSize))
      if subscription.isErr:
        p.invalidSubscription(stream, session, subscription.error)
        return
      session.updateLink(p)
      let topicId = p.validateTopic(session, subscription.get().topicId).valueOr:
        p.invalidSubscription(stream, session, $error)
        return
      if p.topicWhitelist.isSome and TopicId(topicId) notin p.topicWhitelist.get():
        p.invalidSubscription(stream, session, "Topic is not allowed")
        return
      session.setTopic(topicId)
      if session.link != nil:
        p.beginWriter(session)
        p.notify(WaggleEventKind.Subscribed, session.link, session.topicId)
      # The subscriber only writes its handshake; further bytes are a violation.
      var unexpected: byte
      try:
        await stream.readExactly(addr unexpected, 1)
      except LPStreamRemoteClosedError:
        # A subscriber may close its write side after the handshake.
        await stream.join()
        return
      p.invalidSubscription(
        stream, session, "Unexpected data after subscription handshake"
      )
    except LPStreamError as exc:
      if session != nil and not session.ready:
        p.invalidSubscription(stream, session, exc.msg)
      else:
        trace "Waggle subscription stream ended", peer = stream.peerId, err = exc.msg
    finally:
      if session != nil:
        p.forget(session)
        if session.writer != nil:
          await noCancel session.writer.cancelAndWait()
          # Include messages handed to a pop that cancellation interrupted.
          session.link.queued -= session.queued
          session.link.queuedBytes -= session.queuedBytes
          session.queued = 0
          session.queuedBytes = 0
          p.state.removeSubscription(session.topicId, session.link.id)
          p.notify(WaggleEventKind.Unsubscribed, session.link, session.topicId)
      await noCancel stream.reset()

  p.codec = WaggleCodec
  p.handler = handle
  if switch != nil:
    p.manager = switch.connManager
  p

proc subscribe*(
    p: Waggle, stream: Stream, topicId: TopicId, handler: PiecesHandler
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  ## Takes ownership of a stream opened for WaggleCodec, sends the subscription,
  ## and receives until EOF, cancellation, or a returned error. The stream is reset
  ## on every exit.
  doAssert handler != nil
  var session: TopicSession
  try:
    session = ?p.admit(stream, receiving = true)
    session.updateLink(p)
    session.setTopic(?p.validateTopic(session, topicId))
    let subscription = TopicSubscription(topicId: topicId).encode()
    if subscription.len > p.maxMessageSize:
      return err("Waggle subscription exceeds maximum length")
    await stream.writeLp(subscription)
    while true:
      let decoded = ObjectPieces.decode(await stream.readLp(p.maxMessageSize))
      if decoded.isErr:
        return err(decoded.error, WaggleInvalidDataCause)
      await handler(stream.peerId, topicId, decoded.get())
  except LPStreamResetError, LPStreamClosedError, LPStreamConnDownError:
    return err(getCurrentExceptionMsg())
  except LPStreamEOFError as exc:
    trace "Waggle receive stream ended", peer = stream.peerId, err = exc.msg
  except InvalidVarintError, MaxSizeError:
    return err(getCurrentExceptionMsg(), WaggleInvalidDataCause)
  except LPStreamError as exc:
    return err(exc)
  finally:
    if session != nil:
      p.forget(session)
    await noCancel stream.reset()
  return ok()

proc subscribers*(p: Waggle, topicId: TopicId): seq[PeerId] =
  ## Peers with an active inbound subscription for this topic.
  var peers: seq[PeerId]
  for session in p.streams:
    if session.ready and not session.receiving and not session.stream.closed and
        session.topicId == topicId:
      if session.stream.peerId notin peers:
        peers.add(session.stream.peerId)
  return peers

proc send*(
    p: Waggle, peer: PeerId, topicId: TopicId, msg: ObjectPieces
): Future[LPResult[bool]] {.async: (raises: [CancelledError]).} =
  ## Concurrent sends are serialized by a per-stream lock. A cancelled or failed
  ## write resets the stream because its frame may be incomplete.
  ## Returns ok(true) after writing, or ok(false) if no writable subscription exists.
  ## Validation and stream failures return errors; cancellation propagates.
  ## Do not mix this direct wire API with managed publishing on one subscription:
  ## direct sends bypass its queue and do not update reconciliation state.
  if msg.encodedSize() > p.maxMessageSize:
    return err("Waggle message exceeds maximum length")
  for session in p.streams:
    if session.ready and not session.receiving and session.stream.peerId == peer and
        session.topicId == topicId:
      return await p.writeSession(session, msg)
  return ok(false)

proc writeSession(
    p: Waggle, target: TopicSession, msg: ObjectPieces
): Future[LPResult[bool]] {.async: (raises: [CancelledError]).} =
  await target.lock.acquire()
  try:
    if target.stream.closed:
      return ok(false)
    try:
      await target.stream.writeLp(msg.encode())
    except CancelledError as exc:
      await noCancel target.stream.reset()
      raise exc
    except LPStreamError as exc:
      await noCancel target.stream.reset()
      return err(exc)
    return ok(true)
  finally:
    try:
      target.lock.release()
    except AsyncLockError as exc:
      raiseAssert exc.msg

proc beginWriter(p: Waggle, session: TopicSession) =
  session.queue = newAsyncQueue[ObjectPieces](p.maxQueued)
  proc writeLoop() {.async: (raises: [CancelledError]).} =
    try:
      while true:
        let msg = await session.queue.popFirst()
        dec session.link.queued
        dec session.queued
        let size = msg.encodedSize()
        session.link.queuedBytes -= size
        session.queuedBytes -= size
        let written = await p.writeSession(session, msg)
        if written.isErr:
          p.notify(
            WaggleEventKind.StreamFailed,
            session.link,
            session.topicId,
            reason = $written.error,
          )
          return
        if not written.get():
          return
    finally:
      await noCancel session.stream.reset()

  session.writer = writeLoop()
  p.tasks.trackFut(session.writer)

proc target(p: Waggle, link: WaggleConnection, topicId: TopicId): Opt[TopicSession] =
  for session in p.streams:
    if session.link == link and not session.receiving and session.ready and
        session.topicId == topicId and not session.stream.closed:
      return Opt.some(session)
  return Opt.none(TopicSession)

proc enqueue(p: Waggle, session: TopicSession, msg: ObjectPieces): bool =
  let link = session.link
  let topicId = session.topicId
  if p.stopping or session.stream.closed:
    return false
  let size = msg.encodedSize()
  if size > p.maxMessageSize:
    p.notify(
      WaggleEventKind.InvalidData, link, topicId, msg,
      "Outgoing message exceeds maximum length",
    )
    return false
  if link.queued >= p.maxQueued or size > p.maxQueuedBytes - link.queuedBytes:
    p.notify(WaggleEventKind.FullQueue, link, topicId)
    return false
  try:
    session.queue.addLastNoWait(msg)
    inc link.queued
    inc session.queued
    link.queuedBytes += size
    session.queuedBytes += size
    return true
  except AsyncQueueFullError:
    p.notify(WaggleEventKind.FullQueue, link, topicId)
    return false

proc dispatch(p: Waggle, session: TopicSession, tx: Transmission): bool =
  if p.enqueue(session, tx.message):
    tx.commit()
    true
  else:
    false

proc config(p: Waggle, topicId: TopicId): TopicConfig =
  p.topicConfigs.getOrDefault(topicId, p.defaultTopicConfig)

proc setTopicConfig*(
    p: Waggle, topicId: TopicId, config: TopicConfig
): Result[void, string] =
  if config.publishFanout <= 0 or config.forwardFanout <= 0 or config.gossipFanout < 0:
    return err("Waggle publish/forward fanouts must be positive and gossip nonnegative")
  if topicId.len > p.maxTopicSize:
    return err("Waggle topic exceeds maximum length")
  if not p.topicConfigs.hasKey(topicId) and p.topicConfigs.len >= p.maxTopics:
    return err("Waggle topic configuration limit reached")
  p.topicConfigs[topicId] = config
  ok()

proc eligible(
    p: Waggle, topicId: TopicId, exceptLink: WaggleConnection = nil
): seq[TopicSession] =
  var sessions: seq[TopicSession]
  for session in p.streams:
    if session.link != nil and session.link != exceptLink and
        session.link.muxer in p.registeredMuxers and not session.receiving and
        session.ready and session.topicId == topicId and not session.stream.closed:
      sessions.add(session)
  p.random.shuffle(sessions)
  return sessions

proc advertise(
    p: Waggle, topicId: TopicId, objectId: seq[byte], exceptLink: WaggleConnection = nil
): int =
  var sent = 0
  var discovered = 0
  let config = p.config(topicId)
  for session in p.eligible(topicId, exceptLink):
    let link = session.link
    let view = p.state.peerView(topicId, link.id, objectId)
    # Existing observers receive every change; discovery has its own budget.
    if not view.advertised and (view.known or discovered >= config.gossipFanout):
      continue
    let prepared = p.state.prepare(
      topicId, link.id, link.muxer.connection.peerId, objectId, metadataOnly = true
    ).valueOr:
      p.notify(
        WaggleEventKind.InvalidData,
        link,
        topicId,
        ObjectPieces(objectId: objectId),
        error,
      )
      continue
    let tx = prepared.valueOr:
      continue
    if p.dispatch(session, tx):
      inc sent
      if not view.advertised:
        inc discovered
  return sent

proc disseminate(
    p: Waggle,
    topicId: TopicId,
    id: seq[byte],
    candidates: seq[TopicSession],
    existing, changed: bool,
): tuple[sent: int, attempted: bool] =
  var sent = 0
  var seeded = 0
  var forwarded = 0
  var attempted = false
  # Forwarding uses known peer state; initial publication may seed unknown peers.
  let config = p.config(topicId)
  for session in candidates:
    let link = session.link
    let known = p.state.peerView(topicId, link.id, id).known
    if existing and changed and not known:
      continue
    let forwarding = existing and known
    let limit = if forwarding: config.forwardFanout else: config.publishFanout
    let payloads = if forwarding: forwarded else: seeded
    if not forwarding and payloads >= limit:
      continue
    let prepared = p.state.prepare(topicId, link.id, link.muxer.connection.peerId, id).valueOr:
      attempted = true
      p.notify(
        WaggleEventKind.InvalidData, link, topicId, ObjectPieces(objectId: id), error
      )
      continue
    let tx = prepared.valueOr:
      continue
    let budgeted = not forwarding or tx.message.pieces.isSome
    if budgeted and payloads >= limit:
      continue
    attempted = true
    if p.dispatch(session, tx):
      inc sent
      if budgeted:
        if forwarding:
          inc forwarded
        else:
          inc seeded
  return (sent, attempted)

proc publish*(p: Waggle, topicId: TopicId, shard: WaggleShard): Result[int, string] =
  ## Cache a current snapshot and queue initial publication or selective forwarding.
  ## Updated snapshots also advertise metadata to observers and discovery peers.
  if p.stopping or shard == nil:
    return err("Waggle is stopped or the shard is nil")
  let candidates = p.eligible(topicId)
  if candidates.len == 0:
    return err("No peers subscribed to the topic")
  let id = shard.objectId()
  let existing = p.state.hasLocal(topicId, id)
  let changed = ?p.state.store(topicId, shard)
  var (sent, attempted) = p.disseminate(topicId, id, candidates, existing, changed)
  if existing:
    sent += p.advertise(topicId, id)
  if sent == 0 and (changed or attempted):
    err("Message not sent on any connection")
  else:
    ok(sent)

proc processReceived(
    p: Waggle, link: WaggleConnection, topicId: TopicId, msg: ObjectPieces
) =
  if topicId notin p.topics or p.stopping or link notin p.links:
    return
  let action = p.state.received(topicId, link.id, link.muxer.connection.peerId, msg).valueOr:
    p.notify(WaggleEventKind.InvalidData, link, topicId, msg, error)
    return
  if not action.active:
    return
  if action.reply.isSome:
    let session = p.target(link, topicId)
    if session.isSome:
      discard p.dispatch(session.get(), action.reply.get())
  if action.emit:
    p.notify(WaggleEventKind.Received, link, topicId, msg)
  discard p.advertise(topicId, msg.objectId, link)

proc receiveTopic(
    p: Waggle, link: WaggleConnection, topicId: TopicId
): Future[Opt[ReceiverFailure]] {.async: (raises: [CancelledError]).} =
  var stream: Stream
  var opening = true
  try:
    stream = await link.muxer.newStream()
    if not (await MultistreamSelect.select(stream, WaggleCodec)):
      return Opt.some((WaggleEventKind.StreamFailed, "Peer does not support Waggle"))
    proc onPieces(
        peer: PeerId, topicId: TopicId, msg: ObjectPieces
    ) {.async: (raises: [CancelledError]).} =
      p.processReceived(link, topicId, msg)

    dec link.opening
    opening = false
    let received = await p.subscribe(stream, topicId, onPieces)
    if received.isErr:
      let kind =
        if received.isOfError(WaggleInvalidDataCause):
          WaggleEventKind.InvalidData
        else:
          WaggleEventKind.StreamFailed
      return Opt.some((kind, $received.error))
  except InvalidVarintError, MaxSizeError:
    let kind =
      if opening: WaggleEventKind.StreamFailed else: WaggleEventKind.InvalidData
    return Opt.some((kind, getCurrentExceptionMsg()))
  except LPError as exc:
    return Opt.some((WaggleEventKind.StreamFailed, exc.msg))
  finally:
    if opening:
      dec link.opening
    if stream != nil:
      await noCancel stream.reset()
  return Opt.none(ReceiverFailure)

proc beginReceiver(
    p: Waggle, link: WaggleConnection, topicId: TopicId
): Result[void, string] =
  if p.stopping or topicId notin p.topics or link notin p.links:
    return ok()
  if link.readers.hasKey(topicId):
    if not link.readers.getOrDefault(topicId).finished():
      return ok()
    link.readers.del(topicId)
  let peer = link.muxer.connection.peerId
  let pending = p.pendingSlots(peer)
  let activePeer = p.streams.countIt(it.stream.peerId == peer)
  if p.streams.len + pending.total >= p.maxStreams or
      activePeer + pending.perPeer >= p.maxStreamsPerPeer:
    return err("Waggle stream limit reached")
  inc link.opening
  let task = p.receiveTopic(link, topicId)
  link.readers[topicId] = task
  task.addCallback proc(udata: pointer) {.gcsafe, raises: [].} =
    if link.readers.getOrDefault(topicId) == task:
      link.readers.del(topicId)
    # Failure handlers may retry immediately, after receiver cleanup is complete.
    if task.completed() and not p.stopping and link in p.links and topicId in p.topics:
      let failure = task.value()
      if failure.isSome:
        let (kind, reason) = failure.get()
        p.notify(kind, link, topicId, reason = reason)
  ok()

proc beginReceiverOrNotify(p: Waggle, link: WaggleConnection, topicId: TopicId) =
  let admission = p.beginReceiver(link, topicId)
  if admission.isErr:
    p.notify(WaggleEventKind.StreamFailed, link, topicId, reason = admission.error)

proc subscribe*(p: Waggle, topicId: TopicId): Result[SubscriptionAttempt, string] =
  ## Register a topic and retry finished receivers on current connections.
  ## Validation errors leave registration unchanged. The topic remains registered
  ## when connections are blocked, and other or future connections are still attempted.
  ## Explicit admission failures are returned in the report, without failure events.
  ## Negotiation and subsequent stream failures are reported through events.
  if p.stopping:
    return err("Waggle has stopped")
  if topicId.len > p.maxTopicSize:
    return err("Waggle topic exceeds maximum length")
  if p.topicWhitelist.isSome and topicId notin p.topicWhitelist.get():
    return err("Topic is not allowed")
  let added = topicId notin p.topics
  if added and p.topics.len >= p.maxTopics:
    return err("Waggle topic subscription limit reached")
  p.topics.incl(topicId)
  let links = p.links
  var attempt = SubscriptionAttempt(added: added)
  for link in links:
    if p.beginReceiver(link, topicId).isErr:
      attempt.blockedConnections.add(link.id)
  ok(attempt)

proc unsubscribe*(p: Waggle, topicId: TopicId): Future[bool] {.async: (raises: []).} =
  if topicId notin p.topics:
    return false
  p.topics.excl(topicId)
  p.state.removeTopic(topicId)
  p.topicConfigs.del(topicId)
  var readers: seq[Future[Opt[ReceiverFailure]]]
  let links = p.links
  for link in links:
    link.readers.withValue(topicId, task):
      readers.add(task[])
  for task in readers:
    await task.cancelAndWait()
  # A concurrent subscribe waits for the old receiver to finish before reopening.
  for link in links:
    p.beginReceiverOrNotify(link, topicId)
  return true

proc removeConnection(p: Waggle, link: WaggleConnection) {.async: (raises: []).} =
  p.links.keepItIf(it != link)
  p.registeredMuxers.excl(link.muxer)
  p.state.removeConnection(link.id)
  let sessions = p.streams.filterIt(it.link == link)
  for session in sessions:
    await noCancel session.stream.reset()
  let readers = toSeq(link.readers.values)
  link.readers.clear()
  for task in readers:
    await task.cancelAndWait()

proc addConnection*(p: Waggle, muxer: Muxer): Result[bool, string] =
  ## Register an upgraded muxer whose stream handler routes incoming protocols.
  ## Pass a switch to Waggle.new for automatic connection discovery on start.
  if p.stopping or muxer == nil or muxer.handler == nil or muxer.connection.closed:
    return err("Waggle requires a live running muxer")
  if muxer in p.registeredMuxers:
    return ok(false)
  if p.links.len >= p.maxStreams:
    return err("Waggle connection limit reached")
  inc p.nextConnectionId
  let link = WaggleConnection(id: p.nextConnectionId, muxer: muxer)
  p.links.add(link)
  p.registeredMuxers.incl(muxer)
  for topicId in toSeq(p.topics):
    p.beginReceiverOrNotify(link, topicId)
  proc monitor() {.async: (raises: [CancelledError]).} =
    await muxer.handler.join()
    await p.removeConnection(link)

  p.tasks.trackFut(monitor())
  ok(true)

proc refreshConnections(p: Waggle) =
  for connections in p.manager.getConnections().values:
    for muxer in connections:
      let added = p.addConnection(muxer)
      if added.isErr:
        trace "Waggle connection not registered", reason = added.error

method start*(p: Waggle) {.async: (raises: [CancelledError]).} =
  p.stopping = false
  if p.manager != nil:
    if p.connHandler == nil:
      proc onConnection(
          peer: PeerId, event: ConnEvent
      ) {.async: (raises: [CancelledError]).} =
        if not p.stopping:
          for muxer in p.manager.getConnections(peer).get(@[]):
            let added = p.addConnection(muxer)
            if added.isErr:
              trace "Waggle connection not registered", reason = added.error

      p.connHandler = onConnection
    p.manager.addConnEventHandler(p.connHandler, ConnEventKind.Connected)
    p.refreshConnections()
  await procCall LPProtocol(p).start()

method stop*(p: Waggle) {.async: (raises: []).} =
  p.stopping = true
  if p.manager != nil and p.connHandler != nil:
    p.manager.removeConnEventHandler(p.connHandler, ConnEventKind.Connected)
    p.connHandler = nil
  let links = move p.links
  p.registeredMuxers.clear()
  var readers: seq[Future[Opt[ReceiverFailure]]]
  for link in links:
    readers.add(toSeq(link.readers.values))
    link.readers.clear()
  let streams = move p.streams
  await noCancel allFutures(streams.mapIt(it.stream.reset()))
  await readers.cancelAndWait()
  let tasks = move p.tasks
  await tasks.cancelAndWait()
  p.state = WaggleState.new(p.maxCachedObjects, p.maxTopics)
  await procCall LPProtocol(p).stop()
