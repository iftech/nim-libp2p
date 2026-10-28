# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Experimental Waggle dissemination with application-defined object semantics.

{.push raises: [], gcsafe.}

import std/[sequtils, tables, sets, hashes]
import chronos, chronicles
import ./protocol, ./waggle/[messages, shard]
import ../switch, ../muxers/muxer, ../multistream
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

  WaggleEventKind* {.pure.} = enum
    Received
    Subscribed
    Unsubscribed
    InvalidData
    StreamFailed

  WaggleEvent* = object
    kind*: WaggleEventKind
    peerId*: PeerId
    connectionId*: ConnectionId
    topicId*: TopicId
    message*: ObjectPieces
    reason*: string

  WaggleEventHandler* = proc(event: WaggleEvent) {.gcsafe, raises: [].}

  WaggleConnection = ref object
    id: ConnectionId
    muxer: Muxer
    opening: int
    readers: Table[TopicId, Future[void]]

  TopicSession = ref object
    stream: Stream
    topicId: TopicId
    receiving: bool
    ready: bool
    lock: AsyncLock
    link: WaggleConnection

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
    topicWhitelist: Opt[HashSet[TopicId]]
    maxTopics: int
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
  if p.onEvent != nil and link != nil:
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
    maxTopics: int = 64,
    topicWhitelist = Opt.none(HashSet[TopicId]),
    onEvent: WaggleEventHandler = nil,
    switch: Switch = nil,
): T =
  doAssert maxMessageSize > 0 and maxTopicSize >= 0
  doAssert maxStreams > 0 and maxStreamsPerPeer > 0
  doAssert maxTopics > 0
  let p = T(
    maxTopics: maxTopics,
    topicWhitelist: topicWhitelist,
    onEvent: onEvent,
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
        if session.link != nil and session.ready:
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

proc processReceived(
    p: Waggle, link: WaggleConnection, topicId: TopicId, msg: ObjectPieces
) =
  if topicId in p.topics and not p.stopping and link in p.links:
    p.notify(WaggleEventKind.Received, link, topicId, msg)

proc receiveTopic(
    p: Waggle, link: WaggleConnection, topicId: TopicId
) {.async: (raises: [CancelledError]).} =
  var stream: Stream
  var opening = true
  try:
    stream = await link.muxer.newStream()
    if not (await MultistreamSelect.select(stream, WaggleCodec)):
      p.notify(
        WaggleEventKind.StreamFailed,
        link,
        topicId,
        reason = "Peer does not support Waggle",
      )
      return
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
      p.notify(kind, link, topicId, reason = $received.error)
  except InvalidVarintError, MaxSizeError:
    let kind =
      if opening: WaggleEventKind.StreamFailed else: WaggleEventKind.InvalidData
    p.notify(kind, link, topicId, reason = getCurrentExceptionMsg())
  except LPError as exc:
    p.notify(WaggleEventKind.StreamFailed, link, topicId, reason = exc.msg)
  finally:
    if opening:
      dec link.opening
    if stream != nil:
      await noCancel stream.reset()

proc beginReceiver(p: Waggle, link: WaggleConnection, topicId: TopicId) =
  if p.stopping or topicId notin p.topics or link notin p.links:
    return
  if link.readers.hasKey(topicId):
    if not link.readers.getOrDefault(topicId).finished():
      return
    link.readers.del(topicId)
  let peer = link.muxer.connection.peerId
  let pending = p.pendingSlots(peer)
  let activePeer = p.streams.countIt(it.stream.peerId == peer)
  if p.streams.len + pending.total >= p.maxStreams or
      activePeer + pending.perPeer >= p.maxStreamsPerPeer:
    p.notify(
      WaggleEventKind.StreamFailed,
      link,
      topicId,
      reason = "Waggle stream limit reached",
    )
    return
  inc link.opening
  let task = p.receiveTopic(link, topicId)
  link.readers[topicId] = task
  task.addCallback proc(udata: pointer) {.gcsafe, raises: [].} =
    if link.readers.getOrDefault(topicId) == task:
      link.readers.del(topicId)

proc subscribe*(p: Waggle, topicId: TopicId): Result[bool, string] =
  ## Subscribe on every current and future registered connection. Repeating a
  ## subscription reopens finished receivers without retrying failures automatically.
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
  for link in links:
    p.beginReceiver(link, topicId)
  ok(added)

proc unsubscribe*(p: Waggle, topicId: TopicId): Future[bool] {.async: (raises: []).} =
  if topicId notin p.topics:
    return false
  p.topics.excl(topicId)
  var readers: seq[Future[void]]
  let links = p.links
  for link in links:
    link.readers.withValue(topicId, task):
      readers.add(task[])
  for task in readers:
    await task.cancelAndWait()
  # A concurrent subscribe waits for the old receiver to finish before reopening.
  for link in links:
    p.beginReceiver(link, topicId)
  return true

proc removeConnection(p: Waggle, link: WaggleConnection) {.async: (raises: []).} =
  p.links.keepItIf(it != link)
  p.registeredMuxers.excl(link.muxer)
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
    p.beginReceiver(link, topicId)
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
  var readers: seq[Future[void]]
  for link in links:
    readers.add(toSeq(link.readers.values))
    link.readers.clear()
  let streams = move p.streams
  await noCancel allFutures(streams.mapIt(it.stream.reset()))
  await readers.cancelAndWait()
  let tasks = move p.tasks
  await tasks.cancelAndWait()
  await procCall LPProtocol(p).stop()
