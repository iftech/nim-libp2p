# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Experimental Waggle dissemination with application-defined object semantics.

{.push raises: [], gcsafe.}

import std/[sequtils, tables, sets]
import chronos, chronicles
import ./protocol, ./waggle/[messages, shard, state]
import ../switch, ../crypto/rng, ../muxers/muxer, ../multistream
import ../stream/connection
import ../peerid

export protocol, messages, shard, connection

logScope:
  topics = "libp2p waggle"

const WaggleCodec* = "/waggle/1.0"

type
  WaggleError* = object of LPError
  WaggleDecodeError = object of WaggleError

  PiecesHandler* = proc(peer: PeerId, topic: seq[byte], msg: ObjectPieces) {.
    async: (raises: [CancelledError]), gcsafe
  .}

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
    connectionId*: uint64
    topic*: seq[byte]
    message*: ObjectPieces
    reason*: string

  WaggleEventHandler* = proc(event: WaggleEvent) {.gcsafe, raises: [].}

  WaggleConnection = ref object
    id: uint64
    muxer: Muxer
    queued: int
    opening: int
    readers: Table[seq[byte], Future[void]]

  TopicStream = ref object
    stream: Stream
    topic: seq[byte]
    receiving: bool
    ready: bool
    lock: AsyncLock
    link: WaggleConnection
    queue: AsyncQueue[ObjectPieces]
    queued: int
    writer: Future[void]

  Waggle* = ref object of LPProtocol
    streams: seq[TopicStream]
    maxMessageSize: int
    maxTopicSize: int
    maxStreams: int
    maxStreamsPerPeer: int
    stopping: bool
    links: seq[WaggleConnection]
    nextConnectionId: uint64
    topics: HashSet[seq[byte]]
    topicConfigs: Table[seq[byte], TopicConfig]
    defaultTopicConfig: TopicConfig
    topicWhitelist: Opt[HashSet[seq[byte]]]
    maxTopics: int
    maxQueued: int
    maxCachedObjects: int
    objectLifetime: Duration
    state: WaggleState
    random: Rng
    onEvent: WaggleEventHandler
    tasks: seq[Future[void]]
    manager: ConnManager
    connHandler: ConnEventHandler

proc notify(
    p: Waggle,
    kind: WaggleEventKind,
    link: WaggleConnection,
    topic: seq[byte],
    msg = ObjectPieces(),
    reason = "",
) =
  if p.onEvent != nil and link != nil:
    p.onEvent(
      WaggleEvent(
        kind: kind,
        peerId: link.muxer.connection.peerId,
        connectionId: link.id,
        topic: topic,
        message: msg,
        reason: reason,
      )
    )

proc track(p: Waggle, task: Future[void]) =
  p.tasks.keepItIf(not it.finished)
  p.tasks.add(task)

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

proc beginWriter(p: Waggle, session: TopicStream)
proc writeSession(
  p: Waggle, target: TopicStream, msg: ObjectPieces
): Future[bool] {.async: (raises: [CancelledError, LPStreamError, WaggleError]).}

proc pendingSlots(p: Waggle, peer: PeerId): tuple[total, perPeer: int] =
  var slots = (total: 0, perPeer: 0)
  for link in p.links:
    slots.total += link.opening
    if link.muxer.connection.peerId == peer:
      slots.perPeer += link.opening
  return slots

proc admit(
    p: Waggle, stream: Stream, receiving: bool
): TopicStream {.raises: [WaggleError].} =
  if p.stopping:
    raise newException(WaggleError, "Waggle has stopped")
  let pending = p.pendingSlots(stream.peerId)
  if p.streams.len + pending.total >= p.maxStreams or
      p.streams.countIt(it.stream.peerId == stream.peerId) + pending.perPeer >=
      p.maxStreamsPerPeer:
    raise newException(WaggleError, "Waggle stream limit reached")
  let session = TopicStream(
    stream: stream,
    receiving: receiving,
    lock: newAsyncLock(),
    link: p.findConnection(stream),
  )
  p.streams.add(session)
  return session

proc setTopic(
    p: Waggle, session: TopicStream, topic: seq[byte]
) {.raises: [WaggleError].} =
  if session.link == nil:
    session.link = p.findConnection(session.stream)
  if topic.len > p.maxTopicSize:
    raise newException(WaggleError, "Waggle topic exceeds maximum length")
  for other in p.streams:
    if other != session and other.ready and other.receiving == session.receiving and
        other.stream.peerId == session.stream.peerId and other.link == session.link and
        other.topic == topic:
      raise newException(WaggleError, "Duplicate Waggle topic stream")
  session.topic = topic
  session.ready = true

proc forget(p: Waggle, session: TopicStream) =
  p.streams.keepItIf(it != session)

method init*(p: Waggle) =
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    var session: TopicStream
    try:
      session = p.admit(stream, receiving = false)
      let subscription = TopicSubscription.decode(await stream.readLp(p.maxMessageSize))
      if subscription.isErr:
        raise newException(WaggleError, subscription.error)
      let topic = subscription.get().topicId
      if p.topicWhitelist.isSome and topic notin p.topicWhitelist.get():
        raise newException(WaggleError, "Topic is not allowed")
      p.setTopic(session, topic)
      if session.link != nil:
        p.beginWriter(session)
        p.notify(WaggleEventKind.Subscribed, session.link, topic)
      # The subscriber only writes its handshake; further bytes are a violation.
      var unexpected: byte
      await stream.readExactly(addr unexpected, 1)
      p.notify(
        WaggleEventKind.InvalidData,
        session.link,
        session.topic,
        reason = "Unexpected data after subscription handshake",
      )
    except LPStreamEOFError:
      discard
    except LPStreamError as exc:
      if session != nil and not session.ready:
        p.notify(
          WaggleEventKind.InvalidData, session.link, session.topic, reason = exc.msg
        )
      else:
        trace "Waggle subscription stream ended", peer = stream.peerId, err = exc.msg
    except WaggleError as exc:
      let link =
        if session == nil:
          p.findConnection(stream)
        else:
          session.link
      let topic =
        if session == nil:
          @[]
        else:
          session.topic
      p.notify(WaggleEventKind.InvalidData, link, topic, reason = exc.msg)
    finally:
      if session != nil:
        p.forget(session)
        if session.writer != nil:
          await session.writer.cancelAndWait()
          # Include messages handed to a pop that cancellation interrupted.
          session.link.queued -= session.queued
          session.queued = 0
          p.state.removeSubscription(session.topic, session.link.id)
          p.notify(WaggleEventKind.Unsubscribed, session.link, session.topic)
      await stream.reset()

  p.codec = WaggleCodec
  p.handler = handle

proc attach(p: Waggle, manager: ConnManager)

proc new*(
    T: typedesc[Waggle],
    maxMessageSize: int = 65536,
    maxTopicSize: int = 1024,
    maxStreams: int = 128,
    maxStreamsPerPeer: int = 16,
    maxCachedObjects: int = 100,
    maxTopics: int = 64,
    maxQueued: int = 5000,
    objectLifetime = 5.minutes,
    defaultTopicConfig =
      TopicConfig(publishFanout: 50, forwardFanout: 50, gossipFanout: 50),
    topicWhitelist = Opt.none(HashSet[seq[byte]]),
    onEvent: WaggleEventHandler = nil,
    rng: Rng = nil,
    switch: Switch = nil,
): T =
  doAssert maxMessageSize > 0 and maxTopicSize >= 0
  doAssert maxStreams > 0 and maxStreamsPerPeer > 0
  doAssert maxCachedObjects > 0 and maxTopics > 0 and maxQueued > 0
  doAssert objectLifetime > ZeroDuration
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
    objectLifetime: objectLifetime,
    maxTopics: maxTopics,
    maxQueued: maxQueued,
    defaultTopicConfig: defaultTopicConfig,
    topicWhitelist: topicWhitelist,
    onEvent: onEvent,
    state: WaggleState.new(maxCachedObjects, maxTopics, objectLifetime),
    maxMessageSize: maxMessageSize,
    maxTopicSize: maxTopicSize,
    maxStreams: maxStreams,
    maxStreamsPerPeer: maxStreamsPerPeer,
  )
  p.init()
  p.setStreamLimits(
    maxIncomingStreamsTotal = maxStreams,
    maxIncomingStreamsPerPeer = maxStreamsPerPeer,
    maxOutgoingStreamsTotal = maxStreams,
    maxOutgoingStreamsPerPeer = maxStreamsPerPeer,
  )
  if switch != nil:
    p.attach(switch.connManager)
  p

proc subscribe*(
    p: Waggle, stream: Stream, topic: seq[byte], handler: PiecesHandler
) {.async: (raises: [CancelledError, LPStreamError, WaggleError]).} =
  ## Takes ownership of a negotiated stream, sends the subscription, and receives
  ## until EOF or cancellation. The stream is reset on every exit, including errors.
  doAssert handler != nil
  var session: TopicStream
  try:
    session = p.admit(stream, receiving = true)
    p.setTopic(session, topic)
    let subscription = TopicSubscription(topicId: topic).encode()
    if subscription.len > p.maxMessageSize:
      raise newException(WaggleError, "Waggle subscription exceeds maximum length")
    await stream.writeLp(subscription)
    while true:
      let decoded = ObjectPieces.decode(await stream.readLp(p.maxMessageSize))
      if decoded.isErr:
        raise newException(WaggleDecodeError, decoded.error)
      await handler(stream.peerId, topic, decoded.get())
  except LPStreamEOFError:
    discard
  finally:
    if session != nil:
      p.forget(session)
    await stream.reset()

proc subscribers*(p: Waggle, topic: seq[byte]): seq[PeerId] =
  ## Peers with an active inbound subscription for this topic.
  var peers: seq[PeerId]
  for session in p.streams:
    if session.ready and not session.receiving and not session.stream.closed and
        session.topic == topic:
      peers.add(session.stream.peerId)
  return peers

proc send*(
    p: Waggle, peer: PeerId, topic: seq[byte], msg: ObjectPieces
): Future[bool] {.async: (raises: [CancelledError, LPStreamError, WaggleError]).} =
  ## Sends to a subscribed peer, returning false if no subscription exists.
  ## Concurrent sends apply backpressure through a per-stream lock. A cancelled
  ## or failed write resets the stream because its frame may be incomplete.
  if msg.encodedSize() > p.maxMessageSize:
    raise newException(WaggleError, "Waggle message exceeds maximum length")
  var target: TopicStream
  for session in p.streams:
    if session.ready and not session.receiving and session.stream.peerId == peer and
        session.topic == topic:
      target = session
      break
  if target == nil:
    return false
  return await p.writeSession(target, msg)

proc writeSession(
    p: Waggle, target: TopicStream, msg: ObjectPieces
): Future[bool] {.async: (raises: [CancelledError, LPStreamError, WaggleError]).} =
  await target.lock.acquire()
  try:
    if target.stream.closed:
      return false
    try:
      await target.stream.writeLp(msg.encode())
    except CancelledError as exc:
      await target.stream.reset()
      raise exc
    except LPStreamError as exc:
      await target.stream.reset()
      raise exc
    return true
  finally:
    try:
      target.lock.release()
    except AsyncLockError as exc:
      raiseAssert exc.msg

proc beginWriter(p: Waggle, session: TopicStream) =
  session.queue = newAsyncQueue[ObjectPieces](p.maxQueued)
  proc writeLoop() {.async: (raises: [CancelledError]).} =
    try:
      while true:
        let msg = await session.queue.popFirst()
        dec session.link.queued
        dec session.queued
        if not (await p.writeSession(session, msg)):
          return
    except LPStreamError as exc:
      p.notify(
        WaggleEventKind.StreamFailed, session.link, session.topic, reason = exc.msg
      )
    except WaggleError as exc:
      p.notify(
        WaggleEventKind.StreamFailed, session.link, session.topic, reason = exc.msg
      )
    finally:
      await session.stream.reset()

  session.writer = writeLoop()
  p.track(session.writer)

proc target(p: Waggle, link: WaggleConnection, topic: seq[byte]): TopicStream =
  for session in p.streams:
    if session.link == link and not session.receiving and session.ready and
        session.topic == topic and not session.stream.closed:
      return session

proc enqueue(
    p: Waggle, link: WaggleConnection, topic: seq[byte], msg: ObjectPieces
): bool =
  if p.stopping:
    return false
  let session = p.target(link, topic)
  if session == nil:
    return false
  if msg.encodedSize() > p.maxMessageSize:
    p.notify(
      WaggleEventKind.InvalidData, link, topic, msg,
      "Outgoing message exceeds maximum length",
    )
    return false
  if link.queued >= p.maxQueued:
    p.notify(WaggleEventKind.FullQueue, link, topic)
    return false
  try:
    session.queue.addLastNoWait(msg)
    inc link.queued
    inc session.queued
    return true
  except AsyncQueueFullError:
    p.notify(WaggleEventKind.FullQueue, link, topic)
    return false

proc dispatch(
    p: Waggle, link: WaggleConnection, topic: seq[byte], tx: Transmission
): bool =
  if p.enqueue(link, topic, tx.message):
    tx.commit()
    true
  else:
    false

proc config(p: Waggle, topic: seq[byte]): TopicConfig =
  p.topicConfigs.getOrDefault(topic, p.defaultTopicConfig)

proc setTopicConfig*(
    p: Waggle, topic: seq[byte], config: TopicConfig
): Result[void, string] =
  if config.publishFanout <= 0 or config.forwardFanout <= 0 or config.gossipFanout < 0:
    return err("Waggle publish/forward fanouts must be positive and gossip nonnegative")
  if topic.len > p.maxTopicSize or
      (not p.topicConfigs.hasKey(topic) and p.topicConfigs.len >= p.maxTopics):
    return err("Waggle topic configuration limit reached")
  p.topicConfigs[topic] = config
  ok()

proc eligible(
    p: Waggle, topic: seq[byte], exceptLink: WaggleConnection = nil
): seq[WaggleConnection] =
  var connections: seq[WaggleConnection]
  for link in p.links:
    if link != exceptLink and p.target(link, topic) != nil:
      connections.add(link)
  p.random.shuffle(connections)
  return connections

proc advertise(
    p: Waggle, topic, objectId: seq[byte], exceptLink: WaggleConnection = nil
): int =
  var sent = 0
  var discovered = 0
  for link in p.eligible(topic, exceptLink):
    let view = p.state.peerView(topic, link.id, objectId)
    # Existing observers receive every change; discovery has its own budget.
    if not view.advertised and (
      view.known or discovered >= p.config(topic).gossipFanout
    ):
      continue
    let prepared = p.state.prepare(
      topic, link.id, link.muxer.connection.peerId, objectId, metadataOnly = true
    )
    if prepared.isErr:
      p.notify(
        WaggleEventKind.InvalidData,
        link,
        topic,
        ObjectPieces(objectId: objectId),
        prepared.error,
      )
    elif prepared.get().isSome and p.dispatch(link, topic, prepared.get().get()):
      inc sent
      if not view.advertised:
        inc discovered
  return sent

proc removeObject*(p: Waggle, topic, objectId: seq[byte]): bool =
  ## Forget the snapshot and peer views. Already queued transmissions are retained.
  p.state.removeObject(topic, objectId)

proc publish*(p: Waggle, topic: seq[byte], shard: WaggleShard): Result[int, string] =
  ## Cache a current snapshot and queue initial publication or selective forwarding.
  ## Updated snapshots also advertise metadata to observers and discovery peers.
  if p.stopping or shard == nil:
    return err("Waggle is stopped or the shard is nil")
  let candidates = p.eligible(topic)
  if candidates.len == 0:
    return err("No peers subscribed to the topic")
  let id = shard.objectId()
  let existing = p.state.hasLocal(topic, id)
  let changed = ?p.state.store(topic, shard)
  var sent = 0
  var seeded = 0
  var forwarded = 0
  var attempted = false
  # Forwarding uses known peer state; initial publication may seed unknown peers.
  for link in candidates:
    let known = p.state.peerView(topic, link.id, id).known
    if existing and changed and not known:
      continue
    let forwarding = existing and known
    let limit =
      if forwarding:
        p.config(topic).forwardFanout
      else:
        p.config(topic).publishFanout
    let payloads = if forwarding: forwarded else: seeded
    let prepared = p.state.prepare(topic, link.id, link.muxer.connection.peerId, id)
    if prepared.isErr:
      attempted = true
      p.notify(
        WaggleEventKind.InvalidData,
        link,
        topic,
        ObjectPieces(objectId: id),
        prepared.error,
      )
    elif prepared.get().isSome:
      let tx = prepared.get().get()
      let budgeted = not forwarding or tx.message.pieces.isSome
      if budgeted and payloads >= limit:
        continue
      attempted = true
      if p.dispatch(link, topic, tx):
        inc sent
        if budgeted:
          if forwarding:
            inc forwarded
          else:
            inc seeded
  if existing:
    sent += p.advertise(topic, id)
  if sent == 0 and (changed or attempted):
    err("Message not sent on any connection")
  else:
    ok(sent)

proc processReceived(
    p: Waggle, link: WaggleConnection, topic: seq[byte], msg: ObjectPieces
) =
  if topic notin p.topics or p.stopping or link notin p.links:
    return
  let action = p.state.received(topic, link.id, link.muxer.connection.peerId, msg)
  if action.isErr:
    p.notify(WaggleEventKind.InvalidData, link, topic, msg, action.error)
    return
  if not action.get().active:
    return
  if action.get().reply.isSome:
    discard p.dispatch(link, topic, action.get().reply.get())
  if action.get().emit:
    p.notify(WaggleEventKind.Received, link, topic, msg)
  discard p.advertise(topic, msg.objectId, link)

proc beginReceiver(p: Waggle, link: WaggleConnection, topic: seq[byte]) =
  if link.readers.hasKey(topic):
    return
  let peer = link.muxer.connection.peerId
  let pending = p.pendingSlots(peer)
  let activePeer = p.streams.countIt(it.stream.peerId == peer)
  if p.streams.len + pending.total >= p.maxStreams or
      activePeer + pending.perPeer >= p.maxStreamsPerPeer:
    p.notify(
      WaggleEventKind.StreamFailed, link, topic, reason = "Waggle stream limit reached"
    )
    return
  inc link.opening
  proc receive() {.async: (raises: [CancelledError]).} =
    var stream: Stream
    var opening = true
    try:
      stream = await link.muxer.newStream()
      if not (await MultistreamSelect.new().select(stream, WaggleCodec)):
        raise newException(WaggleError, "Peer does not support Waggle")
      proc onPieces(
          peer: PeerId, topic: seq[byte], msg: ObjectPieces
      ) {.async: (raises: [CancelledError]).} =
        p.processReceived(link, topic, msg)

      dec link.opening
      opening = false
      await p.subscribe(stream, topic, onPieces)
    except InvalidVarintError, MaxSizeError:
      let kind =
        if opening: WaggleEventKind.StreamFailed else: WaggleEventKind.InvalidData
      p.notify(kind, link, topic, reason = getCurrentExceptionMsg())
    except WaggleDecodeError as exc:
      p.notify(WaggleEventKind.InvalidData, link, topic, reason = exc.msg)
    except LPError as exc:
      p.notify(WaggleEventKind.StreamFailed, link, topic, reason = exc.msg)
    finally:
      if opening:
        dec link.opening
      if stream != nil:
        await stream.reset()

  link.readers[topic] = receive()

proc subscribe*(p: Waggle, topic: seq[byte]): Result[bool, string] =
  ## Subscribe on every current and future registered connection.
  if p.stopping:
    return err("Waggle has stopped")
  if topic.len > p.maxTopicSize:
    return err("Waggle topic exceeds maximum length")
  if p.topicWhitelist.isSome and topic notin p.topicWhitelist.get():
    return err("Topic is not allowed")
  if topic in p.topics:
    return ok(false)
  if p.topics.len >= p.maxTopics:
    return err("Waggle topic subscription limit reached")
  p.topics.incl(topic)
  for link in p.links:
    p.beginReceiver(link, topic)
  ok(true)

proc unsubscribe*(p: Waggle, topic: seq[byte]): Future[bool] {.async: (raises: []).} =
  if topic notin p.topics:
    return false
  p.topics.excl(topic)
  p.state.removeTopic(topic)
  var readers: seq[Future[void]]
  for link in p.links:
    let task = link.readers.getOrDefault(topic)
    link.readers.del(topic)
    if task != nil:
      readers.add(task)
  for task in readers:
    await task.cancelAndWait()
  return true

proc removeConnection(p: Waggle, link: WaggleConnection) {.async: (raises: []).} =
  p.links.keepItIf(it != link)
  p.state.removeConnection(link.id)
  let sessions = p.streams.filterIt(it.link == link)
  for session in sessions:
    await session.stream.reset()
  let readers = toSeq(link.readers.values)
  link.readers.clear()
  for task in readers:
    await task.cancelAndWait()

proc addConnection*(p: Waggle, muxer: Muxer): Result[bool, string] =
  ## Register an upgraded muxer whose stream handler routes incoming protocols.
  ## Pass a switch to Waggle.new for automatic connection discovery.
  if p.stopping or muxer == nil or muxer.handler == nil or muxer.connection.closed:
    return err("Waggle requires a live running muxer")
  for link in p.links:
    if link.muxer == muxer:
      return ok(false)
  if p.links.len >= p.maxStreams:
    return err("Waggle connection limit reached")
  inc p.nextConnectionId
  let link = WaggleConnection(id: p.nextConnectionId, muxer: muxer)
  p.links.add(link)
  for topic in p.topics:
    p.beginReceiver(link, topic)
  proc monitor() {.async: (raises: [CancelledError]).} =
    await muxer.handler.join()
    await p.removeConnection(link)

  p.track(monitor())
  ok(true)

proc refreshConnections(p: Waggle) =
  for connections in p.manager.getConnections().values:
    for muxer in connections:
      let added = p.addConnection(muxer)
      if added.isErr:
        trace "Waggle connection not registered", reason = added.error

proc attach(p: Waggle, manager: ConnManager) =
  doAssert manager != nil and p.manager == nil
  p.manager = manager
  proc onConnection(
      peer: PeerId, event: ConnEvent
  ) {.async: (raises: [CancelledError]).} =
    if not p.stopping:
      p.refreshConnections()

  p.connHandler = onConnection
  manager.addConnEventHandler(onConnection, ConnEventKind.Connected)
  manager.addConnEventHandler(onConnection, ConnEventKind.Disconnected)
  p.refreshConnections()

method start*(p: Waggle) {.async: (raises: [CancelledError]).} =
  p.stopping = false
  if p.manager != nil:
    p.manager.addConnEventHandler(p.connHandler, ConnEventKind.Connected)
    p.manager.addConnEventHandler(p.connHandler, ConnEventKind.Disconnected)
    p.refreshConnections()
  await procCall LPProtocol(p).start()

method stop*(p: Waggle) {.async: (raises: []).} =
  p.stopping = true
  if p.manager != nil:
    p.manager.removeConnEventHandler(p.connHandler, ConnEventKind.Connected)
    p.manager.removeConnEventHandler(p.connHandler, ConnEventKind.Disconnected)
  let links = p.links
  for link in links:
    await p.removeConnection(link)
  let streams = p.streams
  p.streams = @[]
  for session in streams:
    await session.stream.reset()
  let tasks = p.tasks
  p.tasks = @[]
  for task in tasks:
    await task.cancelAndWait()
  p.state = WaggleState.new(p.maxCachedObjects, p.maxTopics, p.objectLifetime)
  await procCall LPProtocol(p).stop()
