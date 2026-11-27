# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[tables, deques, sequtils]
import chronos, chronicles, metrics
import ../../../results
import ../../../stream/connection
import ../../../peerid
import ./extensions_types
import ../outboundqueue
import ../rpc/[messages, message, protobuf, topicrpc]

export topicrpc, outboundqueue

const
  TopicStreamsCodec* = "/gsts/v0beta"
  TopicStreamDialTimeout = 5.seconds
  TopicStreamHeaderTimeout = 1.seconds

logScope:
  topics = "libp2p pubsub topic-streams"

declareCounter(
  libp2p_gossipsub_topic_stream_frames_rejected,
  "outgoing topic frames rejected before enqueueing",
  labels = ["reason"],
)

when defined(libp2p_testing):
  export libp2p_gossipsub_topic_stream_frames_rejected

type
  TopicStreamsConfig* = object
    ## Experimental draft libp2p/specs#729. Limits apply per peer.
    ## The incoming byte budget must hold a maximum-size header and frame.
    ## Outgoing traffic shares the peer's outbound queue policy.
    maxIncomingStreams*: int = 64 # includes pending headers
    ## Custom and direct writers for the same topic each consume a stream slot.
    maxOutgoingStreams*: int = 64 # includes pending dials
    maxIncomingBytes*: int = 8 * 1024 * 1024 # in-flight frames and retained headers

  TopicStreamDial* =
    proc(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).}
  TopicStreamReceive* = proc(msg: sink RPCMsg, size: int): Future[void] {.
    async: (raises: [CancelledError])
  .}

  TopicWriterKey = tuple[topic: string, custom: bool]

  TopicFrame = object
    data: seq[byte]
    priority: MessagePriority

  TopicWriter = ref object
    stream: Stream
    header: seq[byte]
    headerBytes: int
    headerPriority: MessagePriority
    pending: array[MessagePriority, Deque[seq[byte]]]
    wake: AsyncEvent
    task: Future[void]
    monitor: Future[void]
    closing: bool

  TopicReader = ref object
    stream: Stream
    topic: string
    headerBytes: int

  TopicStreams* = ref object
    config: TopicStreamsConfig
    active: bool
    receivedControl: bool
    stopped: bool
    maxMessageSize: int
    queue: OutboundQueue
    eviction: QueueEviction
    incomingBytes: int
    writers: Table[TopicWriterKey, TopicWriter]
    readers: seq[TopicReader]
    dial: TopicStreamDial
    receive: TopicStreamReceive
    violation: proc() {.gcsafe, raises: [].}
    penalizePeer: proc() {.gcsafe, raises: [].}

  TopicStreamsExtension* = ref object
    config: Opt[TopicStreamsConfig]
    peers: Table[PeerId, TopicStreams]
    updatePeerBehaviorPenalty: UpdatePeerBehaviorPenaltyProc

func validate*(config: TopicStreamsConfig): Result[void, cstring] =
  if config.maxIncomingStreams < 3 or config.maxOutgoingStreams <= 0 or
      config.maxIncomingBytes <= 0:
    return err("gossipsub: invalid topic stream limits")
  ok()

func validate*(config: TopicStreamsConfig, maxMessageSize: int): Result[void, cstring] =
  ?config.validate()
  # Headers and frames are each bounded by maxMessageSize and share the budget.
  if maxMessageSize > config.maxIncomingBytes div 2:
    return err("gossipsub: maxIncomingBytes must be at least twice maxMessageSize")
  ok()

proc evictQueued(s: TopicStreams, priority: MessagePriority, amount: int): int

proc new*(
    T: type TopicStreams,
    config: TopicStreamsConfig,
    maxMessageSize: int,
    dial: TopicStreamDial,
    receive: TopicStreamReceive,
    violation, penalize: proc() {.gcsafe, raises: [].},
    queue: OutboundQueue,
): T =
  let state = T(
    config: config,
    queue: queue,
    maxMessageSize: maxMessageSize,
    dial: dial,
    receive: receive,
    violation: violation,
    penalizePeer: penalize,
  )

  state.eviction = proc(
      priority: MessagePriority, amount: int
  ): int {.gcsafe, raises: [].} =
    state.evictQueued(priority, amount)
  queue.evictTopics = state.eviction
  state

func isActive*(s: TopicStreams): bool =
  not s.isNil and not s.stopped and not s.queue.failed and s.active

proc fail(s: sink TopicStreams, reason: string) =
  # Keep the transport alive while the violation callback disconnects the peer.
  trace "topic stream protocol violation", reason
  if not s.stopped:
    s.stopped = true
    for w in s.writers.values:
      w.closing = true
      w.wake.fire()
    s.violation()

proc penalize(s: TopicStreams, reason: string, topic = "") =
  trace "topic stream limit exceeded", reason, topic
  s.penalizePeer()

proc negotiate*(s: TopicStreams, rpc: RPCMsg): bool =
  ## Called only for control-stream RPCs, before application processing.
  if s.stopped:
    return false
  let ext = rpc.control.get(ControlMessage()).extensions
  if not s.receivedControl:
    let supported = ext.get(ControlExtensions()).topicStreams.get(false)
    if s.active and not supported:
      s.fail("peer denied support after opening a topic stream")
      return false
    s.active = supported
    s.receivedControl = true
  elif ext.isSome and ext.get().topicStreams.get(false) != s.active:
    s.fail("peer changed advertised topic stream support")
    return false
  if s.active and (rpc.messages.len > 0 or rpc.partialMessageExtension.isSome):
    s.fail("application payload received on control stream")
    return false
  true

proc releaseFrame(
    s: TopicStreams, priority: MessagePriority, size: int, queued: bool
): bool =
  s.queue.release(
    priority,
    size,
    topicCount = ord(queued or priority == High),
    evictableBytes = (if queued and priority != High: size else: 0),
  )

proc discardQueued(s: TopicStreams, w: TopicWriter) =
  for priority in MessagePriority:
    for data in w.pending[priority]:
      discard s.releaseFrame(priority, data.len, true)
    w.pending[priority].clear()

proc evictQueued(s: TopicStreams, priority: MessagePriority, amount: int): int =
  ## Evicts at least `amount` bytes when possible; may overshoot by one frame.
  if priority == High:
    return 0
  var freed = 0
  for w in s.writers.values:
    while w.pending[priority].len > 0 and freed < amount:
      let data = w.pending[priority].popFirst()
      if not s.releaseFrame(priority, data.len, true):
        return freed
      freed += data.len
      if s.queue.evicted != nil:
        s.queue.evicted(priority, data.len)
    if freed >= amount:
      break
  return freed

proc monitorWriter(s: TopicStreams, w: TopicWriter) {.async: (raises: []).} =
  try:
    var data: byte
    if (await w.stream.readOnce(addr data, 1)) > 0:
      s.fail("topic stream responder wrote application bytes")
  except CancelledError:
    return
  except LPStreamError:
    discard
  w.closing = true
  w.wake.fire()
  await w.stream.close()

proc popNext(
    s: TopicStreams, w: TopicWriter
): Future[Opt[TopicFrame]] {.async: (raises: [CancelledError]).} =
  while not s.stopped and not s.queue.failed and not w.closing:
    for priority in MessagePriority:
      if w.pending[priority].len > 0:
        return
          Opt.some(TopicFrame(data: w.pending[priority].popFirst(), priority: priority))
    await w.wake.wait()
    w.wake.clear()
  return Opt.none(TopicFrame)

proc writeLoop(
    s: TopicStreams, key: TopicWriterKey, w: TopicWriter, dial: TopicStreamDial
) {.async: (raises: []).} =
  try:
    w.stream = await dial().wait(TopicStreamDialTimeout)
    if s.stopped or s.queue.failed or w.closing:
      return
    w.monitor = s.monitorWriter(w)
    await w.stream.writeLp(w.header)
    w.header = @[]
    while not s.stopped and not s.queue.failed and not w.closing:
      let frame = (await s.popNext(w)).valueOr:
        return
      if frame.priority != High:
        if not s.queue.release(
          frame.priority, 0, topicCount = 1, evictableBytes = frame.data.len
        ):
          return
      try:
        await w.stream.writeLp(frame.data)
      finally:
        discard s.releaseFrame(frame.priority, frame.data.len, false)
  except CancelledError, LPStreamError, AsyncTimeoutError:
    discard
  finally:
    w.closing = true
    var messages = 0
    for pending in w.pending:
      messages += pending.len
    if messages > 0:
      trace "discarding queued topic frames as writer closes",
        topic = key.topic, messages
    s.discardQueued(w)
    w.header = @[]
    if w.monitor != nil:
      await w.monitor.cancelAndWait()
    if w.stream != nil:
      await w.stream.close()
    discard s.queue.release(w.headerPriority, w.headerBytes)
    # Keep the entry until close completes: replacement must close before dial.
    if s.writers.getOrDefault(key) == w:
      s.writers.del(key)

proc sendTopic*(
    s: TopicStreams,
    topic: string,
    data: sink seq[byte],
    priority: MessagePriority,
    customDial: TopicStreamDial = nil,
) =
  if s.stopped or s.queue.failed or s.queue.admit == nil or not s.active:
    libp2p_gossipsub_topic_stream_frames_rejected.inc(labelValues = ["inactive"])
    return
  if data.len == 0 or data.len > s.maxMessageSize:
    trace "dropping invalid outgoing topic frame", topic, size = data.len
    libp2p_gossipsub_topic_stream_frames_rejected.inc(labelValues = ["invalid_frame"])
    return
  let key = (topic: topic, custom: customDial != nil)
  var w = s.writers.getOrDefault(key)
  var header: seq[byte]
  if w == nil:
    if s.writers.len >= s.config.maxOutgoingStreams:
      trace "dropping outgoing topic frame because stream limit is reached", topic
      libp2p_gossipsub_topic_stream_frames_rejected.inc(labelValues = ["stream_limit"])
      return
    header = TopicRPCHeader(topic: Opt.some(topic)).encode()
    if header.len > s.maxMessageSize:
      trace "dropping outgoing topic frame because header exceeds message limit", topic
      libp2p_gossipsub_topic_stream_frames_rejected.inc(labelValues = ["header_limit"])
      return
  elif w.closing:
    trace "dropping outgoing topic frame while writer closes", topic
    libp2p_gossipsub_topic_stream_frames_rejected.inc(labelValues = ["writer_closing"])
    return
  let action = s.queue.admit(priority, data.len + header.len)
  if not action.send:
    trace "dropping outgoing topic frame because queue is full", topic
    libp2p_gossipsub_topic_stream_frames_rejected.inc(labelValues = ["queue_full"])
    return
  if w == nil:
    w = TopicWriter(
      wake: newAsyncEvent(),
      header: header,
      headerBytes: header.len,
      headerPriority: action.priority,
    )
    s.queue.bytes[action.priority] += header.len
    s.writers[key] = w
  s.queue.bytes[action.priority] += data.len
  if action.priority != High:
    s.queue.evictableBytes[action.priority] += data.len
  inc s.queue.topicCounts[action.priority]
  w.pending[action.priority].addLast(move(data))
  if w.task == nil:
    w.task = s.writeLoop(key, w, if customDial == nil: s.dial else: customDial)
  else:
    w.wake.fire()

proc close(w: TopicWriter): Future[void] {.async: (raises: [], raw: true).} =
  w.closing = true
  w.task.cancelAndWait()

proc closeTopic*(
    s: TopicStreams, topic: string, incoming = false
) {.async: (raises: []).} =
  if s == nil:
    return
  for custom in [false, true]:
    let w = s.writers.getOrDefault((topic, custom))
    if w != nil:
      await w.close()
  if incoming:
    let readers = s.readers
    for r in readers:
      if r.topic == topic:
        await r.stream.close()

proc readHeader(
    s: TopicStreams, reader: TopicReader
): Future[LPResult[seq[byte]]] {.async: (raises: [CancelledError, LPStreamError]).} =
  let length = await reader.stream.readVarint()
  if length > uint64(s.maxMessageSize):
    raise newException(MaxSizeError, "topic header exceeds maximum message size")
  if length > uint64(s.config.maxIncomingBytes - s.incomingBytes):
    trace "resetting topic stream because incoming header budget is full"
    return err("topic header exceeds remaining byte budget")
  let size = int(length)
  s.incomingBytes += size
  reader.headerBytes = size
  var data = newSeqUninit[byte](size)
  if size > 0:
    await reader.stream.readExactly(addr data[0], size)
  return ok(data)

proc readTopic*(s: TopicStreams, stream: Stream) {.async: (raises: [CancelledError]).} =
  if s.stopped:
    await stream.reset()
    return
  if s.readers.len >= s.config.maxIncomingStreams:
    s.penalize("incoming stream limit reached")
    await stream.reset()
    return
  if s.receivedControl and not s.active:
    s.fail("topic stream opened without negotiated support")
    await stream.reset()
    return
  s.active = true
  let reader = TopicReader(stream: stream)
  s.readers.add(reader)
  defer:
    await stream.reset()
    s.incomingBytes -= reader.headerBytes
    s.readers.keepItIf(it != reader)

  var headerBytes: seq[byte]
  try:
    headerBytes = (await s.readHeader(reader).wait(TopicStreamHeaderTimeout)).valueOr:
      return
  except MaxSizeError:
    s.penalize("topic stream header exceeds byte limit")
    return
  except LPStreamError, AsyncTimeoutError:
    return
  let header = TopicRPCHeader.decode(move(headerBytes)).valueOr:
    s.fail("invalid topic stream header")
    return
  if header.topic.isNone or header.topic.get().len == 0:
    s.fail("topic stream header omitted topic")
    return
  reader.topic = header.topic.get()
  if s.readers.countIt(it.topic == reader.topic) > 3:
    s.penalize("too many streams for topic", reader.topic)
    return
  while not s.stopped:
    let length =
      try:
        await stream.readVarint()
      except LPStreamError:
        return
    if s.stopped:
      return
    if length == 0:
      s.fail("empty topic RPC frame")
      return
    if length > uint64(s.maxMessageSize):
      s.penalize("incoming frame exceeds maximum message size", reader.topic)
      return
    if length > uint64(s.config.maxIncomingBytes - s.incomingBytes):
      trace "resetting topic stream because incoming frame budget is full",
        topic = reader.topic
      return
    let size = int(length)
    s.incomingBytes += size
    try:
      var data = newSeqUninit[byte](size)
      try:
        await stream.readExactly(addr data[0], size)
      except LPStreamError:
        return
      if s.stopped:
        return
      var decoded = TopicRPC.decode(move(data)).valueOr:
        s.fail("invalid topic RPC frame")
        return
      var rpc = move(decoded).toRPC(reader.topic).valueOr:
          s.fail("invalid topic RPC payload")
          return
      await s.receive(move(rpc), size)
    finally:
      s.incomingBytes -= size

proc stop*(s: TopicStreams) {.async: (raises: []).} =
  if s == nil:
    return
  s.stopped = true
  let writers = toSeq(s.writers.values)
  await noCancel allFutures(writers.mapIt(it.close()))
  let readers = move s.readers
  await noCancel allFutures(readers.mapIt(it.stream.close()))
  if s.queue.evictTopics == s.eviction:
    s.queue.evictTopics = nil
  s.eviction = nil

type PreparedTopicRPC* = object
  control: seq[byte]
  payloads: seq[tuple[topic: string, data: seq[byte]]]

func isZero*(msg: PreparedTopicRPC): bool =
  msg.control.len == 0 and msg.payloads.len == 0

proc makePreparedTopicRPC*(msg: RPCMsg, anonymize: bool): PreparedTopicRPC =
  var payloads: seq[tuple[topic: string, data: seq[byte]]]
  for m in msg.messages:
    if m.data.len > 0:
      payloads.add((m.topic, m.anonymize(anonymize).topicRPC().encode()))
    else:
      trace "empty application message cannot use topic stream", topic = m.topic
  msg.partialMessageExtension.ifValue(partial):
    if partial.topicID.isSome:
      payloads.add((partial.topicID.get(), partial.topicRPC().encode()))
  var control = msg
  control.messages = @[]
  control.partialMessageExtension = Opt.none(PartialMessageExtensionRPC)
  PreparedTopicRPC(payloads: payloads, control: control.encode(anonymize))

proc sendTopicRPC*(
    s: TopicStreams,
    msg: PreparedTopicRPC,
    priority: MessagePriority,
    customDial: TopicStreamDial = nil,
): seq[byte] =
  for payload in msg.payloads:
    s.sendTopic(payload.topic, payload.data, priority, customDial)
  msg.control

proc new*(
    T: type TopicStreamsExtension,
    config: Opt[TopicStreamsConfig],
    updatePeerBehaviorPenalty: UpdatePeerBehaviorPenaltyProc,
): T =
  T(config: config, updatePeerBehaviorPenalty: updatePeerBehaviorPenalty)

proc initTopicStreams*(
    ext: TopicStreamsExtension,
    peerId: PeerId,
    maxMessageSize: int,
    dial: TopicStreamDial,
    receive: TopicStreamReceive,
    violation: proc() {.gcsafe, raises: [].},
    queue: OutboundQueue,
) =
  const TopicStreamBehaviorPenalty = 0.1
  ext.config.ifValue(config):
    proc penalize() {.gcsafe, raises: [].} =
      ext.updatePeerBehaviorPenalty(peerId, TopicStreamBehaviorPenalty)

    ext.peers[peerId] = TopicStreams.new(
      config, maxMessageSize, dial, receive, violation, penalize, queue
    )

proc peerHasTopicStreams*(ext: TopicStreamsExtension, peerId: PeerId): bool =
  ext.peers.getOrDefault(peerId).isActive()

proc negotiateTopicStreams*(
    ext: TopicStreamsExtension, peerId: PeerId, rpc: RPCMsg
): bool =
  ## Return whether the GossipSub RPC may be processed.
  ## Disabled topic streams create no transport state, so RPCs are allowed.
  ext.peers.withValue(peerId, streams):
    return streams[].negotiate(rpc)
  true

proc readTopicStream*(
    ext: TopicStreamsExtension, peerId: PeerId, stream: Stream
) {.async: (raises: [CancelledError]).} =
  let streams = ext.peers.getOrDefault(peerId)
  if streams.isNil:
    await stream.reset()
    return
  await streams.readTopic(stream)

proc sendTopicRPC*(
    ext: TopicStreamsExtension,
    peerId: PeerId,
    msg: PreparedTopicRPC,
    priority: MessagePriority,
    customDial: TopicStreamDial = nil,
): seq[byte] =
  ext.peers.withValue(peerId, streams):
    return streams[].sendTopicRPC(msg, priority, customDial)

proc closeTopicStreams*(
    ext: TopicStreamsExtension, topic: string, incoming = false
): seq[Future[void]] =
  var futures = newSeqOfCap[Future[void]](ext.peers.len)
  for streams in ext.peers.values:
    futures.add(streams.closeTopic(topic, incoming))
  return futures

proc closeTopicStreams*(
    ext: TopicStreamsExtension, peerId: PeerId, topic: string
): Future[void] {.async: (raises: []).} =
  await ext.peers.getOrDefault(peerId).closeTopic(topic)

proc stopTopicStreams*(
    ext: TopicStreamsExtension, peerId: PeerId
) {.async: (raises: []).} =
  var streams: TopicStreams
  # Remove before awaiting so a reconnect cannot inherit this peer's transport.
  if ext.peers.pop(peerId, streams):
    await streams.stop()
