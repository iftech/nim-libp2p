# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[tables, deques, sequtils]
import chronos, results
import ../../../stream/connection
import ../../../peerid
import ./extensions_types
import ../rpc/[messages, message, protobuf, topicrpc]

export topicrpc

const
  TopicStreamsCodec* = "/gsts/v0beta"
  TopicStreamDialTimeout = 5.seconds
  TopicStreamHeaderTimeout = 1.seconds

type
  TopicStreamsConfig* = object
    ## Experimental draft libp2p/specs#729. Limits apply per peer.
    maxStreams*: int = 128 # incoming and outgoing, including pending headers/dials
    maxQueuedBytes*: int = 8 * 1024 * 1024 # queued/in-flight data and stream headers
    maxIncomingBytes*: int = 8 * 1024 * 1024 # in-flight frames and retained headers
    maxQueuedMessages*: int = 1024

  TopicStreamDial* =
    proc(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).}
  TopicStreamReceive* = proc(msg: sink RPCMsg, size: int): Future[void] {.
    async: (raises: [CancelledError])
  .}

  TopicWriter = ref object
    stream: Stream
    header: seq[byte]
    headerBytes: int
    medium, low: Deque[seq[byte]]
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
    queuedBytes, queuedMessages, incomingBytes: int
    writers: Table[string, TopicWriter]
    readers: seq[TopicReader]
    dial: TopicStreamDial
    receive: TopicStreamReceive
    violation: proc() {.gcsafe, raises: [].}
    penalize: proc() {.gcsafe, raises: [].}

  TopicStreamsExtension* = ref object
    config: Opt[TopicStreamsConfig]
    peers: Table[PeerId, TopicStreams]
    updatePeerBehaviorPenalty: UpdatePeerBehaviorPenaltyProc

func validate*(config: TopicStreamsConfig): Result[void, cstring] =
  if config.maxStreams < 3 or config.maxQueuedBytes <= 0 or config.maxIncomingBytes <= 0 or
      config.maxQueuedMessages <= 0:
    return err("gossipsub: invalid topic stream limits")
  ok()

proc new*(
    T: type TopicStreams,
    config: TopicStreamsConfig,
    maxMessageSize: int,
    dial: TopicStreamDial,
    receive: TopicStreamReceive,
    violation, penalize: proc() {.gcsafe, raises: [].},
): T =
  T(
    config: config,
    maxMessageSize: maxMessageSize,
    dial: dial,
    receive: receive,
    violation: violation,
    penalize: penalize,
  )

func isActive*(s: TopicStreams): bool =
  not s.isNil and not s.stopped and s.active

proc fail(s: TopicStreams) =
  if not s.stopped:
    s.stopped = true
    for w in s.writers.values:
      w.closing = true
      w.wake.fire()
    s.violation()

proc negotiate*(s: TopicStreams, rpc: RPCMsg): bool =
  ## Called only for control-stream RPCs, before application processing.
  if s.stopped:
    return false
  let ext = rpc.control.get(ControlMessage()).extensions
  if not s.receivedControl:
    let supported = ext.get(ControlExtensions()).topicStreams.get(false)
    if s.active and not supported:
      s.fail()
      return false
    s.active = supported
    s.receivedControl = true
  elif ext.isSome and ext.get().topicStreams.get(false) != s.active:
    s.fail()
    return false
  if s.active and (rpc.messages.len > 0 or rpc.partialMessageExtension.isSome):
    s.fail()
    return false
  true

proc discardQueued(s: TopicStreams, w: TopicWriter) =
  for data in w.medium:
    s.queuedBytes -= data.len
    dec s.queuedMessages
  for data in w.low:
    s.queuedBytes -= data.len
    dec s.queuedMessages
  w.medium.clear()
  w.low.clear()

proc monitorWriter(s: TopicStreams, w: TopicWriter) {.async: (raises: []).} =
  try:
    var data: byte
    if (await w.stream.readOnce(addr data, 1)) > 0:
      s.fail() # The responder must never write application bytes.
  except CancelledError:
    return
  except LPStreamError:
    discard
  w.closing = true
  w.wake.fire()
  await w.stream.close()

proc popNext(
    s: TopicStreams, w: TopicWriter
): Future[Opt[seq[byte]]] {.async: (raises: [CancelledError]).} =
  while not s.stopped and not w.closing and w.medium.len == 0 and w.low.len == 0:
    await w.wake.wait()
    w.wake.clear()
  if s.stopped or w.closing:
    return Opt.none(seq[byte])
  if w.medium.len > 0:
    return Opt.some(w.medium.popFirst())
  return Opt.some(w.low.popFirst())

proc writeLoop(s: TopicStreams, topic: string, w: TopicWriter) {.async: (raises: []).} =
  try:
    w.stream = await s.dial().wait(TopicStreamDialTimeout)
    if s.stopped or w.closing:
      return
    w.monitor = s.monitorWriter(w)
    await w.stream.writeLp(w.header)
    w.header = @[]
    while not s.stopped and not w.closing:
      let data = (await s.popNext(w)).valueOr:
        return
      try:
        await w.stream.writeLp(data)
      finally:
        s.queuedBytes -= data.len
        dec s.queuedMessages
  except CancelledError, LPStreamError, AsyncTimeoutError:
    discard
  finally:
    w.closing = true
    s.discardQueued(w)
    w.header = @[]
    if w.monitor != nil:
      await w.monitor.cancelAndWait()
    if w.stream != nil:
      await w.stream.close()
    s.queuedBytes -= w.headerBytes
    # Keep the entry until close completes: replacement must close before dial.
    if s.writers.getOrDefault(topic) == w:
      s.writers.del(topic)

proc sendTopic*(s: TopicStreams, topic: string, data: sink seq[byte], medium: bool) =
  if s.stopped or not s.active or data.len == 0 or data.len > s.maxMessageSize:
    return
  if data.len > s.config.maxQueuedBytes - s.queuedBytes or
      s.queuedMessages >= s.config.maxQueuedMessages:
    return
  var w = s.writers.getOrDefault(topic)
  if w == nil:
    if s.writers.len + s.readers.len >= s.config.maxStreams:
      return
    let header = TopicRPCHeader(topic: Opt.some(topic)).encode()
    if header.len > s.maxMessageSize or
        header.len > s.config.maxQueuedBytes - s.queuedBytes - data.len:
      return
    w = TopicWriter(wake: newAsyncEvent(), header: header, headerBytes: header.len)
    s.queuedBytes += header.len
    s.writers[topic] = w
  elif w.closing:
    return
  s.queuedBytes += data.len
  inc s.queuedMessages
  if medium:
    w.medium.addLast(move(data))
  else:
    w.low.addLast(move(data))
  if w.task == nil:
    w.task = s.writeLoop(topic, w)
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
  let w = s.writers.getOrDefault(topic)
  if w != nil:
    await w.close()
  if incoming:
    let readers = s.readers
    for r in readers:
      if r.topic == topic:
        await r.stream.close()

proc readHeader(
    s: TopicStreams, reader: TopicReader
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
  let length = await reader.stream.readVarint()
  if length > uint64(s.maxMessageSize) or
      length > uint64(s.config.maxIncomingBytes - s.incomingBytes):
    raise newException(MaxSizeError, "topic header exceeds byte limit")
  let size = int(length)
  s.incomingBytes += size
  reader.headerBytes = size
  var data = newSeqUninit[byte](size)
  if size > 0:
    await reader.stream.readExactly(addr data[0], size)
  return data

proc readTopic*(s: TopicStreams, stream: Stream) {.async: (raises: [CancelledError]).} =
  if s.stopped:
    await stream.reset()
    return
  if s.writers.len + s.readers.len >= s.config.maxStreams:
    # Only blame the peer when its incoming streams alone exhausted the limit.
    if s.readers.len >= s.config.maxStreams:
      s.penalize()
    await stream.reset()
    return
  if s.receivedControl and not s.active:
    s.fail()
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
    headerBytes = await s.readHeader(reader).wait(TopicStreamHeaderTimeout)
  except MaxSizeError:
    s.penalize()
    return
  except LPStreamError, AsyncTimeoutError:
    return
  let header = TopicRPCHeader.decode(move(headerBytes)).valueOr:
    s.fail()
    return
  if header.topic.isNone or header.topic.get().len == 0:
    s.fail()
    return
  reader.topic = header.topic.get()
  if s.readers.countIt(it.topic == reader.topic) > 3:
    s.penalize()
    return
  while not s.stopped:
    let length =
      try:
        await stream.readVarint()
      except LPStreamError:
        return
    if length == 0:
      s.fail()
      return
    if length > uint64(s.maxMessageSize) or
        length > uint64(s.config.maxIncomingBytes - s.incomingBytes):
      s.penalize()
      return
    let size = int(length)
    s.incomingBytes += size
    try:
      var data = newSeqUninit[byte](size)
      try:
        await stream.readExactly(addr data[0], size)
      except LPStreamError:
        return
      var decoded = TopicRPC.decode(move(data)).valueOr:
        s.fail()
        return
      var rpc = move(decoded).toRPC(reader.topic).valueOr:
          s.fail()
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

type PreparedTopicRPC* = object
  control: seq[byte]
  payloads: seq[tuple[topic: string, data: seq[byte]]]

proc makePreparedTopicRPC*(msg: RPCMsg, anonymize: bool): PreparedTopicRPC =
  for m in msg.messages:
    if m.data.len > 0:
      result.payloads.add((m.topic, m.anonymize(anonymize).topicRPC().encode()))
  msg.partialMessageExtension.ifValue(partial):
    if partial.topicID.isSome:
      result.payloads.add((partial.topicID.get(), partial.topicRPC().encode()))
  var control = msg
  control.messages = @[]
  control.partialMessageExtension = Opt.none(PartialMessageExtensionRPC)
  result.control = control.encode(anonymize)

proc sendTopicRPC*(s: TopicStreams, msg: PreparedTopicRPC, medium: bool): seq[byte] =
  for payload in msg.payloads:
    s.sendTopic(payload.topic, payload.data, medium)
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
) =
  const TopicStreamBehaviorPenalty = 0.1
  ext.config.ifValue(config):
    proc penalize() {.gcsafe, raises: [].} =
      ext.updatePeerBehaviorPenalty(peerId, TopicStreamBehaviorPenalty)

    ext.peers[peerId] =
      TopicStreams.new(config, maxMessageSize, dial, receive, violation, penalize)

proc peerHasTopicStreams*(ext: TopicStreamsExtension, peerId: PeerId): bool =
  ext.peers.getOrDefault(peerId).isActive()

proc negotiateTopicStreams*(
    ext: TopicStreamsExtension, peerId: PeerId, rpc: RPCMsg
): bool =
  ## Return whether control RPC processing may continue; absent transports are ignored.
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
    ext: TopicStreamsExtension, peerId: PeerId, msg: PreparedTopicRPC, medium: bool
): seq[byte] =
  ext.peers.withValue(peerId, streams):
    return streams[].sendTopicRPC(msg, medium)

proc closeTopicStreams*(
    ext: TopicStreamsExtension, topic: string, incoming = false
): seq[Future[void]] =
  result = newSeqOfCap[Future[void]](ext.peers.len)
  for streams in ext.peers.values:
    result.add(streams.closeTopic(topic, incoming))

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
