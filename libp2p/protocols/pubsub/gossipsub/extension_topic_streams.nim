# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[tables, deques, sequtils]
import chronos, results
import ../../../stream/connection
import ../rpc/[messages, topicrpc]

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
      var data = (await s.popNext(w)).valueOr:
        return
      let size = data.len
      try:
        await w.stream.writeLp(data)
      finally:
        data = @[]
        s.queuedBytes -= size
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

proc closeTopic*(
    s: TopicStreams, topic: string, incoming = false
) {.async: (raises: []).} =
  if s == nil:
    return
  let w = s.writers.getOrDefault(topic)
  if w != nil:
    w.closing = true
    await w.task.cancelAndWait()
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
  try:
    var headerBytes = await s.readHeader(reader).wait(TopicStreamHeaderTimeout)
    let header = TopicRPCHeader.decode(move(headerBytes)).valueOr:
      s.fail()
      return
    if header.topic.isNone or header.topic.get().len == 0:
      s.fail()
      return
    reader.topic = header.topic.get()
    var count = 0
    for r in s.readers:
      if r.topic == reader.topic:
        inc count
    if count > 3:
      s.penalize()
      return
    while not s.stopped:
      let length = await stream.readVarint()
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
        await stream.readExactly(addr data[0], size)
        var decoded = TopicRPC.decode(move(data)).valueOr:
          s.fail()
          return
        var rpc = move(decoded).toRPC(reader.topic).valueOr:
            s.fail()
            return
        await s.receive(move(rpc), size)
      finally:
        s.incomingBytes -= size
  except MaxSizeError:
    s.penalize()
  except LPStreamError, AsyncTimeoutError:
    discard
  finally:
    await stream.reset()
    s.incomingBytes -= reader.headerBytes
    s.readers.keepItIf(it != reader)

proc stop*(s: TopicStreams) {.async: (raises: []).} =
  if s == nil:
    return
  s.stopped = true
  var tasks: seq[Future[void]]
  for w in s.writers.values:
    w.closing = true
    tasks.add(w.task)
  await noCancel allFutures(tasks.mapIt(it.cancelAndWait()))
  let readers = s.readers
  await noCancel allFutures(readers.mapIt(it.stream.close()))
