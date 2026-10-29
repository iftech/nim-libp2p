# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import ../../../libp2p/[protocols/waggle, stream/bufferstream, varint]
import ../../tools/[unittest, crypto, bufferstream]

const topic = @[byte 0, 255, 1]

suite "Waggle wire messages":
  test "subscription uses field 1 with opaque bytes":
    let msg = TopicSubscription(topicId: topic)
    check msg.encode() == @[byte 0x0A, 3, 0, 255, 1]
    check TopicSubscription.decode(msg.encode()).get() == msg

  test "pieces use fields 2, 3 and 4":
    let msg = ObjectPieces(
      objectId: @[byte 1],
      piecesMetadata: Opt.some(@[byte 2]),
      pieces: Opt.some(@[byte 3]),
    )
    check msg.encode() == @[byte 0x12, 1, 1, 0x1A, 1, 2, 0x22, 1, 3]
    check msg.encodedSize() == msg.encode().len
    check ObjectPieces.decode(msg.encode()).get() == msg

  test "absent fields differ from present empty fields":
    let absent = ObjectPieces(objectId: @[])
    let present = ObjectPieces(
      objectId: @[],
      piecesMetadata: Opt.some(newSeq[byte]()),
      pieces: Opt.some(newSeq[byte]()),
    )
    check absent.encode() == @[byte 0x12, 0]
    check present.encode() == @[byte 0x12, 0, 0x1A, 0, 0x22, 0]
    check ObjectPieces.decode(absent.encode()).get() == absent
    check ObjectPieces.decode(present.encode()).get() == present

  test "missing required fields and truncated fields are rejected":
    check TopicSubscription.decode(@[]).isErr
    check TopicSubscription.decode(@[byte 0x0A, 2, 1]).isErr
    check ObjectPieces.decode(@[byte 0x1A, 0]).isErr
    check ObjectPieces.decode(@[byte 0x12, 1, 1, 0x22, 2, 1]).isErr

  test "unknown fields are ignored":
    let msg = ObjectPieces(objectId: @[byte 1])
    check ObjectPieces.decode(msg.encode() & @[byte 0x50, 1]).get() == msg

type TestStream = ref object of TestBufferStream
  readRequests: AsyncQueue[int]
  writes: AsyncQueue[seq[byte]]
  readFailure: ref LPStreamError

method readOnce(
    s: TestStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  await s.readRequests.addLast(nbytes)
  let count = await procCall BufferStream(s).readOnce(pbytes, nbytes)
  if s.readFailure != nil:
    raise s.readFailure
  return count

func frame(data: seq[byte]): seq[byte] =
  let prefix = PB.toBytes(uint64(data.len))
  @(prefix.toOpenArray()) & data

proc ignorePieces(
    peer: PeerId, t: seq[byte], msg: ObjectPieces
) {.async: (raises: [CancelledError]).} =
  discard

suite "Waggle direct streams":
  var
    waggle: Waggle
    streams: seq[TestStream]
    tasks: seq[Future[void]]

  proc openStream(peer: PeerId = PeerId.random()): TestStream =
    let writes = newAsyncQueue[seq[byte]]()
    proc write(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      await writes.addLast(data)

    let stream = TestStream.new(write)
    stream.peerId = peer
    stream.readRequests = newAsyncQueue[int]()
    stream.writes = writes
    streams.add(stream)
    stream

  proc handle(stream: TestStream): Future[void] =
    let pending = waggle.handler(stream, WaggleCodec)
    tasks.add(pending)
    pending

  proc receive(
      stream: TestStream, t: seq[byte] = topic, handler: PiecesHandler = ignorePieces
  ): Future[LPResult[void]] =
    let pending = waggle.subscribe(stream, t, handler)
    tasks.add(pending.join())
    pending

  proc handshake(stream: TestStream, t: seq[byte] = topic) {.async.} =
    await stream.pushData(frame(TopicSubscription(topicId: t).encode()))
    # The next read after the handshake observes admission without a polling timer.
    while stream.peerId notin waggle.subscribers(t):
      discard await stream.readRequests.popFirst()

  setup:
    waggle = Waggle.new()
    streams = @[]
    tasks = @[]

  asyncTeardown:
    await waggle.stop()
    for stream in streams:
      await stream.reset()
    for task in tasks:
      await task.cancelAndWait()
    checkTrackers()

  asyncTest "send and subscribers isolate topics and ignore pending or closed streams":
    let stream = openStream()
    discard handle(stream)
    await handshake(stream)
    let other = openStream()
    discard handle(other)
    await handshake(other, @[])
    let pending = openStream()
    discard handle(pending)
    discard await pending.readRequests.popFirst()
    let msg = ObjectPieces(objectId: @[byte 42])

    check:
      waggle.subscribers(topic) == @[stream.peerId]
      waggle.subscribers(@[]) == @[other.peerId]
      waggle.subscribers(@[byte 4]).len == 0
      not (await waggle.send(PeerId.random(), topic, msg)).get()
      not (await waggle.send(stream.peerId, @[byte 4], msg)).get()
      stream.writes.empty()
    check (await waggle.send(other.peerId, @[], msg)).get()
    check (await other.writes.popFirst()) == frame(msg.encode())
    check stream.writes.empty()

    await stream.reset()
    check:
      waggle.subscribers(topic).len == 0
      not (await waggle.send(stream.peerId, topic, msg)).get()

  asyncTest "send accepts the size limit and rejects a larger message without writing":
    let msg = ObjectPieces(objectId: @[byte 42], pieces: Opt.some(newSeq[byte](16)))
    waggle = Waggle.new(maxMessageSize = msg.encodedSize())
    let stream = openStream()
    discard handle(stream)
    await handshake(stream)

    check (await waggle.send(stream.peerId, topic, msg)).get()
    check (await stream.writes.popFirst()) == frame(msg.encode())
    let oversized =
      ObjectPieces(objectId: msg.objectId, pieces: Opt.some(newSeq[byte](17)))
    check:
      (await waggle.send(stream.peerId, topic, oversized)).isOfError(
        "Waggle message exceeds maximum length"
      )
      stream.writes.empty()
      not stream.closed

  asyncTest "concurrent sends serialize writes and preserve frames":
    const messageCount = 20
    let
      stream = openStream()
      started = newAsyncQueue[seq[byte]]()
      release = newAsyncQueue[bool]()
    discard handle(stream)
    await handshake(stream)
    stream.writeHandler = proc(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      await started.addLast(data)
      discard await release.popFirst()

    var sends: seq[Future[LPResult[bool]]]
    for i in 0 ..< messageCount:
      sends.add(waggle.send(stream.peerId, topic, ObjectPieces(objectId: @[byte i])))
    for i in 0 ..< messageCount:
      check (await started.popFirst()) ==
        frame(ObjectPieces(objectId: @[byte i]).encode())
      check started.empty()
      await release.addLast(true)
    for sending in sends:
      check (await sending).get()

  asyncTest "a failed write returns an error and resets the subscription":
    let stream = openStream()
    let handling = handle(stream)
    await handshake(stream)
    stream.writeHandler = proc(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "write failed")

    check (await waggle.send(stream.peerId, topic, ObjectPieces())).isOfError(
      "write failed"
    )
    await handling
    check:
      stream.wasResetLocally
      waggle.subscribers(topic).len == 0

  asyncTest "cancelling a write resets the stream and propagates cancellation":
    let
      stream = openStream()
      started = newAsyncEvent()
      release = newAsyncEvent()
    let handling = handle(stream)
    await handshake(stream)
    stream.writeHandler = proc(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      started.fire()
      await release.wait()

    let sending = waggle.send(stream.peerId, topic, ObjectPieces())
    await started.wait()
    await sending.cancelAndWait()
    expect CancelledError:
      discard await sending
    await handling
    check:
      stream.wasResetLocally
      waggle.subscribers(topic).len == 0

  asyncTest "cancelling a queued send leaves the active write usable":
    let
      stream = openStream()
      started = newAsyncEvent()
      release = newAsyncEvent()
    discard handle(stream)
    await handshake(stream)
    stream.writeHandler = proc(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      started.fire()
      await release.wait()

    let sending = waggle.send(stream.peerId, topic, ObjectPieces())
    await started.wait()
    let queued = waggle.send(stream.peerId, topic, ObjectPieces())
    await queued.cancelAndWait()
    expect CancelledError:
      discard await queued
    check not stream.closed
    release.fire()
    check (await sending).get()

  asyncTest "subscribe writes the handshake and dispatches pieces until EOF":
    let
      stream = openStream()
      received = newAsyncQueue[ObjectPieces]()
      metadata = ObjectPieces(objectId: @[byte 42], piecesMetadata: Opt.some(@[byte 1]))
      piece = ObjectPieces(objectId: @[byte 42], pieces: Opt.some(@[byte 2]))
    proc onPieces(
        peer: PeerId, t: seq[byte], msg: ObjectPieces
    ) {.async: (raises: [CancelledError]).} =
      check peer == stream.peerId
      check t == topic
      await received.addLast(msg)

    let receiving = receive(stream, handler = onPieces)
    check (await stream.writes.popFirst()) ==
      frame(TopicSubscription(topicId: topic).encode())
    check waggle.subscribers(topic).len == 0
    await stream.pushData(frame(metadata.encode()) & frame(piece.encode()))
    check (await received.popFirst()) == metadata
    check (await received.popFirst()) == piece
    await stream.pushEof()
    check (await receiving).isOk
    check stream.wasResetLocally

    let replacement = openStream(stream.peerId)
    discard receive(replacement)
    discard await replacement.writes.popFirst()
    check not replacement.closed

  asyncTest "subscribe rejects an oversized topic before writing":
    waggle = Waggle.new(maxTopicSize = topic.len - 1)
    let stream = openStream()
    check:
      (await receive(stream)).isOfError("Waggle topic exceeds maximum length")
      stream.writes.empty()
      stream.wasResetLocally

  asyncTest "subscribe rejects an oversized encoded handshake before writing":
    waggle =
      Waggle.new(maxMessageSize = TopicSubscription(topicId: topic).encode().len - 1)
    let stream = openStream()
    check:
      (await receive(stream)).isOfError("Waggle subscription exceeds maximum length")
      stream.writes.empty()
      stream.wasResetLocally

  asyncTest "subscribe rejects duplicate topics and releases them after cancellation":
    let stream = openStream()
    let receiving = receive(stream)
    discard await stream.writes.popFirst()
    let duplicate = openStream(stream.peerId)
    check:
      (await receive(duplicate)).isOfError("Duplicate Waggle topic stream")
      duplicate.wasResetLocally
      duplicate.writes.empty()
      not stream.closed

    await receiving.cancelAndWait()
    expect CancelledError:
      discard await receiving
    check stream.wasResetLocally
    let replacement = openStream(stream.peerId)
    discard receive(replacement)
    discard await replacement.writes.popFirst()
    check not replacement.closed

  asyncTest "subscribe enforces the total stream limit across peers":
    waggle = Waggle.new(maxStreams = 1)
    let stream = openStream()
    discard receive(stream)
    discard await stream.writes.popFirst()
    let rejected = openStream()
    check:
      (await receive(rejected)).isOfError("Waggle stream limit reached")
      rejected.wasResetLocally
      not stream.closed

  asyncTest "subscribe enforces per-peer limits without blocking another peer":
    waggle = Waggle.new(maxStreamsPerPeer = 1)
    let stream = openStream()
    discard receive(stream)
    discard await stream.writes.popFirst()
    let rejected = openStream(stream.peerId)
    check:
      (await receive(rejected, @[byte 4])).isOfError("Waggle stream limit reached")
      rejected.wasResetLocally
    let other = openStream()
    discard receive(other)
    discard await other.writes.popFirst()
    check not other.closed

  asyncTest "subscribe tags malformed protobuf, invalid lengths, and oversized frames":
    waggle = Waggle.new(maxMessageSize = 16)
    let peer = PeerId.random()
    for data in [
      frame(@[byte 0x1A, 0]), newSeqWith(10, byte 0x80), frame(newSeq[byte](17))
    ]:
      let stream = openStream(peer)
      let receiving = receive(stream)
      discard await stream.writes.popFirst()
      await stream.pushData(data)
      check:
        (await receiving).isOfError(WaggleInvalidDataCause)
        stream.wasResetLocally

  asyncTest "subscribe reports a truncated frame as a stream error":
    let stream = openStream()
    let receiving = receive(stream)
    discard await stream.writes.popFirst()
    await stream.pushData(@[byte 3, 0x12])
    await stream.pushEof()
    check:
      (await receiving).isOfError("Incomplete data received")
      stream.wasResetLocally

  asyncTest "subscribe returns transport read failures and resets the stream":
    let failures: array[4, ref LPStreamError] = [
      newLPStreamResetError(),
      newLPStreamClosedError(),
      newLPStreamConnDownError(),
      newException(LPStreamError, "read failed"),
    ]
    let peer = PeerId.random()
    for failure in failures:
      let stream = openStream(peer)
      let receiving = receive(stream)
      discard await stream.writes.popFirst()
      stream.readFailure = failure
      await stream.pushData(@[byte 0])
      check:
        (await receiving).isOfError(failure.msg)
        stream.wasResetLocally

  asyncTest "subscribe returns handshake write failures and resets the stream":
    let stream = openStream()
    stream.writeHandler = proc(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "handshake write failed")
    check:
      (await receive(stream)).isOfError("handshake write failed")
      stream.wasResetLocally

  asyncTest "handler rejects malformed, oversized, and trailing subscription data":
    waggle = Waggle.new(maxMessageSize = 16, maxTopicSize = topic.len)
    let valid = frame(TopicSubscription(topicId: topic).encode())
    let peer = PeerId.random()
    for data in [
      frame(@[]),
      newSeqWith(10, byte 0x80),
      frame(newSeq[byte](17)),
      frame(TopicSubscription(topicId: @[byte 1, 2, 3, 4]).encode()),
      valid & @[byte 1],
    ]:
      let stream = openStream(peer)
      let handling = handle(stream)
      await stream.pushData(data)
      await handling
      check:
        stream.wasResetLocally
        waggle.subscribers(topic).len == 0

    let replacement = openStream(peer)
    discard handle(replacement)
    await handshake(replacement)
    check waggle.subscribers(topic) == @[peer]

  asyncTest "handler rejects duplicate subscriptions without closing the original":
    let stream = openStream()
    discard handle(stream)
    await handshake(stream)
    let duplicate = openStream(stream.peerId)
    let handling = handle(duplicate)
    await duplicate.pushData(frame(TopicSubscription(topicId: topic).encode()))
    await handling
    check:
      duplicate.wasResetLocally
      not stream.closed
      waggle.subscribers(topic) == @[stream.peerId]

  asyncTest "handler shares admission limits with receiving streams":
    waggle = Waggle.new(maxStreams = 1)
    let stream = openStream()
    discard receive(stream)
    discard await stream.writes.popFirst()
    let rejected = openStream()
    await handle(rejected)
    check:
      rejected.wasResetLocally
      not stream.closed
      waggle.subscribers(topic).len == 0

  asyncTest "handler cleans up EOF before and during the handshake":
    waggle = Waggle.new(maxStreams = 1)
    let peer = PeerId.random()
    for partial in [false, true]:
      let stream = openStream(peer)
      let handling = handle(stream)
      if partial:
        await stream.pushData(@[byte 5, 0x0A])
      await stream.pushEof()
      await handling
      check stream.wasResetLocally
    let replacement = openStream(peer)
    discard handle(replacement)
    await handshake(replacement)

  asyncTest "handler cancellation releases admission before and after the handshake":
    waggle = Waggle.new(maxStreams = 1)
    let peer = PeerId.random()
    for subscribed in [false, true]:
      let stream = openStream(peer)
      let handling = handle(stream)
      if subscribed:
        await handshake(stream)
      else:
        discard await stream.readRequests.popFirst()
      await handling.cancelAndWait()
      expect CancelledError:
        await handling
      check:
        stream.wasResetLocally
        waggle.subscribers(topic).len == 0
    let replacement = openStream(peer)
    discard handle(replacement)
    await handshake(replacement)

  asyncTest "stop closes both directions and rejects subscriptions until restarted":
    let stream = openStream()
    let handling = handle(stream)
    await handshake(stream)
    let outbound = openStream(stream.peerId)
    let receiving = receive(outbound)
    discard await outbound.writes.popFirst()
    check waggle.subscribers(topic) == @[stream.peerId]

    await waggle.stop()
    await handling
    discard await receiving
    check:
      stream.wasResetLocally
      outbound.wasResetLocally
      waggle.subscribers(topic).len == 0
    let rejected = openStream()
    check (await receive(rejected)).isOfError("Waggle has stopped")
    let rejectedInbound = openStream()
    await handle(rejectedInbound)
    check rejectedInbound.wasResetLocally

    await waggle.start()
    let replacement = openStream()
    discard handle(replacement)
    await handshake(replacement)
    check waggle.subscribers(topic) == @[replacement.peerId]
