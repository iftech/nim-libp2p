# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import ./utils
import ../../../libp2p/stream/bufferstream
import ../../../libp2p/protocols/pubsub/[pubsubpeer, gossipsub]
import ../../tools/[unittest, bufferstream]

type
  FlakyDialer = ref object
    attempts: int
    failures: int
    stream: Stream

  ResetGateStream = ref object of TestBufferStream
    resetStarted: bool
    allowReset: Future[void].Raising([CancelledError])

method resetImpl(s: ResetGateStream) {.async: (raises: []).} =
  s.resetStarted = true
  await noCancel s.allowReset
  await procCall BufferStream(s).resetImpl()

proc getStream(d: FlakyDialer): GetStream =
  return proc(): Future[Stream] {.
      async: (raises: [CancelledError, GetStreamDialError])
  .} =
    inc d.attempts
    if d.attempts <= d.failures:
      raise (ref GetStreamDialError)(msg: "unreachable")
    return d.stream

proc newPeer(
    getStream: GetStream, baseDelay, maxDelay: Duration, onEvent: OnEvent = nil
): PubSubPeer =
  PubSubPeer.new(
    PeerId.random(),
    getStream,
    onEvent,
    GossipSubCodec_12,
    1024,
    voidPeerHandler,
    sendStreamRetryBaseDelay = baseDelay,
    sendStreamRetryMaxDelay = maxDelay,
  )

suite "PubSubPeer send stream":
  teardown:
    checkTrackers()

  asyncTest "retries failed send stream opens until one succeeds":
    let dialer = FlakyDialer(failures: 5, stream: TestBufferStream.new(noop))
    let peer = newPeer(dialer.getStream(), 1.milliseconds, 4.milliseconds)
    peer.connect()

    checkUntilTimeout:
      peer.connected
    check dialer.attempts > dialer.failures

    await peer.stopTasks()

  asyncTest "keeps retrying after the delay reaches the cap":
    let dialer = FlakyDialer(failures: int.high)
    let peer = newPeer(dialer.getStream(), 1.milliseconds, 2.milliseconds)
    peer.connect()

    checkUntilTimeout:
      dialer.attempts >= 20
    check not peer.connected

    await peer.stopTasks()

  asyncTest "stopTasks cancels a pending retry":
    let dialer = FlakyDialer(failures: int.high)
    let peer = newPeer(dialer.getStream(), 1.hours, 1.hours)
    peer.connect()

    checkUntilTimeout:
      dialer.attempts >= 1
    let before = dialer.attempts
    let stopped = await peer.stopTasks().withTimeout(1.seconds)

    check:
      stopped
      dialer.attempts == before

  asyncTest "a failed send stream open emits no StreamClosed":
    var closed = 0
    proc onEvent(peer: PubSubPeer, event: PubSubPeerEvent) {.gcsafe, raises: [].} =
      if event.kind == PubSubPeerEventKind.StreamClosed:
        inc closed

    let dialer = FlakyDialer(failures: int.high)
    let peer = newPeer(dialer.getStream(), 1.milliseconds, 2.milliseconds, onEvent)
    peer.connect()

    checkUntilTimeout:
      dialer.attempts >= 5
    check closed == 0

    await peer.stopTasks()

suite "PubSubPeer receive streams":
  teardown:
    checkTrackers()

  asyncTest "replacements terminate incomplete reads before admitting more streams":
    let peer = newPeer(nil, 1.milliseconds, 2.milliseconds)
    var streams: seq[TestBufferStream]
    var readers: seq[Future[void]]
    for i in 0 ..< 3 * MaxInboundStreamsPerPeer:
      let stream = TestBufferStream.new(noop)
      streams.add(stream)
      readers.add(peer.handleRecvStream(stream))
      # Declare 1024 bytes and leave the body incomplete.
      await stream.pushData(@[byte 0x80, 0x08, 0x01])
      if i >= MaxInboundStreamsPerPeer:
        checkUntilTimeout:
          readers[i - MaxInboundStreamsPerPeer].finished
        check streams[i - MaxInboundStreamsPerPeer].closed
      check readers.countIt(not it.finished) <= MaxInboundStreamsPerPeer

    await peer.stopTasks()
    await allFutures(readers)
    for stream in streams:
      check stream.closed

  asyncTest "concurrent admissions stay bounded and surviving streams deliver":
    var received = 0
    proc handler(
        peer: PubSubPeer, data: sink seq[byte]
    ) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
      check data == @[byte 42]
      inc received

    let peer =
      PubSubPeer.new(PeerId.random(), nil, nil, GossipSubCodec_12, 1024, handler)
    var streams: seq[TestBufferStream]
    var readers: seq[Future[void]]
    for i in 0 ..< MaxInboundStreamsPerPeer * 10:
      let stream = TestBufferStream.new(noop)
      streams.add(stream)
      readers.add(peer.handleRecvStream(stream))

    checkUntilTimeout:
      readers.countIt(it.finished) == readers.len - MaxInboundStreamsPerPeer

    for stream in streams:
      if not stream.closed:
        await stream.pushData(@[byte 1, 42])
        await stream.pushEof()
    await allFutures(readers)
    check received == MaxInboundStreamsPerPeer

    let reopened = TestBufferStream.new(noop)
    let reader = peer.handleRecvStream(reopened)
    await reopened.pushData(@[byte 1, 42])
    await reopened.pushEof()
    await reader
    check received == MaxInboundStreamsPerPeer + 1

    await peer.stopTasks()
    await reopened.close()
    for stream in streams:
      await stream.close()

  asyncTest "eviction drains suspended RPC handlers before admitting replacements":
    var active, cleaned = 0
    let cleanupStarted = Future[void].Raising([CancelledError]).init()
    let allowCleanup = Future[void].Raising([CancelledError]).init()
    proc handler(
        peer: PubSubPeer, data: sink seq[byte]
    ) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
      inc active
      try:
        await Future[void].Raising([CancelledError]).init()
      finally:
        if data == @[byte 0]:
          cleanupStarted.complete()
          await noCancel allowCleanup
        dec active
        inc cleaned

    let peer =
      PubSubPeer.new(PeerId.random(), nil, nil, GossipSubCodec_12, 1024, handler)
    var readers: seq[Future[void]]
    for i in 0 ..< MaxInboundStreamsPerPeer:
      let stream = TestBufferStream.new(noop)
      readers.add(peer.handleRecvStream(stream))
      await stream.pushData(@[byte 1, byte i])
      checkUntilTimeout:
        active == i + 1

    let replacement = TestBufferStream.new(noop)
    readers.add(peer.handleRecvStream(replacement))
    await cleanupStarted
    check:
      active == MaxInboundStreamsPerPeer
      cleaned == 0
      not replacement.reading

    allowCleanup.complete()
    await replacement.pushData(@[byte 1, 42])
    checkUntilTimeout:
      cleaned == 1 and active == MaxInboundStreamsPerPeer

    await peer.stopTasks()
    await allFutures(readers)
    check:
      active == 0
      cleaned == MaxInboundStreamsPerPeer + 1

  asyncTest "stopTasks starts all stream resets before awaiting cleanup":
    let peer = newPeer(nil, 1.milliseconds, 2.milliseconds)
    let allowReset = Future[void].Raising([CancelledError]).init()
    var streams: seq[ResetGateStream]
    var readers: seq[Future[void]]
    for i in 0 ..< MaxInboundStreamsPerPeer:
      let stream = ResetGateStream(writeHandler: noop, allowReset: allowReset)
      stream.initStream()
      streams.add(stream)
      readers.add(peer.handleRecvStream(stream))

    let stopped = peer.stopTasks()
    check:
      streams.allIt(it.resetStarted)
      not stopped.finished
    allowReset.complete()
    await stopped
    await allFutures(readers)
    check streams.allIt(it.closed)

  asyncTest "stopped peers reject inbound streams":
    let peer = newPeer(nil, 1.milliseconds, 2.milliseconds)
    await peer.stopTasks()
    let stream = TestBufferStream.new(noop)
    await peer.handleRecvStream(stream)
    check stream.closed
