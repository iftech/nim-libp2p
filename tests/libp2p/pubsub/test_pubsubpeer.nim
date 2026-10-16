# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./utils
import ../../../libp2p/stream/bufferstream
import ../../../libp2p/protocols/pubsub/[pubsubpeer, gossipsub]
import ../../tools/[unittest, bufferstream]

type FlakyDialer = ref object
  attempts: int
  failures: int
  stream: Stream

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
    randomPeerId(),
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
      var active = 0
      for reader in readers:
        if not reader.finished:
          inc active
      check active <= MaxInboundStreamsPerPeer

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
      PubSubPeer.new(randomPeerId(), nil, nil, GossipSubCodec_12, 1024, handler)
    var streams: seq[TestBufferStream]
    var readers: seq[Future[void]]
    for i in 0 ..< 50:
      let stream = TestBufferStream.new(noop)
      streams.add(stream)
      readers.add(peer.handleRecvStream(stream))

    checkUntilTimeout:
      block:
        var finished = 0
        for reader in readers:
          if reader.finished:
            inc finished
        finished == readers.len - MaxInboundStreamsPerPeer

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
    var active, peak, cleaned = 0
    proc handler(
        peer: PubSubPeer, data: sink seq[byte]
    ) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
      inc active
      peak = max(peak, active)
      try:
        await sleepAsync(1.hours)
      finally:
        await noCancel sleepAsync(1.milliseconds)
        dec active
        inc cleaned

    let peer =
      PubSubPeer.new(randomPeerId(), nil, nil, GossipSubCodec_12, 1024, handler)
    var streams: seq[TestBufferStream]
    var readers: seq[Future[void]]
    for i in 0 .. MaxInboundStreamsPerPeer:
      let stream = TestBufferStream.new(noop)
      streams.add(stream)
      readers.add(peer.handleRecvStream(stream))
      await stream.pushData(@[byte 1, 42])
      checkUntilTimeout:
        active + cleaned == i + 1
    check:
      cleaned == 1
      peak == MaxInboundStreamsPerPeer

    await readers[^1].cancelAndWait()
    await streams[^1].close()
    await peer.stopTasks()
    await allFutures(readers)
    check:
      active == 0
      cleaned == streams.len

    let late = TestBufferStream.new(noop)
    await peer.handleRecvStream(late)
    check late.closed

  asyncTest "handleConn caps each peer independently and preserves send streams":
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(2, "topic")
    var readers: seq[Future[void]]
    var streams: seq[TestBufferStream]
    for peer in peers:
      for i in 0 ..< MaxInboundStreamsPerPeer + 1:
        let stream = TestBufferStream.new(noop)
        stream.peerId = peer.peerId
        streams.add(stream)
        readers.add(gossipSub.handleConn(stream, GossipSubCodec_12))
        await stream.pushData(@[byte 0x80, 0x08, 0x01])

    for peer in peers:
      var active = 0
      for stream in streams:
        if stream.peerId == peer.peerId and not stream.closed:
          inc active
      check active == MaxInboundStreamsPerPeer
      check not peer.sendStream.closed
      await peer.stopTasks()
    await allFutures(readers)
    for stream in streams:
      check stream.closed
    await teardownGossipSub(gossipSub, conns)
