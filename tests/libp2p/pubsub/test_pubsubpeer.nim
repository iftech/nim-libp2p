# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/importutils
import std/sequtils
import chronos
import ./utils
import ../../../libp2p/stream/bufferstream
import ../../../libp2p/protocols/protocol
import ../../../libp2p/protocols/pubsub/[pubsub, pubsubpeer, gossipsub]
import ../../../libp2p/peerstore
import ../../../libp2p/protocols/identify
import ../../../libp2p/protocols/pubsub/rpc/messages
import ../../tools/[unittest, bufferstream, switch_builder, multiaddress]
import ./extensions/extension_recording

privateAccess(PubSubPeer)

type
  FlakyDialer = ref object
    attempts: int
    failures: int
    stream: Stream
    notifyAt: int
    attemptReached: AsyncEvent

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
    if d.attempts == d.notifyAt:
      d.attemptReached.fire()
    if d.attempts <= d.failures:
      raise (ref GetStreamDialError)(msg: "unreachable")
    return d.stream

const
  OtherCodec = ProtoCodec("/other/1")
  TestOtherCodec = ProtoCodec("/test/other/1")

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

proc waitForSendStream(peer: PubSubPeer) {.async: (raises: [CancelledError]).} =
  if peer.connected:
    return
  let opened = newAsyncEvent()
  let onEvent = peer.onEvent
  peer.onEvent = proc(peer: PubSubPeer, event: PubSubPeerEvent) {.gcsafe, raises: [].} =
    if onEvent != nil:
      onEvent(peer, event)
    if event.kind == PubSubPeerEventKind.StreamOpened:
      opened.fire()
  try:
    await opened.wait()
  finally:
    peer.onEvent = onEvent

proc notifyRecvStream(p: PubSub): AsyncEvent =
  let opened = newAsyncEvent()
  let handler = p.handler
  p.handler = proc(
      stream: Stream, proto: ProtoCodec
  ) {.async: (raises: [CancelledError]).} =
    p.handler = handler
    let handling = handler(stream, proto)
    opened.fire()
    await handling
  opened

suite "PubSubPeer send stream":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "Identify skips a light client and protocol updates enable pubsub":
    let
      sw = makeStandardSwitch(TcpAutoAddress)
      remote = makeStandardSwitch(TcpAutoAddress)
      gossip = GossipSub.init(sw, rng = rng())
      remoteId = remote.peerInfo.peerId
    sw.mount(gossip)
    await sw.start()
    await remote.start()
    defer:
      await sw.stop()
      await remote.stop()
    var joined = 0
    proc onJoined(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]).} =
      inc joined
      check peerId notin gossip.peers

    sw.addPeerEventHandler(onJoined, PeerEventKind.Joined)
    remote.peerInfo.protocols = @[]
    await sw.connect(remoteId, remote.peerInfo.addrs)
    check:
      remoteId in sw.peerStore[ProtoBook]
      remoteId notin gossip.peers
    check sw.peerStore[ProtoBook][remoteId].len == 0
    gossip.subscribePeer(remoteId)
    check remoteId notin gossip.peers
    check sw.isConnected(remoteId)
    await sw.disconnect(remoteId)
    sw.peerStore[ProtoBook][remoteId] = gossip.codecs
    check remoteId notin gossip.peers
    await sw.connect(remoteId, remote.peerInfo.addrs)
    check remoteId notin gossip.peers
    check joined == 2

    let remoteGossip = GossipSub.init(remote, rng = rng())
    await remoteGossip.start()
    remote.mount(remoteGossip)
    let received = gossip.notifyRecvStream()
    sw.peerStore.updatePeerInfo(
      IdentifyInfo(peerId: remoteId, protos: remoteGossip.codecs)
    )
    require remoteId in gossip.peers
    await gossip.peers[remoteId].waitForSendStream()
    await received.wait()
    check gossip.peers[remoteId].hasRecvStream()
    # A stale snapshot must not override a negotiated inbound stream.
    sw.peerStore[ProtoBook][remoteId] = @[OtherCodec]
    check gossip.peers[remoteId].connected
    await gossip.stop()
    sw.peerStore[ProtoBook][remoteId] = remoteGossip.codecs
    check gossip.peers.len == 0

  asyncTest "unknown capabilities retry until an unsupported Identify snapshot":
    let
      sw = makeStandardSwitch(TcpAutoAddress)
      remote = makeStandardSwitch(TcpAutoAddress)
      remoteId = remote.peerInfo.peerId
    await sw.start()
    await remote.start()
    defer:
      await sw.stop()
      await remote.stop()
    await sw.connect(remoteId, remote.peerInfo.addrs)
    let gossip = GossipSub.init(sw, rng = rng())
    await gossip.start()
    sw.mount(gossip)
    discard sw.peerStore[ProtoBook].del(remoteId)
    let peer = gossip.getOrCreatePeer(remoteId, gossip.codecs)
    let dialer =
      FlakyDialer(failures: int.high, notifyAt: 3, attemptReached: newAsyncEvent())
    peer.getStream = dialer.getStream()
    peer.sendStreamRetryBaseDelay = 1.milliseconds
    peer.sendStreamRetryMaxDelay = 2.milliseconds
    gossip.subscribePeer(remoteId)
    await dialer.attemptReached.wait()
    sw.peerStore.updatePeerInfo(IdentifyInfo(peerId: remoteId, protos: @[OtherCodec]))
    await sleepAsync(10.milliseconds)
    check:
      remoteId notin gossip.peers
      dialer.attempts == 3
      sw.isConnected(remoteId)

  asyncTest "an inbound pubsub stream overrides an unsupported snapshot":
    let
      sw = makeStandardSwitch(TcpAutoAddress)
      remote = makeStandardSwitch(TcpAutoAddress)
      gossip = GossipSub.init(sw, rng = rng())
      remoteId = remote.peerInfo.peerId
    sw.mount(gossip)
    await sw.start()
    await remote.start()
    defer:
      await sw.stop()
      await remote.stop()
    await sw.connect(remoteId, remote.peerInfo.addrs)
    check remoteId notin gossip.peers
    let remoteGossip = GossipSub.init(remote, rng = rng())
    await remoteGossip.start()
    remote.mount(remoteGossip)
    let received = gossip.notifyRecvStream()
    remoteGossip.subscribePeer(sw.peerInfo.peerId)
    await received.wait()
    require remoteId in gossip.peers
    await gossip.peers[remoteId].waitForSendStream()
    check remoteGossip.codecs.allIt(it notin sw.peerStore[ProtoBook][remoteId])

  asyncTest "unknown peers get five attempts per connection until support is established":
    for inbound in [false, true]:
      let
        sw = makeStandardSwitch(TcpAutoAddress)
        remote = makeStandardSwitch(TcpAutoAddress)
        gossip = GossipSub.init(sw, rng = rng())
        remoteId = remote.peerInfo.peerId
        dialer = FlakyDialer(failures: int.high)
      sw.mount(gossip)
      await sw.start()
      await remote.start()
      defer:
        await sw.stop()
        await remote.stop()

      for connection in 1 .. 2:
        await sw.connect(remoteId, remote.peerInfo.addrs)
        discard sw.peerStore[ProtoBook].del(remoteId)
        let peer = gossip.getOrCreatePeer(remoteId, gossip.codecs)
        let openStream = peer.getStream
        peer.getStream = dialer.getStream()
        peer.sendStreamRetryBaseDelay = 1.milliseconds
        peer.sendStreamRetryMaxDelay = 2.milliseconds
        dialer.notifyAt = connection * 5
        dialer.attemptReached = newAsyncEvent()
        gossip.subscribePeer(remoteId)
        await dialer.attemptReached.wait()
        await sleepAsync(10.milliseconds)
        peer.connect()
        gossip.subscribePeer(remoteId)
        await sleepAsync(10.milliseconds)
        check dialer.attempts == connection * 5

        if connection == 1:
          await sw.disconnect(remoteId)
        elif inbound:
          peer.getStream = openStream
          let remoteGossip = GossipSub.init(remote, rng = rng())
          await remoteGossip.start()
          remote.mount(remoteGossip)
          remoteGossip.subscribePeer(sw.peerInfo.peerId)
          await peer.waitForSendStream()
        else:
          dialer.failures = dialer.attempts + 2
          dialer.stream = TestBufferStream.new(noop)
          sw.peerStore[ProtoBook][remoteId] = gossip.codecs
          await peer.waitForSendStream()
          check dialer.attempts == dialer.failures + 1

  asyncTest "successful unknown stream opens do not consume the failure allowance":
    var attempts = 0
    let sixthAttempt = newAsyncEvent()
    proc dial(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      inc attempts
      if attempts == 6:
        sixthAttempt.fire()
      if attempts == 4:
        let stream = TestBufferStream.new(noop)
        await stream.close()
        return stream
      raise newException(GetStreamDialError, "unreachable")

    let peer = PubSubPeer.new(
      PeerId.random(),
      dial,
      nil,
      UnsetProtoCodec,
      1024,
      voidPeerHandler,
      sendStreamRetryBaseDelay = 1.milliseconds,
      sendStreamRetryMaxDelay = 2.milliseconds,
    )
    defer:
      await peer.stopTasks()
    peer.connect()
    await sixthAttempt.wait()
    await sleepAsync(10.milliseconds)
    check attempts == 6

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

  asyncTest "budget rejection backs off and recovers when a slot is released":
    let remote = newPeer(nil, 50.milliseconds, 200.milliseconds)
    let admitted = Future[void].Raising([CancelledError]).init()
    proc handler(
        stream: Stream, proto: ProtoCodec
    ) {.async: (raises: [CancelledError]).} =
      if not admitted.finished:
        admitted.complete()
      await remote.handleRecvStream(stream)

    let protocol =
      LPProtocol.new(@[GossipSubCodec_12], handler, maxIncomingStreamsTotal = 1)
    let listener = makeStandardSwitch(TcpAutoAddress)
    let dialer = makeStandardSwitch(TcpAutoAddress)
    listener.mount(protocol)
    proc echoHandler(
        stream: Stream, proto: ProtoCodec
    ) {.async: (raises: [CancelledError]).} =
      try:
        for _ in 0 ..< 2:
          await stream.writeLp(await stream.readLp(1024))
      except LPStreamError:
        discard

    listener.mount(LPProtocol.new(@[TestOtherCodec], echoHandler))
    await listener.start()
    await dialer.start()
    defer:
      await dialer.stop()
      await listener.stop()
    let other = await dialer.dial(
      listener.peerInfo.peerId, listener.peerInfo.addrs, TestOtherCodec
    )
    # Complete optimistic negotiation so this idle stream does not block mplex reads.
    await other.writeLp(@[byte 41])
    check (await other.readLp(1024)) == @[byte 41]
    let occupiedBy = PeerId.random()
    check protocol.reserveIncoming(occupiedBy)
    var attempts: seq[Moment]
    let thirdAttempt = Future[void].Raising([CancelledError]).init()
    proc dial(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      attempts.add(Moment.now())
      if attempts.len == 3:
        thirdAttempt.complete()
      try:
        return await dialer.dial(listener.peerInfo.peerId, GossipSubCodec_12)
      except DialFailedError as e:
        raise newException(GetStreamDialError, e.msg)

    let peer = newPeer(dial, 50.milliseconds, 200.milliseconds)
    peer.connect()
    defer:
      await peer.stopTasks()
      await remote.stopTasks()
    await thirdAttempt
    check not admitted.finished
    check attempts[1] - attempts[0] >= 40.milliseconds
    check attempts[2] - attempts[1] >= 80.milliseconds
    check dialer.isConnected(listener)
    await other.writeLp(@[byte 42])
    check (await other.readLp(1024)) == @[byte 42]
    await other.close()
    protocol.releaseIncoming(occupiedBy)
    await admitted
    check peer.connected

  asyncTest "short-lived send streams back off and recover":
    var attempts: seq[Moment]
    let survivor = TestBufferStream.new(noop)
    let connected = Future[void].Raising([CancelledError]).init()
    proc dial(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      attempts.add(Moment.now())
      if attempts.len <= 4:
        let stream = TestBufferStream.new(noop)
        await stream.close()
        return stream
      return survivor

    proc onEvent(peer: PubSubPeer, event: PubSubPeerEvent) {.gcsafe, raises: [].} =
      if event.kind == PubSubPeerEventKind.StreamOpened and peer.sendStream == survivor:
        connected.complete()

    let peer = newPeer(dial, 50.milliseconds, 200.milliseconds, onEvent)
    peer.connect()
    defer:
      await peer.stopTasks()
    await connected
    check attempts.len == 5
    check:
      attempts[1] - attempts[0] >= 40.milliseconds
      attempts[2] - attempts[1] >= 80.milliseconds
      attempts[3] - attempts[2] >= 160.milliseconds
      attempts[4] - attempts[3] >= 160.milliseconds

  asyncTest "a stable stream resets backoff after earlier failures":
    var attempts = 0
    let stable = TestBufferStream.new(noop)
    let recovered = TestBufferStream.new(noop)
    let stableOpened = Future[void].Raising([CancelledError]).init()
    let recoveredOpened = Future[void].Raising([CancelledError]).init()
    proc dial(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      inc attempts
      if attempts <= 3:
        raise newException(GetStreamDialError, "unreachable")
      if attempts == 4:
        return stable
      if attempts == 5:
        let shortLived = TestBufferStream.new(noop)
        await shortLived.close()
        return shortLived
      return recovered

    proc onEvent(peer: PubSubPeer, event: PubSubPeerEvent) {.gcsafe, raises: [].} =
      if event.kind == PubSubPeerEventKind.StreamOpened:
        if peer.sendStream == stable:
          stableOpened.complete()
        elif peer.sendStream == recovered:
          recoveredOpened.complete()

    let peer = newPeer(dial, 50.milliseconds, 400.milliseconds, onEvent)
    peer.connect()
    defer:
      await peer.stopTasks()
      await stable.close()
      await recovered.close()
    await stableOpened
    await sleepAsync(peer.sendStreamRetryMaxDelay + 50.milliseconds)
    await stable.close()
    await recoveredOpened.wait(200.milliseconds)
    check attempts == 6
    check peer.connected

  asyncTest "topic stream routing preserves send observer changes":
    let peer = newPeer(nil, 1.milliseconds, 4.milliseconds)
    peer.extensionsState =
      ExtensionsState.new(rng(), topicStreamsConfig = Opt.some(TopicStreamsConfig()))
    let recorder = TopicStreamsRecorder.new()

    proc onSend(p: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
      msg.messages = @[Message(topic: "changed", data: @[2.byte])]

    peer.observers = new(seq[PubSubObserver])
    peer.observers[].add(PubSubObserver(onSend: onSend))
    peer.extensionsState.initTopicStreams(
      peer.peerId,
      1024,
      recorder.dial(),
      recorder.receive(),
      recorder.violation(),
      peer.outboundQueue,
    )
    defer:
      await peer.extensionsState.stopTopicStreams(peer.peerId)
      await peer.stopTasks()
      await recorder.closeOutgoingStreams()
    check peer.extensionsState.negotiateTopicStreams(
      peer.peerId, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
    )
    let msg = RPCMsg.withMessages(Message(topic: "original", data: @[1.byte]))
    peer.send(msg, false, MessagePriority.Medium)
    check:
      TopicRPCHeader.decode(await recorder.outgoingStreams[0].readLp(1024)).get() ==
        TopicRPCHeader(topic: Opt.some("changed"))
      TopicRPC.decode(await recorder.outgoingStreams[0].readLp(1024)).get() ==
        TopicRPC(publish: Opt.some(TopicScopedMessage(data: @[2.byte])))
      msg == RPCMsg.withMessages(Message(topic: "original", data: @[1.byte]))
      recorder.violations == 0

  asyncTest "topic stream routing carries a message a send observer adds to a subscription":
    let peer = newPeer(nil, 1.milliseconds, 4.milliseconds)
    peer.extensionsState =
      ExtensionsState.new(rng(), topicStreamsConfig = Opt.some(TopicStreamsConfig()))
    let recorder = TopicStreamsRecorder.new()
    let added = Message(topic: topic, data: @[1.byte])

    # the send observer adds a message to every RPC the peer sends
    proc onSend(p: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
      msg.messages.add(added)

    peer.observers = new(seq[PubSubObserver])
    peer.observers[].add(PubSubObserver(onSend: onSend))
    peer.extensionsState.initTopicStreams(
      peer.peerId,
      1024,
      recorder.dial(),
      recorder.receive(),
      recorder.violation(),
      peer.outboundQueue,
    )
    defer:
      await peer.stopTasks()
      await recorder.closeOutgoingStreams()
    # topic streams negotiated, so messages to this peer must go on a topic stream
    check peer.extensionsState.negotiateTopicStreams(
      peer.peerId, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
    )
    # an RPC without messages, only a subscription
    peer.sendResponse(
      RPCMsg.withSubscriptions(
        @[SubOpts(topic: Opt.some(topic), subscribe: Opt.some(true))]
      ),
      false,
      MessagePriority.High,
    )
    # the message the observer added goes out on a topic stream
    check:
      TopicRPCHeader.decode(await recorder.outgoingStreams[0].readLp(1024)).get() ==
        TopicRPCHeader(topic: Opt.some(topic))
      TopicRPC.decode(await recorder.outgoingStreams[0].readLp(1024)).get() ==
        added.topicRPC()
      recorder.violations == 0
      # the written frame no longer counts toward the High count limit
      peer.outboundQueue.topicCounts[MessagePriority.High] == 0

  asyncTest "topic stream writes a Medium priority message before an earlier Low priority one":
    let peer = newPeer(nil, 1.milliseconds, 4.milliseconds)
    peer.extensionsState =
      ExtensionsState.new(rng(), topicStreamsConfig = Opt.some(TopicStreamsConfig()))
    let recorder = TopicStreamsRecorder.new()
    let allowDial = Future[void].Raising([CancelledError]).init("allowDial")

    # the topic stream opens only after the test completes allowDial
    proc heldDial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      let stream = await recorder.dial()()
      # the writer takes no message until the stream opens, so both messages queue first
      await allowDial
      return stream

    peer.extensionsState.initTopicStreams(
      peer.peerId,
      1024,
      heldDial,
      recorder.receive(),
      recorder.violation(),
      peer.outboundQueue,
    )
    defer:
      await peer.stopTasks()
      await recorder.closeOutgoingStreams()
    # topic streams negotiated, so messages to this peer go on a topic stream
    check peer.extensionsState.negotiateTopicStreams(
      peer.peerId, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
    )
    let relayed = Message(topic: topic, data: @[1.byte])
    let published = Message(topic: topic, data: @[2.byte])
    # A pending control write prevents empty-queue promotion of the first topic frame.
    await peer.sendEncoded(@[0.byte], MessagePriority.High)
    # the Low priority message is queued first, the Medium one second
    peer.sendResponse(RPCMsg.withMessages(relayed), false, MessagePriority.Low)
    peer.send(RPCMsg.withMessages(published), false, MessagePriority.Medium)
    allowDial.complete() # the stream opens and the writer starts taking messages
    # after the header, the Medium priority message is written before the Low one
    check:
      TopicRPCHeader.decode(await recorder.outgoingStreams[0].readLp(1024)).get() ==
        TopicRPCHeader(topic: Opt.some(topic))
      TopicRPC.decode(await recorder.outgoingStreams[0].readLp(1024)).get() ==
        published.topicRPC()
      TopicRPC.decode(await recorder.outgoingStreams[0].readLp(1024)).get() ==
        relayed.topicRPC()
      recorder.violations == 0

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

  asyncTest "oversized frames reset the stream, peer keeps serving":
    var received: seq[seq[byte]]
    proc handler(
        peer: PubSubPeer, data: sink seq[byte]
    ) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
      received.add(data)

    let peer = PubSubPeer.new(PeerId.random(), nil, nil, GossipSubCodec_12, 16, handler)
    let stream = TestBufferStream.new(noop)
    let reader = peer.handleRecvStream(stream)

    # Declare 1024 bytes, over the 16-byte limit; the body never has to arrive.
    await stream.pushData(@[byte 0x80, 0x08])
    await reader
    check:
      stream.closed
      received.len == 0

    # The peer is still live: a re-opened stream delivers.
    let reopened = TestBufferStream.new(noop)
    let reopenedReader = peer.handleRecvStream(reopened)
    await reopened.pushData(@[byte 1, 42])
    await reopened.pushEof()
    await reopenedReader
    check received == @[@[byte 42]]

    await peer.stopTasks()
    await reopened.close()
