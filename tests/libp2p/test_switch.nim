# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, sequtils, chronos, stew/byteutils
import
  ../../libp2p/[
    errors,
    dial,
    switch,
    multistream,
    builders,
    stream/bufferstream,
    stream/connection,
    multicodec,
    multiaddress,
    peerinfo,
    crypto/crypto,
    protocols/protocol,
    protocols/secure/noise,
    muxers/muxer,
    muxers/mplex/lpchannel,
    stream/lpstream,
    nameresolving/mockresolver,
    stream/chronosstream,
    transports/tcptransport,
    transports/wstransport,
    transports/quictransport,
  ]
import
  ../tools/[unittest, trackers, futures, crypto, sync, switch_builder, multiaddress]

const TestCodec = "/test/proto/1.0.0"

type TestProto = ref object of LPProtocol

suite "Switch":
  teardown:
    checkTrackers()

  asyncTest "e2e use switch dial proto string":
    let handleFinished = newWaitGroup(1)
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        let msg = string.fromBytes(await stream.readLp(1024))
        check "Hello!" == msg
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in protocol handler"
      finally:
        await stream.close()
        handleFinished.done()

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    let switch1 = makeStandardSwitch()
    switch1.mount(testProto)

    let switch2 = makeStandardSwitch()
    await switch1.start()
    await switch2.start()

    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await stream.writeLp("Hello!")
    let msg = string.fromBytes(await stream.readLp(1024))
    check "Hello!" == msg
    await stream.close()

    await allFuturesRaising(
      handleFinished.wait(5.seconds), switch1.stop(), switch2.stop()
    )

    check not switch1.isConnected(switch2.peerInfo.peerId)
    check not switch2.isConnected(switch1.peerInfo.peerId)

  asyncTest "e2e use switch dial proto string with custom matcher":
    let handleFinished = newWaitGroup(1)
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        let msg = string.fromBytes(await stream.readLp(1024))
        check "Hello!" == msg
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in custom matcher protocol handler"
      finally:
        await stream.close()
        handleFinished.done()

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    let callProto = TestCodec & "/pew"

    proc match(proto: string): bool {.gcsafe.} =
      return proto == callProto

    let switch1 = makeStandardSwitch()
    switch1.mount(testProto, match)

    let switch2 = makeStandardSwitch()
    await switch1.start()
    await switch2.start()

    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, callProto)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await stream.writeLp("Hello!")
    let msg = string.fromBytes(await stream.readLp(1024))
    check "Hello!" == msg
    await stream.close()

    await allFuturesRaising(
      handleFinished.wait(5.seconds), switch1.stop(), switch2.stop()
    )

    check not switch1.isConnected(switch2.peerInfo.peerId)
    check not switch2.isConnected(switch1.peerInfo.peerId)

  asyncTest "e2e should not leak bufferstreams and connections on channel close":
    let handleFinished = newWaitGroup(1)
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        let msg = string.fromBytes(await stream.readLp(1024))
        check "Hello!" == msg
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in bufferstream leak test handler"
      finally:
        await stream.close()
        handleFinished.done()

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    let switch1 = makeStandardSwitch()
    switch1.mount(testProto)

    let switch2 = makeStandardSwitch()
    await switch1.start()
    await switch2.start()

    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await stream.writeLp("Hello!")
    let msg = string.fromBytes(await stream.readLp(1024))
    check "Hello!" == msg
    await stream.close()

    await allFuturesRaising(
      handleFinished.wait(5.seconds), switch1.stop(), switch2.stop()
    )

    check not switch1.isConnected(switch2.peerInfo.peerId)
    check not switch2.isConnected(switch1.peerInfo.peerId)

  asyncTest "e2e use connect then dial":
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        let msg = string.fromBytes(await stream.readLp(1024))
        check "Hello!" == msg
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in connect-then-dial test handler"
      finally:
        await stream.close()

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    let switch1 = makeStandardSwitch()
    switch1.mount(testProto)

    let switch2 = makeStandardSwitch()
    await switch1.start()
    await switch2.start()

    await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)
    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await stream.writeLp("Hello!")
    let msg = string.fromBytes(await stream.readLp(1024))
    check "Hello!" == msg

    await allFuturesRaising(stream.close(), switch1.stop(), switch2.stop())

    check not switch1.isConnected(switch2.peerInfo.peerId)
    check not switch2.isConnected(switch1.peerInfo.peerId)

  asyncTest "e2e connect to peer with unknown PeerId":
    let resolver = MockResolver.new()
    let switch1 = makeStandardSwitch()
    let switch2 = makeStandardSwitchBuilder().withNameResolver(resolver).build()
    await switch1.start()
    await switch2.start()

    # via dnsaddr
    resolver.txtResponses["_dnsaddr.test.io"] =
      @["dnsaddr=" & $switch1.peerInfo.addrs[0] & "/p2p/" & $switch1.peerInfo.peerId]

    check:
      (await switch2.connect(ma("/dnsaddr/test.io/"), true)) == switch1.peerInfo.peerId
    await switch2.disconnect(switch1.peerInfo.peerId)

    # via direct ip
    check not switch2.isConnected(switch1.peerInfo.peerId)
    check:
      (await switch2.connect(switch1.peerInfo.addrs[0], true)) == switch1.peerInfo.peerId

    await switch2.disconnect(switch1.peerInfo.peerId)

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e connect to peer with known PeerId":
    let switch1 = makeStandardSwitch()
    let switch2 = makeStandardSwitch()
    await switch1.start()
    await switch2.start()

    # via direct ip
    check not switch2.isConnected(switch1.peerInfo.peerId)

    # without specifying allow unknown, will fail
    expect(DialFailedError):
      discard await switch2.connect(switch1.peerInfo.addrs[0])

    # with invalid PeerId, will fail
    let fakeMa = concat(
        switch1.peerInfo.addrs[0],
        MultiAddress.init(multiCodec("p2p"), PeerId.random(rng()).tryGet().data).tryGet(),
      )
      .tryGet()
    expect(DialFailedError):
      discard (await switch2.connect(fakeMa))

    # real thing works
    let fullAddr = switch1.peerInfo.fullAddrs.tryGet()[0]
    let connectedPeerId = await switch2.connect(fullAddr)
    check connectedPeerId == switch1.peerInfo.peerId

    await switch2.disconnect(switch1.peerInfo.peerId)

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e should not leak on peer disconnect":
    let switch1 = makeStandardSwitch()
    let switch2 = makeStandardSwitch()
    await switch1.start()
    await switch2.start()

    let startCounts = @[
      switch1.connManager.availableSlots(Direction.In),
      switch1.connManager.availableSlots(Direction.Out),
      switch2.connManager.availableSlots(Direction.In),
      switch2.connManager.availableSlots(Direction.Out),
    ]

    await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await switch2.disconnect(switch1.peerInfo.peerId)

    check not switch2.isConnected(switch1.peerInfo.peerId)
    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)

    checkUntilTimeout:
      startCounts ==
        @[
          switch1.connManager.availableSlots(Direction.In),
          switch1.connManager.availableSlots(Direction.Out),
          switch2.connManager.availableSlots(Direction.In),
          switch2.connManager.availableSlots(Direction.Out),
        ]

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e should trigger connection events (remote)":
    let switch1 = makeStandardSwitch()
    let switch2 = makeStandardSwitch()

    var step = 0
    var kinds: set[ConnEventKind]
    proc hook(peerId: PeerId, event: ConnEvent) {.async: (raises: [CancelledError]).} =
      kinds = kinds + {event.kind}
      case step
      of 0:
        check:
          event.kind == ConnEventKind.Connected
          peerId == switch1.peerInfo.peerId
      of 1:
        check:
          event.kind == ConnEventKind.Disconnected

        check peerId == switch1.peerInfo.peerId
      else:
        raiseAssert "Connection event hook called more than expected"

      step.inc()

    switch2.addConnEventHandler(hook, ConnEventKind.Connected)
    switch2.addConnEventHandler(hook, ConnEventKind.Disconnected)

    await switch1.start()
    await switch2.start()

    await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await switch2.disconnect(switch1.peerInfo.peerId)

    check not switch2.isConnected(switch1.peerInfo.peerId)
    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)

    check:
      kinds == {ConnEventKind.Connected, ConnEventKind.Disconnected}

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e should trigger connection events (local)":
    let switch1 = makeStandardSwitch()
    let switch2 = makeStandardSwitch()

    var step = 0
    var kinds: set[ConnEventKind]
    proc hook(peerId: PeerId, event: ConnEvent) {.async: (raises: [CancelledError]).} =
      kinds = kinds + {event.kind}
      case step
      of 0:
        check:
          event.kind == ConnEventKind.Connected
          peerId == switch2.peerInfo.peerId
      of 1:
        check:
          event.kind == ConnEventKind.Disconnected

        check peerId == switch2.peerInfo.peerId
      else:
        raiseAssert "Connection event hook called more than expected"

      step.inc()

    switch1.addConnEventHandler(hook, ConnEventKind.Connected)
    switch1.addConnEventHandler(hook, ConnEventKind.Disconnected)

    await switch1.start()
    await switch2.start()

    await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await switch2.disconnect(switch1.peerInfo.peerId)

    check not switch2.isConnected(switch1.peerInfo.peerId)
    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)

    check:
      kinds == {ConnEventKind.Connected, ConnEventKind.Disconnected}

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e should trigger peer events (remote)":
    let switch1 = makeStandardSwitch()
    let switch2 = makeStandardSwitch()

    var step = 0
    var kinds: set[PeerEventKind]
    proc handler(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]).} =
      kinds = kinds + {event.kind}
      case step
      of 0:
        check:
          event.kind == PeerEventKind.Joined
          peerId == switch2.peerInfo.peerId
      of 1:
        check:
          event.kind == PeerEventKind.Left
          peerId == switch2.peerInfo.peerId
      else:
        raiseAssert "Peer event handler called more than expected"

      step.inc()

    switch1.addPeerEventHandler(handler, PeerEventKind.Joined)
    switch1.addPeerEventHandler(handler, PeerEventKind.Left)

    await switch1.start()
    await switch2.start()

    await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await switch2.disconnect(switch1.peerInfo.peerId)

    check not switch2.isConnected(switch1.peerInfo.peerId)
    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)

    check:
      kinds == {PeerEventKind.Joined, PeerEventKind.Left}

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e should trigger peer events (local)":
    let switch1 = makeStandardSwitch()
    let switch2 = makeStandardSwitch()

    var step = 0
    var kinds: set[PeerEventKind]
    proc handler(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]).} =
      kinds = kinds + {event.kind}
      case step
      of 0:
        check:
          event.kind == PeerEventKind.Joined
          peerId == switch1.peerInfo.peerId
      of 1:
        check:
          event.kind == PeerEventKind.Left
          peerId == switch1.peerInfo.peerId
      else:
        raiseAssert "Peer event handler called more than expected"

      step.inc()

    switch2.addPeerEventHandler(handler, PeerEventKind.Joined)
    switch2.addPeerEventHandler(handler, PeerEventKind.Left)

    await switch1.start()
    await switch2.start()

    await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await switch2.disconnect(switch1.peerInfo.peerId)

    check not switch2.isConnected(switch1.peerInfo.peerId)
    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)

    check:
      kinds == {PeerEventKind.Joined, PeerEventKind.Left}

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e should trigger peer events only once per peer":
    let switch1 = makeStandardSwitchBuilder().withMaxConnsPerPeer(2).build()

    # use same private keys to emulate two connection from same peer
    let privKey = PrivateKey.random(rng()).tryGet()
    let switch2 = makeStandardSwitchBuilder().withPrivateKey(privKey).build()

    let switch3 = makeStandardSwitchBuilder().withPrivateKey(privKey).build()

    var step = 0
    var kinds: set[PeerEventKind]
    proc handler(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]).} =
      kinds = kinds + {event.kind}
      case step
      of 0:
        check:
          event.kind == PeerEventKind.Joined
      of 1:
        check:
          event.kind == PeerEventKind.Left
      else:
        raiseAssert "Peer event handler called more than expected"

      step.inc()

    switch1.addPeerEventHandler(handler, PeerEventKind.Joined)
    switch1.addPeerEventHandler(handler, PeerEventKind.Left)

    await switch1.start()
    await switch2.start()
    await switch3.start()

    await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)
      # should trigger 1st Join event
    await switch3.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)
      # should trigger 2nd Join event

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)
    check switch3.isConnected(switch1.peerInfo.peerId)

    await switch2.disconnect(switch1.peerInfo.peerId) # should trigger 1st Left event
    await switch3.disconnect(switch1.peerInfo.peerId) # should trigger 2nd Left event

    check not switch2.isConnected(switch1.peerInfo.peerId)
    check not switch3.isConnected(switch1.peerInfo.peerId)
    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)
    checkUntilTimeout:
      not switch1.isConnected(switch3.peerInfo.peerId)

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)

    check:
      kinds == {PeerEventKind.Joined, PeerEventKind.Left}

    await allFuturesRaising(switch1.stop(), switch2.stop(), switch3.stop())

  asyncTest "e2e should allow dropping peer from connection events":
    # use same private keys to emulate two connection from same peer
    let
      privateKey = PrivateKey.random(rng()).tryGet()
      peerInfo = PeerInfo.new(privateKey)

    var switches: seq[Switch]
    let onDisconnect = newWaitGroup(1)
    let onConnect = newWaitGroup(1)

    proc hook(peerId: PeerId, event: ConnEvent) {.async: (raises: [CancelledError]).} =
      try:
        case event.kind
        of ConnEventKind.Connected:
          await onConnect.wait()
          await switches[0].disconnect(peerInfo.peerId) # trigger disconnect
        of ConnEventKind.Disconnected:
          check not switches[0].isConnected(peerInfo.peerId)
          onDisconnect.done()
      except DialFailedError:
        raiseAssert "Unexpected DialFailedError in connection event hook"

    switches.add(makeStandardSwitch())

    switches[0].addConnEventHandler(hook, ConnEventKind.Connected)
    switches[0].addConnEventHandler(hook, ConnEventKind.Disconnected)
    await switches[0].start()

    switches.add(makeStandardSwitchBuilder().withPrivateKey(privateKey).build())
    await switches[1].connect(switches[0].peerInfo.peerId, switches[0].peerInfo.addrs)
    onConnect.done()

    await onDisconnect.wait()

    await allFuturesRaising(switches.mapIt(it.stop()))

  asyncTest "e2e should allow dropping multiple connections for peer from connection events":
    let privateKey = PrivateKey.random(rng()).tryGet()
    let peerInfo = PeerInfo.new(privateKey)

    var switches: seq[Switch]
    let allDisconnected = newWaitGroup(5)
    let allConnected = newWaitGroup(5)

    proc hook(_: PeerId, event: ConnEvent) {.async: (raises: [CancelledError]).} =
      case event.kind
      of ConnEventKind.Connected:
        allConnected.done()
      of ConnEventKind.Disconnected:
        allDisconnected.done()

    # Start first switch
    switches.add(
      makeStandardSwitchBuilder(TcpAutoAddress).withMaxConnsPerPeer(10).build()
    )
    switches[0].addConnEventHandler(hook, ConnEventKind.Connected)
    switches[0].addConnEventHandler(hook, ConnEventKind.Disconnected)
    await switches[0].start()

    # Connect remaining switches sequentially
    for i in 1 .. 5:
      switches.add(
        makeStandardSwitchBuilder(TcpAutoAddress).withPrivateKey(privateKey).build()
      )
      switches[i].addConnEventHandler(hook, ConnEventKind.Connected)
      switches[i].addConnEventHandler(hook, ConnEventKind.Disconnected)
      await switches[i].connect(switches[0].peerInfo.peerId, switches[0].peerInfo.addrs)

    # Wait until all 5 are connected
    await allConnected.wait(5.seconds)

    # Trigger disconnect safely
    await switches[0].disconnect(peerInfo.peerId)

    # Wait until all disconnected
    await allDisconnected.wait(5.seconds)
    check not switches[0].isConnected(peerInfo.peerId)

    checkUntilTimeout:
      not isCounterLeaked(LPChannelTrackerName)
      not isCounterLeaked(SecureConnTrackerName)

    await allFuturesRaising(switches[0].stop())

  asyncTest "e2e drop peer from inside its own stream handler":
    let disconnected = newWaitGroup(1)
    let futSwitch1Connected = newWaitGroup(1)
    var events: set[PeerEventKind]

    let switch1 = makeStandardSwitch(TcpAutoAddress)
    let switch2 = makeStandardSwitch(TcpAutoAddress)

    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      # Wait for the remote's dial to fully complete before disconnecting,
      # to avoid racing with multistream protocol negotiation completion
      # (the handler fires before the remote reads the protocol confirmation).
      await futSwitch1Connected.wait()
      try:
        await switch1.disconnect(stream.peerId)
        disconnected.done()
      finally:
        await stream.close()

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle
    switch1.mount(testProto)

    proc peerHandler(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]).} =
      events.incl(event.kind)

    switch1.addPeerEventHandler(peerHandler, PeerEventKind.Joined)
    switch1.addPeerEventHandler(peerHandler, PeerEventKind.Left)

    await switch1.start()
    await switch2.start()

    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

    # Signal to the handler that the dial has completed so it can proceed with the disconnect.
    futSwitch1Connected.done()

    # with the deadlock, the disconnect never completes and this times out
    await disconnected.wait(5.seconds)

    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)
      not switch2.isConnected(switch1.peerInfo.peerId)
      PeerEventKind.Left in events

    await stream.closeWithEOF()
    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e closing remote raw connection should not leak":
    let transport = TcpTransport.new(upgrade = Upgrade())
    await transport.start(@[TcpWildcardAddress])

    proc acceptHandler() {.async.} =
      let rawConn = await transport.accept()
      await rawConn.closeWithEOF()

    let handlerWait = acceptHandler()
    let switch = makeStandardSwitch(TcpAutoAddress)

    await switch.start()

    var peerId = PeerId.init(PrivateKey.random(ECDSA, rng()).get()).get()
    expect DialFailedError:
      await switch.connect(peerId, transport.addrs)

    await handlerWait

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)
    checkTracker(ChronosStreamTrackerName)

    await allFuturesRaising(transport.stop(), switch.stop())

  asyncTest "e2e calling closeWithEOF on the same stream should not assert":
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        discard await stream.readLp(100)
      except LPStreamError:
        check true # should be here

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    let switch1 = makeStandardSwitch()
    switch1.mount(testProto)

    let switch2 = makeStandardSwitch()

    await switch1.start()

    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

    proc closeReader() {.async.} =
      await stream.closeWithEOF()

    var readers: seq[Future[void]]
    for i in 0 .. 10:
      readers.add(closeReader())

    await allFuturesRaising(readers)
    await switch2.stop() #Otherwise this leaks
    checkUntilTimeout:
      not switch1.isConnected(switch2.peerInfo.peerId)

    checkTracker(LPChannelTrackerName)
    checkTracker(SecureConnTrackerName)
    checkTracker(ChronosStreamTrackerName)

    await switch1.stop()

  asyncTest "connect to inexistent peer":
    let switch2 = makeStandardSwitch(TcpAutoAddress)
    await switch2.start()
    let someAddr = ma("/ip4/127.128.0.99")
    let seckey = PrivateKey.random(ECDSA, rng()).get()
    let somePeer = PeerInfo.new(seckey, [someAddr])
    expect(DialFailedError):
      discard await switch2.dial(somePeer.peerId, somePeer.addrs, TestCodec)
    await switch2.stop()

  asyncTest "e2e total connection limits on incoming connections":
    var switches: seq[Switch]
    let destSwitch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withConnectionLimits(ConnectionLimits.maxTotal(3))
      .build()
    switches.add(destSwitch)
    await destSwitch.start()

    let destPeerInfo = destSwitch.peerInfo
    for i in 0 ..< 3:
      let switch = makeStandardSwitch(TcpAutoAddress)
      switches.add(switch)
      await switch.start()

      check await switch.connect(destPeerInfo.peerId, destPeerInfo.addrs).withTimeout(
        1000.millis
      )

    let switchFail = makeStandardSwitch(TcpAutoAddress)
    switches.add(switchFail)
    await switchFail.start()

    expect DialFailedError:
      await switchFail.connect(destPeerInfo.peerId, destPeerInfo.addrs).wait(10.seconds)

    await allFuturesRaising(switches.mapIt(it.stop()))

  asyncTest "e2e total connection limits on incoming connections":
    var switches: seq[Switch]
    for i in 0 ..< 3:
      switches.add(makeStandardSwitch(TcpAutoAddress))
      await switches[i].start()

    let srcSwitch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withConnectionLimits(ConnectionLimits.maxTotal(3))
      .build()
    await srcSwitch.start()
    switches.add(srcSwitch)

    let dstSwitch = makeStandardSwitch(TcpAutoAddress)
    await dstSwitch.start()
    switches.add(dstSwitch)

    for s in switches:
      check await srcSwitch.connect(s.peerInfo.peerId, s.peerInfo.addrs).withTimeout(
        1000.millis
      )

    expect DialFailedError:
      await srcSwitch.connect(dstSwitch.peerInfo.peerId, dstSwitch.peerInfo.addrs)

    await allFuturesRaising(switches.mapIt(it.stop()))

  asyncTest "e2e max incoming connection limits":
    var switches: seq[Switch]
    let destSwitch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withConnectionLimits(ConnectionLimits.maxInOut(3, 1))
      .build()
    switches.add(destSwitch)
    await destSwitch.start()

    let destPeerInfo = destSwitch.peerInfo
    for i in 0 ..< 3:
      let switch = makeStandardSwitch(TcpAutoAddress)
      switches.add(switch)
      await switch.start()

      check await switch.connect(destPeerInfo.peerId, destPeerInfo.addrs).withTimeout(
        1000.millis
      )

    let switchFail = makeStandardSwitch(TcpAutoAddress)
    switches.add(switchFail)
    await switchFail.start()

    expect DialFailedError:
      await switchFail.connect(destPeerInfo.peerId, destPeerInfo.addrs).wait(10.seconds)

    await allFuturesRaising(switches.mapIt(it.stop()))

  asyncTest "e2e max outgoing connection limits":
    var switches: seq[Switch]
    for i in 0 ..< 3:
      switches.add(makeStandardSwitch(TcpAutoAddress))
      await switches[i].start()

    let srcSwitch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withConnectionLimits(ConnectionLimits.maxInOut(1, 3))
      .build()
    await srcSwitch.start()

    let dstSwitch = makeStandardSwitch(TcpAutoAddress)
    await dstSwitch.start()

    for s in switches:
      check await srcSwitch.connect(s.peerInfo.peerId, s.peerInfo.addrs).withTimeout(
        1000.millis
      )

    expect DialFailedError:
      await srcSwitch.connect(dstSwitch.peerInfo.peerId, dstSwitch.peerInfo.addrs)

    switches.add(srcSwitch)
    switches.add(dstSwitch)

    await allFuturesRaising(switches.mapIt(it.stop()))

  asyncTest "e2e peer store":
    let handleFinished = newWaitGroup(1)
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        let msg = string.fromBytes(await stream.readLp(1024))
        check "Hello!" == msg
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in peer store test handler"
      finally:
        await stream.close()
        handleFinished.done()

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    let switch1 = makeStandardSwitch(TcpAutoAddress)
    switch1.mount(testProto)
    await switch1.start()

    let switch2 =
      makeStandardSwitchBuilder(TcpAutoAddress).withPeerStore(capacity = 0).build()
    await switch2.start()

    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await stream.writeLp("Hello!")
    let msg = string.fromBytes(await stream.readLp(1024))
    check "Hello!" == msg
    await stream.close()

    await allFuturesRaising(
      handleFinished.wait(5.seconds), switch1.stop(), switch2.stop()
    )

    check not switch1.isConnected(switch2.peerInfo.peerId)
    check not switch2.isConnected(switch1.peerInfo.peerId)

    check:
      switch1.peerStore[AddressBook][switch2.peerInfo.peerId] == switch2.peerInfo.addrs
      switch1.peerStore[ProtoBook][switch2.peerInfo.peerId] == switch2.peerInfo.protocols

      switch1.peerStore[LastSeenBook][switch2.peerInfo.peerId].isSome()

      switch1.peerInfo.peerId notin switch2.peerStore[AddressBook]
      switch1.peerInfo.peerId notin switch2.peerStore[ProtoBook]

  asyncTest "e2e LastSeenOutboundBook tracks outbound connections":
    let handleFinished = newWaitGroup(1)
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        let msg = string.fromBytes(await stream.readLp(1024))
        check "Hello!" == msg
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in LastSeenOutboundBook test handler"
      finally:
        await stream.close()
        handleFinished.done()

    let testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    let switch1 = makeStandardSwitch()
    switch1.mount(testProto)

    let switch2 = makeStandardSwitch()
    await switch1.start()
    await switch2.start()

    # Switch2 dials switch1 (outbound from switch2's perspective)
    let stream =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

    check switch1.isConnected(switch2.peerInfo.peerId)
    check switch2.isConnected(switch1.peerInfo.peerId)

    await stream.writeLp("Hello!")
    let msg = string.fromBytes(await stream.readLp(1024))
    check "Hello!" == msg
    await stream.close()

    await allFuturesRaising(
      handleFinished.wait(5.seconds), switch1.stop(), switch2.stop()
    )

    # Switch2 dialed switch1, so switch2 should have switch1 in LastSeenOutboundBook
    check:
      # Switch2 made an outbound connection to switch1
      switch2.peerStore[LastSeenOutboundBook][switch1.peerInfo.peerId].isSome()
      # Switch1 received an inbound connection from switch2, so NO entry in LastSeenOutboundBook
      switch1.peerStore[LastSeenOutboundBook][switch2.peerInfo.peerId].isNone()
      # Both should have entries in regular LastSeenBook (stores all connections)
      switch2.peerStore[LastSeenBook][switch1.peerInfo.peerId].isSome()
      switch1.peerStore[LastSeenBook][switch2.peerInfo.peerId].isSome()

  asyncTest "e2e should allow multiple local addresses":
    when defined(windows):
      # this randomly locks the Windows CI job
      skip()
    else:
      proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
        try:
          let msg = string.fromBytes(await stream.readLp(1024))
          check "Hello!" == msg
          await stream.writeLp("Hello!")
        except LPStreamError:
          raiseAssert "Unexpected LPStreamError in multiple local addresses test handler"
        finally:
          await stream.close()

      let testProto = new TestProto
      testProto.codec = TestCodec
      testProto.handler = handle

      let addrs = @[TcpAutoAddressIP4, TcpAutoAddressIP6]

      let switch1 = makeStandardSwitch(addrs)
      switch1.mount(testProto)

      let switch2 = makeStandardSwitch(TcpAutoAddress)
      let switch3 = makeStandardSwitch(TcpAutoAddress)

      await allFuturesRaising(switch1.start(), switch2.start(), switch3.start())

      check IP4.matchPartial(switch1.peerInfo.addrs[0])
      check IP6.matchPartial(switch1.peerInfo.addrs[1])

      let stream = await switch2.dial(
        switch1.peerInfo.peerId, @[switch1.peerInfo.addrs[0]], TestCodec
      )

      check switch1.isConnected(switch2.peerInfo.peerId)
      check switch2.isConnected(switch1.peerInfo.peerId)

      await stream.writeLp("Hello!")
      check "Hello!" == string.fromBytes(await stream.readLp(1024))
      await stream.close()

      let connv6 = await switch3.dial(
        switch1.peerInfo.peerId, @[switch1.peerInfo.addrs[1]], TestCodec
      )

      check switch1.isConnected(switch3.peerInfo.peerId)
      check switch3.isConnected(switch1.peerInfo.peerId)

      await connv6.writeLp("Hello!")
      check "Hello!" == string.fromBytes(await connv6.readLp(1024))
      await connv6.close()

      await allFuturesRaising(switch1.stop(), switch2.stop(), switch3.stop())

      check not switch1.isConnected(switch2.peerInfo.peerId)
      check not switch2.isConnected(switch1.peerInfo.peerId)

  asyncTest "e2e dial dns4 address":
    let resolver = MockResolver.new()
    resolver.ipResponses[("localhost", false)] = @["127.0.0.1"]
    resolver.ipResponses[("localhost", true)] = @["::1"]

    let
      srcSwitch =
        makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver).build()
      destSwitch = makeStandardSwitch(TcpAutoAddress)

    await destSwitch.start()
    await srcSwitch.start()

    let testAddr = ma("/dns4/localhost/") & destSwitch.peerInfo.addrs[0][1].tryGet()

    await srcSwitch.connect(destSwitch.peerInfo.peerId, @[testAddr])
    check srcSwitch.isConnected(destSwitch.peerInfo.peerId)

    await destSwitch.stop()
    await srcSwitch.stop()

  asyncTest "e2e dial dnsaddr with multiple transports":
    let resolver = MockResolver.new()

    let
      srcTcpSwitch =
        makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver).build()
      srcWsSwitch =
        makeStandardSwitchBuilder(WsAutoAddress).withNameResolver(resolver).build()
      destSwitch = makeStandardSwitch(@[TcpAutoAddress, WsAutoAddress])

    await destSwitch.start()
    await srcWsSwitch.start()

    resolver.txtResponses["_dnsaddr.test.io"] = @[
      "dnsaddr=/dns4/localhost" & $destSwitch.peerInfo.addrs[0][1 ..^ 1].tryGet() &
        "/p2p/" & $destSwitch.peerInfo.peerId,
      "dnsaddr=/dns4/localhost" & $destSwitch.peerInfo.addrs[1][1 ..^ 1].tryGet(),
    ]
    resolver.ipResponses[("localhost", false)] = @["127.0.0.1"]

    let testAddr = ma("/dnsaddr/test.io/")

    await srcTcpSwitch.connect(destSwitch.peerInfo.peerId, @[testAddr])
    check srcTcpSwitch.isConnected(destSwitch.peerInfo.peerId)

    await srcWsSwitch.connect(destSwitch.peerInfo.peerId, @[testAddr])
    check srcWsSwitch.isConnected(destSwitch.peerInfo.peerId)

    await destSwitch.stop()
    await srcWsSwitch.stop()
    await srcTcpSwitch.stop()

  asyncTest "e2e quic transport":
    let
      srcSwitch = makeStandardSwitch(QuicAutoAddress)
      destSwitch = makeStandardSwitch(QuicAutoAddress)

    await destSwitch.start()
    await srcSwitch.start()

    await srcSwitch.connect(destSwitch.peerInfo.peerId, destSwitch.peerInfo.addrs)
    check srcSwitch.isConnected(destSwitch.peerInfo.peerId)

    await destSwitch.stop()
    await srcSwitch.stop()

  asyncTest "e2e multiple transports coexistence":
    let
      destSwitch = makeStandardSwitch(@[TcpAutoAddress, WsAutoAddress, QuicAutoAddress])
      srcTcpSwitch = makeStandardSwitch(TcpAutoAddress)
      srcWsSwitch = makeStandardSwitch(WsAutoAddress)
      srcQuicSwitch = makeStandardSwitch(QuicAutoAddress)

    let switches = @[destSwitch, srcTcpSwitch, srcWsSwitch, srcQuicSwitch]
    await allFutures(switches.mapIt(it.start()))
    defer:
      await allFutures(switches.mapIt(it.stop()))

    # Verify all three transport types are available in destSwitch
    check destSwitch.peerInfo.addrs.len == 3

    # Test TCP transport connection
    let tcpAddr = destSwitch.peerInfo.addrs.filterIt(TCP.match(it))[0]
    await srcTcpSwitch.connect(destSwitch.peerInfo.peerId, @[tcpAddr])
    check srcTcpSwitch.isConnected(destSwitch.peerInfo.peerId)

    # Test WebSocket transport connection
    let wsAddr = destSwitch.peerInfo.addrs.filterIt(WebSockets.match(it))[0]
    await srcWsSwitch.connect(destSwitch.peerInfo.peerId, @[wsAddr])
    check srcWsSwitch.isConnected(destSwitch.peerInfo.peerId)

    # Test QUIC transport connection
    let quicAddr = destSwitch.peerInfo.addrs.filterIt(QUIC_V1.match(it))[0]
    await srcQuicSwitch.connect(destSwitch.peerInfo.peerId, @[quicAddr])
    check srcQuicSwitch.isConnected(destSwitch.peerInfo.peerId)

  asyncTest "mount unstarted protocol":
    let handleFinished = newWaitGroup(1)
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        check "test123" == string.fromBytes(await stream.readLp(1024))
        await stream.writeLp("test456")
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in mount unstarted protocol test handler"
      finally:
        await stream.close()
        handleFinished.done()

    let
      src = makeStandardSwitch()
      dst = makeStandardSwitch()
      testProto = new TestProto
    testProto.codec = TestCodec
    testProto.handler = handle

    await src.start()
    await dst.start()
    defer:
      await allFutures(@[src, dst].mapIt(it.stop()))
    expect LPError:
      dst.mount(testProto)
    await testProto.start()
    dst.mount(testProto)

    let stream = await src.dial(dst.peerInfo.peerId, dst.peerInfo.addrs, TestCodec)

    await stream.writeLp("test123")
    check "test456" == string.fromBytes(await stream.readLp(1024))
    await stream.close()
    await handleFinished.wait(5.seconds)

  test "tryMount rejects a protocol with no handler or codec":
    let switch = makeStandardSwitch()

    let noHandler = new TestProto
    noHandler.codec = TestCodec
    check switch.tryMount(noHandler).error ==
      "Protocol has to define a handle method or proc"

    let noCodec = LPProtocol.new(
      @[""],
      proc(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
        discard,
    )
    check switch.tryMount(noCodec).error == "Protocol has to define a codec string"
    check TestCodec notin switch.peerInfo.protocols

  asyncTest "switch failing to start stops properly":
    let switch = makeStandardSwitch(@[TcpWildcardAddress, ma("/ip4/1.1.1.1/tcp/0")])

    expect LPError:
      await switch.start()
    # test is that this doesn't leak

  asyncTest "starting two times does not crash":
    let switch = makeStandardSwitch()

    await switch.start()
    await switch.start()

    await allFuturesRaising(switch.stop())

  asyncTest "withAnnouncedAddresses overrides what peers see":
    # Bind locally, but advertise a fake public address. Listen addrs must
    # reflect the actual bound socket; announced addrs must be returned by
    # peerInfo.addrs verbatim regardless of the mapper chain (including the
    # wildcard resolver, which would normally rewrite/expand listenAddrs).
    let
      announcedAddr = ma("/ip4/203.0.113.7/tcp/9000")
      switch = makeStandardSwitchBuilder(TcpAutoAddress)
        .withAnnouncedAddresses(@[announcedAddr])
        .build()

    await switch.start()
    defer:
      await switch.stop()

    # Transport actually bound a local socket — listenAddrs is populated, and
    # the *original* zero-port address has been resolved to something else.
    check switch.peerInfo.listenAddrs.len == 1
    check switch.peerInfo.listenAddrs[0] != TcpAutoAddress

    # Announced set wins regardless of wildcard-resolver or other mappers.
    check switch.peerInfo.addrs == @[announcedAddr]

  test "withUndialableAddresses and withAgentVersion reach the built switch":
    let switch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withUndialableAddresses()
      .withAgentVersion("test-agent/1.0")
      .build()

    check:
      switch.peerStore.allowUndialableAddrs
      switch.peerInfo.agentVersion == "test-agent/1.0"

  test "a builder without an rng or secure manager defaults to Noise":
    let switch = SwitchBuilder
      .new()
      .withAddresses(@[TcpAutoAddress])
      .withTcpTransport()
      .withMplex()
      .build()

    check:
      switch.transports.len == 1
      switch.transports[0].upgrader.secureManagers.len == 1
      switch.transports[0].upgrader.secureManagers[0] of Noise

  asyncTest "accept loop not blocked by upgrade semaphore":
    # Regression: old code held the upgrade semaphore in the accept loop, blocking
    # it when ConcurrentUpgrades (4) were in flight; manifested as 80+ kad nodes
    # getting stuck on bootstrap.
    const NumPeers = 85
    let server = makeStandardSwitchBuilder(TcpAutoAddress)
      .withConnectionLimits(ConnectionLimits.maxTotal(NumPeers))
      .build()
    await server.start()

    var clients: seq[Switch]
    for _ in 0 ..< NumPeers:
      let c = makeStandardSwitch(TcpAutoAddress)
      await c.start()
      clients.add(c)
    defer:
      await allFuturesRaising(clients.mapIt(it.stop()) & @[server.stop()])

    let connects =
      clients.mapIt(it.connect(server.peerInfo.peerId, server.peerInfo.addrs))
    let allConnects = allFuturesRaising(connects)
    check await allConnects.withTimeout(30.seconds)
    await allConnects

suite "Switch :: IdentifyPusher Service":
  var
    switch1 {.threadvar.}: Switch
    switch2 {.threadvar.}: Switch

  asyncSetup:
    switch1 = makeStandardSwitchBuilder(TcpAutoAddress).withIdentifyPusher().build()
    switch2 = makeStandardSwitchBuilder(TcpAutoAddress).withIdentifyPusher().build()
    await switch1.start()
    await switch2.start()
    await switch1.connect(switch2.peerInfo.peerId, switch2.peerInfo.addrs)

  asyncTeardown:
    await switch1.stop()
    await switch2.stop()

  asyncTest "broadcasts on mount of new protocol":
    checkUntilTimeout:
      switch1.isConnected(switch2.peerInfo.peerId)
      switch2.isConnected(switch1.peerInfo.peerId)

    # mount new protocol to switch2
    let codecs = "/switch/protocol/1.0.0"
    proc dummyHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      await stream.close()

    let dummy = LPProtocol.new(@[codecs], dummyHandler)
    await dummy.start()
    switch2.mount(dummy)

    # switch1 should get information about new protocol
    checkUntilTimeout:
      codecs in switch1.peerStore[ProtoBook][switch2.peerInfo.peerId]

  asyncTest "broadcasts on updateAddrs":
    checkUntilTimeout:
      switch1.isConnected(switch2.peerInfo.peerId)
      switch2.isConnected(switch1.peerInfo.peerId)

    # switch2 starts listening on new address
    let extra = ma("/ip4/127.0.0.1/tcp/999")
    switch2.peerInfo.listenAddrs.add(extra)
    await switch2.peerInfo.update()

    # switch1 should receive new address
    checkUntilTimeout:
      extra in switch1.peerStore[AddressBook][switch2.peerInfo.peerId]

  asyncTest "restarted switch accepts identified connections":
    let listener = makeStandardSwitch(TcpAutoAddress)
    let dialer = makeStandardSwitch(TcpAutoAddress)
    await listener.start()
    await listener.stop()
    await listener.start()
    await dialer.start()
    defer:
      await allFutures(listener.stop(), dialer.stop())
    await dialer.connect(listener.peerInfo.peerId, listener.peerInfo.addrs).wait(
      2.seconds
    )
    check listener.isConnected(dialer.peerInfo.peerId)
    check (await listener.connManager.waitForPeerReady(dialer.peerInfo.peerId))
