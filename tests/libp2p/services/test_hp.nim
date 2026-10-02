# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

{.push raises: [].}

import chronos
import
  ../../../libp2p/
    [builders, switch, wire, services/hpservice, services/autorelayservice]
import ../../../libp2p/protocols/connectivity/relay/[relay, client]
import ../../../libp2p/protocols/connectivity/autonat/[service]
import ../../../libp2p/nameresolving/[nameresolver, mockresolver]
import ../../stubs/[autonatclientstub, switchstub]
import ../../tools/[unittest, futures, resolver, crypto, switch_builder, multiaddress]

proc createSwitch(
    r: Relay = nil, hpService: Service = nil, nameResolver: NameResolver = nil
): Switch {.raises: [LPError].} =
  let switch = makeStandardSwitchBuilder(TcpAutoAddress)
    .withAutonat()
    .withMaxConnsPerPeer(2)
    # HP needs relay + direct to coexist briefly during upgrade
    .withCircuitRelay(r)
    .withNameResolver(nameResolver)
    .build()

  switch.add(hpService)

  return switch

suite "Hole Punching":
  teardown:
    checkTrackers()

  test "HPService shares the observers of its AutonatService":
    # HPService produces no reachability of its own, so it hands out the
    # observers of the AutoNAT v1 service that it drives.
    # A nil client and a nil AutoRelayService are safe because this test only
    # constructs the services and reads their shared observer collection.
    let autonatService = AutonatService.new(nil, rng())
    let hpService = HPService.new(autonatService, nil)

    check hpService.reachabilityObservers == autonatService.reachabilityObservers

  template directConnection(restart: bool) =
    let autonatClientStub = AutonatClientStub.new(expectedDials = 1)
    autonatClientStub.answer = NotReachable
    let autonatService = AutonatService.new(autonatClientStub, rng(), maxQueueSize = 1)

    let relayClient = RelayClient.new()
    let privatePeerRelayAddr = newFuture[seq[MultiAddress]]()

    let publicPeerSwitch = createSwitch(RelayClient.new())

    proc checkMA(address: seq[MultiAddress]) =
      if not privatePeerRelayAddr.completed():
        privatePeerRelayAddr.complete(address)

    let autoRelayService = AutoRelayService.new(1, relayClient, checkMA, rng())

    let hpservice = HPService.new(autonatService, autoRelayService)

    let privatePeerSwitch =
      createSwitch(relayClient, hpservice, nameresolver = MockResolver.default())
    let peerSwitch = createSwitch()
    let switchRelay = createSwitch(Relay.new())

    await allFuturesRaising(
      switchRelay.start(),
      privatePeerSwitch.start(),
      publicPeerSwitch.start(),
      peerSwitch.start(),
    )
    if restart:
      await hpservice.stop(privatePeerSwitch)
      await hpservice.start(privatePeerSwitch)

    publicPeerSwitch.peerInfo.addrs.add(
      [ma("/dns4/localhost/") & publicPeerSwitch.peerInfo.addrs[0][1].tryGet()]
    )

    await privatePeerSwitch.connect(
      switchRelay.peerInfo.peerId, switchRelay.peerInfo.addrs
    )
    await privatePeerSwitch.connect(
      peerSwitch.peerInfo.peerId, peerSwitch.peerInfo.addrs
    ) # for autonat

    await publicPeerSwitch.connect(
      privatePeerSwitch.peerInfo.peerId, (await privatePeerRelayAddr)
    )

    checkUntilTimeoutCustom(10.seconds, 100.milliseconds):
      privatePeerSwitch.connManager.connCount(publicPeerSwitch.peerInfo.peerId) == 1
      not isRelayed(
        privatePeerSwitch.connManager.selectMuxer(publicPeerSwitch.peerInfo.peerId).connection
      )

    await allFuturesRaising(
      privatePeerSwitch.stop(),
      publicPeerSwitch.stop(),
      switchRelay.stop(),
      peerSwitch.stop(),
    )

  asyncTest "Direct connection must work when peer address is public":
    directConnection(false)

  asyncTest "Direct connection works after restarting HPService":
    directConnection(true)

  asyncTest "Direct connection must work when peer address is public and dns is used":
    let autonatClientStub = AutonatClientStub.new(expectedDials = 1)
    autonatClientStub.answer = NotReachable
    let autonatService = AutonatService.new(autonatClientStub, rng(), maxQueueSize = 1)

    let relayClient = RelayClient.new()
    let privatePeerRelayAddr = newFuture[seq[MultiAddress]]()

    let publicPeerSwitch = createSwitch(RelayClient.new())

    proc checkMA(address: seq[MultiAddress]) =
      if not privatePeerRelayAddr.completed():
        privatePeerRelayAddr.complete(address)

    let autoRelayService = AutoRelayService.new(1, relayClient, checkMA, rng())

    let hpservice = HPService.new(autonatService, autoRelayService)

    let privatePeerSwitch =
      createSwitch(relayClient, hpservice, nameResolver = MockResolver.default())
    let peerSwitch = createSwitch()
    let switchRelay = createSwitch(Relay.new())

    await allFuturesRaising(
      switchRelay.start(),
      privatePeerSwitch.start(),
      publicPeerSwitch.start(),
      peerSwitch.start(),
    )
    publicPeerSwitch.peerInfo.addrs.add(
      [ma("/dns4/localhost/") & publicPeerSwitch.peerInfo.addrs[0][1].tryGet()]
    )

    await privatePeerSwitch.connect(
      switchRelay.peerInfo.peerId, switchRelay.peerInfo.addrs
    )
    await privatePeerSwitch.connect(
      peerSwitch.peerInfo.peerId, peerSwitch.peerInfo.addrs
    ) # for autonat

    await publicPeerSwitch.connect(
      privatePeerSwitch.peerInfo.peerId, (await privatePeerRelayAddr)
    )

    checkUntilTimeoutCustom(10.seconds, 100.milliseconds):
      privatePeerSwitch.connManager.connCount(publicPeerSwitch.peerInfo.peerId) == 1
      not isRelayed(
        privatePeerSwitch.connManager.selectMuxer(publicPeerSwitch.peerInfo.peerId).connection
      )

    await allFuturesRaising(
      privatePeerSwitch.stop(),
      publicPeerSwitch.stop(),
      switchRelay.stop(),
      peerSwitch.stop(),
    )

  proc holePunchingTest(
      initiatorConnectStub: connectStubType,
      rcvConnectStub: connectStubType,
      answer: NetworkReachability,
  ) {.async.} =
    # There's no check in this test cause it can't test hole punching locally. It exists just to be sure the rest of
    # the code works properly.

    let autonatClientStub1 = AutonatClientStub.new(expectedDials = 1)
    autonatClientStub1.answer = NotReachable
    let autonatService1 =
      AutonatService.new(autonatClientStub1, rng(), maxQueueSize = 1)

    let autonatClientStub2 = AutonatClientStub.new(expectedDials = 1)
    autonatClientStub2.answer = answer
    let autonatService2 =
      AutonatService.new(autonatClientStub2, rng(), maxQueueSize = 1)

    let relayClient1 = RelayClient.new()
    let relayClient2 = RelayClient.new()
    let privatePeerRelayAddr1 = newFuture[seq[MultiAddress]]()

    proc checkMA(address: seq[MultiAddress]) =
      if not privatePeerRelayAddr1.completed():
        privatePeerRelayAddr1.complete(address)

    let autoRelayService1 = AutoRelayService.new(1, relayClient1, checkMA, rng())
    let autoRelayService2 = AutoRelayService.new(1, relayClient2, nil, rng())

    let hpservice1 = HPService.new(autonatService1, autoRelayService1)
    let hpservice2 = HPService.new(autonatService2, autoRelayService2)

    let privatePeerSwitch1 = SwitchStub.new(
      createSwitch(relayClient1, hpservice1, nameresolver = MockResolver.default())
    )
    let privatePeerSwitch2 = SwitchStub.new(createSwitch(relayClient2, hpservice2))

    let switchRelay = createSwitch(Relay.new())
    let switchAux = createSwitch()
    let switchAux2 = createSwitch()
    let switchAux3 = createSwitch()
    let switchAux4 = createSwitch()

    await allFuturesRaising(
      switchRelay.start(),
      privatePeerSwitch1.start(),
      privatePeerSwitch2.start(),
      switchAux.start(),
      switchAux2.start(),
      switchAux3.start(),
      switchAux4.start(),
    )

    await privatePeerSwitch1.connect(
      switchRelay.peerInfo.peerId, switchRelay.peerInfo.addrs
    )
    await privatePeerSwitch2.connect(
      switchAux.peerInfo.peerId, switchAux.peerInfo.addrs
    )

    await sleepAsync(100.millis)

    await privatePeerSwitch1.connect(
      switchAux2.peerInfo.peerId, switchAux2.peerInfo.addrs
    )
    await privatePeerSwitch1.connect(
      switchAux3.peerInfo.peerId, switchAux3.peerInfo.addrs
    )
    await privatePeerSwitch1.connect(
      switchAux4.peerInfo.peerId, switchAux4.peerInfo.addrs
    )

    await privatePeerSwitch2.connect(
      switchAux2.peerInfo.peerId, switchAux2.peerInfo.addrs
    )
    await privatePeerSwitch2.connect(
      switchAux3.peerInfo.peerId, switchAux3.peerInfo.addrs
    )
    await privatePeerSwitch2.connect(
      switchAux4.peerInfo.peerId, switchAux4.peerInfo.addrs
    )

    privatePeerSwitch1.connectStub = initiatorConnectStub
    await privatePeerSwitch2.connect(
      privatePeerSwitch1.peerInfo.peerId, (await privatePeerRelayAddr1)
    )
    privatePeerSwitch2.connectStub = rcvConnectStub

    # wait for hole punching to finish in the background
    await sleepAsync(300.millis)

    await allFuturesRaising(
      privatePeerSwitch1.stop(),
      privatePeerSwitch2.stop(),
      switchRelay.stop(),
      switchAux.stop(),
      switchAux2.stop(),
      switchAux3.stop(),
      switchAux4.stop(),
    )

  asyncTest "Hole punching when peers addresses are private":
    await holePunchingTest(nil, nil, NotReachable)

  asyncTest "Hole punching when peers addresses are private and there is an error in the initiator side":
    proc connectStub(
        self: SwitchStub,
        peerId: PeerId,
        addrs: seq[MultiAddress],
        forceDial = false,
        reuseConnection = true,
        dir = Direction.Out,
    ): Future[void] {.async: (raises: [DialFailedError, CancelledError]).} =
      self.connectStub = nil # this stub should be called only once
      raise newException(DialFailedError, "error")

    await holePunchingTest(connectStub, nil, Reachable)
