# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

{.push raises: [].}

import std/sequtils
import chronos
import ../../../libp2p/[builders, switch, wire, services/autorelayservice]
import ../../../libp2p/utils/collections
import ../../../libp2p/services/hpservice {.all.}
import ../../../libp2p/protocols/connectivity/relay/[relay, client]
import ../../../libp2p/protocols/connectivity/dcutr/client as dcutr_client
import ../../../libp2p/protocols/connectivity/autonat/[service]
import ../../../libp2p/nameresolving/[nameresolver, mockresolver]
import ../../stubs/[autonatclientstub, switchstub]
import ../../tools/[unittest, futures, resolver, crypto, switch_builder, multiaddress]

proc createSwitch(
    r: Relay = nil, nameResolver: NameResolver = nil
): Switch {.raises: [LPError].} =
  return makeStandardSwitchBuilder(TcpAutoAddress)
    .withAutonat()
    .withMaxConnsPerPeer(2)
    # HP needs relay + direct to coexist briefly during upgrade
    .withCircuitRelay(r)
    .withNameResolver(nameResolver)
    .build()

proc startHpSwitch(switch: Switch, service: HPService) {.async.} =
  await switch.start()
  await service.start(switch)

proc stopHpSwitch(switch: Switch, service: HPService) {.async.} =
  try:
    await service.stop(switch)
  finally:
    await switch.stop()

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

  asyncTest "tryStartingDirectConn filters, ranks and batches the dials":
    type DirectCase = object
      name: string
      book: seq[MultiAddress]
      verified: seq[MultiAddress]
      silent: seq[MultiAddress]
      dialed: seq[MultiAddress]
      expected: bool

    let
      dcutrClient = DcutrClient.new(connectTimeout = 100.milliseconds)
      cap = dcutrClient.maxDialableAddrs
      peerId = PeerId.random(rng()).tryGet()
      nonPublic = @[
        ma("/ip4/8.8.4.4/tcp/4001/p2p-circuit"),
        ma("/ip4/192.168.1.5/tcp/4001"),
        ma("/ip4/127.0.0.1/tcp/4001"),
      ]
      dnsAddr = @[ma("/dns4/example.com/tcp/4001")]
      public = toSeq(1 .. 50).mapIt(ma("/ip4/8.8.8." & $it & "/tcp/4001"))
      cases = @[
        DirectCase(
          name: "every public addr is dialed when all fail",
          book: nonPublic & public,
          dialed: public,
          expected: false,
        ),
        DirectCase(
          name: "a verified addr past the first batch is dialed first",
          book: public,
          verified: public[^1 .. ^1],
          dialed: public[^1 .. ^1] & public[0 ..< ^1],
          expected: false,
        ),
        DirectCase(
          name: "a success in the first batch skips the next batches",
          book: public,
          dialed: public[0 ..< cap],
          expected: true,
        ),
        DirectCase(
          name: "a silent first batch moves on to the next batch",
          book: public[0 .. cap],
          silent: public[0 ..< cap],
          dialed: public[0 .. cap],
          expected: true,
        ),
        DirectCase(
          name: "success returns true",
          book: nonPublic & public[0 .. 1],
          dialed: public[0 .. 1],
          expected: true,
        ),
        DirectCase(
          name: "only silent addrs time out",
          book: public[0 .. 1],
          silent: public[0 .. 1],
          dialed: public[0 .. 1],
          expected: false,
        ),
        DirectCase(
          name: "dns addr is dialed alongside public ip addr",
          book: nonPublic & dnsAddr & public[0 .. 0],
          dialed: dnsAddr & public[0 .. 0],
          expected: true,
        ),
        DirectCase(
          name: "no public addr makes no connect call",
          book: nonPublic,
          dialed: @[],
          expected: false,
        ),
      ]

    let switch = SwitchStub.new(createSwitch())
    var
      calls: seq[seq[MultiAddress]]
      forcedOrReused: seq[bool]
      fails = false
      silent: seq[MultiAddress]

    proc recordConnect(
        self: SwitchStub,
        peerId: PeerId,
        addrs: seq[MultiAddress],
        forceDial = false,
        reuseConnection = true,
        dir = Direction.Out,
    ): Future[void] {.async: (raises: [DialFailedError, CancelledError]).} =
      calls.add(addrs)
      forcedOrReused.add(forceDial or reuseConnection)
      if addrs.anyIt(it in silent):
        await Future[void].Raising([CancelledError]).init("test_hp.silent")
      if fails:
        raise newException(DialFailedError, "unreachable")

    switch.connectStub = recordConnect
    let hp = HPService.new(nil, nil)

    for c in cases:
      checkpoint c.name
      calls.setLen(0)
      forcedOrReused.setLen(0)
      fails = not c.expected
      silent = c.silent
      discard switch.peerStore[AddressBook].del(peerId)
      switch.peerStore[AddressBook].set(peerId, c.verified, AddressConfidence.High)
      switch.peerStore[AddressBook][peerId] = c.book

      check:
        (
          await hp.tryStartingDirectConn(
            switch, peerId, cap, dcutrClient.connectTimeout
          )
        ) == c.expected
        calls == c.dialed.toChunks(cap)
        forcedOrReused == newSeqWith(calls.len, false)

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
      createSwitch(relayClient, nameresolver = MockResolver.default())
    let peerSwitch = createSwitch()
    let switchRelay = createSwitch(Relay.new())

    await allFuturesRaising(
      switchRelay.start(),
      startHpSwitch(privatePeerSwitch, hpservice),
      publicPeerSwitch.start(),
      peerSwitch.start(),
    )
    if restart:
      await hpservice.stop(privatePeerSwitch)
      await hpservice.start(privatePeerSwitch)

    publicPeerSwitch.peerInfo.addrs.add(
      [ma("/dns4/localhost/") & publicPeerSwitch.peerInfo.addrs[0][1].tryGet()]
    )

    await privatePeerSwitch.connect(switchRelay)
    await privatePeerSwitch.connect(peerSwitch) # for autonat

    await publicPeerSwitch.connect(
      privatePeerSwitch.peerInfo.peerId, (await privatePeerRelayAddr)
    )

    checkUntilTimeoutCustom(10.seconds, 100.milliseconds):
      privatePeerSwitch.connManager.connCount(publicPeerSwitch.peerInfo.peerId) == 1
      not isRelayed(
        privatePeerSwitch.connManager.selectMuxer(publicPeerSwitch.peerInfo.peerId).connection
      )

    await allFuturesRaising(
      stopHpSwitch(privatePeerSwitch, hpservice),
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
      createSwitch(relayClient, nameResolver = MockResolver.default())
    let peerSwitch = createSwitch()
    let switchRelay = createSwitch(Relay.new())

    await allFuturesRaising(
      switchRelay.start(),
      startHpSwitch(privatePeerSwitch, hpservice),
      publicPeerSwitch.start(),
      peerSwitch.start(),
    )
    publicPeerSwitch.peerInfo.addrs.add(
      [ma("/dns4/localhost/") & publicPeerSwitch.peerInfo.addrs[0][1].tryGet()]
    )

    await privatePeerSwitch.connect(switchRelay)
    await privatePeerSwitch.connect(peerSwitch) # for autonat

    await publicPeerSwitch.connect(
      privatePeerSwitch.peerInfo.peerId, (await privatePeerRelayAddr)
    )

    checkUntilTimeoutCustom(10.seconds, 100.milliseconds):
      privatePeerSwitch.connManager.connCount(publicPeerSwitch.peerInfo.peerId) == 1
      not isRelayed(
        privatePeerSwitch.connManager.selectMuxer(publicPeerSwitch.peerInfo.peerId).connection
      )

    await allFuturesRaising(
      stopHpSwitch(privatePeerSwitch, hpservice),
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

    let privatePeerSwitch1 =
      SwitchStub.new(createSwitch(relayClient1, nameresolver = MockResolver.default()))
    let privatePeerSwitch2 = SwitchStub.new(createSwitch(relayClient2))

    let switchRelay = createSwitch(Relay.new())
    let switchAux = createSwitch()
    let switchAux2 = createSwitch()
    let switchAux3 = createSwitch()
    let switchAux4 = createSwitch()

    await allFuturesRaising(
      switchRelay.start(),
      startHpSwitch(privatePeerSwitch1, hpservice1),
      startHpSwitch(privatePeerSwitch2, hpservice2),
      switchAux.start(),
      switchAux2.start(),
      switchAux3.start(),
      switchAux4.start(),
    )

    await privatePeerSwitch1.connect(switchRelay)
    await privatePeerSwitch2.connect(switchAux)

    await sleepAsync(100.millis)

    await privatePeerSwitch1.connect(switchAux2)
    await privatePeerSwitch1.connect(switchAux3)
    await privatePeerSwitch1.connect(switchAux4)

    await privatePeerSwitch2.connect(switchAux2)
    await privatePeerSwitch2.connect(switchAux3)
    await privatePeerSwitch2.connect(switchAux4)

    privatePeerSwitch1.connectStub = initiatorConnectStub
    await privatePeerSwitch2.connect(
      privatePeerSwitch1.peerInfo.peerId, (await privatePeerRelayAddr1)
    )
    privatePeerSwitch2.connectStub = rcvConnectStub

    # wait for hole punching to finish in the background
    await sleepAsync(300.millis)

    await allFuturesRaising(
      stopHpSwitch(privatePeerSwitch1, hpservice1),
      stopHpSwitch(privatePeerSwitch2, hpservice2),
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
