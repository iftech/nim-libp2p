# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    builders,
    switch,
    address_manager,
    protocols/connectivity/autonatv2/types,
    protocols/connectivity/autonatv2/service,
    protocols/connectivity/autonatv2/mockclient,
    utils/future,
  ]
import ../../tools/[unittest, futures, crypto, multiaddress]

const VerifyInterval = 50.milliseconds

proc createSwitch(minCount = DefaultObservedAddrMinCount): Switch =
  return SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[TcpWildcardAddress])
    .withWildcardResolver(false)
    .withTcpTransport()
    .withYamux()
    .withNoise()
    .withAddressManager(
      AddressManagerConfig(verifyInterval: VerifyInterval, minCount: minCount)
    )
    .withAutonatV2Server()
    .build()

proc startAutonatSwitch(switch: Switch, service: AutonatV2Service) {.async.} =
  await switch.start()
  await service.start(switch)

proc stopAutonatSwitch(switch: Switch, service: AutonatV2Service) {.async.} =
  try:
    await service.stop(switch)
  finally:
    await switch.stop()

proc mockResponse(reachability: NetworkReachability): AutonatV2Response =
  let dialStatus =
    if reachability == Reachable: DialStatus.Ok else: DialStatus.EDialError
  AutonatV2Response(
    reachability: reachability,
    dialResp: DialResponse(
      status: ResponseStatus.Ok,
      dialStatus: Opt.some(dialStatus),
      addrIdx: Opt.some(0.AddrIdx),
    ),
  )

type DelayedClientMock = ref object of AutonatV2ClientMock
  delay: Duration

method sendDialRequest(
    self: DelayedClientMock, pid: PeerId, testAddrs: seq[MultiAddress]
): Future[AutonatV2Response] {.
    async: (raises: [AutonatV2Error, CancelledError, DialFailedError, LPStreamError])
.} =
  await sleepAsync(self.delay)
  await procCall AutonatV2ClientMock(self).sendDialRequest(pid, testAddrs)

proc newService(
    reachability: NetworkReachability,
    expectedDials = 1,
    config: AutonatV2ServiceConfig = AutonatV2ServiceConfig.new(),
): (AutonatV2Service, AutonatV2ClientMock) =
  let client =
    AutonatV2ClientMock.new(mockResponse(reachability), expectedDials = expectedDials)
  (AutonatV2Service.new(rng(), client = client, config = config), client)

proc awaitReachability(
    service: AutonatV2Service, expected: NetworkReachability
): Future[void] =
  let fut = newFuture[void]()
  discard service.reachabilityObservers.add(
    proc(
        reachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if reachability == expected:
        fut.completeOnce()
  )
  fut

suite "AutonatV2 Service":
  teardown:
    checkTrackers()

  asyncTest "reachability is unknown before the switch starts":
    let (service, _) = newService(Reachable)
    discard createSwitch()
    check service.networkReachability == NetworkReachability.Unknown

  asyncTest "a confirmed candidate makes the node reachable and notifies every subscriber":
    let
      (service, _) = newService(Reachable)
      switch = createSwitch()
      peer = createSwitch()
      first = service.awaitReachability(Reachable)
      second = service.awaitReachability(Reachable)

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    await switch.connect(peer)

    await first
    await second

    check:
      service.networkReachability == Reachable
      switch.addressManager.confirmedAddrs().len > 0

  asyncTest "a failed dial back drops the public address and keeps the LAN ones":
    let
      (service, _) = newService(NotReachable)
      switch = createSwitch()
      peer = createSwitch()
      notified = service.awaitReachability(NotReachable)
      publicAddr = ma("/ip4/1.2.3.4/tcp/4040")

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    switch.addressManager.add(publicAddr, AddrSource.Upnp)
    await switch.connect(peer)

    await notified

    checkUntilTimeout:
      service.networkReachability == NotReachable
      switch.addressManager.confirmedAddrs().len == 0
      publicAddr notin switch.peerInfo.addrs
      switch.peerInfo.addrs.len > 0

  asyncTest "an unknown verdict changes nothing and notifies nobody":
    let
      (service, _) = newService(Unknown)
      switch = createSwitch()
      peer = createSwitch()

    discard service.reachabilityObservers.add(
      proc(
          reachability: NetworkReachability,
          confidence: Opt[float],
          dialBackAddr: Opt[MultiAddress],
      ) {.async: (raises: [CancelledError]).} =
        fail()
    )

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    await switch.connect(peer)

    await sleepAsync(VerifyInterval * 4)
    check service.networkReachability == NetworkReachability.Unknown

  asyncTest "a node which becomes reachable later notifies both changes":
    let
      (service, client) = newService(NotReachable, expectedDials = 2)
      switch = createSwitch()
      peer = createSwitch()
      notReachable = service.awaitReachability(NotReachable)
      reachable = service.awaitReachability(Reachable)

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    await switch.connect(peer)

    await notReachable
    client.response = mockResponse(Reachable)
    await reachable

    check service.networkReachability == Reachable

  asyncTest "an observed address becomes a verified candidate when derivation is on":
    let
      (service, _) = newService(
        Reachable, config = AutonatV2ServiceConfig.new(enableDialableCandidates = true)
      )
      switch = createSwitch(minCount = 3)
      peer = createSwitch()
      notified = service.awaitReachability(Reachable)

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    await switch.connect(peer)

    let observedAddr = ma("/ip4/8.8.8.8/tcp/4040")
    for _ in 0 ..< 3:
      check switch.addressManager.addObservation(PeerId.random(), observedAddr)

    await notified

    checkUntilTimeout:
      observedAddr in switch.addressManager.confirmedAddrs()

  asyncTest "no candidate is derived from observations by default":
    let
      (service, _) = newService(Reachable)
      switch = createSwitch(minCount = 3)
      peer = createSwitch()
      notified = service.awaitReachability(Reachable)

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    await switch.connect(peer)

    let observedAddr = ma("/ip4/8.8.8.8/tcp/4040")
    for _ in 0 ..< 3:
      check switch.addressManager.addObservation(PeerId.random(), observedAddr)

    await notified
    await sleepAsync(VerifyInterval * 4)

    check observedAddr notin switch.addressManager.confirmedAddrs()

  asyncTest "the schedule interval does not cancel a valid dial request":
    let
      interval = 10.milliseconds
      client = DelayedClientMock(
        delay: interval * 4,
        response: mockResponse(Reachable),
        finished: newFuture[void](),
      )
      service = AutonatV2Service.new(
        rng(),
        client = client,
        config = AutonatV2ServiceConfig.new(scheduleInterval = Opt.some(interval)),
      )
      switch = createSwitch()
      peer = createSwitch()

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    await switch.connect(peer)

    checkUntilTimeout:
      service.networkReachability == Reachable

  asyncTest "a peer which dialed us triggers no verification":
    let
      (service, client) = newService(Reachable)
      switch = createSwitch()
      peer = createSwitch()

    await allFuturesRaising(startAutonatSwitch(switch, service), peer.start())
    defer:
      await allFuturesRaising(stopAutonatSwitch(switch, service), peer.stop())
    await peer.connect(switch)

    await sleepAsync(VerifyInterval * 4)

    check:
      client.dials == 0
      service.networkReachability == NetworkReachability.Unknown
