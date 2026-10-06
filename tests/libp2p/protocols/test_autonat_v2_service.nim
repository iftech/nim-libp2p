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

proc createSwitch(
    service: AutonatV2Service = nil, minCount = DefaultObservedAddrMinCount
): Switch =
  let switch = SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[TcpWildcardAddress], false)
    .withTcpTransport()
    .withYamux()
    .withNoise()
    .withAddressManager(
      AddressManagerConfig(verifyInterval: VerifyInterval, minCount: minCount)
    )
    .build()

  if not service.isNil():
    switch.add(service)

  switch

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
    discard createSwitch(service)
    check service.networkReachability == NetworkReachability.Unknown

  asyncTest "a confirmed candidate makes the node reachable and notifies every subscriber":
    let
      (service, _) = newService(Reachable)
      switch = createSwitch(service)
      peer = createSwitch()
      first = service.awaitReachability(Reachable)
      second = service.awaitReachability(Reachable)

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    await switch.connect(peer.peerInfo.peerId, peer.peerInfo.addrs)

    await first
    await second

    check:
      service.networkReachability == Reachable
      switch.addressManager.confirmedAddrs().len > 0

  asyncTest "a failed dial back drops the public address and keeps the LAN ones":
    let
      (service, _) = newService(NotReachable)
      switch = createSwitch(service)
      peer = createSwitch()
      notified = service.awaitReachability(NotReachable)
      publicAddr = ma("/ip4/1.2.3.4/tcp/4040")

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    switch.addressManager.add(publicAddr, AddrSource.Upnp)
    await switch.connect(peer.peerInfo.peerId, peer.peerInfo.addrs)

    await notified

    checkUntilTimeout:
      service.networkReachability == NotReachable
      switch.addressManager.confirmedAddrs().len == 0
      publicAddr notin switch.peerInfo.addrs
      switch.peerInfo.addrs.len > 0

  asyncTest "an unknown verdict changes nothing and notifies nobody":
    let
      (service, _) = newService(Unknown)
      switch = createSwitch(service)
      peer = createSwitch()

    discard service.reachabilityObservers.add(
      proc(
          reachability: NetworkReachability,
          confidence: Opt[float],
          dialBackAddr: Opt[MultiAddress],
      ) {.async: (raises: [CancelledError]).} =
        fail()
    )

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    await switch.connect(peer.peerInfo.peerId, peer.peerInfo.addrs)

    await sleepAsync(VerifyInterval * 4)
    check service.networkReachability == NetworkReachability.Unknown

  asyncTest "a node which becomes reachable later notifies both changes":
    let
      (service, client) = newService(NotReachable, expectedDials = 2)
      switch = createSwitch(service)
      peer = createSwitch()
      notReachable = service.awaitReachability(NotReachable)
      reachable = service.awaitReachability(Reachable)

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    await switch.connect(peer.peerInfo.peerId, peer.peerInfo.addrs)

    await notReachable
    client.response = mockResponse(Reachable)
    await reachable

    check service.networkReachability == Reachable

  asyncTest "an observed address becomes a verified candidate when derivation is on":
    let
      (service, _) = newService(
        Reachable, config = AutonatV2ServiceConfig.new(enableDialableCandidates = true)
      )
      switch = createSwitch(service, minCount = 3)
      peer = createSwitch()
      notified = service.awaitReachability(Reachable)

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    await switch.connect(peer.peerInfo.peerId, peer.peerInfo.addrs)

    let observedAddr = ma("/ip4/8.8.8.8/tcp/4040")
    for _ in 0 ..< 3:
      check switch.addressManager.addObservation(randomPeerId(), observedAddr)

    await notified

    checkUntilTimeout:
      observedAddr in switch.addressManager.confirmedAddrs()

  asyncTest "no candidate is derived from observations by default":
    let
      (service, _) = newService(Reachable)
      switch = createSwitch(service, minCount = 3)
      peer = createSwitch()
      notified = service.awaitReachability(Reachable)

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    await switch.connect(peer.peerInfo.peerId, peer.peerInfo.addrs)

    let observedAddr = ma("/ip4/8.8.8.8/tcp/4040")
    for _ in 0 ..< 3:
      check switch.addressManager.addObservation(randomPeerId(), observedAddr)

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
      switch = createSwitch(service)
      peer = createSwitch()

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    await switch.connect(peer.peerInfo.peerId, peer.peerInfo.addrs)

    checkUntilTimeout:
      service.networkReachability == Reachable

  asyncTest "a peer which dialed us triggers no verification":
    let
      (service, client) = newService(Reachable)
      switch = createSwitch(service)
      peer = createSwitch()

    await allFuturesRaising(switch.start(), peer.start())
    defer:
      await allFuturesRaising(switch.stop(), peer.stop())
    await peer.connect(switch.peerInfo.peerId, switch.peerInfo.addrs)

    await sleepAsync(VerifyInterval * 4)

    check:
      client.dials == 0
      service.networkReachability == NetworkReachability.Unknown
