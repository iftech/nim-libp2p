# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import
  ../../../libp2p/[
    address_manager,
    builders,
    switch,
    crypto/crypto,
    protocols/connectivity/relay/relay,
    protocols/connectivity/relay/client,
    services/autorelayservice,
    utils/future,
  ]
import ../../tools/[unittest, crypto, switch_builder, multiaddress, lifecycle]

proc createSwitch(r: Relay, autorelay: Service = nil): Switch =
  let switch = makeStandardSwitchBuilder(TcpAutoAddress).withCircuitRelay(r).build()

  switch.add(autorelay)

  switch

proc buildRelayMA(switchRelay: Switch, switchClient: Switch): seq[MultiAddress] =
  var addrs: seq[MultiAddress]
  for i in 0 ..< switchRelay.peerInfo.addrs.len():
    addrs.add(
      MultiAddress
        .init(
          $switchRelay.peerInfo.addrs[i] & "/p2p/" & $switchRelay.peerInfo.peerId &
            "/p2p-circuit"
        )
        .get()
    )
  addrs

suite "Autorelay":
  asyncTeardown:
    checkTrackers()

  var
    switchRelay {.threadvar.}: Switch
    switchClient {.threadvar.}: Switch
    relayClient {.threadvar.}: RelayClient
    autorelay {.threadvar.}: AutoRelayService

  asyncTest "Simple test":
    switchRelay = createSwitch(Relay.new())
    relayClient = RelayClient.new()
    let fut = newFuture[void]()
    proc checkMA(addresses: seq[MultiAddress]) =
      if not fut.finished:
        check:
          addresses == buildRelayMA(switchRelay, switchClient)
        fut.complete()

    autorelay = AutoRelayService.new(3, relayClient, checkMA, rng())
    switchClient = createSwitch(relayClient, autorelay)
    await allFutures(switchClient.start(), switchRelay.start())
    await switchClient.connect(switchRelay)
    await fut
    let addresses = autorelay.getAddresses()
    check:
      addresses == buildRelayMA(switchRelay, switchClient)
    await allFutures(switchClient.stop(), switchRelay.stop())

  asyncTest "Connect after starting switches":
    switchRelay = createSwitch(Relay.new())
    relayClient = RelayClient.new()
    let fut = newFuture[void]()
    proc checkMA(address: seq[MultiAddress]) =
      if not fut.finished:
        check:
          address == buildRelayMA(switchRelay, switchClient)
        fut.complete()

    let autorelay = AutoRelayService.new(3, relayClient, checkMA, rng())
    switchClient = createSwitch(relayClient, autorelay)
    await allFutures(switchClient.start(), switchRelay.start())
    await sleepAsync(250.millis)
    await switchClient.connect(switchRelay)
    await fut
    let addresses = autorelay.getAddresses()

    check:
      addresses == buildRelayMA(switchRelay, switchClient)
    for address in addresses:
      check address in switchClient.peerInfo.addrs

    await allFutures(switchClient.stop(), switchRelay.stop())

  asyncTest "a confirmed direct address withdraws only the same-family relay address":
    switchRelay = createSwitch(Relay.new())
    relayClient = RelayClient.new()
    autorelay = AutoRelayService.new(3, relayClient, nil, rng())
    switchClient = createSwitch(relayClient, autorelay)
    startAndDeferStop(@[switchClient, switchRelay])
    await switchClient.connect(switchRelay)

    # the relay listens on IPv4, so its circuit addresses are the IPv4 family
    let
      relayMAs = buildRelayMA(switchRelay, switchClient)
      manager = switchClient.addressManager
      directIp6 = ma("/ip6/2a01::1/tcp/1")
      directIp4 = ma("/ip4/1.2.3.4/tcp/1")
      directPrivate = ma("/ip4/192.168.1.20/tcp/1")

    checkUntilTimeout:
      relayMAs.allIt(it in switchClient.peerInfo.addrs)

    manager.add(directIp6, AddrSource.Upnp)
    manager.update(directIp6, AddrState.Confirmed)
    await switchClient.peerInfo.update()
    for relayMA in relayMAs:
      check relayMA in switchClient.peerInfo.addrs

    # a confirmed private address proves only LAN reachability: the relay stays
    manager.add(directPrivate, AddrSource.Upnp)
    manager.update(directPrivate, AddrState.Confirmed)
    await switchClient.peerInfo.update()
    for relayMA in relayMAs:
      check relayMA in switchClient.peerInfo.addrs

    manager.add(directIp4, AddrSource.Upnp)
    manager.update(directIp4, AddrState.Confirmed)
    await switchClient.peerInfo.update()
    for relayMA in relayMAs:
      check relayMA notin switchClient.peerInfo.addrs

    manager.update(directIp4, AddrState.Unreachable)
    await switchClient.peerInfo.update()
    for relayMA in relayMAs:
      check relayMA in switchClient.peerInfo.addrs

  asyncTest "an expired confirmed mapping restores the relay immediately":
    switchRelay = createSwitch(Relay.new())
    relayClient = RelayClient.new()
    autorelay = AutoRelayService.new(3, relayClient, nil, rng())
    switchClient = createSwitch(relayClient, autorelay)

    let
      directAddr = ma("/ip4/1.2.3.4/tcp/1")
      manager = switchClient.addressManager
    var mappingAvailable = true
    proc mappingMapper(
        listenAddrs: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      if mappingAvailable:
        return listenAddrs & directAddr
      listenAddrs

    # registered before AutoRelay starts, so it produces before the relay mapper runs
    manager.addMapper(mappingMapper, AddrSource.Upnp)
    startAndDeferStop(@[switchClient, switchRelay])
    await switchClient.connect(switchRelay)
    let relayMAs = buildRelayMA(switchRelay, switchClient)

    checkUntilTimeout:
      relayMAs.allIt(it in switchClient.peerInfo.addrs)

    manager.update(directAddr, AddrState.Confirmed)
    await switchClient.peerInfo.update()
    check relayMAs.allIt(it notin switchClient.peerInfo.addrs)

    # the candidate stays confirmed until this pass ends, so AutoRelay reads the pass
    mappingAvailable = false
    await switchClient.peerInfo.update()
    check relayMAs.allIt(it in switchClient.peerInfo.addrs)

  asyncTest "stopping cancels an in-flight reservation":
    let
      relay = Relay.new()
      reservationRequested = newFuture[void]()
      reservationHandled = newFuture[void]()
      answerReservation = newAsyncEvent()
      relayHandler = relay.handler

    # the relay takes the reservation request and holds its response back
    relay.handler = proc(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      reservationRequested.completeOnce()
      await answerReservation.wait()
      try:
        await relayHandler(stream, proto)
      finally:
        reservationHandled.completeOnce()

    switchRelay = createSwitch(relay)
    relayClient = RelayClient.new()
    autorelay = AutoRelayService.new(3, relayClient, nil, rng())
    switchClient = createSwitch(relayClient, autorelay)

    startAndDeferStop(@[switchClient, switchRelay])
    await switchClient.connect(switchRelay)

    # stop the service while the reservation is still unanswered
    await reservationRequested
    await autorelay.stop(switchClient)

    # from here on, anything reaching relayAddresses was written by a stopped service
    check autorelay.getAddresses().len == 0

    answerReservation.fire()
    await reservationHandled
    check autorelay.getAddresses().len == 0

  asyncTest "restart does not announce the previous cycle's relay address":
    switchRelay = createSwitch(Relay.new())
    relayClient = RelayClient.new()
    autorelay = AutoRelayService.new(3, relayClient, nil, rng())
    switchClient = createSwitch(relayClient, autorelay)

    # the relay switch is stopped mid-test, so it is not in the deferred stop
    startAndDeferStop(@[switchClient])
    await switchRelay.start()
    await switchClient.connect(switchRelay)

    let relayMAs = buildRelayMA(switchRelay, switchClient)
    checkUntilTimeout:
      relayMAs.allIt(it in switchClient.peerInfo.addrs)

    await autorelay.stop(switchClient)
    check:
      relayMAs.allIt(it notin switchClient.peerInfo.addrs)
      autorelay.getAddresses().len == 0

    # the relay is gone, so this cycle reserves nothing of its own
    await switchRelay.stop()
    await autorelay.start(switchClient)
    check relayMAs.allIt(it notin switchClient.peerInfo.addrs)

    check autorelay.getAddresses().len == 0

  asyncTest "losing the last relay withdraws its announced address":
    switchRelay = createSwitch(Relay.new())
    relayClient = RelayClient.new()
    autorelay = AutoRelayService.new(1, relayClient, nil, rng())
    switchClient = createSwitch(relayClient, autorelay)
    startAndDeferStop(@[switchClient, switchRelay])
    await switchClient.connect(switchRelay)
    let relayMAs = buildRelayMA(switchRelay, switchClient)
    checkUntilTimeout:
      autorelay.getAddresses() == relayMAs
    await switchRelay.stop()
    checkUntilTimeout:
      autorelay.getAddresses().len == 0
    check relayMAs.allIt(it notin switchClient.peerInfo.addrs)

  asyncTest "Three relays connections":
    type RelayReservationState = enum
      Relay1Reserved
      Relay1AndRelay2Reserved
        # Although switchClient is connected to rel3, rel3 isn't reserved due to the maximum number of relays set to 2.
      Relay2UnreservedAndRelay1Reserved
      Relay1AndRelay3Reserved

    var state = Relay1Reserved
    let
      rel1 = createSwitch(Relay.new())
      rel2 = createSwitch(Relay.new())
      rel3 = createSwitch(Relay.new())
      rel1Checked = newFuture[void]()
      rel1And2Checked = newFuture[void]()
    relayClient = RelayClient.new()

    proc containsAll(addresses, expected: seq[MultiAddress]): bool =
      for a in expected:
        if a notin addresses:
          return false
      true

    proc checkMA(addresses: seq[MultiAddress]) =
      if state == Relay1Reserved or state == Relay2UnreservedAndRelay1Reserved:
        let relayMAs = buildRelayMA(rel1, switchClient)
        for relayMA in relayMAs:
          check:
            relayMA in addresses
        if state == Relay1Reserved:
          if not rel1Checked.finished:
            state = Relay1AndRelay2Reserved
            rel1Checked.complete()
        elif state == Relay2UnreservedAndRelay1Reserved:
          state = Relay1AndRelay3Reserved
      elif state == Relay1AndRelay2Reserved:
        let relay1MAs = buildRelayMA(rel1, switchClient)
        for relayMA in relay1MAs:
          check:
            relayMA in addresses
        let relay2MAs = buildRelayMA(rel2, switchClient)
        for relayMA in relay2MAs:
          check:
            relayMA in addresses
        if not rel1And2Checked.finished:
          state = Relay2UnreservedAndRelay1Reserved
          rel1And2Checked.complete()
      elif state == Relay1AndRelay3Reserved:
        discard # final state is checked below with retry/polling

    let autorelay = AutoRelayService.new(maxNumRelays = 2, relayClient, checkMA, rng())
    switchClient = createSwitch(relayClient, autorelay)
    await allFutures(switchClient.start(), rel1.start(), rel2.start(), rel3.start())
    await switchClient.connect(rel1)
    await rel1Checked
    await switchClient.connect(rel2)
    await switchClient.connect(rel3)
    await rel1And2Checked
    await rel2.stop()

    # final state check
    let relay1MAs = buildRelayMA(rel1, switchClient)
    let relay3MAs = buildRelayMA(rel3, switchClient)
    checkUntilTimeout:
      block:
        let addresses = autorelay.getAddresses()
        containsAll(addresses, relay1MAs) and containsAll(addresses, relay3MAs)

    await allFutures(switchClient.stop(), rel1.stop(), rel3.stop())
