# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, tables]
import chronos, results
import ../../../libp2p/[address_manager, builders, switch]
import ../../../libp2p/protocols/kademlia
import ../../../libp2p/services/natservice
import ../../tools/[multiaddress, switch_builder, unittest]
import ./utils

const
  Tick = 20.milliseconds
  Poll = 5.milliseconds
  VerifyTimeout = 100.milliseconds
  Window = 300.milliseconds
  # Scheduler jitter delays a mode switch past its window.
  TimingMargin = 300.milliseconds
  Limit = Window + TimingMargin
  WindowedAutoMode = AutoModeConfig.init(
    promotionWindow = Window, demotionWindow = Window, cooldown = ZeroDuration
  )
  TransientAutoMode = AutoModeConfig.init(
    promotionWindow = Limit, demotionWindow = Window, cooldown = ZeroDuration
  )
  UnknownDemotionAutoMode = AutoModeConfig.init(
    promotionWindow = Window,
    demotionWindow = Window,
    cooldown = ZeroDuration,
    unknownDemotion = Opt.some(Window),
  )
  Reachable = NetworkReachability.Reachable
  NotReachable = NetworkReachability.NotReachable
  Unknown = NetworkReachability.Unknown

type
  ScriptedVerifier = ref object of Verifier
    verdicts: Table[MultiAddress, Opt[AddrState]]
    asked: seq[MultiAddress]

  Fixture = ref object
    switch: Switch
    kad: KadDHT
    verifier: ScriptedVerifier
    mapper: AddressMapper

method verify(
    self: ScriptedVerifier, address: MultiAddress
): Future[Opt[AddrState]] {.async: (raises: [CancelledError]).} =
  self.asked.add(address)
  self.verdicts.getOrDefault(address)

proc constantMapper(addrs: seq[MultiAddress]): AddressMapper =
  proc(
      listenAddrs: seq[MultiAddress]
  ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    listenAddrs & addrs

proc newFixture(
    config: AutoModeConfig, mapped: seq[MultiAddress]
): Fixture {.raises: [LPError].} =
  let switch = makeStandardSwitchBuilder(TcpAutoAddress)
    .withAddressManager(
      AddressManagerConfig(verifyInterval: Tick, verifyTimeout: VerifyTimeout)
    )
    .withNAT(autonatConfig(AutonatV2))
    .withKademlia(mode = KadMode.Auto, autoMode = config)
    .build()
  Fixture(
    switch: switch,
    kad: switch.mountedKad().get(),
    verifier: ScriptedVerifier(),
    mapper: constantMapper(mapped),
  )

proc start(fixture: Fixture) {.async.} =
  await fixture.switch.start()
  fixture.switch.addressManager.addMapper(fixture.mapper, AddrSource.Upnp)
  # the service installs its own verifier on start
  fixture.switch.addressManager.verifier = fixture.verifier
  await fixture.switch.peerInfo.update()

template startFixture(
    fixture: untyped, config: AutoModeConfig, mapped: seq[MultiAddress]
) =
  let fixture = newFixture(config, mapped)
  defer:
    await fixture.switch.stop()
  await fixture.start()

func script(fixture: Fixture, address: MultiAddress, verdict: Opt[AddrState]) =
  fixture.verifier.verdicts[address] = verdict

func script(fixture: Fixture, address: MultiAddress, state: AddrState) =
  fixture.script(address, Opt.some(state))

func timesAsked(fixture: Fixture, address: MultiAddress): int =
  fixture.verifier.asked.countIt(it == address)

func reachability(fixture: Fixture): NetworkReachability =
  fixture.switch.addressManager.reachability()

func stateOf(fixture: Fixture, address: MultiAddress): Opt[AddrState] =
  for candidate in fixture.switch.addressManager.candidates():
    if candidate.address == address:
      return Opt.some(candidate.state)
  Opt.none(AddrState)

proc waitForMode(
    kad: KadDHT, isServer: bool, limit: Duration
): Future[bool] {.async: (raises: [CancelledError]).} =
  let until = Moment.now() + limit
  while kad.isServer != isServer:
    if Moment.now() >= until:
      return false
    await sleepAsync(Poll)
  true

proc holdsMode(
    kad: KadDHT, isServer: bool, duration: Duration
): Future[bool] {.async: (raises: [CancelledError]).} =
  let until = Moment.now() + duration
  while Moment.now() < until:
    if kad.isServer != isServer:
      return false
    await sleepAsync(Poll)
  kad.isServer == isServer

proc promote(fixture: Fixture, address: MultiAddress) {.async.} =
  fixture.script(address, AddrState.Confirmed)
  check await fixture.kad.waitForMode(isServer = true, Limit)

proc loseMapper(fixture: Fixture) {.async.} =
  fixture.switch.addressManager.removeMapper(fixture.mapper)
  await fixture.switch.peerInfo.update()

suite "Kad auto mode through AutoNAT v2":
  teardown:
    checkTrackers()

  let first = ma("/ip4/1.2.3.4/tcp/4001")

  asyncTest "a sustained Confirmed address promotes within the window plus timing margin":
    startFixture(fixture, WindowedAutoMode, @[first])
    check not fixture.kad.isServer

    let startedAt = Moment.now()
    fixture.script(first, AddrState.Confirmed)
    check await fixture.kad.waitForMode(isServer = true, Limit)

    check Moment.now() - startedAt >= Window

  asyncTest "a transient Confirmed address stays a client":
    startFixture(fixture, TransientAutoMode, @[first])

    fixture.script(first, AddrState.Confirmed)
    checkUntilTimeoutCustom(Limit, Poll):
      fixture.reachability() == Reachable
    fixture.script(first, AddrState.Unreachable)
    checkUntilTimeoutCustom(Limit, Poll):
      fixture.reachability() == NotReachable

    check await fixture.kad.holdsMode(isServer = false, Limit)

  asyncTest "an inconclusive verdict keeps the old one":
    startFixture(fixture, WindowedAutoMode, @[first])
    await fixture.promote(first)

    fixture.script(first, Opt.none(AddrState))
    let asked = fixture.timesAsked(first)
    checkUntilTimeout:
      fixture.timesAsked(first) >= asked + 3

    check:
      fixture.stateOf(first) == Opt.some(AddrState.Confirmed)
      fixture.reachability() == Reachable
      fixture.kad.isServer

  asyncTest "a sustained Unreachable address demotes within the window plus timing margin":
    startFixture(fixture, WindowedAutoMode, @[first])
    await fixture.promote(first)

    let startedAt = Moment.now()
    fixture.script(first, AddrState.Unreachable)
    check await fixture.kad.waitForMode(isServer = false, Limit)

    check:
      Moment.now() - startedAt >= Window
      fixture.reachability() == NotReachable

  asyncTest "losing the last Confirmed address demotes within the window plus timing margin":
    startFixture(fixture, UnknownDemotionAutoMode, @[first])
    await fixture.promote(first)

    let startedAt = Moment.now()
    await fixture.loseMapper()
    check await fixture.kad.waitForMode(isServer = false, Limit)

    check:
      Moment.now() - startedAt >= Window
      fixture.reachability() == Unknown

  asyncTest "losing the last Confirmed address stays a server without unknownDemotion":
    startFixture(fixture, WindowedAutoMode, @[first])
    await fixture.promote(first)

    await fixture.loseMapper()
    checkUntilTimeout:
      fixture.reachability() == Unknown

    check await fixture.kad.holdsMode(isServer = true, Limit)
