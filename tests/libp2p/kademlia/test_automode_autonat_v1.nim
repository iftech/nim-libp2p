# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/deques
import chronos
import
  ../../../libp2p/[protocols/kademlia, protocols/connectivity/autonat/service, switch]
from ../../../libp2p/services/reachabilityobservers import ReachabilityHandler
from ../../../libp2p/protocols/connectivity/autonat/types import
  AutonatError, AutonatUnreachableError
import ../../stubs/autonatclientstub
import ../../tools/[crypto, multiaddress, switch_builder, unittest]
import ./utils

const
  Tick = 20.milliseconds
  Poll = 5.milliseconds
  Window = 300.milliseconds
  # Scheduler jitter delays a mode switch past its window.
  TimingMargin = 300.milliseconds
  Limit = Window + TimingMargin
  SmallQueue = 4
  DefaultQueue = 10
  WindowedAutoMode = AutoModeConfig.init(
    promotionWindow = Window, demotionWindow = Window, cooldown = ZeroDuration
  )
  Reachable = NetworkReachability.Reachable
  NotReachable = NetworkReachability.NotReachable
  Unknown = NetworkReachability.Unknown

type
  ScriptedStub = ref object of AutonatClientStub
    script: Deque[Answer]
    fallback: Answer

  Fixture = ref object
    probe, peer: Switch
    service: AutonatService
    stub: ScriptedStub
    kad: KadDHT
    verdicts: seq[NetworkReachability]
    handlers: seq[ReachabilityHandler]

method dialMe*(
    self: ScriptedStub,
    switch: Switch,
    pid: PeerId,
    addrs: seq[MultiAddress] = newSeq[MultiAddress](),
): Future[MultiAddress] {.
    async: (raises: [AutonatError, AutonatUnreachableError, CancelledError])
.} =
  self.answer =
    if self.script.len() > 0:
      self.script.popFirst()
    else:
      self.fallback
  return await procCall dialMe(AutonatClientStub(self), switch, pid, addrs)

proc newFixture(config: AutoModeConfig, maxQueueSize: int): Fixture =
  let stub = ScriptedStub(answer: Unknown, fallback: Unknown)
  let service = AutonatService.new(
    stub,
    rng(),
    scheduleInterval = Opt.some(Tick),
    askNewConnectedPeers = false,
    maxQueueSize = maxQueueSize,
  )
  let fixture = Fixture(
    probe: makeStandardSwitch(TcpAutoAddress),
    peer: makeStandardSwitch(TcpAutoAddress),
    service: service,
    stub: stub,
    kad: setupKad(isServer = false),
  )

  let current = proc(): NetworkReachability {.gcsafe, raises: [].} =
    service.networkReachability
  let recorder = proc(
      reachability: NetworkReachability,
      confidence: Opt[float],
      dialBackAddr: Opt[MultiAddress],
  ) {.async: (raises: [CancelledError]).} =
    if fixture.verdicts.len() == 0 or fixture.verdicts[^1] != reachability:
      fixture.verdicts.add(reachability)
  fixture.handlers = @[fixture.kad.enableAutoMode(current, config), recorder]
  for handler in fixture.handlers:
    check service.reachabilityObservers.add(handler)
  fixture

proc start(fixture: Fixture) {.async.} =
  await fixture.probe.start()
  await fixture.peer.start()
  await fixture.probe.connect(fixture.peer)
  await fixture.service.start(fixture.probe)
  await fixture.kad.start()

proc stop(fixture: Fixture) {.async.} =
  for handler in fixture.handlers:
    check fixture.service.reachabilityObservers.remove(handler)
  await fixture.kad.stop()
  await fixture.service.stop(fixture.probe)
  await fixture.peer.stop()
  await fixture.probe.stop()

template startFixture(fixture: untyped, config: AutoModeConfig, maxQueueSize: int) =
  let fixture = newFixture(config, maxQueueSize)
  defer:
    await fixture.stop()
  await fixture.start()

proc script(fixture: Fixture, answers: varargs[Answer]) =
  for answer in answers:
    fixture.stub.script.addLast(answer)

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

proc promote(fixture: Fixture) {.async.} =
  fixture.stub.fallback = Reachable
  check await fixture.kad.waitForMode(isServer = true, Limit)

suite "Kad auto mode through AutoNAT v1":
  teardown:
    checkTrackers()

  asyncTest "a transient Reachable stays a client":
    startFixture(fixture, WindowedAutoMode, SmallQueue)

    fixture.stub.fallback = NotReachable
    fixture.script(Reachable, Reachable)

    check await fixture.kad.holdsMode(isServer = false, Limit)
    check Reachable in fixture.verdicts

  asyncTest "a transient NotReachable stays a server":
    startFixture(fixture, WindowedAutoMode, SmallQueue)

    await fixture.promote()
    fixture.script(NotReachable, NotReachable, NotReachable)

    check await fixture.kad.holdsMode(isServer = true, Limit)
    check NotReachable in fixture.verdicts

  asyncTest "a sustained Reachable promotes within the window plus timing margin":
    startFixture(fixture, WindowedAutoMode, SmallQueue)

    let startedAt = Moment.now()
    fixture.stub.fallback = Reachable
    check await fixture.kad.waitForMode(isServer = true, Limit)

    check Moment.now() - startedAt >= Window

  asyncTest "a sustained NotReachable demotes within the window plus timing margin":
    startFixture(fixture, WindowedAutoMode, SmallQueue)

    await fixture.promote()
    let startedAt = Moment.now()
    fixture.stub.fallback = NotReachable
    check await fixture.kad.waitForMode(isServer = false, Limit)

    check Moment.now() - startedAt >= Window

  asyncTest "an inconclusive answer does not delay a pending promotion":
    startFixture(fixture, WindowedAutoMode, SmallQueue)

    let startedAt = Moment.now()
    fixture.script(Reachable, Reachable)
    check await fixture.kad.waitForMode(isServer = true, Limit)

    check:
      Moment.now() - startedAt >= Window
      fixture.verdicts == @[Reachable]
      fixture.service.networkReachability == Reachable

  asyncTest "an inconclusive answer does not delay a pending demotion":
    startFixture(fixture, WindowedAutoMode, SmallQueue)

    await fixture.promote()
    fixture.stub.fallback = Unknown
    let startedAt = Moment.now()
    fixture.script(NotReachable, NotReachable, NotReachable)
    check await fixture.kad.waitForMode(isServer = false, Limit)

    check:
      Moment.now() - startedAt >= Window
      fixture.verdicts == @[Reachable, NotReachable]
      fixture.service.networkReachability == NotReachable

  asyncTest "a flip from 2/10 to 3/10 Reachable and back does not switch":
    startFixture(fixture, WindowedAutoMode, DefaultQueue)

    fixture.stub.fallback = NotReachable
    # Ten answers hold 2 Reachable; the next Reachable makes 3/10, the next NotReachable 2/10.
    fixture.script(NotReachable, Reachable, Reachable)
    for _ in 0 ..< 7:
      fixture.script(NotReachable)
    fixture.script(Reachable, NotReachable)

    check await fixture.kad.holdsMode(isServer = false, 12 * Tick + Limit)
    check:
      Reachable in fixture.verdicts
      fixture.verdicts[^1] == NotReachable
