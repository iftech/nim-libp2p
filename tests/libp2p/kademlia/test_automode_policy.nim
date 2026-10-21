# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/protocols/kademlia/automode
import ../../../libp2p/utils/opt
import ../../tools/unittest

const
  PromotionWindow = 10.seconds
  DemotionWindow = 20.seconds
  Cooldown = 60.seconds
  UnknownDemotion = 30.seconds

type
  StepKind = enum
    Observe
    Apply
    Reset

  Step = object
    at: Duration
    case kind: StepKind
    of Observe:
      verdict: NetworkReachability
      expected: Opt[Duration]
    of Apply:
      isServer: bool
    of Reset:
      discard

  PolicyCase = object
    name: string
    isServer: bool
    unknownDemotion: Opt[Duration]
    steps: seq[Step]
    deadline: Opt[Duration]

const
  Client = false
  Server = true
  Reachable = NetworkReachability.Reachable
  NotReachable = NetworkReachability.NotReachable
  Unknown = NetworkReachability.Unknown

func observe(at: Duration, verdict: NetworkReachability): Step =
  Step(at: at, kind: Observe, verdict: verdict, expected: Opt.none(Duration))

func observe(at: Duration, verdict: NetworkReachability, deadline: Duration): Step =
  Step(at: at, kind: Observe, verdict: verdict, expected: Opt.some(deadline))

func apply(at: Duration, isServer: bool): Step =
  Step(at: at, kind: Apply, isServer: isServer)

func reset(at: Duration): Step =
  Step(at: at, kind: Reset)

func policyCase(
    name: string,
    isServer: bool,
    steps: seq[Step],
    deadline = Opt.none(Duration),
    unknownDemotion = Opt.none(Duration),
): PolicyCase =
  PolicyCase(
    name: name,
    isServer: isServer,
    steps: steps,
    deadline: deadline,
    unknownDemotion: unknownDemotion,
  )

let cases = [
  policyCase(
    "a transient promotion cancels",
    Client,
    @[observe(0.seconds, Reachable, PromotionWindow), observe(5.seconds, NotReachable)],
  ),
  policyCase(
    "a transient demotion cancels",
    Server,
    @[observe(0.seconds, NotReachable, DemotionWindow), observe(5.seconds, Reachable)],
  ),
  policyCase(
    "a sustained promotion fires after its window",
    Client,
    @[observe(0.seconds, Reachable, PromotionWindow)],
    deadline = Opt.some(PromotionWindow),
  ),
  policyCase(
    "a sustained demotion fires after its window",
    Server,
    @[observe(0.seconds, NotReachable, DemotionWindow)],
    deadline = Opt.some(DemotionWindow),
  ),
  policyCase(
    "a repeat verdict keeps the first deadline",
    Client,
    @[
      observe(0.seconds, Reachable, PromotionWindow),
      observe(5.seconds, Reachable, PromotionWindow),
      observe(9.seconds, Reachable, PromotionWindow),
    ],
    deadline = Opt.some(PromotionWindow),
  ),
  policyCase(
    "Unknown keeps a pending promotion",
    Client,
    @[
      observe(0.seconds, Reachable, PromotionWindow),
      observe(5.seconds, Unknown, PromotionWindow),
    ],
    deadline = Opt.some(PromotionWindow),
  ),
  policyCase(
    "Unknown keeps a pending demotion",
    Server,
    @[
      observe(0.seconds, NotReachable, DemotionWindow),
      observe(5.seconds, Unknown, DemotionWindow),
    ],
    deadline = Opt.some(DemotionWindow),
  ),
  policyCase(
    "Unknown on a server without unknownDemotion starts nothing",
    Server,
    @[observe(0.seconds, Unknown)],
  ),
  policyCase(
    "Unknown on a client starts nothing",
    Client,
    @[observe(0.seconds, Unknown)],
    unknownDemotion = Opt.some(UnknownDemotion),
  ),
  policyCase(
    "Unknown on a server with unknownDemotion starts a demotion",
    Server,
    @[observe(0.seconds, Unknown, UnknownDemotion)],
    deadline = Opt.some(UnknownDemotion),
    unknownDemotion = Opt.some(UnknownDemotion),
  ),
  policyCase(
    "NotReachable after Unknown keeps t0 and takes the shorter window",
    Server,
    @[
      observe(0.seconds, Unknown, UnknownDemotion),
      observe(5.seconds, NotReachable, DemotionWindow),
    ],
    deadline = Opt.some(DemotionWindow),
    unknownDemotion = Opt.some(UnknownDemotion),
  ),
  policyCase(
    "Reachable cancels an Unknown demotion",
    Server,
    @[observe(0.seconds, Unknown, UnknownDemotion), observe(5.seconds, Reachable)],
    unknownDemotion = Opt.some(UnknownDemotion),
  ),
  policyCase(
    "the cooldown pushes the deadline of the next change",
    Client,
    @[
      observe(0.seconds, Reachable, PromotionWindow),
      apply(10.seconds, Server),
      observe(15.seconds, NotReachable, 10.seconds + Cooldown),
    ],
    deadline = Opt.some(10.seconds + Cooldown),
  ),
  policyCase(
    "a change after the cooldown fires after its window",
    Client,
    @[
      observe(0.seconds, Reachable, PromotionWindow),
      apply(10.seconds, Server),
      observe(100.seconds, NotReachable, 100.seconds + DemotionWindow),
    ],
    deadline = Opt.some(100.seconds + DemotionWindow),
  ),
  policyCase(
    "applying the current mode starts no cooldown",
    Client,
    @[
      apply(0.seconds, Client),
      observe(1.seconds, Reachable, 1.seconds + PromotionWindow),
    ],
    deadline = Opt.some(1.seconds + PromotionWindow),
  ),
  policyCase(
    "reset drops a pending change",
    Client,
    @[observe(0.seconds, Reachable, PromotionWindow), reset(5.seconds)],
  ),
  policyCase(
    "reset drops the cooldown",
    Client,
    @[
      observe(0.seconds, Reachable, PromotionWindow),
      apply(10.seconds, Server),
      reset(11.seconds),
      observe(15.seconds, NotReachable, 15.seconds + DemotionWindow),
    ],
    deadline = Opt.some(15.seconds + DemotionWindow),
  ),
  policyCase("due is none before any observe", Client, @[]),
  policyCase(
    "a verdict after a cancel restarts t0",
    Client,
    @[
      observe(0.seconds, Reachable, PromotionWindow),
      observe(5.seconds, NotReachable),
      observe(8.seconds, Reachable, 8.seconds + PromotionWindow),
    ],
    deadline = Opt.some(8.seconds + PromotionWindow),
  ),
  policyCase(
    "a window that ends after the cooldown is not shortened",
    Server,
    @[
      apply(0.seconds, Client),
      observe(Cooldown - 5.seconds, Reachable, Cooldown - 5.seconds + PromotionWindow),
    ],
    deadline = Opt.some(Cooldown - 5.seconds + PromotionWindow),
  ),
  policyCase(
    "Unknown after an Unknown demotion keeps t0",
    Server,
    @[
      observe(0.seconds, Unknown, UnknownDemotion),
      observe(5.seconds, Unknown, UnknownDemotion),
    ],
    deadline = Opt.some(UnknownDemotion),
    unknownDemotion = Opt.some(UnknownDemotion),
  ),
  policyCase(
    "NotReachable after the Unknown window ran out puts the deadline in the past",
    Server,
    @[
      observe(0.seconds, Unknown, UnknownDemotion),
      observe(25.seconds, NotReachable, DemotionWindow),
    ],
    deadline = Opt.some(DemotionWindow),
    unknownDemotion = Opt.some(UnknownDemotion),
  ),
  policyCase(
    "the cooldown pushes the deadline of an Unknown demotion",
    Client,
    @[apply(0.seconds, Server), observe(1.seconds, Unknown, Cooldown)],
    deadline = Opt.some(Cooldown),
    unknownDemotion = Opt.some(UnknownDemotion),
  ),
  policyCase(
    "applying the opposite mode clears a pending promotion",
    Client,
    @[observe(0.seconds, Reachable, PromotionWindow), apply(5.seconds, Server)],
  ),
  policyCase(
    "applying the opposite mode clears a pending demotion",
    Server,
    @[observe(0.seconds, NotReachable, DemotionWindow), apply(5.seconds, Client)],
  ),
  policyCase(
    "applying the current mode keeps a pending change",
    Client,
    @[observe(0.seconds, Reachable, PromotionWindow), apply(5.seconds, Client)],
    deadline = Opt.some(PromotionWindow),
  ),
  policyCase(
    "a verdict that arrives after the fire time still cancels",
    Server,
    @[
      observe(0.seconds, NotReachable, DemotionWindow),
      observe(DemotionWindow + 5.seconds, Reachable),
    ],
  ),
]

func since(d: Opt[Duration], origin: Moment): Opt[Moment] =
  d.map(
    proc(d: Duration): Moment =
      origin + d
  )

proc run(c: PolicyCase, origin: Moment): AutoModePolicy =
  let config =
    AutoModeConfig.init(PromotionWindow, DemotionWindow, Cooldown, c.unknownDemotion)
  var policy = AutoModePolicy.init(config, c.isServer)
  for step in c.steps:
    let now = origin + step.at
    case step.kind
    of Observe:
      check policy.observe(step.verdict, now) == step.expected.since(origin)
    of Apply:
      policy.applied(step.isServer, now)
    of Reset:
      policy.reset()
  policy

suite "KadDHT - Auto mode policy":
  test "each case reaches the expected deadline and fires there":
    let origin = Moment.init(1, Minute)
    for c in cases:
      checkpoint c.name
      let policy = c.run(origin)
      let expected = c.deadline.since(origin)
      check policy.deadline() == expected
      expected.ifValue(deadline):
        check:
          not policy.due(deadline - 1.nanoseconds)
          policy.due(deadline)
      else:
        check not policy.due(origin + 1.hours)
