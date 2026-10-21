# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Decides when a kad node in auto mode switches between client and server.
## A pure state machine. The caller feeds reachability verdicts and wakes at the
## deadline that ``observe`` returns.

{.push raises: [].}

import chronos
import ../../utils/opt
import ../connectivity/autonat/types

export NetworkReachability

const
  DefaultPromotionWindow* = 1.minutes
  DefaultDemotionWindow* = 1.minutes
  DefaultAutoModeCooldown* = 5.minutes

type
  AutoModeConfig* = object
    promotionWindow*: Duration ## How long Reachable must hold before client -> server.
    demotionWindow*: Duration ## How long NotReachable must hold before server -> client.
    cooldown*: Duration ## The minimum time between two mode changes.
    unknownDemotion*: Opt[Duration]
      ## Demotes a server after this long on Unknown. None keeps the server on Unknown.

  PendingChange = object
    since: Moment
    window: Duration

  AutoModePolicy* = object
    config: AutoModeConfig
    isServer: bool
    lastChange: Opt[Moment]
    pending: Opt[PendingChange]

func init*(
    T: type AutoModeConfig,
    promotionWindow: Duration = DefaultPromotionWindow,
    demotionWindow: Duration = DefaultDemotionWindow,
    cooldown: Duration = DefaultAutoModeCooldown,
    unknownDemotion: Opt[Duration] = Opt.none(Duration),
): T =
  T(
    promotionWindow: promotionWindow,
    demotionWindow: demotionWindow,
    cooldown: cooldown,
    unknownDemotion: unknownDemotion,
  )

func init*(T: type AutoModePolicy, config: AutoModeConfig, isServer: bool): T =
  T(config: config, isServer: isServer)

func deadline*(p: AutoModePolicy): Opt[Moment] =
  let change = p.pending.valueOr:
    return Opt.none(Moment)
  let settled = change.since + change.window

  p.lastChange.ifValue(last):
    return Opt.some(max(settled, last + p.config.cooldown))
  Opt.some(settled)

func start(p: var AutoModePolicy, window: Duration, now: Moment) =
  # A repeat keeps since, so a source that notifies often cannot defer the change.
  let change = p.pending.valueOr:
    PendingChange(since: now, window: window)
  p.pending =
    Opt.some(PendingChange(since: change.since, window: min(change.window, window)))

func observeUnknown(p: var AutoModePolicy, now: Moment) =
  if p.pending.isSome() or not p.isServer:
    return
  p.config.unknownDemotion.ifValue(window):
    p.start(window, now)

func observe*(
    p: var AutoModePolicy, verdict: NetworkReachability, now: Moment
): Opt[Moment] =
  case verdict
  of NetworkReachability.Unknown:
    p.observeUnknown(now)
  of NetworkReachability.Reachable, NetworkReachability.NotReachable:
    let wantServer = verdict.isReachable()
    if wantServer == p.isServer:
      p.pending = Opt.none(PendingChange)
    elif wantServer:
      p.start(p.config.promotionWindow, now)
    else:
      p.start(p.config.demotionWindow, now)
  p.deadline()

func due*(p: AutoModePolicy, now: Moment): bool =
  let deadline = p.deadline().valueOr:
    return false
  now >= deadline

func applied*(p: var AutoModePolicy, isServer: bool, now: Moment) =
  if isServer == p.isServer:
    return
  p.isServer = isServer
  p.lastChange = Opt.some(now)
  p.pending = Opt.none(PendingChange)

func reset*(p: var AutoModePolicy) =
  p.lastChange = Opt.none(Moment)
  p.pending = Opt.none(PendingChange)
