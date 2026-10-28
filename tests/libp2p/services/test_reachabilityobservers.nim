# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import ../../../libp2p/multiaddress
import ../../../libp2p/services/reachabilityobservers
import ../../tools/unittest

suite "ReachabilityObservers":
  asyncTest "notify reaches every subscriber, and skips an unsubscribed one":
    let observers = ReachabilityObservers.new()

    var seen: seq[NetworkReachability]
    let handler: ReachabilityHandler = proc(
        reachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      seen.add(reachability)

    check:
      observers.len() == 0
      observers.add(handler)
      observers.len() == 1
      observers.lastReachability() == NetworkReachability.Unknown
      # A nil handler would crash the next dispatch, so it never reaches the seq.
      not observers.add(nil)
      # One handler holds one subscription, so a second add changes nothing.
      not observers.add(handler)

    await observers.notify(NetworkReachability.Reachable, Opt.some(1.0))
    check:
      seen == @[NetworkReachability.Reachable]
      observers.lastReachability() == NetworkReachability.Reachable

    check:
      observers.remove(handler)
      observers.len() == 0
      # The handler is gone, so a second remove reports that it removed nothing.
      not observers.remove(handler)

    await observers.notify(NetworkReachability.NotReachable, Opt.some(1.0))
    check:
      seen == @[NetworkReachability.Reachable]
      observers.lastReachability() == NetworkReachability.NotReachable

  asyncTest "reset clears lastReachability without a notify":
    let observers = ReachabilityObservers.new()

    var seen: seq[NetworkReachability]
    let handler: ReachabilityHandler = proc(
        reachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      seen.add(reachability)

    check observers.add(handler)
    await observers.notify(NetworkReachability.Reachable, Opt.some(1.0))
    check observers.lastReachability() == NetworkReachability.Reachable

    observers.reset()
    check:
      observers.lastReachability() == NetworkReachability.Unknown
      seen == @[NetworkReachability.Reachable]

    await observers.notify(NetworkReachability.NotReachable, Opt.some(1.0))
    check:
      seen == @[NetworkReachability.Reachable, NetworkReachability.NotReachable]
      observers.lastReachability() == NetworkReachability.NotReachable
