# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/sequtils
import chronos, results
import ../multiaddress
import ../protocols/connectivity/autonat/types
import ../utils/[collections, future]

export types.NetworkReachability

type
  ReachabilityHandler* = proc(
    reachability: NetworkReachability,
    confidence: Opt[float],
    dialBackAddr: Opt[MultiAddress],
  ): Future[void] {.gcsafe, async: (raises: [CancelledError]).}
    ## A subscriber of reachability changes. A subscriber that needs no
    ## `confidence` or `dialBackAddr` leaves those parameters unused. AutoNAT v1
    ## reports `dialBackAddr` as none, because it observes no dial-back address.

  ReachabilityObservers* = ref object
    ## The subscribers of reachability changes. A service that observes
    ## reachability holds one and notifies it on every change.
    handlers: seq[ReachabilityHandler]
    reachability: NetworkReachability

proc new*(T: typedesc[ReachabilityObservers]): T =
  T(reachability: NetworkReachability.Unknown)

proc add*(self: ReachabilityObservers, handler: ReachabilityHandler): bool =
  ## Appends `handler`. False means no subscription: a nil handler is dropped,
  ## and so is a handler that is subscribed already.
  if handler.isNil() or handler in self.handlers:
    return false

  self.handlers.add(handler)
  true

proc remove*(self: ReachabilityObservers, handler: ReachabilityHandler): bool =
  ## Removes `handler`. False means it was not subscribed.
  self.handlers.removeFirstIfIt(it == handler)

func len*(self: ReachabilityObservers): int =
  self.handlers.len()

func lastReachability*(self: ReachabilityObservers): NetworkReachability =
  ## The reachability of the last `notify`, `Unknown` before the first one. It
  ## lets a late subscriber read the current value instead of waiting for the
  ## next change.
  self.reachability

proc notify*(
    self: ReachabilityObservers,
    reachability: NetworkReachability,
    confidence: Opt[float],
    dialBackAddr = Opt.none(MultiAddress),
) {.async: (raises: [CancelledError]).} =
  self.reachability = reachability
  # Handlers start in subscription order, then run concurrently, so a subscriber
  # that blocks does not delay the subscribers behind it.
  await allOrCancel(self.handlers.mapIt(it(reachability, confidence, dialBackAddr)))
