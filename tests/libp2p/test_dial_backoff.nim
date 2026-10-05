# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, metrics, results
import ../../libp2p/[dial_backoff, multiaddress, multicodec, peerid]
import ../tools/[unittest, crypto]

proc memoryAddr(i: int): MultiAddress =
  MultiAddress.init("/memorytransport/addr-" & $i).tryGet()

suite "Dial backoff":
  let
    config =
      DialBackoffConfig(tolerance: 2, base: 1.seconds, factor: 2, maxDelay: 8.seconds)
    noTolerance =
      DialBackoffConfig(tolerance: 0, base: 1.seconds, factor: 2, maxDelay: 8.seconds)
    peerId = PeerId.random(rng()).tryGet()

  test "A failure under the tolerance blocks nothing":
    let
      backoff = DialBackoff.new(config)
      start = Moment.now()

    backoff.recordFailure(peerId, start)
    backoff.recordFailure(peerId, start)

    check not backoff.blocked(peerId, start)

  test "The wait doubles with each further failure":
    let
      backoff = DialBackoff.new(config)
      start = Moment.now()

    for _ in 0 ..< 3:
      backoff.recordFailure(peerId, start)
    check:
      backoff.blocked(peerId, start + 900.milliseconds)
      not backoff.blocked(peerId, start + 1100.milliseconds)

    backoff.recordFailure(peerId, start)
    check:
      backoff.blocked(peerId, start + 1900.milliseconds)
      not backoff.blocked(peerId, start + 2100.milliseconds)

  test "The wait stops at the ceiling":
    let
      backoff = DialBackoff.new(config)
      start = Moment.now()

    for _ in 0 ..< 20:
      backoff.recordFailure(peerId, start)

    check:
      backoff.blocked(peerId, start + 7.seconds)
      not backoff.blocked(peerId, start + 9.seconds)

  test "A successful dial clears the backoff":
    let
      backoff = DialBackoff.new(config)
      start = Moment.now()

    for _ in 0 ..< 4:
      backoff.recordFailure(peerId, start)
    check backoff.blocked(peerId, start)

    backoff.recordSuccess(peerId)
    check not backoff.blocked(peerId, start)

    backoff.recordFailure(peerId, start)
    backoff.recordFailure(peerId, start)
    check not backoff.blocked(peerId, start)

  test "The peer scope and the address scope count apart":
    let
      backoff = DialBackoff.new(noTolerance)
      address = memoryAddr(0)
      start = Moment.now()

    backoff.recordFailure(address, start)
    check:
      backoff.blocked(address, start)
      not backoff.blocked(peerId, start)

    backoff.recordSuccess(address)
    backoff.recordFailure(peerId, start)
    check:
      not backoff.blocked(address, start)
      backoff.blocked(peerId, start)

  test "A dial without a peer id is never blocked":
    let
      backoff = DialBackoff.new(noTolerance)
      start = Moment.now()

    backoff.recordFailure(Opt.none(PeerId), start)
    check not backoff.blocked(Opt.none(PeerId), start)

  test "An idle entry decays, and the count starts over":
    let
      backoff = DialBackoff.new(config)
      address = memoryAddr(0)
      start = Moment.now()

    for _ in 0 ..< 3:
      backoff.recordFailure(address, start)
    check backoff.blocked(address, start)

    let later = start + 1.seconds + 8.seconds + 1.seconds
    backoff.recordFailure(address, later)
    backoff.recordFailure(address, later)
    check not backoff.blocked(address, later)

  test "A factor of one repeats the base wait":
    let
      backoff = DialBackoff.new(
        DialBackoffConfig(tolerance: 0, base: 1.seconds, factor: 1, maxDelay: 8.seconds)
      )
      address = memoryAddr(0)
      start = Moment.now()

    for _ in 0 ..< 5:
      backoff.recordFailure(address, start)

    check:
      backoff.blocked(address, start + 900.milliseconds)
      not backoff.blocked(address, start + 1100.milliseconds)

  test "A base of zero blocks nothing":
    let
      backoff = DialBackoff.new(
        DialBackoffConfig(
          tolerance: 0, base: ZeroDuration, factor: 2, maxDelay: 8.seconds
        )
      )
      address = memoryAddr(0)
      start = Moment.now()

    for _ in 0 ..< 5:
      backoff.recordFailure(address, start)

    check not backoff.blocked(address, start)

  test "The jitter draws the wait down, never up":
    let start = Moment.now()

    for i in 0 ..< 50:
      let
        backoff = DialBackoff.new(
          DialBackoffConfig(
            tolerance: 0, base: 1.seconds, factor: 2, maxDelay: 8.seconds, jitter: 0.5
          )
        )
        address = memoryAddr(i)

      backoff.recordFailure(address, start)
      check:
        backoff.blocked(address, start + 499.milliseconds)
        not backoff.blocked(address, start + 1.seconds)

  test "An address is keyed by the peer it reaches":
    let
      relayId = PeerId.random(rng()).tryGet()
      relay =
        MultiAddress.init("/ip4/1.2.3.4/tcp/4001").tryGet() &
        MultiAddress.init(multiCodec("p2p"), relayId.data).tryGet() &
        MultiAddress.init("/p2p-circuit").tryGet()
      direct = memoryAddr(0)
      first = PeerId.random(rng()).tryGet()
      second = PeerId.random(rng()).tryGet()

    check:
      backoffKey(direct, Opt.none(PeerId)) == direct
      backoffKey(relay, Opt.none(PeerId)) == relay
      backoffKey(direct, Opt.some(first)) != direct
      backoffKey(direct, Opt.some(first)) != backoffKey(direct, Opt.some(second))
      backoffKey(relay, Opt.some(first)) != relay
      backoffKey(relay, Opt.some(first)) != backoffKey(relay, Opt.some(second))

  test "A full table drops the entry whose wait ends first":
    let
      backoff = DialBackoff.new(
        DialBackoffConfig(tolerance: 0, base: 1.minutes, factor: 1, maxDelay: 1.minutes)
      )
      start = Moment.now()
      extra = memoryAddr(MaxBackoffEntries)

    for i in 0 ..< MaxBackoffEntries:
      backoff.recordFailure(memoryAddr(i), start + i.milliseconds)

    let now = start + 2.seconds
    backoff.recordFailure(extra, now)
    check:
      libp2p_dial_backoff_entries.value(["address"]) == float(MaxBackoffEntries)
      backoff.blocked(extra, now)
      not backoff.blocked(memoryAddr(0), now)
      backoff.blocked(memoryAddr(1), now)

  test "The entries gauge follows the size of each table":
    let
      backoff = DialBackoff.new(noTolerance)
      start = Moment.now()

    for i in 0 ..< 3:
      backoff.recordFailure(memoryAddr(i), start)
    backoff.recordFailure(peerId, start)
    check:
      libp2p_dial_backoff_entries.value(["address"]) == 3
      libp2p_dial_backoff_entries.value(["peer"]) == 1

    backoff.recordSuccess(memoryAddr(0))
    check libp2p_dial_backoff_entries.value(["address"]) == 2
