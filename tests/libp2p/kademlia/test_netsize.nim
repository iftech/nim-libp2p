# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/math
import chronos, results
import ../../../libp2p/[peerid, protocols/kademlia]
import ../../tools/unittest
import ./utils

suite "KadDHT - Network Size Estimator":
  test "gamma inverse matches reference values":
    # From mpmath's inverse regularized lower incomplete gamma, solving
    # P(a, x) == p at 30-digit precision.
    check:
      abs(gammaIncRegInv(20.0, 0.1) - 14.5252614653) < 1e-6
      abs(gammaIncRegInv(11.0, 0.9) - 15.4066411720) < 1e-6
      abs(gammaIncRegInv(5.0, 0.5) - 4.6709088828) < 1e-6
      abs(gammaIncRegInv(2.0, 0.25) - 0.9612787631) < 1e-6
      abs(gammaIncRegInv(50.0, 0.1) - 41.1790679062) < 1e-6
      # For a == 1 the inverse is the closed form -ln(1 - p).
      abs(gammaIncRegInv(1.0, 0.75) - (-ln(0.25))) < 1e-8
      gammaIncRegInv(20.0, 0.0) == 0.0

  test "normed distance spans the unit interval":
    var zero, half, all: XorDistance
    half[0] = 0x80 # top bit set → exactly one half of the keyspace
    for i in 0 ..< IdLength:
      all[i] = 0xFF
    check:
      normedDistance(zero) == 0.0
      abs(normedDistance(half) - 0.5) < 1e-12
      # The top 8 bytes hold 2^64-1, which float64 rounds up to 2^64.
      normedDistance(all) > 0.9999
      normedDistance(all) <= 1.0

  test "recovers the network size from a linear distance profile":
    for netSize in [200, 1000, 5000]:
      let est = NetworkSizeEstimator.new(20)
      check est.networkSize().isErr() # no measurements yet
      est.seedLinearMeasurements(netSize)
      let res = est.networkSize()
      check res
      if res.isOk():
        # Float rounding around the integer truncation can shift it by one.
        check abs(res.get() - netSize) <= 2

  test "track rejects a peer list that is not bucket-sized":
    let key = Key.init(@[1.byte, 2, 3, 4])
    check NetworkSizeEstimator.new(4).track(RoutingTable.new(key), key, @[]).isErr()

  test "track records one measurement per closest-peer index":
    let
      est = NetworkSizeEstimator.new(4)
      target = randomPeerId().toKey()
      rtable = RoutingTable.new(randomPeerId().toKey())
      peers = PeerId.random(4, rng()).get()

    check est.track(rtable, target, peers)

    for i, p in peers:
      check:
        est.measurements[i].len == 1
        est.measurements[i][0].distance ==
          normedDistance(xorDistance(p, target, rtable.config.hasher))
        est.measurements[i][0].weight == est.measurements[0][0].weight
        est.measurements[i][0].weight > 0.0
        est.measurements[i][0].weight <= 1.0

  test "all-zero distances give a degenerate regression":
    let est = NetworkSizeEstimator.new(2)
    let now = Moment.now()
    for i in 0 ..< est.bucketSize:
      for _ in 0 ..< 5:
        est.measurements[i].add(
          NetSizeMeasurement(distance: 0.0, weight: 1.0, timestamp: now)
        )

    check est.networkSize().error() == "degenerate regression"
