# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Estimate the size of the Kademlia network.
## Ported from go-libp2p-kad-dht's ``netsize`` package.
## A converged lookup yields ``k`` closest peers,
## where peer ``i`` sits at an expected normalized distance ``i / (N + 1)``.
## ``provider.nim`` turns that estimate into distance thresholds through ``gammaIncRegInv``.

{.push raises: [].}

import std/[math, sequtils]
import chronos, results
import ../../peerid
import ./[types, routing_table]

const
  MaxMeasurementAge = 2.hours
  MinMeasurementsThreshold = 5 ## per index, before an estimate is produced
  MaxMeasurementsThreshold = 150 ## newest kept per index
  TopBytesScale = 18446744073709551616.0 ## 2^64, the float64-usable distance part
  MinStdDev = 1e-12 ## floor that keeps an inverse-variance weight finite

func new*(T: typedesc[NetworkSizeEstimator], bucketSize: int): T =
  NetworkSizeEstimator(
    bucketSize: bucketSize, measurements: newSeq[seq[NetSizeMeasurement]](bucketSize)
  )

func normedDistance*(dist: XorDistance): float64 =
  ## XOR distance on the unit interval, ``dist / 2^256``. Bytes past the top 8
  ## exceed float64 precision, so they are dropped.
  var acc = 0.0
  for i in 0 ..< 8:
    acc = acc * 256.0 + dist[i].float64
  acc / TopBytesScale

func calcWeight(
    est: NetworkSizeEstimator, rtable: RoutingTable, target: Key, peers: seq[PeerId]
): float64 =
  ## Down-weight a measurement drawn from a non-full bucket exponentially: it is
  ## a less reliable distance sample than one from a full bucket.
  let cpl = rtable.commonPrefixLen(target)
  var level = rtable.nPeersForCpl(cpl)
  if level < est.bucketSize:
    level = max(level, peers.countIt(rtable.commonPrefixLen(it.toKey()) == cpl))
  pow(2.0, float64(level - est.bucketSize))

proc track*(
    est: NetworkSizeEstimator, rtable: RoutingTable, target: Key, peers: seq[PeerId]
): LPResult[void] =
  ## Record the `peers` of a converged lookup on `target`, closest first. They
  ## must be exactly ``bucketSize`` many.
  if peers.len != est.bucketSize:
    return err("expected bucket size number of peers")

  let now = Moment.now()
  let maxAgeTs = now - MaxMeasurementAge
  let weight = est.calcWeight(rtable, target, peers)
  let hasher = rtable.config.hasher

  for i, p in peers:
    let dist = normedDistance(xorDistance(p, target, hasher))
    est.measurements[i].add(
      NetSizeMeasurement(distance: dist, weight: weight, timestamp: now)
    )
    let kept = est.measurements[i].filterIt(it.timestamp > maxAgeTs)
    est.measurements[i] = kept[max(0, kept.len - MaxMeasurementsThreshold) .. ^1]

  ok()

func weightedStats(obs: seq[NetSizeMeasurement]): (float64, float64) =
  ## Weighted mean distance and its weighted standard deviation.
  var sumDistances, sumWeights = 0.0
  for m in obs:
    sumDistances += m.weight * m.distance
    sumWeights += m.weight
  let avg = sumDistances / sumWeights

  var sumWeightedDiffs = 0.0
  for m in obs:
    sumWeightedDiffs += m.weight * (m.distance - avg) * (m.distance - avg)
  let denom = float64(obs.len - 1) / float64(obs.len) * sumWeights
  (avg, sqrt(sumWeightedDiffs / denom))

proc networkSize*(est: NetworkSizeEstimator): LPResult[int] =
  ## Current estimate, or an error while there is not enough data yet.
  # Linear regression through the origin, inverse variances as fit weights: a
  # noisier index pulls the fit less than a stable one.
  let maxAgeTs = Moment.now() - MaxMeasurementAge
  var x2Sum, xySum = 0.0
  for i in 0 ..< est.bucketSize:
    est.measurements[i] = est.measurements[i].filterIt(it.timestamp > maxAgeTs)
    if est.measurements[i].len < MinMeasurementsThreshold:
      return err("not enough data")

    let (avg, stddev) = est.measurements[i].weightedStats()
    let stddevFloored = max(stddev, MinStdDev)
    let fitWeight = 1.0 / (stddevFloored * stddevFloored)
    let x = float64(i + 1)
    xySum += fitWeight * x * avg
    x2Sum += fitWeight * x * x

  if xySum <= 0.0:
    return err("degenerate regression")

  let netSize = int(x2Sum / xySum - 1.0)
  if netSize < 1:
    return err("network size estimate below one")

  ok(netSize)

func gammp(a, x: float64): float64 =
  ## Regularized lower incomplete gamma P(a, x), summed as a series. Every term
  ## is positive, so it stays accurate over the range `gammaIncRegInv` searches.
  if x <= 0.0:
    return 0.0
  var
    ap = a
    del = 1.0 / a
    sum = del
  for _ in 0 ..< 1000:
    ap += 1.0
    del *= x / ap
    sum += del
    if abs(del) < abs(sum) * 1e-15:
      break
  sum * exp(-x + a * ln(x) - lgamma(a))

func gammaIncRegInv*(a, p: float64): float64 =
  ## Inverse of the regularized lower incomplete gamma: ``x`` such that
  ## ``P(a, x) == p``, by bisection since ``P`` rises monotonically in ``x``.
  if p <= 0.0:
    return 0.0

  var hi = max(1.0, a)
  while hi < 4.0 * a + 64.0 and gammp(a, hi) < p:
    hi *= 2.0

  var lo = 0.0
  while hi - lo > 1e-12 * hi:
    let mid = 0.5 * (lo + hi)
    if gammp(a, mid) < p:
      lo = mid
    else:
      hi = mid
  0.5 * (lo + hi)
