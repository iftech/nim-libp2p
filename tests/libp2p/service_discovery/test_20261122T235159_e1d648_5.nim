# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261122T235159-e1d648/5.
# Spec, "Formula": "The waiting time for an advertisement MUST be calculated
# using: w(ad) = E x (1/(1 - c/C)^P_occ) x (...)"; "Occupancy Score": "The
# higher the value of `P_occ`, the faster the increase."

import std/net
import chronos
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/5 - configured P_occ is used in the formula":
  test "P_occ = 20 gives a longer wait than P_occ = 10 on a half-full cache":
    let registrar = Registrar.new(100)
    let serviceId = makeServiceId(1)
    let ips = @[parseIpAddress("198.51.100.7")]
    let now = Moment.now()

    # 50 of 100 slots used, one of them under `serviceId`; no IPs tracked.
    registrar.ads.seedOccupancy(50, now)
    check registrar.ads.len == 50

    let w10 = registrar.waitingTime(
      ServiceDiscoveryConfig.new(advertCacheCap = 100, occupancyExp = 10.0),
      serviceId,
      ips,
      now,
    )
    let w20 = registrar.waitingTime(
      ServiceDiscoveryConfig.new(advertCacheCap = 100, occupancyExp = 20.0),
      serviceId,
      ips,
      now,
    )

    # 900 * 2^10 * 0.01 = 9216 s versus 900 * 2^20 * 0.01 = 9437184 s
    checkpoint "w(P_occ=10) = " & $w10 & ", w(P_occ=20) = " & $w20
    check w20 > w10
