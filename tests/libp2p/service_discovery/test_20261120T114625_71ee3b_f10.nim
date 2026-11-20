# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/10.
# Spec, Formula: "The waiting time for an advertisement MUST be calculated using:
# w(ad) = E x (1/(1 - c/C)^P_occ) x (c(ad.service_id_hash)/C + score(...) + G)".
# Spec, System Parameters: "Implementations SHOULD modify them as needed";
# Occupancy Score: "The higher the value of P_occ, the faster the increase."

import chronos, results, net
import ../../../libp2p/[extended_peer_record, peerid]
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../tools/unittest
import ./utils

suite "Proof 20261120T114625-71ee3b/10 - occupancy exponent P_occ":
  test "a configured P_occ above 10 raises the waiting time of a half-full cache":
    let registrar = Registrar.new(8)
    let serviceId = makeServiceId(1)
    let now = Moment.init(Moment.now().epochSeconds, Second)

    # c = 4 of C = 8, all under one service: occupancy base (1 - c/C) = 0.5.
    for i in 0 ..< 4:
      let ad = makeAdvertisement($serviceId)
      registrar.ads.put(
        serviceId, ad.data.peerId, ad, @[parseIpAddress("10.0.0." & $(i + 1))], now
      )

    let ips = @[parseIpAddress("200.0.0.1")]
    let w10 = registrar.waitingTime(
      ServiceDiscoveryConfig.new(advertCacheCap = 8, occupancyExp = 10.0),
      serviceId,
      ips,
      now,
    )
    let w12 = registrar.waitingTime(
      ServiceDiscoveryConfig.new(advertCacheCap = 8, occupancyExp = 12.0),
      serviceId,
      ips,
      now,
    )

    # E * 2^10 * 0.5 = 460800 s and E * 2^12 * 0.5 = 1843200 s.
    checkpoint "P_occ = 10: " & $w10 & ", P_occ = 12: " & $w12
    check w10.seconds == 460800
    check w12.seconds == 1843200
