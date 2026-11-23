# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/net
import chronos
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/11 - IP score contribution":
  test "waiting time includes the IP score from the cache":
    let config = ServiceDiscoveryConfig.new(
      advertCacheCap = 2, occupancyExp = 1.0, ipSimCoefficient = 0.0
    )
    let registrar = Registrar.new(config.advertCacheCap)
    let ips = @[parseIpAddress("192.0.2.10")]
    registrar.seedAd(makeServiceId(1), makeAdvertisement(), ips = ips)

    # One of two slots occupied, no ads for the requested service, and exact IP
    # match. The occupancy factor is 2 and the IP score is at least 31/32.
    let wait = registrar.waitingTime(config, makeServiceId(2), ips, Moment.now())
    check wait >= 1744.secs
