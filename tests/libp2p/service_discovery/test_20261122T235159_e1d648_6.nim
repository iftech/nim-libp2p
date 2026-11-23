# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/tables
import chronos
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/6 - lower bound lifetime":
  test "a service bound survives while its cache entry is live":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let now = Moment.init(Moment.now().epochSeconds, Second)
    let expiry = 100.secs

    registrar.updateLowerBounds(serviceId, @[], expiry, now - 101.secs)
    registrar.seedAd(serviceId, makeAdvertisement(), now - 1.secs)
    registrar.pruneExpiredAds(expiry)

    check registrar.ads.contains(serviceId)
    check serviceId in registrar.boundService
