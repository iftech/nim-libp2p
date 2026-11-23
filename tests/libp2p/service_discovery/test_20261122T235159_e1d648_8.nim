# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/net
import chronos
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../../libp2p/utils/iptree
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/8 - cache expiry boundary":
  test "pruning at the expiry timestamp removes the entry and its IP":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement()
    let admission = Moment.now()
    let expiry = 900.secs
    registrar.seedAd(serviceId, ad, admission, ips = @[parseIpAddress("192.0.2.10")])

    check registrar.ads.pruneExpired(admission + expiry, expiry) == 1
    check registrar.ads.getServiceCachedAds(serviceId, 10).len == 0
    check registrar.ads.ipTree.ipsLen == 0
