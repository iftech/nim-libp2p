# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/net
import chronos
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../../libp2p/utils/iptree
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/7 - IP membership per cache entry":
  test "two addresses with the same host IP contribute one count":
    let disco = setupServiceDiscoveryNode()
    let ad = makeAdvertisement()
    let serviceId = makeServiceId()
    let ip = parseIpAddress("192.0.2.10")
    disco.acceptAdvertisement(Moment.now(), serviceId, ad.data.peerId, ad, @[ip, ip])

    check disco.registrar.ads.len == 1
    check disco.registrar.ads.ipTree.ipsLen == 1
