# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/10 - replacement at admission":
  test "admission for an existing peer and service replaces the cached advertisement":
    let registrar = Registrar.new()
    let protocolId = "/example/replace/1.0.0"
    let serviceId = protocolId.hashServiceId()
    let privateKey = randomKey()
    let first = makeAdvertisement(protocolId, privateKey, seqNo = 2)
    let replacement = makeAdvertisement(protocolId, privateKey, seqNo = 1)
    let now = Moment.now()
    registrar.seedAd(serviceId, first, now)
    registrar.seedAd(serviceId, replacement, now + 1.secs)

    let cached = registrar.ads.getCachedAd(serviceId, first.data.peerId).get()
    check registrar.ads.len == 1
    check cached.ad.data.seqNo == replacement.data.seqNo
    check cached.timestamp == now + 1.secs
