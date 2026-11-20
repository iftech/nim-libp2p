# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/5.
# Spec, Handling REGISTER requests, step 5: "add the ad to the ad_cache ... If
# an entry for this peer_id and service_id already exists, this replaces it."
# Example REGISTER algorithm: "if ad_cache.contains(ad.peer_id,
# ad.service_id_hash): ad_cache.replace(ad)".

import chronos, results, net
import ../../../libp2p/[extended_peer_record, peerid]
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../tools/unittest
import ./utils

suite "Proof 20261120T114625-71ee3b/5 - one cache entry per ad peer_id and service":
  test "the same ad admitted from two connections keeps a single entry":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "proof-single-entry"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName)
    let now = Moment.init(Moment.now().epochSeconds, Second)

    # Two different connected peers submit the very same signed advertisement.
    disco.acceptAdvertisement(
      now, serviceId, PeerId.random(), ad, @[parseIpAddress("10.0.0.1")]
    )
    disco.acceptAdvertisement(
      now, serviceId, PeerId.random(), ad, @[parseIpAddress("200.0.0.1")]
    )

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
    check disco.registrar.ads.len == 1

    let reply = disco.getAdvertisements(
      PeerId.random(), Message(msgType: MessageType.getAds, key: serviceId)
    )
    check reply.getAds.get().advertisements.len == 1
