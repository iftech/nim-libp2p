# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/3.
# Spec, Registrars: the ad_cache associates each advertisement with an "expiry
# timestamp based on admission time plus configured expiry time, E. Once an ad
# has expired, it SHOULD be removed from the ad_cache."
# Spec, Handling REGISTER requests, step 5: "add the ad to the ad_cache, with an
# expiry timestamp set to current_time + E".

import chronos, results, net
import ../../../libp2p/[extended_peer_record, peerid]
import ../../tools/unittest
import ./utils

suite "Proof 20261120T114625-71ee3b/3 - expired advertisements":
  test "GET_ADS does not serve an ad admitted more than E ago":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "proof-expired-ad"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName)

    let now = Moment.init(Moment.now().epochSeconds, Second)
    # Admitted E + 60s ago: its expiry timestamp (admission + E) passed a minute ago.
    let admittedAt = now - disco.discoConfig.advertExpiry - 60.secs
    disco.acceptAdvertisement(
      admittedAt, serviceId, ad.data.peerId, ad, @[parseIpAddress("10.0.0.1")]
    )

    let reply = disco.getAdvertisements(
      PeerId.random(), Message(msgType: MessageType.getAds, key: serviceId)
    )

    check reply.getAds.get().advertisements.len == 0

  test "an ad admitted more than E ago no longer counts as cache occupancy":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "proof-expired-occupancy"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName)

    let now = Moment.init(Moment.now().epochSeconds, Second)
    let admittedAt = now - disco.discoConfig.advertExpiry - 60.secs
    let ips = @[parseIpAddress("10.0.0.1")]
    disco.acceptAdvertisement(admittedAt, serviceId, ad.data.peerId, ad, ips)

    # With the entry expired, the same IP and service see an empty cache again.
    let fresh = Registrar.new()
    check disco.registrar.waitingTime(disco.discoConfig, serviceId, ips, now) ==
      fresh.waitingTime(disco.discoConfig, serviceId, ips, now)
