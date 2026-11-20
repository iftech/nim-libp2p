# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/6.
# Spec, Looking up services: "The discoverer MUST attempt to find up to F_lookup
# advertisers for this service_id_hash ... During the lookup procedure, the
# discoverer SHOULD keep track of unique foundPeers, terminating the procedure
# once F_lookup advertisers have been found, or if all buckets have been
# traversed."

import std/sequtils
import chronos, results
import
  ../../../libp2p/[
    crypto/crypto, extended_peer_record, peerid, protocols/service_discovery/discoverer
  ]
import ../../tools/[lifecycle, unittest]
import ./utils

suite "Proof 20261120T114625-71ee3b/6 - lookup counts unique advertisers":
  teardown:
    checkTrackers()

  asyncTest "two records of one advertiser do not end a lookup for two advertisers":
    let conf = ServiceDiscoveryConfig.new(fLookup = 2)
    # Two registrars in bucket 0 of the service table, one in bucket 1.
    let (farRegistrars, serviceName) = setupRegistrarsInSameBucket(conf, 2)
    let closeKey = PrivateKey.init(serviceBucketLookupTable[serviceName][1][0]).get()
    let closeRegistrar =
      setupServiceDiscoveryNode(discoConfig = conf, privateKey = Opt.some(closeKey))
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(farRegistrars & @[closeRegistrar, discovererNode])
    for registrar in farRegistrars & @[closeRegistrar]:
      await connect(registrar, discovererNode)

    let serviceId = serviceName.hashServiceId()

    # Advertiser P re-published after an address change: the two far registrars
    # hold its record at different sequence numbers.
    let keyP = randomKey()
    farRegistrars[0].registrar.seedAd(
      serviceId, makeAdvertisement(serviceName, keyP, seqNo = 1)
    )
    farRegistrars[1].registrar.seedAd(
      serviceId, makeAdvertisement(serviceName, keyP, seqNo = 2)
    )
    # A second advertiser Q is registered one bucket closer to the service.
    let adQ = makeAdvertisement(serviceName)
    closeRegistrar.registrar.seedAd(serviceId, adQ)

    let found = await discovererNode.lookup(serviceId)
    require found.isOk()

    let advertisers = found.get().mapIt(it.data.peerId).deduplicate()
    checkpoint "ads returned: " & $found.get().len & ", unique advertisers: " &
      $advertisers.len
    # F_lookup = 2 and two advertisers are reachable.
    check advertisers.len == 2
    check adQ.data.peerId in advertisers
