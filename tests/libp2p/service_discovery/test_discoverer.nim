# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results
import
  ../../../libp2p/[
    peerid,
    protocols/kademlia,
    protocols/service_discovery,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/types,
  ]
import ../../tools/[lifecycle, unittest]
import ./utils

suite "Discoverer - lookup":
  teardown:
    checkTrackers()

  asyncTest "creates service routing table on first call":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()

    check not disco.rtManager.hasService(serviceId)

    let res = await disco.lookup(serviceId)

    check res.isOk()
    check disco.rtManager.hasService(serviceId)

  asyncTest "empty routing table returns ok with empty peers":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()

    let res = await disco.lookup(serviceId)

    check res.isOk()
    check res.get().len == 0

  asyncTest "empty routing table still returns cached advertisements":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo("local-service")
    let serviceId = service.id.hashServiceId()
    let ad = makeAdvertisement(service.id)
    disco.registrar.seedAd(serviceId, ad)

    let res = await disco.lookup(serviceId)

    check res.isOk()
    check res.get() == @[ad]

  asyncTest "calling lookup twice for same service is idempotent":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()

    let res1 = await disco.lookup(serviceId)
    let res2 = await disco.lookup(serviceId)

    check res1.isOk()
    check res2.isOk()
    check disco.rtManager.hasService(serviceId)

  asyncTest "distinct service IDs get independent routing tables":
    let disco = setupServiceDiscoveryNode()
    let sid1 = makeServiceId(1)
    let sid2 = makeServiceId(2)

    discard await disco.lookup(sid1)
    discard await disco.lookup(sid2)

    check disco.rtManager.hasService(sid1)
    check disco.rtManager.hasService(sid2)
    check disco.rtManager.count() == 2

  asyncTest "lookup by ServiceInfo hashes to same table as lookup by ServiceId":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo("my-service")
    let serviceId = service.id.hashServiceId()

    let res = await disco.lookup(service)

    check res.isOk()
    check disco.rtManager.hasService(serviceId)

  asyncTest "drops cached advertisements that fail validation":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo("local-service")
    let serviceId = service.id.hashServiceId()
    disco.registrar.seedAds(
      serviceId,
      @[makeOversizedAdvertisement(service.id), makeAdvertisement("other-service")],
    )

    let res = await disco.lookup(serviceId)

    check:
      disco.countAdsInCache(serviceId) == 2
      res.get().len == 0

  asyncTest "local advertisements past fLookup are not returned":
    let fLookup = 2
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(fLookup = fLookup, fReturn = 10)
    )
    let service = makeServiceInfo("local-service")
    let serviceId = service.id.hashServiceId()
    for _ in 0 .. fLookup:
      disco.registrar.seedAd(serviceId, makeAdvertisement(service.id))

    let res = await disco.lookup(serviceId)

    check res.get().len == fLookup

  asyncTest "walks past an empty first bucket":
    let disco = setupServiceDiscoveryNode()
    startAndDeferStop(@[disco])
    let service = makeServiceInfo("remote-service")
    let serviceId = service.id.hashServiceId()
    check disco.registerInterest(service.id)
    let table = disco.rtManager.getTable(serviceId).get()

    var peerId = randomPeerId()
    while table.bucketIndex(peerId.toKey()) == 0:
      peerId = randomPeerId()
    check table.insert(peerId)

    let res = await disco.lookup(serviceId)

    check:
      table.buckets[0].peers.len == 0
      res.get().len == 0

suite "Discoverer - register/unregister interest":
  teardown:
    checkTrackers()

  test "registers an Interest routing table":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()

    let added = disco.registerInterest(service.id)

    check added
    check disco.rtManager.hasService(service.id.hashServiceId())

  test "returns false when called again for the same service":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()

    discard disco.registerInterest(service.id)
    let added = disco.registerInterest(service.id)

    check not added

  test "distinct services get independent tables":
    let disco = setupServiceDiscoveryNode()
    let s1 = makeServiceInfo("svc-1")
    let s2 = makeServiceInfo("svc-2")

    discard disco.registerInterest(s1.id)
    discard disco.registerInterest(s2.id)

    check disco.rtManager.hasService(s1.id.hashServiceId())
    check disco.rtManager.hasService(s2.id.hashServiceId())
    check disco.rtManager.count() == 2

  test "unregisterInterest removes Interest entry":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()

    check disco.registerInterest(service.id)
    disco.unregisterInterest(service.id)

    check not disco.rtManager.hasService(service.id.hashServiceId())

  test "unregisterInterest does not affect a different service":
    let disco = setupServiceDiscoveryNode()
    let s1 = makeServiceInfo("svc-1")
    let s2 = makeServiceInfo("svc-2")

    check disco.registerInterest(s1.id)
    check disco.registerInterest(s2.id)
    disco.unregisterInterest(s1.id)

    check not disco.rtManager.hasService(s1.id.hashServiceId())
    check disco.rtManager.hasService(s2.id.hashServiceId())
