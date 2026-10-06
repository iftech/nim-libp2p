# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results, sequtils
import
  ../../../../libp2p/[
    crypto/crypto,
    peerid,
    protocols/kademlia/types,
    protocols/service_discovery/advertiser,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/types,
    switch,
  ]
import ../../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../../tools/[lifecycle, unittest]
import ../utils

suite "Service Discovery Component - Lookup Get Ads":
  teardown:
    checkTrackers()

  asyncTest "GET_ADS on empty registrar cache returns no ads":
    let registrarNode = setupServiceDiscoveryNode()
    let discovererNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceId = "empty-service".hashServiceId()
    let lookupResp = await discovererNode.lookup(serviceId)
    check lookupResp.isOk()
    check lookupResp.get().len == 0

  asyncTest "GET_ADS returns ads stored in registrar cache":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, advertiserNode, discovererNode])
    await connect(registrarNode, advertiserNode)
    await connect(registrarNode, discovererNode)

    let serviceName = "cached-service"
    let serviceId = serviceName.hashServiceId()
    let adBytes = makeAdvertisement(
        serviceName, advertiserNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()

    let regResult = await advertiserNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, adBytes
    )
    check regResult.isOk()
    check regResult.get().status == kad_protobuf.RegistrationStatus.Confirmed

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()
    check found.get().len == 1
    check found.containsPeer(advertiserNode)

  asyncTest "lookup queries closer peers learned during the same lookup":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    # The relay sits in bucket 0 and the holder in bucket 1, so the discoverer's
    # walk reaches the holder's bucket after the relay has named it.
    let (relayNode, holderNode, serviceName) = setupRegistrarsInDistinctBuckets(conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[holderNode, relayNode, advertiserNode, discovererNode])
    await connect(holderNode, advertiserNode)
    await connect(holderNode, relayNode)
    await connect(relayNode, discovererNode)

    let serviceId = serviceName.hashServiceId()
    let adBytes = makeAdvertisement(
        serviceName, advertiserNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()
    let regResult = await advertiserNode.sendRegister(
      holderNode.switch.peerInfo.peerId, serviceId, adBytes
    )
    check regResult.isOk()
    check regResult.get().status == kad_protobuf.RegistrationStatus.Confirmed

    # Only the relay's reply can tell the discoverer about the holder.
    check not discovererNode.rtable.hasPeer(holderNode.switch.peerInfo.peerId.toKey())

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()
    check found.get().len == 1
    check found.containsPeer(advertiserNode)

  asyncTest "local duplicates do not consume the remaining lookup quota":
    let conf = ServiceDiscoveryConfig.new(fLookup = 2, fReturn = 2)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceName = "overlapping-service"
    let serviceId = serviceName.hashServiceId()
    let ads = @[makeAdvertisement(serviceName), makeAdvertisement(serviceName)]
    registrarNode.registrar.seedAds(serviceId, ads)

    # Duplicate the first remote result so it precedes the unseen advertisement.
    let firstAd = registrarNode.getAdsInCache(serviceId)[0]
    discovererNode.registrar.seedAd(serviceId, firstAd)

    let found = await discovererNode.lookup(serviceId)
    require found.isOk()
    check:
      found.get().len == 2
      ads[0] in found.get()
      ads[1] in found.get()

  asyncTest "GET_ADS respects F_return limit":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0, fReturn = 2)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceName = "limited-service"
    let serviceId = serviceName.hashServiceId()

    for _ in 0 ..< 4:
      let ad = makeAdvertisement(serviceName)
      let now = Moment.now()
      registrarNode.acceptAd(now, serviceId, ad)

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()
    check found.get().len <= 2

  asyncTest "discoverer discards ads with the service not matching the key":
    let registrarNode = setupServiceDiscoveryNode()
    let discovererNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceIdA = "service-A".hashServiceId()
    let adB = makeAdvertisement(serviceId = "service-B")
    # Plant ad for service-B under key for service-A.
    # The registrar will return it, the discoverer must drop it.
    registrarNode.registrar.seedAd(serviceIdA, adB)

    let found = await discovererNode.lookup(serviceIdA)
    check found.isOk()
    check found.get().len == 0

  asyncTest "lookup stops querying once F_lookup ads are found":
    # fLookup small so one GET_ADS response fits under ServiceDiscoveryMaxMsgSize.
    const fLookup = 8
    let conf = ServiceDiscoveryConfig.new(
      safetyParam = 0.0, fLookup = fLookup, fReturn = fLookup
    )
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)

    let (queriedFirst, queriedSecond, serviceName) =
      setupRegistrarsInDistinctBuckets(conf)
    let serviceId = serviceName.hashServiceId()

    startAndDeferStop(@[discovererNode, queriedFirst, queriedSecond])
    await connect(discovererNode, queriedFirst)
    await connect(discovererNode, queriedSecond)

    # The first-queried registrar fills the result on its own.
    var firstBucketAds: seq[Advertisement]
    for _ in 0 ..< fLookup:
      firstBucketAds.add(makeAdvertisement(serviceName))
    queriedFirst.registrar.seedAds(serviceId, firstBucketAds)

    # The other should never be queried, so should not appear in the result.
    let otherKey = randomKey()
    let otherAd = makeAdvertisement(serviceName, privateKey = otherKey)
    let otherPeerId = PeerId.init(otherKey).get()
    queriedSecond.registrar.seedAd(serviceId, otherAd)

    let found = await discovererNode.lookup(serviceId)
    check:
      found.get().len == fLookup
      not found.get().anyIt(it.data.peerId == otherPeerId)

  asyncTest "lookup queries K_lookup registrars per bucket":
    const kLookup = 2
    let conf = ServiceDiscoveryConfig.new(
      safetyParam = 0.0, kLookup = kLookup, fLookup = 30, fReturn = 1
    )
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)

    let (registrars, serviceName) = setupRegistrarsInSameBucket(conf, kLookup + 2)
    let serviceId = serviceName.hashServiceId()

    startAndDeferStop(@[discovererNode] & registrars)
    for registrar in registrars:
      await connect(discovererNode, registrar)
      registrar.registrar.seedAd(serviceId, makeAdvertisement(serviceName))

    let found = await discovererNode.lookup(serviceId)
    check:
      found.isOk()
      found.get().len == kLookup

  asyncTest "lookup iterates buckets from farthest to closest":
    # fLookup=1, only the first-queried registrar's ad is returned
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0, fLookup = 1)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)

    let (queriedFirst, queriedSecond, serviceName) =
      setupRegistrarsInDistinctBuckets(conf)
    let serviceId = serviceName.hashServiceId()

    startAndDeferStop(@[discovererNode, queriedFirst, queriedSecond])
    await connect(discovererNode, queriedFirst)
    await connect(discovererNode, queriedSecond)

    let firstBucketKey = randomKey()
    let firstBucketAd = makeAdvertisement(serviceName, privateKey = firstBucketKey)
    let secondBucketAd = makeAdvertisement(serviceName)
    queriedFirst.registrar.seedAd(serviceId, firstBucketAd)
    queriedSecond.registrar.seedAd(serviceId, secondBucketAd)

    let found = await discovererNode.lookup(serviceId)
    check:
      found.get().len == 1
      found.get()[0].data.peerId == PeerId.init(firstBucketKey).get()

  asyncTest "discoverer learns closer peers from GET_ADS reply":
    let discovererNode = setupServiceDiscoveryNode()
    let registrarNode = setupServiceDiscoveryNode()
    let otherNode = setupServiceDiscoveryNode()

    startAndDeferStop(@[discovererNode, registrarNode, otherNode])
    await connect(registrarNode, otherNode)
    await connect(registrarNode, discovererNode)

    let
      serviceId = "service".hashServiceId()
      otherKey = otherNode.switch.peerInfo.peerId.toKey()

    check:
      not discovererNode.rtable.hasPeer(otherKey)
      discovererNode.rtManager.getTable(serviceId).isNone()

    let found = await discovererNode.lookup(serviceId)
    check:
      found.get().len == 0

    let serviceTable = discovererNode.rtManager.getTable(serviceId).get()
    checkUntilTimeout:
      serviceTable.hasPeer(otherKey)
      discovererNode.rtable.hasPeer(otherKey)

  asyncTest "closer peers from one registrar are capped at one per bucket":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)

    # Three candidates share a service bucket. K_register is 3, so the registrar
    # names all of them in a single reply and only the cap keeps them apart.
    let (sharedBucketNodes, serviceName) = setupRegistrarsInSameBucket(conf, 3)

    # The registrar and the discoverer sit in another bucket, so neither takes a
    # slot the shared bucket would otherwise use.
    let otherBucketKeys = serviceBucketLookupTable[serviceName][1]
    let registrarNode = setupServiceDiscoveryNode(
      discoConfig = conf,
      privateKey = Opt.some(PrivateKey.init(otherBucketKeys[0]).get()),
    )
    let discovererNode = setupServiceDiscoveryNode(
      discoConfig = conf,
      privateKey = Opt.some(PrivateKey.init(otherBucketKeys[1]).get()),
    )

    startAndDeferStop(@[registrarNode, discovererNode] & sharedBucketNodes)
    for node in sharedBucketNodes:
      await connect(registrarNode, node)
    await connect(registrarNode, discovererNode)

    let serviceId = serviceName.hashServiceId()
    let sharedBucketKeys = sharedBucketNodes.mapIt(it.switch.peerInfo.peerId.toKey())

    # Only the registrar's reply can name them.
    check:
      sharedBucketKeys.allIt(registrarNode.rtable.hasPeer(it))
      not sharedBucketKeys.anyIt(discovererNode.rtable.hasPeer(it))

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()

    let serviceTable = discovererNode.rtManager.getTable(serviceId).get()
    checkUntilTimeout:
      sharedBucketKeys.countIt(serviceTable.hasPeer(it)) == 1
      sharedBucketKeys.countIt(discovererNode.rtable.hasPeer(it)) == 1
