# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results, std/[sequtils, sets, tables]
import
  ../../../../libp2p/[
    crypto/crypto,
    peerid,
    peerinfo,
    protocols/kademlia/types,
    protocols/service_discovery,
    protocols/service_discovery/advertiser,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/routing_table_manager,
    protocols/service_discovery/types,
    switch,
  ]
import ../../../tools/[crypto, lifecycle, multiaddress, unittest, topology]
import ../utils

suite "Service Discovery Component - Advertise Discover":
  teardown:
    checkTrackers()

  asyncTest "addProvidedService registers service, lookup finds it":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let registrarNode1 = setupServiceDiscoveryNode(discoConfig = conf)
    let registrarNode2 = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode1, registrarNode2, advertiserNode, discovererNode])

    await connect(registrarNode1, advertiserNode)
    await connect(registrarNode2, advertiserNode)
    await connect(registrarNode1, discovererNode)
    await connect(registrarNode2, discovererNode)

    let service = makeServiceInfo("e2e-test-service")
    let serviceId = service.id.hashServiceId()

    check advertiserNode.addProvidedService(service)

    checkUntilTimeout:
      registrarNode1.countAdsInCache(serviceId) == 1 or
        registrarNode2.countAdsInCache(serviceId) == 1

    let found = await discovererNode.lookup(serviceId)
    check found
    check found.get().len >= 1
    check found.containsPeer(advertiserNode)

  asyncTest "registerInterest seeds per-service table from main routing table":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    let peerA = setupServiceDiscoveryNode(discoConfig = conf)
    let peerB = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[discovererNode, peerA, peerB])

    await connectHub(discovererNode, @[peerA, peerB])

    let serviceId = "service"
    let serviceHash = serviceId.hashServiceId()
    let peerAKey = peerA.switch.peerInfo.peerId.toKey()
    let peerBKey = peerB.switch.peerInfo.peerId.toKey()

    check:
      hasPeer(discovererNode.rtable, peerAKey)
      hasPeer(discovererNode.rtable, peerBKey)
      not discovererNode.rtManager.hasService(serviceHash)

    check discovererNode.rtManager.getTable(serviceHash).isNone()

    check discovererNode.registerInterest(serviceId)

    let table = discovererNode.rtManager.getTable(serviceHash)
    check:
      table.isSome()
      hasPeer(table.get(), peerAKey)
      hasPeer(table.get(), peerBKey)

    discovererNode.unregisterInterest(serviceId)
    check not discovererNode.rtManager.hasService(serviceHash)

  asyncTest "two advertisers register the same service - both discoverable":
    # Zeroed safety/IP terms and a large cache cap keep the wait time under 0.5s,
    # so both ads are admitted on the first REGISTER with no flaky retry window.
    let conf = ServiceDiscoveryConfig.new(
      safetyParam = 0.0, ipSimCoefficient = 0.0, advertCacheCap = 1_000_000
    )
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserA = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserB = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, advertiserA, advertiserB, discovererNode])

    await connectHub(registrarNode, @[advertiserA, advertiserB, discovererNode])

    let service = makeServiceInfo("shared-service")
    let serviceId = service.id.hashServiceId()

    check advertiserA.addProvidedService(service)
    check advertiserB.addProvidedService(service)

    checkUntilTimeout:
      block:
        let ads = registrarNode.getAdsInCache(serviceId)
        ads.anyIt(it.data.peerId == advertiserA.switch.peerInfo.peerId) and
          ads.anyIt(it.data.peerId == advertiserB.switch.peerInfo.peerId)

    checkUntilTimeout:
      block:
        let found = await discovererNode.lookup(serviceId)
        found.get().len == 2 and found.containsPeer(advertiserA) and
          found.containsPeer(advertiserB)

  asyncTest "one advertiser provides two services - both discoverable":
    # TODO: vacp2p/nim-libp2p#2430 service-disco: missing API for multi-service registration
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0, ipSimCoefficient = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, advertiserNode, discovererNode])

    await connectHub(registrarNode, @[advertiserNode, discovererNode])

    let svcA = makeServiceInfo("service-A")
    let svcB = makeServiceInfo("service-B")
    let svcAId = svcA.id.hashServiceId()
    let svcBId = svcB.id.hashServiceId()

    check advertiserNode.addProvidedService(svcA)

    checkUntilTimeout:
      registrarNode.countAdsInCache(svcAId) == 1

    check advertiserNode.addProvidedService(svcB)

    checkUntilTimeout:
      registrarNode.countAdsInCache(svcBId) == 1

    checkUntilTimeout:
      block:
        let foundA = await discovererNode.lookup(svcAId)
        foundA.get().anyIt(it.data.peerId == advertiserNode.switch.peerInfo.peerId) and
          foundA.get().len == 1
      block:
        let foundB = await discovererNode.lookup(svcBId)
        foundB.get().anyIt(it.data.peerId == advertiserNode.switch.peerInfo.peerId) and
          foundB.get().len == 1
          # Regression for vacp2p/nim-libp2p#2431: this lookup previously returned a duplicate.

  asyncTest "lookup dedups byte-identical adverts but keeps same (peerId, seqNo) variants":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let registrar1 = setupServiceDiscoveryNode(discoConfig = conf)
    let registrar2 = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrar1, registrar2, discovererNode])

    await connect(registrar1, discovererNode)
    await connect(registrar2, discovererNode)

    let service = makeServiceInfo("service")
    let serviceId = service.id.hashServiceId()

    let key = PrivateKey.random(rng()).get()
    let seqNo = 1234'u64
    let ad1 = makeAdvertisement(
      serviceId = service.id,
      privateKey = key,
      addrs = @[makeMultiAddress("1.2.3.4")],
      seqNo = seqNo,
    )
    let ad2 = makeAdvertisement(
      serviceId = service.id,
      privateKey = key,
      addrs = @[makeMultiAddress("5.6.7.8")],
      seqNo = seqNo,
    )
    check:
      ad1.data.peerId == ad2.data.peerId
      ad1.data.seqNo == ad2.data.seqNo
      ad1.envelope.signature.data != ad2.envelope.signature.data

    registrar1.registrar.seedAd(serviceId, ad1)
    registrar2.registrar.seedAd(serviceId, ad2)

    let found = await discovererNode.lookup(serviceId)
    check:
      found.get().len == 2
      found.get().anyIt(it.envelope.signature.data == ad1.envelope.signature.data)
      found.get().anyIt(it.envelope.signature.data == ad2.envelope.signature.data)

  asyncTest "advertiser learns closer peers from REGISTER reply":
    # The registrar's REGISTER reply carries closerPeers.
    # The advertiser must add them to the service-specific routing table so
    # subsequent rounds can reach beyond the initially known registrar.
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let otherNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[advertiserNode, registrarNode, otherNode])

    # The registrar already knows the otherNode, the advertiser does not.
    await connect(registrarNode, otherNode)
    await connect(registrarNode, advertiserNode)

    let service = makeServiceInfo("service-A")
    let serviceId = service.id.hashServiceId()

    check advertiserNode.addProvidedService(service)

    let otherKey = otherNode.switch.peerInfo.peerId.toKey()
    checkUntilTimeout:
      advertiserNode.rtManager.getTable(serviceId).get().hasPeer(otherKey)

  asyncTest "advertiser retries with the ticket after Wait and gets Confirmed":
    # First REGISTER gets Wait + ticket, advertiser sleeps then retries
    # with the ticket and the registrar admits the ad. The registration
    # window is widened to 10s so the retry's handshake has time to complete.
    let conf = ServiceDiscoveryConfig.new(registrationWindow = 10.secs)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let service = makeServiceInfo("service")
    let serviceId = service.id.hashServiceId()

    check advertiserNode.addProvidedService(service)

    checkUntilTimeout:
      registrarNode.countAdsInCache(serviceId) == 1

    let ads = registrarNode.getAdsInCache(serviceId)
    check ads[0].data.peerId == advertiserNode.switch.peerInfo.peerId

  asyncTest "remote registration task terminates after one Confirmed cycle and maintenance refills the slot":
    let conf = ServiceDiscoveryConfig.new(advertExpiry = 300.millis, safetyParam = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let service = makeServiceInfo("service")
    let serviceId = service.id.hashServiceId()

    check advertiserNode.addProvidedService(service)

    # Wait for the first registration to succeed on the remote registrar
    checkUntilTimeout:
      registrarNode.countAdsInCache(serviceId) == 1

    # Capture the remote tasks that were started for this service
    # (the local registration now lives in localRegistrationLoop, not in running).
    var remoteTasks = advertiserNode.advertiser.running.filterIt(
      it.serviceId == serviceId and it.registrar != advertiserNode.switch.peerInfo.peerId
    )

    check remoteTasks.len > 0

    # After one advertExpiry following Confirmed, the remote tasks should
    # have terminated (new behavior: they return instead of looping).
    checkUntilTimeout:
      remoteTasks.allIt(it.fut.finished)

    # Force a maintenance tick. This simulates the bucket refresh and
    # should detect the deficit (no active remote tasks for the bucket)
    # and start new registration task(s).
    await advertiserNode.maintainRegistrations()

    # There should now be new remote registration task(s) for the service.
    remoteTasks = advertiserNode.advertiser.running.filterIt(
      it.serviceId == serviceId and it.registrar != advertiserNode.switch.peerInfo.peerId
    )

    check remoteTasks.len > 0
    # The newly created tasks should still be running (not yet finished).
    check remoteTasks.anyIt(not it.fut.finished)

  asyncTest "advertiser stops after the registrar replies Rejected":
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let serviceId = makeServiceId()

    # Seed the per-service table directly so we skip the bucket-iteration
    # tasks that addProvidedService would start.
    check advertiserNode.rtManager.addService(
      serviceId, advertiserNode.rtable, advertiserNode.config.replication,
      advertiserNode.discoConfig.bucketsCount, Provided,
    )

    # Malformed bytes force a Rejected reply.
    let badAdvert = @[1'u8, 2, 3, 4]

    # The advertiser should hit Rejected, break its retry loop, and return.
    await advertiserNode.advertiseToRegistrar(
      serviceId, registrarNode.switch.peerInfo.peerId, Opt.none(Ticket), badAdvert
    )

    check registrarNode.countAdsInCache(serviceId) == 0

  asyncTest "advertiser stops on send failure":
    let advertiserNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[advertiserNode])

    let serviceId = makeServiceId()

    check advertiserNode.rtManager.addService(
      serviceId, advertiserNode.rtable, advertiserNode.config.replication,
      advertiserNode.discoConfig.bucketsCount, Provided,
    )

    # A peer with no address in the peer store triggers an immediate send failure.
    let unreachablePeer = randomPeerId()

    # sendRegister fails and the task returns without retrying.
    await advertiserNode.advertiseToRegistrar(
      serviceId, unreachablePeer, Opt.none(Ticket), @[1'u8, 2, 3, 4]
    )

    check advertiserNode.countAdsInCache(serviceId) == 0

  asyncTest "auto-advertise on start":
    # Using ipSimCoefficient = 0.0 to not trigger sybil protection when advertising multiple services
    # TODO: vacp2p/nim-libp2p#2430 service-disco: missing API for multi-service registration
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0, ipSimCoefficient = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)

    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceA = makeServiceInfo("service-A")
    let serviceB = makeServiceInfo("service-B")
    let serviceAId = serviceA.id.hashServiceId()
    let serviceBId = serviceB.id.hashServiceId()

    let advertiserNode = setupServiceDiscoveryNode(
      discoConfig = conf,
      bootstrapNodes =
        @[(registrarNode.switch.peerInfo.peerId, registrarNode.switch.peerInfo.addrs)],
      services = @[serviceA, serviceB],
    )

    startAndDeferStop(@[advertiserNode])

    checkUntilTimeout:
      block:
        let foundA = await discovererNode.lookup(serviceAId)
        let foundB = await discovererNode.lookup(serviceBId)
        foundA.containsPeer(advertiserNode) and foundB.containsPeer(advertiserNode)

  asyncTest "advertiser registers with peers discovered after addProvidedService":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let initialRegistrar = setupServiceDiscoveryNode(discoConfig = conf)
    let lateRegistrar = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)

    # maintainAdvertiser runs maintainRegistrations every bucketRefreshTime (default 10 min).
    # Set it short so multiple refresh cycles complete within the test window.
    advertiserNode.config.bucketRefreshTime = 50.millis

    startAndDeferStop(@[initialRegistrar, lateRegistrar, advertiserNode])

    # Only initialRegistrar is known when addProvidedService spawns tasks.
    await connect(initialRegistrar, advertiserNode)

    let service = makeServiceInfo("service")
    let serviceId = service.id.hashServiceId()

    check advertiserNode.addProvidedService(service)

    checkUntilTimeout:
      initialRegistrar.countAdsInCache(serviceId) == 1

    # Simulate a peer discovered after the initial task spawn
    await connect(lateRegistrar, advertiserNode)
    check advertiserNode.insertPeer(
      serviceId,
      PeerInfo(
        peerId: lateRegistrar.switch.peerInfo.peerId,
        addrs: lateRegistrar.switch.peerInfo.addrs,
      ),
    )

    # The maintenance loop rotates the new bucket peer in and registers with it.
    checkUntilTimeout:
      lateRegistrar.countAdsInCache(serviceId) == 1

  asyncTest "an IPv6-only node is subject to IP-similarity throttling like an IPv4 node":
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode = setupServiceDiscoveryNode(addresses = @[TcpAutoAddressIP6()])
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let firstService = makeServiceInfo("ipv6-service-1")
    let firstServiceId = firstService.id.hashServiceId()
    check advertiserNode.addProvidedService(firstService)
    checkUntilTimeout:
      registrarNode.countAdsInCache(firstServiceId) == 1

    let secondService = makeServiceInfo("ipv6-service-2")
    let secondServiceId = secondService.id.hashServiceId()
    check advertiserNode.addProvidedService(secondService)
    checkUntilTimeout:
      registrarNode.registrar.boundService.hasKey(secondServiceId)
    check registrarNode.countAdsInCache(secondServiceId) == 0

  asyncTest "a dual-stack node follows the normal path and is told to Wait":
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode =
      setupServiceDiscoveryNode(addresses = @[TcpAutoAddressIP4(), TcpAutoAddressIP6()])
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let firstService = makeServiceInfo("dual-stack-service-1")
    let firstServiceId = firstService.id.hashServiceId()
    check advertiserNode.addProvidedService(firstService)
    checkUntilTimeout:
      registrarNode.countAdsInCache(firstServiceId) == 1

    let secondService = makeServiceInfo("dual-stack-service-2")
    let secondServiceId = secondService.id.hashServiceId()
    check advertiserNode.addProvidedService(secondService)
    # The registrar answered Wait, not Confirmed: it records the Wait in
    # boundService and does not admit the second ad to the cache.
    checkUntilTimeout:
      registrarNode.registrar.boundService.hasKey(secondServiceId)
    check registrarNode.countAdsInCache(secondServiceId) == 0
