# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results, sequtils
import
  ../../../../libp2p/[
    crypto/crypto,
    peerid,
    peerinfo,
    protocols/kademlia/routing_table,
    protocols/kademlia/types,
    protocols/service_discovery/advertiser,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/registrar,
    protocols/service_discovery/routing_table_manager,
    protocols/service_discovery/types,
    switch,
  ]
import ../../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../../tools/[lifecycle, unittest]
import ../utils

suite "Service Discovery Component - Registrar Closer Peers":
  teardown:
    checkTrackers()

  asyncTest "REGISTER closerPeers come from RegT when available":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let serviceName = "service"
    # One peer per bucket is returned, so the two probes need distinct buckets
    # or the reply can only carry whichever of them is drawn.
    let bucketKeys = serviceBucketLookupTable[serviceName]
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceOnlyNode = setupServiceDiscoveryNode(
      discoConfig = conf, privateKey = Opt.some(PrivateKey.init(bucketKeys[0][0]).get())
    )
    let kadOnlyNode = setupServiceDiscoveryNode(
      discoConfig = conf, privateKey = Opt.some(PrivateKey.init(bucketKeys[1][0]).get())
    )

    startAndDeferStop(@[registrarNode, advertiserNode, serviceOnlyNode, kadOnlyNode])
    await connect(registrarNode, advertiserNode)
    await connect(registrarNode, kadOnlyNode)

    let serviceId = serviceName.hashServiceId()

    # serviceOnlyNode has addresses in the peer store but is not in the main Kad table.
    # Insert it into RegT only.
    registrarNode.switch.peerStore[AddressBook][serviceOnlyNode.switch.peerInfo.peerId] =
      serviceOnlyNode.switch.peerInfo.addrs

    discard registrarNode.rtManager.addService(
      serviceId, registrarNode.rtable, registrarNode.config.replication,
      conf.bucketsCount, Interest,
    )
    check registrarNode.insertPeer(
      serviceId,
      PeerInfo(
        peerId: serviceOnlyNode.switch.peerInfo.peerId,
        addrs: serviceOnlyNode.switch.peerInfo.addrs,
      ),
    )

    let adBytes = makeAdvertisement(serviceName).encode().get()
    let response = await advertiserNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, adBytes
    )

    check response.isOk()
    let closerPeerIds = response.get().closerPeers.mapIt(it.peerId)

    check:
      serviceOnlyNode.switch.peerInfo.peerId in closerPeerIds
      kadOnlyNode.switch.peerInfo.peerId in closerPeerIds

  asyncTest "GET_ADS closerPeers come from RegT when available":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let serviceName = "service"
    # The discoverer files one closer peer per bucket, so the two probes need
    # distinct buckets or only whichever is named first survives.
    let bucketKeys = serviceBucketLookupTable[serviceName]
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceOnlyNode = setupServiceDiscoveryNode(
      discoConfig = conf, privateKey = Opt.some(PrivateKey.init(bucketKeys[0][0]).get())
    )
    let kadOnlyNode = setupServiceDiscoveryNode(
      discoConfig = conf, privateKey = Opt.some(PrivateKey.init(bucketKeys[1][0]).get())
    )

    startAndDeferStop(@[registrarNode, discovererNode, serviceOnlyNode, kadOnlyNode])
    await connect(registrarNode, discovererNode)
    await connect(registrarNode, kadOnlyNode)

    let serviceId = serviceName.hashServiceId()

    # serviceOnlyNode has addresses in the peer store but is not in the main Kad table.
    # Insert it into RegT only.

    registrarNode.switch.peerStore[AddressBook][serviceOnlyNode.switch.peerInfo.peerId] =
      serviceOnlyNode.switch.peerInfo.addrs

    discard registrarNode.rtManager.addService(
      serviceId, registrarNode.rtable, registrarNode.config.replication,
      conf.bucketsCount, Interest,
    )
    check registrarNode.insertPeer(
      serviceId,
      PeerInfo(
        peerId: serviceOnlyNode.switch.peerInfo.peerId,
        addrs: serviceOnlyNode.switch.peerInfo.addrs,
      ),
    )

    let serviceOnlyKey = serviceOnlyNode.switch.peerInfo.peerId.toKey()

    check:
      not discovererNode.rtable.hasPeer(serviceOnlyKey)

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()
    checkUntilTimeout:
      discovererNode.rtable.hasPeer(serviceOnlyKey)

  asyncTest "GET_ADS closerPeers are centred on the service when there is no RegT":
    # kRegister = fReturn = 1: the reply is one peer from the bucket nearest the
    # service. Unclamped buckets keep that bucket to the target alone.
    let conf = ServiceDiscoveryConfig.new(
      kRegister = 1, fReturn = 1, bucketsCount = MaxBucketsLimit
    )
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let rtable = registrarNode.rtable

    # Peer ids are random and could all fall in one bucket, so add peers until
    # they span at least two.
    var others: seq[ServiceDiscovery]
    var keys: seq[Key]
    var buckets: seq[int]
    while others.len < 12 or buckets.min() == buckets.max():
      let node = setupServiceDiscoveryNode(discoConfig = conf)
      others.add(node)
      keys.add(node.switch.peerInfo.peerId.toKey())
      buckets.add(rtable.bucketIndex(keys[^1]))

    startAndDeferStop(@[registrarNode] & others)
    for node in others:
      await connect(registrarNode, node)

    checkUntilTimeout:
      keys.allIt(rtable.hasPeer(it))

    # Centre the service on a peer in the registrar's farthest bucket, so the
    # peer nearest the service is not in the registrar's own nearest bucket.
    let targetIdx = buckets.minIndex()
    check buckets[targetIdx] < buckets.max()

    let serviceId = Key.init(keys[targetIdx].hashFor(rtable.config.hasher))
    check registrarNode.rtManager.getTable(serviceId).isNone()

    # Ask as a peer other than the target.
    let requester = others[(targetIdx + 1) mod others.len]
    let response = registrarNode.getAdvertisements(
      requester.switch.peerInfo.peerId,
      Message(msgType: Opt.some(MessageType.getAds), key: Opt.some(serviceId)),
    )

    check response.closerPeers.toPeerIds() == @[
      others[targetIdx].switch.peerInfo.peerId
    ]

  asyncTest "GET_ADS closerPeers without a RegT follow the configured bucketsCount":
    # With one service bucket every peer shares it, so kRegister = 1 caps the
    # reply at one peer although fReturn allows two.
    let conf = ServiceDiscoveryConfig.new(kRegister = 1, fReturn = 2, bucketsCount = 1)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let hasher = registrarNode.rtable.config.hasher
    let serviceId = "service".hashServiceId()

    # Add peers until they sit at two distances from the service, so a view with
    # more buckets than configured would return two peers.
    var others: seq[ServiceDiscovery]
    var prefixLens: seq[int]
    while prefixLens.len < 2 or prefixLens.min() == prefixLens.max():
      let node = setupServiceDiscoveryNode(discoConfig = conf)
      let hashed = Key.fromBytes(node.switch.peerInfo.peerId.toKey().hashFor(hasher))
      others.add(node)
      prefixLens.add(xorDistance(serviceId, hashed).leadingZeros())

    startAndDeferStop(@[registrarNode] & others)
    for node in others:
      await connect(registrarNode, node)

    checkUntilTimeout:
      others.allIt(registrarNode.rtable.hasPeer(it.switch.peerInfo.peerId.toKey()))
    check registrarNode.rtManager.getTable(serviceId).isNone()

    let response = registrarNode.getAdvertisements(
      others[0].switch.peerInfo.peerId,
      Message(msgType: Opt.some(MessageType.getAds), key: Opt.some(serviceId)),
    )

    check response.closerPeers.len == 1

  asyncTest "GET_ADS closerPeers hold one peer per bucket at the default config":
    # Pins the shipped default. The per-bucket cap used to be K_register, so it
    # could return three peers from one bucket with nothing turning red.
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let (sameBucketNodes, serviceName) = setupRegistrarsInSameBucket(conf, 3)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let requester = setupServiceDiscoveryNode(discoConfig = conf)

    startAndDeferStop(@[registrarNode, requester] & sameBucketNodes)
    for node in sameBucketNodes:
      await connect(registrarNode, node)
    await connect(registrarNode, requester)

    let serviceId = serviceName.hashServiceId()
    let sharedBucketIds = sameBucketNodes.mapIt(it.switch.peerInfo.peerId)

    check:
      conf.kRegister == 3
      sharedBucketIds.allIt(registrarNode.rtable.hasPeer(it.toKey()))

    let response = registrarNode.getAdvertisements(
      requester.switch.peerInfo.peerId,
      Message(msgType: Opt.some(MessageType.getAds), key: Opt.some(serviceId)),
    )

    check response.closerPeers.toPeerIds().countIt(it in sharedBucketIds) == 1

  asyncTest "GET_ADS closerPeers do not name the requester":
    # The requester is seated on every query, so naming it back would spend its
    # bucket's only slot on the one peer the requester already knows.
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let requester = setupServiceDiscoveryNode(discoConfig = conf)

    startAndDeferStop(@[registrarNode, requester])
    await connect(registrarNode, requester)

    let requesterId = requester.switch.peerInfo.peerId
    check registrarNode.rtable.hasPeer(requesterId.toKey())

    let response = registrarNode.getAdvertisements(
      requesterId,
      Message(
        msgType: Opt.some(MessageType.getAds), key: Opt.some("service".hashServiceId())
      ),
    )

    check requesterId notin response.closerPeers.toPeerIds()

  asyncTest "REGISTER with Wait adds advertiser to RegT":
    # Use safetyParam = 0 so the first registration is Confirmed, and
    # advertCacheCap = 1 so the cache is full after that, forcing the
    # second registration to return Wait.
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0, advertCacheCap = 1)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let confirmedNode = setupServiceDiscoveryNode(discoConfig = conf)
    let waitNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, confirmedNode, waitNode])
    await connect(registrarNode, confirmedNode)

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()

    let confirmedAdBytes = makeAdvertisement(
        serviceName, confirmedNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()
    let confirmedResponse = await confirmedNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, confirmedAdBytes
    )
    check:
      confirmedResponse.isOk()
      confirmedResponse.get().status == kad_protobuf.RegistrationStatus.Confirmed

    let confirmedKey = confirmedNode.switch.peerInfo.peerId.toKey()
    let tableAfterConfirmed = registrarNode.rtManager.getTable(serviceId)
    check:
      tableAfterConfirmed.isSome()
      tableAfterConfirmed.get().hasPeer(confirmedKey)

    # Connect waitNode after the service table is created so it is not
    # seeded into it from the main Kad table.
    await connect(registrarNode, waitNode)

    let waitKey = waitNode.switch.peerInfo.peerId.toKey()
    check not tableAfterConfirmed.get().hasPeer(waitKey)

    # The cache is full so the registrar returns Wait.
    let waitAdBytes =
      makeAdvertisement(serviceName, waitNode.switch.peerInfo.privateKey).encode().get()
    let waitResponse = await waitNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, waitAdBytes
    )
    check:
      waitResponse.isOk()
      waitResponse.get().status == kad_protobuf.RegistrationStatus.Wait

    let tableAfterWait = registrarNode.rtManager.getTable(serviceId)
    check tableAfterWait.isSome()
    checkUntilTimeout:
      tableAfterWait.get().hasPeer(waitKey)

  asyncTest "REGISTER from a node without the codec mounted seats it nowhere":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let unmountedNode = setupServiceDiscoveryNode(discoConfig = conf, mount = false)
    startAndDeferStop(@[registrarNode, unmountedNode])

    # A switch starts and stops the protocols it mounts, so this one needs both by hand.
    await unmountedNode.start()
    defer:
      await unmountedNode.stop()

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let senderId = unmountedNode.switch.peerInfo.peerId

    unmountedNode.switch.peerStore[AddressBook][registrarNode.switch.peerInfo.peerId] =
      registrarNode.switch.peerInfo.addrs
    registrarNode.switch.peerStore[AddressBook][senderId] =
      unmountedNode.switch.peerInfo.addrs
    discard registrarNode.rtManager.addService(
      serviceId, registrarNode.rtable, registrarNode.config.replication,
      conf.bucketsCount, Interest,
    )

    let adBytes = makeAdvertisement(serviceName).encode().get()
    let response = await unmountedNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, adBytes
    )

    check:
      response.isOk()
      response.get().status == kad_protobuf.RegistrationStatus.Confirmed

    checkUntilTimeout:
      registrarNode.admissionProbes.len == 0
    check:
      not registrarNode.hasPeerInMainTable(senderId)
      not registrarNode.hasPeerInServiceTable(serviceId, senderId)

  asyncTest "REGISTER with an invalid advertisement seats the sender nowhere":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let senderNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, senderNode])

    let serviceId = "service".hashServiceId()
    let senderId = senderNode.switch.peerInfo.peerId

    senderNode.switch.peerStore[AddressBook][registrarNode.switch.peerInfo.peerId] =
      registrarNode.switch.peerInfo.addrs
    registrarNode.switch.peerStore[AddressBook][senderId] =
      senderNode.switch.peerInfo.addrs
    discard registrarNode.rtManager.addService(
      serviceId, registrarNode.rtable, registrarNode.config.replication,
      conf.bucketsCount, Interest,
    )

    let response = await senderNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, @[1'u8, 2, 3, 4]
    )

    check:
      response.isOk()
      response.get().status == kad_protobuf.RegistrationStatus.Rejected

    checkUntilTimeout:
      registrarNode.admissionProbes.len == 0
    check:
      not registrarNode.hasPeerInMainTable(senderId)
      not registrarNode.hasPeerInServiceTable(serviceId, senderId)

  asyncTest "GET_ADS adds discoverer to RegT":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let discovererNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, advertiserNode, discovererNode])
    await connect(registrarNode, advertiserNode)

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let adBytes = makeAdvertisement(
        serviceName, advertiserNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()

    # Create RegT via a Confirmed registration before the discoverer is
    # connected, so the discoverer is not seeded into it.
    let response = await advertiserNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, adBytes
    )
    check response.isOk()
    check response.get().status == kad_protobuf.RegistrationStatus.Confirmed

    await connect(registrarNode, discovererNode)

    let discovererKey = discovererNode.switch.peerInfo.peerId.toKey()
    let tableBefore = registrarNode.rtManager.getTable(serviceId)
    check:
      tableBefore.isSome()
      not tableBefore.get().hasPeer(discovererKey)

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()
    check found.get().len == 1

    let tableAfter = registrarNode.rtManager.getTable(serviceId)
    check tableAfter.isSome()
    checkUntilTimeout:
      tableAfter.get().hasPeer(discovererKey)
