# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results, std/sequtils
import
  ../../../../libp2p/[
    peerinfo,
    protocols/kademlia,
    protocols/service_discovery,
    protocols/service_discovery/advertiser,
    protocols/service_discovery/types,
    switch,
  ]
import ../../../tools/[lifecycle, unittest]
import ../utils

suite "Service Discovery Component - Client Mode":
  teardown:
    checkTrackers()

  asyncTest "client-mode node does not serve REGISTER":
    # The codec stays mounted, because there is no multistream unmount.
    let clientNode = setupServiceDiscoveryNode(client = true)
    let serverNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[clientNode, serverNode])
    await connect(serverNode, clientNode)

    check:
      ExtendedServiceDiscoveryCodec in serverNode.switch.peerInfo.protocols
      ExtendedServiceDiscoveryCodec in clientNode.switch.peerInfo.protocols

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName).encode().get()
    let response =
      await serverNode.sendRegister(clientNode.switch.peerInfo.peerId, serviceId, ad)
    check:
      response.isErr
      clientNode.registrar.ads.len == 0

  asyncTest "a peer that resets a request loses its seats":
    let clientNode = setupServiceDiscoveryNode(client = true)
    let serverNode = setupServiceDiscoveryNode()
    let registrarNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[clientNode, serverNode, registrarNode])
    await connect(serverNode, clientNode)
    await connect(serverNode, registrarNode)

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    check serverNode.rtManager.addService(
      serviceId, serverNode.rtable, serverNode.config.replication,
      serverNode.discoConfig.bucketsCount, Interest,
    )

    let clientId = clientNode.switch.peerInfo.peerId
    let registrarId = registrarNode.switch.peerInfo.peerId
    check:
      serverNode.hasPeerInServiceTable(serviceId, clientId)
      serverNode.hasPeerInServiceTable(serviceId, registrarId)

    let ad = makeAdvertisement(serviceName).encode().get()
    let refused = await serverNode.sendRegister(clientId, serviceId, ad)
    let answered = await serverNode.sendRegister(registrarId, serviceId, ad)

    check:
      refused.isErr()
      answered.isOk()
      not serverNode.rtable.hasPeer(clientId.toKey())
      not serverNode.hasPeerInServiceTable(serviceId, clientId)
      serverNode.rtable.hasPeer(registrarId.toKey())
      serverNode.hasPeerInServiceTable(serviceId, registrarId)

  asyncTest "client-mode node returns no ads when targeted by lookup":
    let clientNode = setupServiceDiscoveryNode(client = true)
    let discovererNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[clientNode, discovererNode])
    await connect(discovererNode, clientNode)

    check ExtendedServiceDiscoveryCodec in clientNode.switch.peerInfo.protocols

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    # Seed the client's cache so lookup would find the ad if the client were serving GET_ADS.
    clientNode.registrar.seedAd(serviceId, makeAdvertisement(serviceName))

    let found = await discovererNode.lookup(serviceId)
    check:
      found.get().len == 0

  asyncTest "client-mode node successfully completes lookup against server-mode registrars":
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let clientDiscoverer = setupServiceDiscoveryNode(discoConfig = conf, client = true)
    let serverRegistrar = setupServiceDiscoveryNode(discoConfig = conf)
    let serverAdvertiser = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[clientDiscoverer, serverRegistrar, serverAdvertiser])

    await connect(clientDiscoverer, serverRegistrar)
    await connect(serverAdvertiser, serverRegistrar)

    let service = makeServiceInfo("service")
    let serviceId = service.id.hashServiceId()

    check serverAdvertiser.addProvidedService(service)

    checkUntilTimeout:
      serverRegistrar.countAdsInCache(serviceId) == 1

    let found = await clientDiscoverer.lookup(serviceId)
    check:
      found.get().anyIt(it.data.peerId == serverAdvertiser.switch.peerInfo.peerId)

  asyncTest "client-mode node rejects addProvidedService":
    let clientNode = setupServiceDiscoveryNode(client = true)
    startAndDeferStop(@[clientNode])

    let service = makeServiceInfo("service")

    check clientNode.addProvidedService(service).isErr()
    check not clientNode.rtManager.hasService(service.id.hashServiceId())

  asyncTest "a downgrade to client mode stops new advertising":
    let advertiserNode = setupServiceDiscoveryNode()
    let registrarNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[advertiserNode, registrarNode])
    await connect(advertiserNode, registrarNode)

    let service = makeServiceInfo("service")
    let serviceId = service.id.hashServiceId()

    check advertiserNode.addProvidedService(service)
    checkUntilTimeout:
      registrarNode.countAdsInCache(serviceId) == 1

    check await advertiserNode.changeMode(isServer = false)

    let other = makeServiceInfo("other-service")
    check advertiserNode.addProvidedService(other).isErr()
    check registrarNode.countAdsInCache(other.id.hashServiceId()) == 0

  asyncTest "a downgrade to client mode ends the running registrations":
    # a task already inside its loop stops at its next refresh
    let conf = ServiceDiscoveryConfig.new(advertExpiry = 100.millis)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[advertiserNode, registrarNode])
    await connect(advertiserNode, registrarNode)

    let service = makeServiceInfo("service")
    let serviceId = service.id.hashServiceId()

    check advertiserNode.addProvidedService(service)
    check advertiserNode.advertiser.running.len() > 0
    checkUntilTimeout:
      advertiserNode.countAdsInCache(serviceId) == 1

    check await advertiserNode.changeMode(isServer = false)

    checkUntilTimeout:
      advertiserNode.localRegistrationLoop.finished()
      advertiserNode.advertiser.running.allIt(it.fut.finished())
