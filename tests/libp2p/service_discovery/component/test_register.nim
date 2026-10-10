# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

from std/times import getTime, toUnix
import chronos, results
import
  ../../../../libp2p/
    [protocols/service_discovery/advertiser, protocols/service_discovery/types, switch]
import ../../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../../tools/[lifecycle, unittest]
import ../utils

suite "Service Discovery Component - Register":
  teardown:
    checkTrackers()

  asyncTest "first REGISTER with no ticket returns Confirm":
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let serviceName = "test-register-service"
    let serviceId = serviceName.hashServiceId()
    let adBytes = makeAdvertisement(serviceName).encode().get()

    let regResp = await advertiserNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, adBytes
    )
    check regResp
    check regResp.get().status == kad_protobuf.RegistrationStatus.Confirmed

  asyncTest "REGISTER with out-of-window ticket ignores ticket and returns Rejected":
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let serviceName = "out-of-window-service"
    let serviceId = serviceName.hashServiceId()
    let adBytes = makeAdvertisement(
        serviceName, advertiserNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()
    let registrarKey = registrarNode.switch.peerInfo.privateKey
    let now = getTime().toUnix()
    var ticket = Ticket(
      advertisement: adBytes,
      tInit: now - 10000000,
      tMod: now - 10000000,
      tWaitFor: 0.secs,
      signature: Opt.none(seq[byte]),
    )
    check ticket.sign(registrarKey)

    let regResp = await advertiserNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, adBytes, Opt.some(ticket)
    )
    check regResp
    check regResp.get().status == kad_protobuf.RegistrationStatus.Rejected

  asyncTest "back-to-back REGISTERs return identical waits":
    # Anti-grinding: tMod + tWaitFor (eligibility moment) must never move earlier across retries.
    # Seed another advertiser's ad so occupancy forces Wait for a first-time registration.
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode = setupServiceDiscoveryNode()
    let seederNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, advertiserNode, seederNode])
    await connect(registrarNode, advertiserNode)
    await connect(registrarNode, seederNode)

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let advertiserKey = advertiserNode.switch.peerInfo.privateKey
    let seedAdBytes = makeAdvertisement(
        serviceName, seederNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()
    let adBytes =
      makeAdvertisement(serviceName, advertiserKey, seqNo = 1).encode().get()
    let registrarPeerId = registrarNode.switch.peerInfo.peerId

    let seedResponse: RegistrationResponse =
      (await seederNode.sendRegister(registrarPeerId, serviceId, seedAdBytes)).get()
    check seedResponse.status == kad_protobuf.RegistrationStatus.Confirmed

    proc requestTicket(): Future[Ticket] {.async.} =
      let response: RegistrationResponse =
        (await advertiserNode.sendRegister(registrarPeerId, serviceId, adBytes)).get()
      check response.status == kad_protobuf.RegistrationStatus.Wait
      check response.ticket.isSome()
      return response.ticket.get()

    let second = await requestTicket()
    let third = await requestTicket()
    check:
      third.tWaitFor == second.tWaitFor
      third.tMod.get() >= second.tMod.get()

  asyncTest "REGISTER replaces ad for the same advertiser":
    # Use a non-zero subsecond expiry: the waiting-time formula rounds it down
    # to zero seconds, while registrar maintenance still has a real interval.
    let conf = ServiceDiscoveryConfig.new(advertExpiry = 999.millis)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let advertiserNode = setupServiceDiscoveryNode(discoConfig = conf)

    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let registrarPeerId = registrarNode.switch.peerInfo.peerId
    let advertiserKey = advertiserNode.switch.peerInfo.privateKey
    let addrA = makeMultiAddress("10.0.0.1")
    let addrB = makeMultiAddress("10.0.0.2")
    let addrC = makeMultiAddress("10.0.0.3")

    let originalAd =
      makeAdvertisement(serviceName, advertiserKey, addrs = @[addrA], seqNo = 1)
    let duplicateSameSeqAd =
      makeAdvertisement(serviceName, advertiserKey, addrs = @[addrB], seqNo = 1)
    let newerSeqAd =
      makeAdvertisement(serviceName, advertiserKey, addrs = @[addrB], seqNo = 2)
    let staleLowerSeqAd =
      makeAdvertisement(serviceName, advertiserKey, addrs = @[addrC], seqNo = 0)

    # First REGISTER stores the advertiser's initial ad.
    var registerResponse = await advertiserNode.sendRegister(
      registrarPeerId, serviceId, originalAd.encode().get()
    )
    check registerResponse.get().status == kad_protobuf.RegistrationStatus.Confirmed
    check registrarNode.countAdsInCache(serviceId) == 1
    check registrarNode.getAdsInCache(serviceId)[0].data.addresses[0].address == addrA

    # Identical ad re-registration replaces (refreshes) the same slot.
    registerResponse = await advertiserNode.sendRegister(
      registrarPeerId, serviceId, originalAd.encode().get()
    )
    check registerResponse.get().status == kad_protobuf.RegistrationStatus.Confirmed
    check registrarNode.countAdsInCache(serviceId) == 1
    check registrarNode.getAdsInCache(serviceId)[0].envelope.signature.data ==
      originalAd.envelope.signature.data

    # Same peer/seqNo with different payload replaces the slot.
    registerResponse = await advertiserNode.sendRegister(
      registrarPeerId, serviceId, duplicateSameSeqAd.encode().get()
    )
    check registerResponse.get().status == kad_protobuf.RegistrationStatus.Confirmed
    check registrarNode.countAdsInCache(serviceId) == 1
    check registrarNode.getAdsInCache(serviceId)[0].envelope.signature.data ==
      duplicateSameSeqAd.envelope.signature.data

    # Higher seqNo replaces.
    registerResponse = await advertiserNode.sendRegister(
      registrarPeerId, serviceId, newerSeqAd.encode().get()
    )
    check registerResponse.get().status == kad_protobuf.RegistrationStatus.Confirmed
    check registrarNode.countAdsInCache(serviceId) == 1
    check registrarNode.getAdsInCache(serviceId)[0].data.seqNo == 2

    # Lower seqNo is rejected; the newer payload stays.
    registerResponse = await advertiserNode.sendRegister(
      registrarPeerId, serviceId, staleLowerSeqAd.encode().get()
    )
    check registerResponse.get().status == kad_protobuf.RegistrationStatus.Rejected
    check registrarNode.countAdsInCache(serviceId) == 1
    check registrarNode.getAdsInCache(serviceId)[0].data.seqNo == 2

  asyncTest "REGISTER with invalid-signature ticket is rejected":
    let conf =
      ServiceDiscoveryConfig.new(advertCacheCap = 10, registrationWindow = 5.secs)
    let registrarNode = setupServiceDiscoveryNode(discoConfig = conf)
    let maloryNode = setupServiceDiscoveryNode(discoConfig = conf)
    let legitimateNode = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[registrarNode, maloryNode, legitimateNode])
    await connect(registrarNode, maloryNode)
    await connect(registrarNode, legitimateNode)

    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let registrarPeerId = registrarNode.switch.peerInfo.peerId

    let maloryAdBytes = makeAdvertisement(
        serviceName, maloryNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()
    let legitimateAdBytes = makeAdvertisement(
        serviceName, legitimateNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()

    let oldTInit = getTime().toUnix() - 3600
    var invalidTicket = Ticket(
      advertisement: maloryAdBytes,
      tInit: oldTInit,
      tMod: getTime().toUnix(),
      tWaitFor: 0.secs,
      signature: Opt.none(seq[byte]),
    )
    check invalidTicket.sign(maloryNode.switch.peerInfo.privateKey)

    let maliciousResp = await maloryNode.sendRegister(
      registrarPeerId, serviceId, maloryAdBytes, Opt.some(invalidTicket)
    )
    check:
      maliciousResp.isOk()
      maliciousResp.get().status == kad_protobuf.RegistrationStatus.Rejected
      maliciousResp.get().ticket.isNone()
    check registrarNode.countAdsInCache(serviceId) == 0

    let maloryResp =
      await maloryNode.sendRegister(registrarPeerId, serviceId, maloryAdBytes)
    check maloryResp
    check maloryResp.get().status == kad_protobuf.RegistrationStatus.Confirmed

    let legitimateResp =
      await legitimateNode.sendRegister(registrarPeerId, serviceId, legitimateAdBytes)
    check legitimateResp
    check legitimateResp.get().status == kad_protobuf.RegistrationStatus.Wait

  asyncTest "self-registration refresh after Wait-Confirmed does not present a stale ticket":
    ## Regression: after Wait → Confirmed, `currentTicket` must be cleared. If the
    ## next refresh reuses that ticket past its eligibility window
    ## [tMod + tWaitFor, tMod + tWaitFor + registrationWindow], the registrar
    ## rejects it as "ticket outside valid time window" and the local task exits.
    let conf = ServiceDiscoveryConfig.new(
      # empty-cache wait ≈ advertExpiry * safetyParam = 2s → first REGISTER is Wait
      advertExpiry = 2.secs,
      safetyParam = 1.0,
      registrationWindow = 1.secs,
    )
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    startAndDeferStop(@[disco])

    let serviceName = "self-stale-ticket"
    let serviceId = serviceName.hashServiceId()
    check disco.rtManager.addService(
      serviceId, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
      Provided,
    )

    let adBytes =
      makeAdvertisement(serviceName, disco.switch.peerInfo.privateKey).encode().get()
    let selfPeer = disco.switch.peerInfo.peerId

    let fut = disco.advertiseToRegistrar(serviceId, selfPeer, Opt.none(Ticket), adBytes)

    let minTaskTime = conf.advertExpiry * 3
    # Timeline with this config:
    #   ~0s: Wait (tWaitFor ≈ 2s)
    #   ~2s: retry with ticket → Confirmed (ticket cleared)
    #   ~4s: sleep advertExpiry done; re-register with no ticket
    # Task must still be running after the refresh.
    check not (await fut.withTimeout(minTaskTime))

    await fut.cancelAndWait()
