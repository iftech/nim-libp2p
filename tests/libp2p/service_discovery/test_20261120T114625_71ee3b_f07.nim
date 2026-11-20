# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/7.
# Spec, Distributing ads across registrars: "If the status is Rejected, the
# advertiser MUST remove the registrar from the ongoing registrations for that
# bucket and SHOULD NOT attempt further registrations with this registrar for
# this advertisement."

import std/sequtils
import chronos, results, sets
import
  ../../../libp2p/
    [extended_peer_record, peerid, protocols/service_discovery/advertiser, switch]
import ../../tools/[lifecycle, unittest]
import ./utils

suite "Proof 20261120T114625-71ee3b/7 - no retry at a rejecting registrar":
  teardown:
    checkTrackers()

  asyncTest "a registrar that rejected the advertisement is not asked again":
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)
    defer:
      await advertiserNode.stopRegistrations()

    let service = makeServiceInfo("proof-rejected-registrar")
    let serviceId = service.id.hashServiceId()
    let registrarId = registrarNode.switch.peerInfo.peerId
    let key = advertiserNode.switch.peerInfo.privateKey

    # The registrar already caches a newer record of this advertiser, so it
    # answers the older one below with Rejected.
    registrarNode.registrar.seedAd(
      serviceId, makeAdvertisement(service.id, key, seqNo = 100)
    )
    let advert = makeAdvertisement(service.id, key, seqNo = 1).encode().get()

    let direct = await advertiserNode.sendRegister(registrarId, serviceId, advert)
    require direct.isOk()
    require direct.get().status == RegistrationStatus.Rejected

    # Advertising schedules a registration with the only registrar in the table.
    require advertiserNode.startAdvertising(service, Opt.some(advert)).isOk()
    let first = toSeq(advertiserNode.advertiser.running)
    require first.len == 1
    require first[0].registrar == registrarId
    require await first[0].fut.withTimeout(5.seconds) # ends on the Rejected reply

    # The next maintenance round must leave the rejecting registrar alone.
    await advertiserNode.maintainRegistrations()

    check not toSeq(advertiserNode.advertiser.running).anyIt(
      it.registrar == registrarId and it.serviceId == serviceId
    )
