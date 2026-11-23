# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

# Proof for finding 20261123T002054-cd9688/3.
#
# logos-service-discovery.md, "GET_ADS Response":
#
#   | `getAds.advertisements` | REQUIRED | List of encoded advertisements
#   (up to `F_return` = 10) |
#
# A GET_ADS response carrying F_return valid advertisements is a response the
# protocol defines, so a discoverer has to be able to read it.

import std/sequtils
import chronos, results
import
  ../../../libp2p/[
    crypto/crypto,
    extended_peer_record,
    multiaddress,
    peerid,
    protocols/kademlia/types,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/types,
    switch,
  ]
import ../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../tools/[lifecycle, unittest, multiaddress]
import ./utils

const ServiceName = "/waku/store/1.0.0"

proc makeMultiAddrAdvertisement(idx: int): Advertisement =
  ## A valid advertisement of a node reachable over several named endpoints.
  let privateKey = randomKey()
  var addrs: seq[MultiAddress]
  for i in 0 ..< 8:
    addrs.add(
      ma("/dns4/node-" & $idx & "-" & $i & ".fleet.example.logos.co/tcp/443/wss")
    )
  let record = ExtendedPeerRecord.init(
    PeerId.init(privateKey).get(), addrs, 1, @[ServiceInfo(id: ServiceName)]
  )
  # `build` enforces the implementation's own ad limits (MaxXPRSize).
  SignedExtendedPeerRecord.build(privateKey, record).get()

suite "Spec proof 20261123T002054-cd9688/3 - GET_ADS response of F_return ads":
  teardown:
    checkTrackers()

  test "a GET_ADS response of F_return valid ads fits the reader's limit":
    let registrarNode = setupServiceDiscoveryNode()
    let serviceId = ServiceName.hashServiceId()
    let fReturn = registrarNode.discoConfig.fReturn
    check fReturn == 10

    let ads = (0 ..< fReturn).mapIt(makeMultiAddrAdvertisement(it))
    for ad in ads:
      check ad.isValid()
      check ad.encode().get().len <= MaxXPRSize
    registrarNode.registrar.seedAds(serviceId, ads)

    let request =
      Message(msgType: Opt.some(MessageType.getAds), key: Opt.some(serviceId))
    let response = registrarNode.getAdvertisements(PeerId.random(), request)
    check response.getAds.get().advertisements.len == fReturn

    # connection.nim reads every reply with readLp(ServiceDiscoveryMaxMsgSize).
    check response.encode().len <= ServiceDiscoveryMaxMsgSize

  asyncTest "a discoverer receives the F_return ads a registrar holds":
    let registrarNode = setupServiceDiscoveryNode()
    let discovererNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceId = ServiceName.hashServiceId()
    let fReturn = registrarNode.discoConfig.fReturn
    let ads = (0 ..< fReturn).mapIt(makeMultiAddrAdvertisement(it))
    registrarNode.registrar.seedAds(serviceId, ads)
    check registrarNode.countAdsInCache(serviceId) == fReturn

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()
    check found.get().len == fReturn
