# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021802-f38c5f/8.
# Spec, "Handling GET_ADS requests": "Registrars SHOULD respond to GET_ADS
# requests from discoverers with a GET_ADS response: 1. Include up to
# `F_return` advertisements from the `ad_cache` for the requested
# `service_id_hash`." The reply has to be one the discoverer can read: the
# protocol reads every message with a limit of ServiceDiscoveryMaxMsgSize.

import chronos, results
import
  ../../../libp2p/[
    crypto/crypto,
    extended_peer_record,
    multiaddress,
    peerid,
    protocols/service_discovery/connection,
    routing_record,
    signed_envelope,
    switch,
  ]
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/[lifecycle, unittest]
import ./utils

const AdsHeld = 5 # fewer than F_return (10)

proc makeLargeAdvertisement(serviceName: string): Advertisement =
  ## The largest ad of this shape that the registrar still admits on REGISTER
  ## (encoded size <= MaxXPRSize): a signed record listing many addresses.
  let privateKey = randomKey()
  var addrCount = 90
  while true:
    var addrs: seq[AddressInfo]
    for i in 0 ..< addrCount:
      let ip = "10.1." & $(i div 250) & "." & $(i mod 250 + 1)
      addrs.add(AddressInfo(address: makeMultiAddress(ip)))
    let record = ExtendedPeerRecord(
      peerId: PeerId.init(privateKey).get(),
      seqNo: 1,
      addresses: addrs,
      services: @[makeServiceInfo(serviceName)],
    )
    let ad = SignedExtendedPeerRecord.init(privateKey, record).get()
    if ad.encode().get().len <= MaxXPRSize:
      return ad
    dec addrCount

suite "Proof 20261123T021802-f38c5f/8 - GET_ADS reply fits the message size limit":
  teardown:
    checkTrackers()

  test "a reply built from admissible ads stays within ServiceDiscoveryMaxMsgSize":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "proof-8-service"
    let serviceId = serviceName.hashServiceId()
    check AdsHeld < disco.discoConfig.fReturn

    for i in 0 ..< AdsHeld:
      let ad = makeLargeAdvertisement(serviceName)
      let bytes = ad.encode().get()
      # The registrar accepts each of these on REGISTER.
      check bytes.len <= MaxXPRSize
      check isValidAdvertisement(
        kadprotobuf.RegisterMessage(advertisement: Opt.some(bytes)), serviceId
      )
      .isOk()
      disco.registrar.seedAd(serviceId, ad)

    let reply = disco.getAdvertisements(
      PeerId.random(),
      kadprotobuf.Message(msgType: kadprotobuf.MessageType.getAds, key: serviceId),
    )
    let size = reply.encode().len
    checkpoint "ads in reply = " & $reply.getAds.get().advertisements.len &
      ", encoded reply = " & $size & " bytes, limit = " & $ServiceDiscoveryMaxMsgSize
    check size <= ServiceDiscoveryMaxMsgSize

  asyncTest "a discoverer can read the GET_ADS reply of a registrar holding such ads":
    let registrarNode = setupServiceDiscoveryNode()
    let discovererNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceName = "proof-8-service"
    let serviceId = serviceName.hashServiceId()
    for i in 0 ..< AdsHeld:
      registrarNode.registrar.seedAd(serviceId, makeLargeAdvertisement(serviceName))

    let reply = await discovererNode.send(
      registrarNode.switch.peerInfo.peerId,
      kadprotobuf.Message(msgType: kadprotobuf.MessageType.getAds, key: serviceId),
    )
    if reply.isErr():
      checkpoint "GET_ADS failed: " & $reply.error
    check reply.isOk()
    let ads =
      reply.get(kadprotobuf.Message()).getAds.get(kadprotobuf.GetAdsMessage())
    check ads.advertisements.len > 0
