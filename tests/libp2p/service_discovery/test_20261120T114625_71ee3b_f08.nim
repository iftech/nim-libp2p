# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/8.
# Spec, GET_ADS Response: "getAds.advertisements | REQUIRED | List of encoded
# advertisements (up to F_return = 10)". Spec, Handling GET_ADS requests:
# "Include up to F_return advertisements from the ad_cache for the requested
# service_id_hash."

import chronos, results
import
  ../../../libp2p/[
    extended_peer_record, multiaddress, peerid,
    protocols/service_discovery/discoverer, switch,
  ]
import ../../tools/[lifecycle, unittest]
import ./utils

proc nodeAddresses(i: int): seq[MultiAddress] =
  ## A dual-stack node on TCP and QUIC that is also reachable through four
  ## circuit relays.
  let v4 = "/ip4/10.0." & $i & ".1"
  let v6 = "/ip6/2001:db8:0:" & $i & "::1"
  var addrs = @[
    MultiAddress.init(v4 & "/tcp/9000").get(),
    MultiAddress.init(v4 & "/udp/9000/quic-v1").get(),
    MultiAddress.init(v6 & "/tcp/9000").get(),
    MultiAddress.init(v6 & "/udp/9000/quic-v1").get(),
  ]
  for relay in 1 .. 4:
    addrs.add(
      MultiAddress
      .init(
        "/ip4/192.0.2." & $relay & "/tcp/4001/p2p/" & $PeerId.random() & "/p2p-circuit"
      )
      .get()
    )
  addrs

suite "Proof 20261120T114625-71ee3b/8 - GET_ADS reply with F_return ads":
  teardown:
    checkTrackers()

  asyncTest "a discoverer receives F_return valid ads from one registrar":
    let registrarNode = setupServiceDiscoveryNode()
    let discovererNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, discovererNode])
    await connect(registrarNode, discovererNode)

    let serviceName = "proof-f-return"
    let serviceId = serviceName.hashServiceId()
    let fReturn = registrarNode.discoConfig.fReturn

    var allAccepted = true
    var adSize = 0
    for i in 0 ..< fReturn:
      let ad = makeAdvertisement(serviceName, addrs = nodeAddresses(i))
      # Every ad is one this implementation accepts on REGISTER.
      adSize = ad.encode().get().len
      allAccepted = allAccepted and ad.isValid() and adSize <= MaxXPRSize
      registrarNode.registrar.seedAd(serviceId, ad)
    check allAccepted

    let reply = registrarNode.getAdvertisements(
      discovererNode.switch.peerInfo.peerId,
      Message(msgType: MessageType.getAds, key: serviceId),
    )
    check reply.getAds.get().advertisements.len == fReturn
    checkpoint "ad size: " & $adSize & " bytes (limit " & $MaxXPRSize &
      "), encoded GET_ADS reply: " & $reply.encode().len & " bytes, reader limit: " &
      $ServiceDiscoveryMaxMsgSize

    let found = await discovererNode.lookup(serviceId)
    check found.isOk()
    check found.get(@[]).len == fReturn
