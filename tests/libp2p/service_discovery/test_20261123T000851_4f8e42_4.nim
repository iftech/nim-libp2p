# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for audit finding 20261123T000851-4f8e42/4.
# Spec, GET_ADS Response: `getAds.advertisements` holds up to `F_return`;
# System Parameters: F_return = max number of service-specific peers returned
# from a single registrar.

import chronos, results
import
  ../../../libp2p/[
    multiaddress,
    peerid,
    protocols/kademlia,
    protocols/service_discovery,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/types,
    stream/connection,
    switch,
  ]
import ../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../tools/[fault_stream, unittest]
import ./utils

proc lengthPrefixed(payload: seq[byte]): seq[byte] =
  var prefixed: seq[byte]
  var n = payload.len
  while n >= 0x80:
    prefixed.add(byte(n and 0x7f) or 0x80'u8)
    n = n shr 7
  prefixed.add(byte(n))
  prefixed.add(payload)
  prefixed

proc addRegistrar(
    disco: ServiceDiscovery, serviceName: string, stream: FaultStream
): PeerId =
  ## One registrar in DiscT(service); every dial to it is answered by `stream`.
  doAssert disco.registerInterest(serviceName)
  let table = disco.rtManager.getTable(serviceName.hashServiceId()).get()
  let registrar = PeerId.random()
  doAssert table.insert(registrar)
  disco.switch.peerStore[AddressBook][registrar] = @[makeMultiAddress("127.0.0.1")]
  disco.switch = FaultSwitch.new(disco.switch, stream)
  registrar

suite "Proof 20261123T000851-4f8e42/4 - one registrar yields at most F_return ads":
  teardown:
    checkTrackers()

  asyncTest "a response with more than F_return ads is capped":
    let fReturn = 3
    let offered = fReturn * 4
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(fReturn = fReturn)
    )
    let serviceName = "oversupplied"
    let serviceId = serviceName.hashServiceId()

    var ads: seq[seq[byte]]
    for _ in 0 ..< offered:
      ads.add(makeAdvertisement(serviceName, randomKey(), seqNo = 1).encode())
    let reply = kad_protobuf.Message(
      msgType: Opt.some(kad_protobuf.MessageType.getAds),
      getAds: Opt.some(GetAdsMessage(advertisements: ads)),
    )
    let encoded = lengthPrefixed(reply.encode())
    let stream = FaultStream.new(reply = encoded)
    defer:
      await stream.close()
    discard disco.addRegistrar(serviceName, stream)

    let found = (await disco.lookup(serviceId)).get()

    check:
      encoded.len < ServiceDiscoveryMaxMsgSize
      disco.discoConfig.fLookup > offered
      # a single registrar contributed every advertisement of this lookup
      found.len <= fReturn
