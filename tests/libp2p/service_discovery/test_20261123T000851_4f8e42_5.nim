# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results
import
  ../../../libp2p/[
    extended_peer_record,
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

suite "Proof 20261123T000851-4f8e42/5 - unrelated service data is opaque":
  teardown:
    checkTrackers()

  asyncTest "lookup accepts a signed ad with unrelated service metadata":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "requested-service"
    let serviceId = serviceName.hashServiceId()
    let control = makeAdvertisement(serviceName)
    let key = randomKey()
    var record = makeAdvertisement(serviceName, key).data
    record.services.add(
      ServiceInfo(id: "other-service", data: Opt.some(newSeq[byte](MaxServiceDataSize + 1)))
    )
    let ad = SignedExtendedPeerRecord.init(key, record).get()
    let encoded = ad.encode()
    require encoded.len <= MaxXPRSize
    require Advertisement.decode(encoded).isOk()
    require ad.advertisesService(serviceId)

    let reply = kad_protobuf.Message(
      msgType: Opt.some(kad_protobuf.MessageType.getAds),
      getAds: Opt.some(GetAdsMessage(advertisements: @[control.encode(), encoded])),
    )
    let stream = FaultStream.new(reply = lengthPrefixed(reply.encode()))
    defer:
      await stream.close()
    discard disco.addRegistrar(serviceName, stream)

    let found = (await disco.lookup(serviceId)).get()
    check:
      control in found
      ad in found
