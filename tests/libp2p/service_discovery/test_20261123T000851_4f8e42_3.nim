# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for audit finding 20261123T000851-4f8e42/3.
# Spec, GET_ADS Response: `type` REQUIRED `GET_ADS` (7); Error Handling:
# missing required fields / invalid message -> close stream (nothing accepted).

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

proc lookupWithReply(msgType: Opt[kad_protobuf.MessageType]): Future[int] {.async.} =
  ## Number of ads a lookup accepts from a registrar whose response carries a
  ## valid advertisement under the given message type.
  let disco = setupServiceDiscoveryNode()
  let serviceName = "typed-reply"
  let serviceId = serviceName.hashServiceId()
  let ad = makeAdvertisement(serviceName, randomKey(), seqNo = 1)
  let reply = kad_protobuf.Message(
    msgType: msgType, getAds: Opt.some(GetAdsMessage(advertisements: @[ad.encode()]))
  )
  let stream = FaultStream.new(reply = lengthPrefixed(reply.encode()))
  defer:
    await stream.close()
  discard disco.addRegistrar(serviceName, stream)
  return (await disco.lookup(serviceId)).get().len

suite "Proof 20261123T000851-4f8e42/3 - GET_ADS response type is checked":
  teardown:
    checkTrackers()

  asyncTest "control: a response typed GET_ADS is accepted":
    check (await lookupWithReply(Opt.some(kad_protobuf.MessageType.getAds))) == 1

  asyncTest "a response typed REGISTER is not accepted as a GET_ADS response":
    check (await lookupWithReply(Opt.some(kad_protobuf.MessageType.register))) == 0

  asyncTest "a response without the required type is not accepted":
    check (await lookupWithReply(Opt.none(kad_protobuf.MessageType))) == 0
