# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for audit finding 20261123T000851-4f8e42/1.
# Spec, Looking up services: the discoverer SHOULD keep track of unique
# `foundPeers`, terminating once `F_lookup` advertisers have been found.

import std/[sets, sequtils]
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

suite "Proof 20261123T000851-4f8e42/1 - F_lookup counts unique advertisers":
  teardown:
    checkTrackers()

  asyncTest "two adverts of one advertiser do not fill F_lookup":
    let fLookup = 2
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(fLookup = fLookup)
    )
    let serviceName = "unique-advertisers"
    let serviceId = serviceName.hashServiceId()

    # Advertiser A re-signed its advert (newer seqNo). The local registrar cache
    # still serves the older one, the remote registrar serves the newer one.
    let keyA = randomKey()
    let oldAdA = makeAdvertisement(serviceName, keyA, seqNo = 1)
    let newAdA = makeAdvertisement(serviceName, keyA, seqNo = 2)
    let adB = makeAdvertisement(serviceName, randomKey(), seqNo = 1)
    disco.registrar.seedAd(serviceId, oldAdA)

    let reply = kad_protobuf.Message(
      msgType: Opt.some(kad_protobuf.MessageType.getAds),
      getAds:
        Opt.some(GetAdsMessage(advertisements: @[newAdA.encode(), adB.encode()])),
    )
    let stream = FaultStream.new(reply = lengthPrefixed(reply.encode()))
    defer:
      await stream.close()
    discard disco.addRegistrar(serviceName, stream)

    let found = (await disco.lookup(serviceId)).get()
    let advertisers = found.mapIt(it.data.peerId).toHashSet()

    check:
      # two distinct advertisers (A and B) were offered and F_lookup is 2
      advertisers.len == fLookup
      found.len == advertisers.len
