# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils]
import ../../../libp2p/[extended_peer_record, multiaddress, peerid, peerinfo]
import ../../../libp2p/protocols/service_discovery/[connection, types]
import ../../tools/[unittest]
import ../kademlia/utils
import ./utils

proc typicalAddrs(): seq[MultiAddress] =
  (0 ..< MaxPeerAddrs).mapIt(
    MultiAddress.init("/dns4/registrar-node-" & $it & ".example.com/tcp/443/wss").get()
  )

proc longAddrs(): seq[MultiAddress] =
  let host = repeat('a', 63) & "." & repeat('b', 63) & "." & repeat('c', 63) & ".com"
  (0 ..< MaxPeerAddrs).mapIt(
    MultiAddress.init("/dns4/" & host & "/tcp/" & $(4000 + it) & "/wss").get()
  )

proc getAdsReply(count: int, addrs: seq[MultiAddress]): Message =
  Message(
    msgType: Opt.some(MessageType.getAds),
    getAds: Opt.some(
      GetAdsMessage(advertisements: newSeqWith(count, newSeq[byte](MaxXPRSize)))
    ),
    closerPeers:
      (0 ..< count).mapIt(Peer(id: Opt.some(PeerId.random().getBytes()), addrs: addrs)),
  )

suite "Service Discovery types":
  test "encode: empty seq encodes to empty result":
    let ads: seq[Advertisement] = @[]
    check ads.encode(10).len == 0

  test "encode: fReturn 0 encodes nothing":
    let ads = @[makeAdvertisement("svc")]
    check ads.encode(0).len == 0

  test "encode: single advertisement encodes and round-trips":
    let ad = makeAdvertisement("svc")
    let encoded = @[ad].encode(10)
    check encoded.len == 1
    let decoded = SignedExtendedPeerRecord.decode(encoded[0])
    check:
      decoded.isOk()
      decoded.get() == ad

  test "encode: all advertisements encoded when count is within fReturn":
    let ads = @[makeAdvertisement("a"), makeAdvertisement("b"), makeAdvertisement("c")]
    let encoded = ads.encode(10)
    check encoded.len == 3

  test "encode: fReturn cap limits output count":
    let ads = @[
      makeAdvertisement("a"),
      makeAdvertisement("b"),
      makeAdvertisement("c"),
      makeAdvertisement("d"),
    ]
    check ads.encode(2).len == 2

  test "encode: encoded advertisements decode back correctly":
    let origAds = @[makeAdvertisement("x"), makeAdvertisement("y")]
    let encoded = origAds.encode(10)
    check encoded.len == 2
    for i, bytes in encoded:
      let decoded = SignedExtendedPeerRecord.decode(bytes)
      check:
        decoded.isOk()
        decoded.get() == origAds[i]

  test "ExtEntryValidator accepts a record signed by the peer its key names":
    let ad = makeAdvertisement()
    let record = EntryRecord(value: ad.encode(), time: Timestamp.now())
    check ExtEntryValidator().isValid(ad.data.peerId, record)

  test "ExtEntryValidator rejects a record signed by another peer":
    let ad = makeAdvertisement()
    let record = EntryRecord(value: ad.encode(), time: Timestamp.now())
    check not ExtEntryValidator().isValid(PeerId.random(), record)

  test "ExtEntryValidator rejects a record with oversized service data":
    let ad = makeOversizedAdvertisement("svc")
    let record = EntryRecord(value: ad.encode(), time: Timestamp.now())
    check not ExtEntryValidator().isValid(ad.data.peerId, record)

  test "ExtEntrySelector rejects an empty record list":
    check ExtEntrySelector().select(PeerId.random(), @[]).isErr()

  test "ExtEntrySelector rejects records that do not decode":
    let records = @[
      EntryRecord(value: @[1'u8, 2, 3], time: Timestamp.now()),
      EntryRecord(value: @[], time: Timestamp.now()),
    ]
    check ExtEntrySelector().select(PeerId.random(), records).isErr()

  test "ExtEntrySelector skips undecodable records and picks the highest seqNo":
    let privateKey = randomKey()
    let key = PeerId.init(privateKey).get()
    let records = @[
      EntryRecord(value: @[1'u8, 2, 3], time: Timestamp.now()),
      EntryRecord(
        value: makeAdvertisement(privateKey = privateKey, seqNo = 1).encode(),
        time: Timestamp.now(),
      ),
      EntryRecord(
        value: makeAdvertisement(privateKey = privateKey, seqNo = 5).encode(),
        time: Timestamp.now(),
      ),
    ]
    check ExtEntrySelector().select(key, records).get() == 2

  test "toPeerInfos drops peers without an id or with an undecodable id":
    let peerId = PeerId.random()
    let addrs = @[MultiAddress.init("/ip4/10.0.0.1/tcp/4001").get()]
    let peers = @[
      Peer(id: Opt.none(seq[byte]), addrs: addrs),
      Peer(id: Opt.some(@[1'u8, 2, 3]), addrs: addrs),
      Peer(id: Opt.some(peerId.getBytes()), addrs: addrs),
    ]

    let infos = peers.toPeerInfos()

    check:
      infos.len == 1
      infos[0].peerId == peerId
      infos[0].addrs == addrs

  test "a GET_ADS reply of MaxFReturn max-size ads and closer peers fits the read limit":
    var response = getAdsReply(MaxFReturn, typicalAddrs())
    let closerPeers = response.closerPeers

    check:
      response.encodeWithinReadLimit().len <= ServiceDiscoveryMaxMsgSize
      response.closerPeers == closerPeers

  test "encodeWithinReadLimit drops the farthest closer peers of an oversized reply":
    var response = getAdsReply(MaxFReturn, longAddrs())
    let closerPeers = response.closerPeers
    check response.encode().len > ServiceDiscoveryMaxMsgSize

    let bytes = response.encodeWithinReadLimit()

    check:
      bytes.len <= ServiceDiscoveryMaxMsgSize
      response.closerPeers.len in 1 ..< closerPeers.len
      response.closerPeers == closerPeers[0 ..< response.closerPeers.len]
