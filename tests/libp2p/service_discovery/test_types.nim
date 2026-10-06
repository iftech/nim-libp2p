# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../libp2p/[extended_peer_record, multiaddress, peerid, peerinfo]
import ../../../libp2p/protocols/service_discovery/types
import ../../tools/[unittest]
import ../kademlia/utils
import ./utils

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
    check ExtEntryValidator().isValid(ad.data.peerId.toKey(), record)

  test "ExtEntryValidator rejects a record signed by another peer":
    let ad = makeAdvertisement()
    let record = EntryRecord(value: ad.encode(), time: Timestamp.now())
    check not ExtEntryValidator().isValid(randomPeerId().toKey(), record)

  test "ExtEntryValidator rejects a record with oversized service data":
    let ad = makeOversizedAdvertisement("svc")
    let record = EntryRecord(value: ad.encode(), time: Timestamp.now())
    check not ExtEntryValidator().isValid(ad.data.peerId.toKey(), record)

  test "ExtEntrySelector rejects an empty record list":
    check ExtEntrySelector().select(randomPeerId().toKey(), @[]).isErr()

  test "ExtEntrySelector rejects records that do not decode":
    let records = @[
      EntryRecord(value: @[1'u8, 2, 3], time: Timestamp.now()),
      EntryRecord(value: @[], time: Timestamp.now()),
    ]
    check ExtEntrySelector().select(randomPeerId().toKey(), records).isErr()

  test "ExtEntrySelector skips undecodable records and picks the highest seqNo":
    let privateKey = randomKey()
    let key = PeerId.init(privateKey).get().toKey()
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
    let peerId = randomPeerId()
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
