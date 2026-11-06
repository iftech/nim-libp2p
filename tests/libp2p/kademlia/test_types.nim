# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/strformat
import ../../../libp2p/[protocols/kademlia, peerid]
import ./utils
import ../../tools/[unittest, crypto]

suite "KadDHT Types":
  teardown:
    checkTrackers()

  test "EntryRecord initializer accepts a Value":
    let
      value = Value.init([1.byte, 2, 3])
      time: Timestamp = "2026-01-01T00:00:00Z"
      record = EntryRecord.init(value, Opt.some(time))

    check:
      record.value == value
      record.time == time

  test "Key and Value are not interchangeable":
    check:
      compiles(
        block:
          discard EntryRecord.init(Value.init([1.byte]), Opt.none(Timestamp))
      )

    check:
      not compiles(
        block:
          discard EntryRecord.init(Key.init([1.byte]), Opt.none(Timestamp))
      )

    check:
      not compiles(
        block:
          discard xorDistance(Value.init([1.byte]), Key.init([1.byte]))
      )

  test "toPeerIds skips a peer without a valid id":
    let pid = PeerId.random()
    let peers = @[
      Peer(id: Opt.none(seq[byte])),
      Peer(id: Opt.some(@[0xFF'u8])),
      Peer(id: Opt.some(pid.getBytes())),
    ]

    check peers.toPeerIds() == @[pid]

  test "DefaultEntrySelector rejects an empty record list":
    check DefaultEntrySelector().select(Key.init([1.byte]), @[]).isErr()

  test "Value supports index assignment and shortLog":
    var value = Value.init([1.byte, 2, 3])
    value[0] = 0xAB

    check:
      value[0] == 0xAB
      value.shortLog() == "ab0203"

  test "RecordKey accepts 1..MaxRecordKeyLen bytes":
    check:
      RecordKey.fromBytes(@[1.byte]).isOk()
      RecordKey.fromBytes(newSeq[byte](MaxRecordKeyLen)).isOk()
      RecordKey.init(Key.init([1.byte])).isOk()

  test "RecordKey rejects an empty key and one over MaxRecordKeyLen":
    let
      empty = RecordKey.fromBytes(@[])
      long = RecordKey.fromBytes(newSeq[byte](MaxRecordKeyLen + 1))

    check:
      empty.isErr()
      empty.error == "invalid record key length (0 not in 1..256)"
      long.isErr()
      long.error == "invalid record key length (257 not in 1..256)"

  test "RecordKey supports equality, hash, len, toBytes, toKey, $ and shortLog":
    let
      key = RecordKey.fromBytes(@[0xAB.byte, 2, 3]).tryGet()
      same = RecordKey.fromBytes(@[0xAB.byte, 2, 3]).tryGet()
      other = RecordKey.fromBytes(@[0xAB.byte, 2, 4]).tryGet()

    check:
      key == same
      key != other
      key.hash() == same.hash()
      key.len() == 3
      key.toBytes() == @[0xAB.byte, 2, 3]
      key.toKey() == Key.fromBytes(@[0xAB.byte, 2, 3])
      $key == "@[171, 2, 3]"
      key.shortLog() == "ab0203"

  test "ProvidedKey holds the multihash of its CID":
    let
      cid = makeProvidedCid(1)
      key = ProvidedKey.init(cid)
      same = ProvidedKey.fromBytes(cid.toKey().toBytes()).tryGet()
      other = ProvidedKey.init(makeProvidedCid(2))

    check:
      key.toKey() == cid.toKey()
      key.toBytes() == cid.toKey().toBytes()
      key.len() == cid.toKey().len
      key == same
      key.hash() == same.hash()
      key != other
      (key < other) != (other < key)
      not (key < same)
      $key == $cid.toKey()

  test "ProvidedKey rejects bytes that are not a multihash":
    let
      valid = ProvidedKey.init(makeProvidedCid(1)).toBytes()
      res = ProvidedKey.fromBytes(@[0xAB.byte, 2, 3])

    check:
      res.isErr()
      res.error == "provided key is not a multihash (3 bytes: ab0203)"
    for bytes in [valid[0 ..< valid.high], valid & @[0.byte], valid[0 ..< 2], @[]]:
      checkpoint(bytes.shortLog)
      let res = ProvidedKey.fromBytes(bytes)
      check:
        res.isErr()
        res.error ==
          fmt"provided key is not a multihash ({bytes.len} bytes: {bytes.shortLog})"

  test "ProvidedKey is not interchangeable with Key or RecordKey":
    let
      provided = ProvidedKey.init(makeProvidedCid(1))
      record = RecordKey.init(provided.toKey()).get()

    check:
      compiles(provided == provided)
      not compiles(provided == record)
      not compiles(provided == provided.toKey())
      not compiles(
        block:
          let key: Key = provided
      )
      not compiles(
        block:
          discard default(ProvidedKey)
      )
      not compiles(
        block:
          discard ProvidedKey.init(provided.toKey())
      )
