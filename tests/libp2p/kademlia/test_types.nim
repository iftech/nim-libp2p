# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

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
    let pid = randomPeerId()
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
