# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../libp2p/[protocols/kademlia, peerid]
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
