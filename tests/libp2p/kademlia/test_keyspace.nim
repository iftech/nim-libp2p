# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sets
import chronos, results
import ../../../libp2p/[peerid, protocols/kademlia, crypto/crypto]
import ../../tools/[unittest, crypto]

# The no-op hasher makes a key its own hash, so a test picks its bits directly.
let NoHash = Opt.some(noOpHasher)
# Opt.none picks the default sha256 hasher, the one a running node uses.
let DefaultHash = Opt.none(XorDHasher)

proc regionPrefixNoHash(key: Key, bits: int): RegionPrefix =
  RegionPrefix.init(key, bits, NoHash)

proc makeKeyInBucket(bucket: int, tag: byte): Key =
  ## Key landing in `bucket` of an all-zero selfId table. `tag` keeps keys apart.
  var buf: array[IdLength, byte]
  buf[bucket div 8] = 0x80'u8 shr (bucket mod 8)
  buf[IdLength - 1] = tag
  Key.fromBytes(@buf)

proc makeEmptyTable(replication: int): RoutingTable =
  RoutingTable.new(
    Key.init([0'u8]),
    RoutingTableConfig.new(
      replication = replication, hasher = NoHash, selfIdPreHashed = true
    ),
  )

proc fillBucket(rtable: RoutingTable, bucket: int, count: int) =
  for i in 0 ..< count:
    doAssert rtable.insert(makeKeyInBucket(bucket, i.byte))

suite "KadDHT Keyspace Regions":
  test "region prefix keeps the leading bits and clears the rest":
    let key = Key.init([0b1011_0110'u8, 0b1111_0000])
    check:
      key.regionPrefixNoHash(0) == newSeq[byte](0)
      key.regionPrefixNoHash(1) == @[0b1000_0000'u8]
      key.regionPrefixNoHash(4) == @[0b1011_0000'u8]
      key.regionPrefixNoHash(8) == @[0b1011_0110'u8]
      key.regionPrefixNoHash(12) == @[0b1011_0110'u8, 0b1111_0000]

  test "region prefix is clamped to the hash length":
    check Key.init([0xFF'u8]).regionPrefixNoHash(MaxRegionBits + 8).len == IdLength

  test "keys share a region exactly when their leading bits match":
    let
      a = Key.init([0b1010_0000'u8])
      b = Key.init([0b1011_0000'u8])
    check:
      a.regionPrefixNoHash(3) == b.regionPrefixNoHash(3)
      a.regionPrefixNoHash(4) != b.regionPrefixNoHash(4)

  test "zero bits groups every key into one region":
    let keys = @[Key.init([0x00'u8]), Key.init([0x80'u8]), Key.init([0xFF'u8])]
    check keys.keyspaceRegions(0, NoHash) == @[keys]

  test "regions partition the keys by prefix":
    let
      zeroPrefix = @[Key.init([0x00'u8]), Key.init([0x01'u8])]
      onePrefix = @[Key.init([0x80'u8]), Key.init([0xC0'u8]), Key.init([0xFF'u8])]
    check (zeroPrefix & onePrefix).keyspaceRegions(1, NoHash) == @[
      zeroPrefix, onePrefix
    ]

  test "an empty key set yields no regions":
    check newSeq[Key]().keyspaceRegions(4, NoHash).len == 0

  test "region bits are unknown while no bucket is full":
    let rtable = makeEmptyTable(4)
    check rtable.regionBits().isNone()

    rtable.fillBucket(2, 3)
    check rtable.regionBits().isNone()

  test "region bits follow the deepest full bucket":
    let rtable = makeEmptyTable(4)

    rtable.fillBucket(2, 4)
    check rtable.regionBits() == 3

    rtable.fillBucket(5, 4)
    check rtable.regionBits() == 6

    # A deeper bucket that is not full carries no evidence of network size.
    rtable.fillBucket(7, 3)
    check rtable.regionBits() == 6

  test "closestFirst orders peers by distance to the key":
    let key = PeerId.random().toKey()
    let peers = PeerId.random(8)

    let ordered = peers.closestFirst(key, DefaultHash)
    check:
      ordered.len == peers.len
      ordered.toHashSet() == peers.toHashSet()

    for i in 1 ..< ordered.len:
      check xorDistance(ordered[i - 1], key, DefaultHash) <=
        xorDistance(ordered[i], key, DefaultHash)
