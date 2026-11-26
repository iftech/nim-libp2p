# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, tables]
import results
import ../../../libp2p/[protocols/kademlia, switch, peerid, peerstore]
import ../../tools/[unittest, multiaddress]
import ./utils.nim

proc peerIdInBucket(kad: KadDHT, bucket: int): PeerId =
  ## A draw lands in `bucket` with probability ~2^-(bucket+1), so keep drawing.
  for _ in 0 ..< 1000:
    let peerId = PeerId.random()
    if kad.rtable.bucketIndex(peerId.toKey()) == bucket:
      return peerId
  raiseAssert "no random peer id landed in bucket " & $bucket

proc kadWithBucketSubnetCap(cap: int): KadDHT =
  var limits = KadDHTLimits.new(DefaultReplication, DefaultQuorum)
  limits.maxPeersPerIpv4SubnetPerBucket = cap
  setupKad(KadDHTConfig.new(limits = Opt.some(limits)))

suite "KadDHT IP diversity":
  teardown:
    checkTrackers()

  test "updatePeers enforces per-bucket IP diversity limits":
    let kad = kadWithBucketSubnetCap(1)
    let
      firstOfBucket0 = kad.peerIdInBucket(0)
      secondOfBucket0 = kad.peerIdInBucket(0)
      firstOfBucket1 = kad.peerIdInBucket(1)

    kad.updatePeers(
      @[
        PeerInfo(peerId: firstOfBucket0, addrs: @[ma("/ip4/8.8.8.1/tcp/4001")]),
        PeerInfo(peerId: secondOfBucket0, addrs: @[ma("/ip4/8.8.8.2/tcp/4001")]),
        PeerInfo(peerId: firstOfBucket1, addrs: @[ma("/ip4/8.8.8.3/tcp/4001")]),
      ]
    )

    # The table-wide /24 cap (10) leaves room; only the bucket cap rejects.
    let keys = kad.rtable.allKeys()
    check:
      firstOfBucket0.toKey() in keys
      secondOfBucket0.toKey() notin keys
      firstOfBucket1.toKey() in keys

  test "per-bucket IP diversity limits count in-flight admission probes":
    let kad = kadWithBucketSubnetCap(1)
    let
      probed = kad.peerIdInBucket(0)
      sameBucket = kad.peerIdInBucket(0)
      otherBucket = kad.peerIdInBucket(1)
      addressBook = kad.switch.peerStore[AddressBook]
      caps = kad.config.limits.diversityCaps()

    addressBook.extend(probed, @[ma("/ip4/8.8.8.1/tcp/4001")], AddressConfidence.Low)

    # `probed` is still absent from the table: only the pending list holds its slot.
    check:
      not addressBook.hasIpDiversity(
        kad.rtable, sameBucket, @[ma("/ip4/8.8.8.2/tcp/4001")], caps, @[probed]
      )
      addressBook.hasIpDiversity(
        kad.rtable, otherBucket, @[ma("/ip4/8.8.8.3/tcp/4001")], caps, @[probed]
      )

  test "a probe that already joined the table counts once":
    let kad = kadWithBucketSubnetCap(2)
    let
      probed = kad.peerIdInBucket(0)
      candidate = kad.peerIdInBucket(0)
      addressBook = kad.switch.peerStore[AddressBook]
      caps = kad.config.limits.diversityCaps()

    kad.updatePeers(@[PeerInfo(peerId: probed, addrs: @[ma("/ip4/8.8.8.1/tcp/4001")])])

    # `probed` sits in the table and in the pending list: it holds one slot of two.
    check:
      probed.toKey() in kad.rtable.allKeys()
      addressBook.hasIpDiversity(
        kad.rtable, candidate, @[ma("/ip4/8.8.8.2/tcp/4001")], caps, @[probed]
      )

  test "updateShortlist refuses a peer the IP diversity cap would not admit":
    ## Admission is what records the addresses, so such a peer never gets dialed.
    let kad = kadWithBucketSubnetCap(1)
    let
      admitted = kad.peerIdInBucket(0)
      refused = kad.peerIdInBucket(0)

    kad.updatePeers(
      @[PeerInfo(peerId: admitted, addrs: @[ma("/ip4/8.8.8.1/tcp/4001")])]
    )

    let state = LookupState.init(kad, PeerId.random().toKey())
    state.shortlist.clear()

    let added = state.updateShortlist(
      Message(
        msgType: MessageType.findNode,
        closerPeers: @[Peer(id: refused.toKey(), addrs: @[ma("/ip4/8.8.8.2/tcp/4001")])],
      )
    )

    check:
      added.len == 0
      refused notin state.shortlist

  test "an unset per-bucket cap leaves the table-wide cap in charge":
    let kad = kadWithBucketSubnetCap(0)
    let peers = (1 .. 3).mapIt(
      PeerInfo(
        peerId: kad.peerIdInBucket(0), addrs: @[ma("/ip4/8.8.8." & $it & "/tcp/4001")]
      )
    )

    kad.updatePeers(peers)

    let keys = kad.rtable.allKeys()
    check peers.allIt(it.peerId.toKey() in keys)

  test "updatePeers enforces the per-bucket IPv6 /64 limit":
    var limits = KadDHTLimits.new(DefaultReplication, DefaultQuorum)
    limits.maxPeersPerIpv6SubnetPerBucket = 1
    let kad = setupKad(KadDHTConfig.new(limits = Opt.some(limits)))
    let
      first = kad.peerIdInBucket(0)
      sameSubnet = kad.peerIdInBucket(0)
      otherSubnet = kad.peerIdInBucket(0)

    kad.updatePeers(
      @[
        PeerInfo(peerId: first, addrs: @[ma("/ip6/2600::1/tcp/4001")]),
        PeerInfo(peerId: sameSubnet, addrs: @[ma("/ip6/2600::2/tcp/4001")]),
        PeerInfo(peerId: otherSubnet, addrs: @[ma("/ip6/2600:0:0:1::1/tcp/4001")]),
      ]
    )

    let keys = kad.rtable.allKeys()
    check:
      first.toKey() in keys
      sameSubnet.toKey() notin keys
      otherSubnet.toKey() in keys
