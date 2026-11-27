# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/importutils
import std/sequtils
import chronos
import ../../../libp2p/[peerid, peerinfo, peerstore, multiaddress, protocols/kademlia]
import ../../../libp2p/protocols/kademlia/[find, types]
import ../../tools/[unittest, multiaddress]
import ./utils

privateAccess(LookupState)

suite "Kademlia reply resource limits":
  teardown:
    checkTrackers()

  test "oversized replies retain bounded peers and addresses":
    let kad = setupKad()
    let excluded = PeerId.random()
    let state = LookupState.init(kad, excluded.toKey())
    var addrs: seq[MultiAddress]
    for i in 1 .. 1000:
      addrs.add(MultiAddress.init("/ip4/8.8.8.8/tcp/" & $i).get())
    var msg = Message()
    for i in 0 ..< MaxCloserPeers:
      var peerAddrs = addrs
      peerAddrs[0] = ma("/ip4/8.8." & $i & ".1/tcp/1")
      msg.closerPeers.add(
        Peer(id: Opt.some(PeerId.random().getBytes()), addrs: peerAddrs)
      )
    msg.closerPeers.add(Peer(id: Opt.some(excluded.getBytes()), addrs: addrs))
    let peers = state.updateShortlist(msg)
    check peers.len == MaxCloserPeers
    check excluded notin state.shortlist
    for i, peer in peers:
      check peer.addrs == msg.closerPeers[i].addrs[0 ..< MaxPeerAddrs]
    let pid = PeerId.random()
    let book = kad.switch.peerStore[AddressBook]
    book.extend(pid, addrs)
    book.extend(pid, addrs[100 .. ^1])
    check book[pid].len <= MaxAddressesPerPeer
    let connected = MultiAddress.init("/ip4/1.1.1.1/tcp/1").get()
    book.markConnected(pid, connected)
    check connected in book[pid]
    check book[pid].len <= MaxAddressesPerPeer
    book[pid] = addrs
    check book[pid].len <= MaxAddressesPerPeer

  test "reply intake scales with configured replication":
    let kad = setupKad(testKadConfig(replication = 50))
    let excluded = PeerId.random()
    let state = LookupState.init(kad, excluded.toKey())
    var msg = Message()
    for i in 0 ..< 100:
      msg.closerPeers.add(
        Peer(
          id: Opt.some(PeerId.random().getBytes()),
          addrs: @[ma("/ip4/127.0.0.1/tcp/" & $(i + 1))],
        )
      )
    msg.closerPeers.add(
      Peer(id: Opt.some(excluded.getBytes()), addrs: @[ma("/ip4/127.0.0.1/tcp/101")])
    )
    check state.updateShortlist(msg).len == 100
    check state.shortlist.len == 100
    check excluded notin state.shortlist

  test "outgoing replies prefer live verified addresses":
    let kad = setupKad()
    let pid = PeerId.random()
    let book = kad.switch.peerStore[AddressBook]
    let addrs = (1 .. MaxPeerAddrs).toSeq().mapIt(ma("/ip4/8.8.8.8/tcp/" & $it))
    book.set(pid, addrs)
    let verified = ma("/ip4/1.1.1.1/tcp/1")
    let infinite = ma("/ip4/1.1.1.1/tcp/2")
    let expired = ma("/ip4/1.1.1.1/tcp/3")
    book.markConnected(pid, verified)
    book.extend(pid, @[infinite], AddressConfidence.Infinite)
    book.extend(pid, @[expired], AddressConfidence.High)
    book.book[pid][^1].lastUpdated = Moment.now() - 25.hours
    let reply = pid.toKey().toPeer(kad.switch).get()
    check reply.addrs.len == MaxPeerAddrs
    check reply.addrs[0 .. 1] == @[infinite, verified]
    check expired notin reply.addrs

  test "admission filters undialable addresses before limiting stored addresses":
    let kad = setupKad()
    let pid = PeerId.random()
    let direct = ma("/ip4/8.8.8.8/tcp/1")
    let addrs = repeat(ma("/ip4/0.0.0.0/tcp/1"), MaxPeerAddrs) & @[direct]
    kad.updatePeers(@[PeerInfo(peerId: pid, addrs: addrs)])
    check kad.switch.peerStore[AddressBook][pid] == @[direct]
    check pid.toKey() in kad.rtable.allKeys()
