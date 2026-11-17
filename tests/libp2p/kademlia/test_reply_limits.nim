# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import ../../../libp2p/[peerid, peerstore, multiaddress, protocols/kademlia]
import ../../../libp2p/protocols/kademlia/[find, types]
import ../../tools/[unittest, multiaddress]
import ./utils

suite "Kademlia reply resource limits":
  test "oversized replies retain bounded peers and addresses":
    let kad = setupKad()
    let target = PeerId.random().toKey()
    let state = LookupState.init(kad, target)
    var addrs: seq[MultiAddress]
    for i in 1 .. 1000:
      addrs.add(MultiAddress.init("/ip4/8.8.8.8/tcp/" & $i).get())
    var msg = Message()
    for i in 0 ..< 100:
      msg.closerPeers.add(Peer(id: Opt.some(PeerId.random().getBytes()), addrs: addrs))
    let peers = state.updateShortlist(msg)
    check peers.len <= MaxCloserPeers
    for peer in peers:
      check peer.addrs.len <= MaxPeerAddrs
      check peer.toPeer().addrs.len <= MaxPeerAddrs
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
