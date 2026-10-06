# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/[protocols/kademlia, peerid, switch]
import ../../tools/[lifecycle, unittest]
import ./[mock_kademlia, utils]

suite "KadDHT fixLowPeers":
  teardown:
    checkTrackers()

  asyncTest "healthy routing table is left alone":
    let kad = setupMockKad(testKadConfig(minRoutingTableSize = 5))
    startAndDeferStop(@[kad])

    kad.populateRoutingTable(10)
    kad.findNodeCalls = @[]
    await kad.fixLowPeers()

    check kad.findNodeCalls.len == 0

  asyncTest "low routing table forces a refresh":
    let kad = setupMockKad(testKadConfig(minRoutingTableSize = 5))
    startAndDeferStop(@[kad])

    kad.populateRoutingTable(2)
    let nonEmpty = kad.nonEmptyBuckets()
    kad.findNodeCalls = @[]
    await kad.fixLowPeers()

    # No bucket is stale, so only a forced refresh reaches them.
    check kad.findNodeCalls.len == nonEmpty.len + 1
    check kad.findNodeCalls[0] == kad.rtable.selfId

  asyncTest "bootstrap nodes are re-inserted after they are evicted":
    let bootstrap = setupMockKad()
    startAndDeferStop(@[bootstrap])
    let bootstrapId = bootstrap.switch.peerInfo.peerId

    let kad = setupMockKad(
      testKadConfig(minRoutingTableSize = 5),
      bootstrapNodes = @[(bootstrapId, bootstrap.switch.peerInfo.addrs)],
    )
    startAndDeferStop(@[kad])
    check kad.rtable.peerCount() == 1

    check kad.rtable.removePeer(bootstrapId)
    check kad.rtable.peerCount() == 0

    await kad.fixLowPeers()

    check kad.rtable.contains(bootstrapId.toKey())

  asyncTest "connected peers are admitted into the routing table":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    let (kad, peer) = (kads[0], kads[1])
    let peerId = peer.switch.peerInfo.peerId

    await kad.switch.connect(peerId, peer.switch.peerInfo.addrs)
    # Set explicitly rather than wait for identify to fill it in.
    kad.switch.peerStore[AddressBook][peerId] = peer.switch.peerInfo.addrs
    check kad.rtable.peerCount() == 0

    await kad.fixLowPeers()

    checkUntilTimeout:
      kad.rtable.contains(peerId.toKey())

  asyncTest "connected peers without a known address are skipped":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    let (kad, peer) = (kads[0], kads[1])
    let peerId = peer.switch.peerInfo.peerId

    await kad.switch.connect(peerId, peer.switch.peerInfo.addrs)
    discard kad.switch.peerStore[AddressBook].del(peerId)

    await kad.fixLowPeers()

    check:
      kad.switch.isConnected(peerId)
      not kad.rtable.contains(peerId.toKey())
      kad.admissionProbes.len == 0

  asyncTest "the loop re-seeds without an explicit call":
    let bootstrap = setupMockKad()
    startAndDeferStop(@[bootstrap])
    let bootstrapId = bootstrap.switch.peerInfo.peerId

    let kad = setupMockKad(
      testKadConfig(
        minRoutingTableSize = 5, fixLowPeersInterval = chronos.milliseconds(50)
      ),
      bootstrapNodes = @[(bootstrapId, bootstrap.switch.peerInfo.addrs)],
    )
    startAndDeferStop(@[kad])

    check kad.rtable.removePeer(bootstrapId)

    checkUntilTimeout:
      kad.rtable.contains(bootstrapId.toKey())
