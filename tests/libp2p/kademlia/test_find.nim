# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, sequtils, tables
import ../../../libp2p/[protocols/kademlia, switch, builders]
import ../../../libp2p/protocols/kademlia/[find, types]
import ../../tools/[lifecycle, topology, unittest, multiaddress]
import ./utils.nim

suite "KadDHT Find":
  teardown:
    checkTrackers()

  asyncTest "Simple find node":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    # Connect nodes: kads[0] <-> kads[1], kad0 <-> kads[2]
    await connectHub(kads[0], kads[1 ..^ 1])

    # kads[1] doesn't know kads[2] yet
    check not kads[1].hasKey(kads[2].rtable.selfId)

    discard await kads[1].findNode(kads[2].rtable.selfId)

    # After findNode, kads[1] discovers kads[2] through kad[0]
    checkUntilTimeout:
      kads[1].hasKey(kads[2].rtable.selfId)

  asyncTest "Relay find node":
    let kads = setupKadSwitches(4)
    startAndDeferStop(kads)

    # Setup: kads[0] <-> kads[1], kads[0] <-> kads[2], kads[2] <-> kads[3]
    await connect(kads[0], kads[1])
    await connect(kads[0], kads[2])
    await connect(kads[2], kads[3])

    check:
      kads[0].hasKeys(@[kads[1].rtable.selfId, kads[2].rtable.selfId])
      kads[2].hasKey(kads[3].rtable.selfId)
      # kads[1] doesn't know kads[2], kads[3] yet
      kads[1].hasNoKeys(@[kads[2].rtable.selfId, kads[3].rtable.selfId])

    discard await kads[1].findNode(kads[3].rtable.selfId)

    # kads[1] discovers kads[2] and kads[3] through relay
    checkUntilTimeout:
      kads[1].hasKeys(@[kads[2].rtable.selfId, kads[3].rtable.selfId])

  asyncTest "Find node accumulates peers from multiple responses":
    let kads = setupKadSwitches(4)
    startAndDeferStop(kads)

    # Connect nodes in a chain: kads[0] <-> kads[1] <-> kads[2] <-> kads[3]
    await connectChain(kads)

    # Verify initial state: each node only knows its neighbors
    check:
      kads[0].hasKey(kads[1].rtable.selfId)
      kads[0].hasNoKeys(@[kads[2].rtable.selfId, kads[3].rtable.selfId])

      kads[1].hasKeys(@[kads[0].rtable.selfId, kads[2].rtable.selfId])
      not kads[1].hasKey(kads[3].rtable.selfId)

      kads[2].hasKeys(@[kads[1].rtable.selfId, kads[3].rtable.selfId])
      not kads[2].hasKey(kads[0].rtable.selfId)

      kads[3].hasKey(kads[2].rtable.selfId)
      kads[3].hasNoKeys(@[kads[0].rtable.selfId, kads[1].rtable.selfId])

    # kads[0] performs lookup for kads[3]
    # Round 1: kads[0] -> kads[1], learns kads[2]
    # Round 2: kads[0] -> kads[2], learns kads[3]
    discard await kads[0].findNode(kads[3].rtable.selfId)

    # kads[0] accumulated kads[2] and kads[3], and they learned about kads[0]
    checkUntilTimeout:
      kads[0].hasKeys(@[kads[2].rtable.selfId, kads[3].rtable.selfId])
      kads[2].hasKey(kads[0].rtable.selfId)
      kads[3].hasKey(kads[0].rtable.selfId)

  asyncTest "Find node merges results from parallel queries":
    #         node[1] - node[3]
    #        /                 \
    # node[0]                   node[5]
    #        \                 /
    #         node[2] - node[4]

    let kads = setupKadSwitches(6)
    startAndDeferStop(kads)

    # Set alpha=2 to ensure both branches are queried in parallel
    kads[0].config.alpha = 2

    await connect(kads[0], kads[1])
    await connect(kads[0], kads[2])
    await connect(kads[1], kads[3])
    await connect(kads[2], kads[4])
    await connect(kads[3], kads[5])
    await connect(kads[4], kads[5])

    # Verify initial state
    check:
      kads[0].hasKeys(@[kads[1].rtable.selfId, kads[2].rtable.selfId])
      kads[0].hasNoKeys(
        @[kads[3].rtable.selfId, kads[4].rtable.selfId, kads[5].rtable.selfId]
      )

    let targetKey = randomPeerId().toKey()
    let foundPeers = await kads[0].findNode(targetKey)

    # Results from both branches are merged and deduplicated
    check foundPeers ==
      kads[1 .. 5].pluckPeerIds().sortPeers(targetKey, kads[0].rtable.config.hasher)

    checkUntilTimeout:
      kads[0].hasKey(kads[3].rtable.selfId)
      kads[0].hasKey(kads[4].rtable.selfId)
      kads[0].hasKey(kads[5].rtable.selfId)

  asyncTest "Find node returns the actual k closest":
    let nodeCount = 8
    let kads = setupKadSwitches(nodeCount)
    startAndDeferStop(kads)

    # Set replication factor to 3
    let k = 3
    kads[0].config.replication = k

    # Node[0] is directly connected to all other nodes
    await connectHub(kads[0], kads[1 ..^ 1])
    check kads[0].getPeersFromRoutingTable().len == nodeCount - 1

    let targetKey = kads[1].rtable.selfId
    let foundPeers = await kads[0].findNode(targetKey)

    # Must return exactly k peers
    check foundPeers.len == k

    # Compute expected k closest by XOR distance
    let allOtherPeers = kads[1 ..< nodeCount].pluckPeerIds()
    let sortedByDistance =
      allOtherPeers.sortPeers(targetKey, kads[0].rtable.config.hasher)
    let expectedKClosest = sortedByDistance[0 ..< k]

    check foundPeers == expectedKClosest

  asyncTest "Find node excludes already-queried peers from candidates":
    # Each node knows the other two, creating potential for infinite loops
    # Without exclusion: kads[0] queries kads[1]/kads[2] -> they return each other -> repeat
    # With exclusion: kads[0] queries kads[1]/kads[2] once, marks them responded, terminates
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    # Create fully connected triangle
    await connectStar(kads)

    # Verify initial state: each node knows the other two
    check:
      kads[0].hasKeys(@[kads[1].rtable.selfId, kads[2].rtable.selfId])
      kads[1].hasKeys(@[kads[0].rtable.selfId, kads[2].rtable.selfId])
      kads[2].hasKeys(@[kads[0].rtable.selfId, kads[1].rtable.selfId])

    # Search for non-existent peer
    # Round 1: kads[0] queries kads[1] and kads[2] (both in routing table)
    # kads[1] returns [kads[0], kads[2]], kads[2] returns [kads[0], kads[1]]
    # kads[1] and kads[2] marked as responded
    # No new unqueried candidates -> lookup terminates
    # Without exclusion: would re-query kads[1]/kads[2] until all attempts exhausted
    let targetKey = randomPeerId().toKey()
    let peerIds = await kads[0].findNode(targetKey)

    # Lookup completed without hanging (proves exclusion works)
    # Returns both known peers sorted by distance to target
    check peerIds ==
      pluckPeerIds(@[kads[1], kads[2]]).sortPeers(
        targetKey, kads[0].rtable.config.hasher
      )

  asyncTest "Find peer":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    # Setup: kads[0] <-> kads[1], kads[0] <-> kads[2]
    await connectHub(kads[0], kads[1 ..^ 1])

    let res1 = await kads[1].findPeer(kads[2].switch.peerInfo.peerId)
    check res1.get().peerId == kads[2].switch.peerInfo.peerId

    # try to find peer that does not exist
    let res2 = await kads[1].findPeer(randomPeerId())
    check res2.isErr()

  asyncTest "Find peer returns a connected peer without a lookup":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    let target = kads[1].switch.peerInfo.peerId
    await kads[0].switch.connect(target, kads[1].switch.peerInfo.addrs)
    check kads[0].rtable.peerCount() == 0

    let res = await kads[0].findPeer(target)
    check res.get().peerId == target

  asyncTest "Discovered peer failing its admission probe is not admitted":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    # kads[1] vouches for a peer nothing is listening for
    let deadPeerId = randomPeerId()
    let deadAddrs = @[ma("/ip4/127.0.0.1/tcp/59999")]
    kads[1].updatePeers(@[(deadPeerId, deadAddrs)])

    discard await kads[0].findNode(deadPeerId.toKey())

    # once no probe is in flight the admission decision is final
    checkUntilTimeout:
      kads[0].admissionProbes.len == 0

    check:
      not kads[0].hasKey(deadPeerId.toKey())
      # still dialable by lookups and findPeer
      kads[0].switch.peerStore[AddressBook][deadPeerId] == deadAddrs

  asyncTest "Find node via refresh stale buckets":
    # Setup: kads[0] <-> kads[1] <-> kads[2] (kads[0] doesn't initially know kads[2])
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    await connectChain(kads)

    check not kads[0].hasKey(kads[2].rtable.selfId)

    # Make kads[1]'s bucket stale to trigger refresh
    let bucketIdx = kads[0].rtable.bucketIndex(kads[1].rtable.selfId)
    makeBucketStale(kads[0].rtable, bucketIdx)

    check kads[0].rtable.isStale(bucketIdx)
    check not kads[0].hasKey(kads[2].rtable.selfId)

    await kads[0].bootstrap()

    # kads[0] discovers kads[2] via kads[1]
    checkUntilTimeout:
      kads[0].hasKey(kads[2].rtable.selfId)

  asyncTest "Find node with empty key returns closest peers":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    # Setup: kads[0] <-> kads[1], kads[0] <-> kads[2]
    await connectHub(kads[0], kads[1 ..^ 1])

    # Send FIND_NODE with empty key directly
    let emptyKey: Key = @[]
    let response =
      (await kads[1].dispatchFindNode(kads[0].switch.peerInfo.peerId, emptyKey)).value()

    # Empty key is accepted and a valid response is returned
    check:
      response.msgType == MessageType.findNode
      response.closerPeers.len == 1
      response.closerPeers[0].id.get() == kads[2].rtable.selfId

  asyncTest "Find node for own PeerID excludes the requester":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    # Setup: kads[0] <-> kads[1], kads[0] <-> kads[2]
    await connectHub(kads[0], kads[1 ..^ 1])

    # kads[1] asks kads[0] for peers closest to kads[1]'s own PeerID
    let ownKey = kads[1].rtable.selfId
    let response =
      (await kads[1].dispatchFindNode(kads[0].switch.peerInfo.peerId, ownKey)).value()

    let closerPeersIds = response.closerPeers.mapIt(it.id.get())
    check:
      response.msgType == MessageType.findNode
      response.closerPeers.len == 1
      kads[1].rtable.selfId notin closerPeersIds
      kads[2].rtable.selfId in closerPeersIds

  asyncTest "Find node for a known target returns it once":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    let response = (
      await kads[1].dispatchFindNode(
        kads[0].switch.peerInfo.peerId, kads[2].rtable.selfId
      )
    ).value()

    check:
      response.closerPeers.len == 1
      response.closerPeers[0].id.get() == kads[2].rtable.selfId

  asyncTest "Find node for an unknown target omits it":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    let unknownTarget = randomPeerId().toKey()
    let response = (
      await kads[1].dispatchFindNode(kads[0].switch.peerInfo.peerId, unknownTarget)
    ).value()

    let closerPeersIds = response.closerPeers.mapIt(it.id.get())
    check:
      unknownTarget notin closerPeersIds
      kads[2].rtable.selfId in closerPeersIds

  asyncTest "Find node returns a target known only from the address book":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    # A client-mode peer is in nobody's routing table, but its addresses are known.
    let client = randomPeerId()
    kads[0].switch.peerStore[AddressBook][client] = @[ma("/ip4/127.0.0.1/tcp/9999")]

    let response = (
      await kads[1].dispatchFindNode(kads[0].switch.peerInfo.peerId, client.toKey())
    ).value()

    check:
      not kads[0].hasKey(client.toKey())
      response.closerPeers[0].id.get() == client.toKey()

  asyncTest "Find node excludes the requester for an unrelated target":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    # kads[0] knows kads[1] and kads[2], and both fit in a reply, so pre-filter
    # kads[1] would get itself back even though the target is unrelated to it.
    let response = (
      await kads[1].dispatchFindNode(
        kads[0].switch.peerInfo.peerId, randomPeerId().toKey()
      )
    ).value()

    let closerPeersIds = response.closerPeers.mapIt(it.id.get())
    check:
      kads[1].rtable.selfId notin closerPeersIds
      kads[2].rtable.selfId in closerPeersIds

  asyncTest "Find node with empty routing table returns empty result":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    # Routing table is empty (no peers connected)
    check kads[0].getPeersFromRoutingTable().len == 0

    let peerIds = await kads[0].findNode(randomPeerId().toKey())

    # Returns empty - no peers to query
    check peerIds.len == 0

  asyncTest "Find node continues when peer fails immediately":
    # kads[0] knows kads[1] (will fail immediately) and kads[2] (responds)
    # kads[2] knows kads[3]
    let kads = setupKadSwitches(4)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])
    await connect(kads[0], kads[2])
    await connect(kads[2], kads[3])

    # Stop kads[1] - dial will fail immediately with DialFailedError
    # This is marked as RespondedStatus.Failed; kads[1] stays eligible for
    # retry (gated by attempts/retries) but every retry fails the same way
    # since the switch is stopped, so the lookup still proceeds via kads[2].
    await kads[1].switch.stop()

    check not kads[0].hasKey(kads[3].rtable.selfId)

    # Lookup still succeeds via kads[2] despite kads[1] failure
    let peerIds = await kads[0].findNode(kads[3].rtable.selfId)

    check kads[3].switch.peerInfo.peerId in peerIds
    checkUntilTimeout:
      kads[0].hasKey(kads[3].rtable.selfId)

  asyncTest "Find node retries timed-out peer until max retries exhausted":
    # Test the retry path: peer that doesn't finish within timeout gets retried
    const retries = 5
    let kad =
      setupKad(config = testKadConfig(timeout = 100.milliseconds, retries = retries))
    let mockKad = setupMockKad(handleFindNodeDelay = 500.milliseconds) # > timeout
    let responsiveKad = setupKad()
    startAndDeferStop(@[kad, mockKad, responsiveKad])

    await connect(kad, mockKad)
    await connect(kad, responsiveKad)

    # Dial up front: a cold handshake can outlast the 100ms timeout on a loaded
    # machine, which would exhaust the responsive peer's retries too and leave
    # the lookup with nothing to return.
    for peer in [mockKad.KadDHT, responsiveKad]:
      await kad.switch.connect(peer.switch.peerInfo.peerId, peer.switch.peerInfo.addrs)

    check mockKad.handleFindNodeCalls == 0

    let peerIds = await kad.findNode(mockKad.rtable.selfId)

    # Lookup terminates gracefully after retry exhaustion
    check:
      responsiveKad.switch.peerInfo.peerId in peerIds
      mockKad.handleFindNodeCalls == retries + 1 # (initial call + retries)

  asyncTest "Find node retries a peer that responded with an error, not just silent peers":
    const retries = 3
    let kad = setupKad(config = testKadConfig(retries = retries))
    let mockKad = setupMockKad(handleFindNodeMalformedResponse = true)
    let responsiveKad = setupKad()
    startAndDeferStop(@[kad, mockKad, responsiveKad])

    await connect(kad, mockKad)
    await connect(kad, responsiveKad)

    check mockKad.handleFindNodeCalls == 0

    let peerIds = await kad.findNode(mockKad.rtable.selfId)

    check:
      responsiveKad.switch.peerInfo.peerId in peerIds
      mockKad.handleFindNodeCalls == retries + 1 # (initial call + retries)

  asyncTest "closerPeers does not advertise an observed inbound address":
    let kads = setupKadSwitches(3)
    let (a, b, c) = (kads[0], kads[1], kads[2])
    startAndDeferStop(kads)

    let
      bId = b.switch.peerInfo.peerId
      bKey = bId.toKey()
      bListenAddrs = b.switch.peerInfo.addrs

    # B's inbound connection to A uses an ephemeral source port.
    await b.switch.connect(a.switch.peerInfo.peerId, a.switch.peerInfo.addrs)
    discard (await b.dispatchFindNode(a.switch.peerInfo.peerId, bKey)).expect(
      "FIND_NODE reply"
    )

    check a.switch.peerStore[AddressBook][bId].allIt(it in bListenAddrs)

    await c.switch.connect(a.switch.peerInfo.peerId, a.switch.peerInfo.addrs)
    let reply = (await c.dispatchFindNode(a.switch.peerInfo.peerId, bKey)).value()
    let bCloser =
      reply.closerPeers.filterIt(it.id.isSome and it.id.get() == bId.getBytes())
    check bCloser.mapIt(it.addrs).concat().allIt(it in bListenAddrs)
