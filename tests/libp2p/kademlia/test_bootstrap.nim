# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/[protocols/kademlia, peerid, switch]
import ../../tools/[lifecycle, unittest, multiaddress]
import ./[mock_kademlia, utils]

suite "KadDHT Bootstrap":
  teardown:
    checkTrackers()

  asyncTest "bootstrap calls findNode on self first and skips empty buckets":
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    check kad.rtable.buckets.len == 0

    kad.findNodeCalls = @[]
    await kad.bootstrap()

    # Only self lookup should occur
    check:
      kad.findNodeCalls.len == 1
      kad.findNodeCalls[0] == kad.rtable.selfId

  asyncTest "bootstrap skips fresh buckets":
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    # Add peers - they will be fresh (just added)
    kad.populateRoutingTable(5)
    check kad.nonEmptyBuckets().len >= 1

    kad.findNodeCalls = @[]
    await kad.bootstrap()

    # Only self lookup - fresh buckets are skipped
    check kad.findNodeCalls.len == 1

  asyncTest "bootstrap refreshes stale buckets":
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    # Add multiple peers to create multiple buckets
    kad.populateRoutingTable(20)

    # Make all buckets stale
    let bucketIndices = kad.nonEmptyBuckets()
    check bucketIndices.len >= 2

    for index in bucketIndices:
      makeBucketStale(kad.rtable, index)

    kad.findNodeCalls = @[]
    await kad.bootstrap()

    # Self lookup + one lookup per stale bucket
    check kad.findNodeCalls.len == bucketIndices.len + 1

  asyncTest "bootstrap with mixed fresh and stale buckets refreshes only stale":
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    kad.populateRoutingTable(20)

    # Get non-empty bucket indices
    let bucketIndices = kad.nonEmptyBuckets()
    check bucketIndices.len >= 2

    # Make only the first bucket stale
    let staleBucketIndex = bucketIndices[0]
    makeBucketStale(kad.rtable, staleBucketIndex)
    check kad.rtable.isStale(staleBucketIndex)

    # Verify that the rest of non-empty buckets is fresh
    for i in 1 ..< bucketIndices.len:
      check not kad.rtable.isStale(bucketIndices[i])

    kad.findNodeCalls = @[]
    await kad.bootstrap()

    # Self lookup + only the stale bucket refresh
    check:
      kad.findNodeCalls.len == 2
      kad.findNodeCalls[0] == kad.rtable.selfId # first call always self lookup

  asyncTest "bootstrap with forceRefresh=true refreshes all non-empty buckets":
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    kad.populateRoutingTable(20)

    let nonEmptyBucketCount = kad.nonEmptyBuckets().len
    check nonEmptyBucketCount >= 1

    kad.findNodeCalls = @[]
    await kad.bootstrap(forceRefresh = true)

    # Self lookup + one lookup per non-empty bucket
    check kad.findNodeCalls.len == nonEmptyBucketCount + 1

  asyncTest "bootstrap cancels itself when it runs out of time":
    let kad = setupMockKad()
    kad.config.bootstrapTimeout = 200.milliseconds
    kad.findNodeStalls = true
    defer:
      await stopNodes(@[kad])

    await startNodes(@[kad]).wait(5.seconds)

    check:
      kad.started
      kad.findNodeCancels == 1

  asyncTest "start returns before the bootstrap completes":
    let kad = setupMockKad()
    kad.findNodeStalls = true
    await kad.switch.start().wait(5.seconds)
    defer:
      await kad.switch.stop()

    check:
      kad.started
      kad.findNodeCalls.len == 1
      not kad.waitBootstrap().finished()

  asyncTest "concurrent start calls run one bootstrap":
    let kad = setupMockKad()
    kad.findNodeStalls = true

    await allFutures(kad.start(), kad.start())
    check kad.findNodeCalls.len == 1

    await kad.stop()
    check kad.findNodeCancels == 1

  asyncTest "waitBootstrap completes after the table refresh":
    let kad = setupMockKad()
    kad.populateRoutingTable(20)
    let nonEmptyBucketCount = kad.nonEmptyBuckets().len
    check nonEmptyBucketCount >= 1

    await kad.switch.start()
    defer:
      await kad.switch.stop()
    await kad.waitBootstrap().wait(5.seconds)

    check:
      kad.bootstrapFut.completed()
      kad.findNodeCalls.len == nonEmptyBucketCount + 1

  asyncTest "cancelling waitBootstrap leaves the bootstrap running":
    let kad = setupMockKad()
    kad.findNodeStalls = true
    await kad.switch.start()
    defer:
      await kad.switch.stop()

    await kad.waitBootstrap().cancelAndWait()

    check:
      not kad.bootstrapFut.finished()
      kad.findNodeCancels == 0

  asyncTest "stop during bootstrap cancels the bootstrap":
    let kad = setupMockKad()
    kad.findNodeStalls = true
    await kad.switch.start()
    let bootstrap = kad.bootstrapFut
    let waiter = kad.waitBootstrap()

    await kad.switch.stop()

    check:
      bootstrap.cancelled()
      kad.bootstrapFut.isNil()
      kad.findNodeCancels == 1
      waiter.completed()
      kad.waitBootstrap().completed()

  asyncTest "waitBootstrap is complete when bootstrapping is disabled":
    let kad = setupMockKad(config = testKadConfig(disableBootstrapping = true))
    await kad.switch.start()
    defer:
      await kad.switch.stop()

    check:
      kad.bootstrapFut.isNil()
      kad.waitBootstrap().completed()

  asyncTest "bucket maintenance cancels a refresh that runs out of time":
    let kad = setupMockKad()
    kad.config.bucketRefreshTime = 200.milliseconds
    kad.config.bootstrapTimeout = 200.milliseconds
    kad.findNodeStalls = true
    defer:
      await stopNodes(@[kad])

    await startNodes(@[kad]).wait(5.seconds)
    let afterBootstrap = kad.findNodeCancels

    # Every round would otherwise leave a lookup behind, still sending RPCs.
    checkUntilTimeout:
      kad.findNodeCancels > afterBootstrap

suite "KadDHT Bootstrap Component":
  teardown:
    checkTrackers()

  asyncTest "bootstrap discovers new peers through network":
    # 1 hub + 9 nodes bootstrapping from hub
    let hubKad = setupKad()
    startAndDeferStop(@[hubKad])

    let kads = setupKadSwitches(
      9,
      bootstrapNodes = @[(hubKad.switch.peerInfo.peerId, hubKad.switch.peerInfo.addrs)],
    )

    # The nodes bootstrap at the same instant, so the hub admits no one yet when
    # they query it. A short refresh interval makes them query the hub again.
    # bucketRefreshTime also limits each refresh, so keep it above the RPC timeout.
    for kad in kads:
      kad.config.bucketRefreshTime = 2.seconds
    startAndDeferStop(kads)

    # All nodes should know about all other nodes after bootstrap
    proc allPeersKnowEachOther(): bool =
      for i, kad in kads:
        for j, otherKad in kads:
          if i != j and not kad.hasKey(otherKad.rtable.selfId):
            return false
      true

    checkUntilTimeout:
      allPeersKnowEachOther()

  asyncTest "bootstrap with unreachable peer completes gracefully":
    # Fake bootstrap peer with valid address format
    let fakePeerId = randomPeerId()
    let fakeAddrs = @[ma("/ip4/127.0.0.1/tcp/59999")]

    let config = testKadConfig(timeout = chronos.milliseconds(100))
    let kad = setupKad(config = config, bootstrapNodes = @[(fakePeerId, fakeAddrs)])
    startAndDeferStop(@[kad])

    check:
      kad.hasKey(fakePeerId.toKey()) # fake peer should be in routing table
      kad.started # node should be operational

  asyncTest "probeAndEvictPeers removes peers past liveness grace that fail probe":
    let hub = setupKad()
    let leaf = setupKad(config = testKadConfig(timeout = chronos.milliseconds(200)))
    startAndDeferStop(@[hub, leaf])
    await connect(hub, leaf)

    let leafId = leaf.switch.peerInfo.peerId
    check hub.hasKey(leafId.toKey())

    # Stop the leaf so the next probe fails, then age hub's entry past grace.
    await leaf.stop()
    await leaf.switch.stop()

    agePeerPastLivenessGrace(hub.rtable, leafId.toKey())

    await hub.probeAndEvictPeers(hub.rtable)

    check not hub.hasKey(leafId.toKey())

  asyncTest "probeAndEvictPeers retains peers that answer the probe":
    let hub = setupKad()
    let leaf = setupKad()
    startAndDeferStop(@[hub, leaf])
    await connect(hub, leaf)

    let leafId = leaf.switch.peerInfo.peerId
    check hub.hasKey(leafId.toKey())

    # Age past grace so a probe is required; leaf is still alive.
    agePeerPastLivenessGrace(hub.rtable, leafId.toKey())

    await hub.probeAndEvictPeers(hub.rtable)

    check hub.hasKey(leafId.toKey())
    # Successful probe marks the peer useful again.
    check hub.isPeerUseful(leafId.toKey())

  asyncTest "probeAndEvictPeers skips peers still within liveness grace":
    let hub = setupKad()
    let leaf = setupKad(config = testKadConfig(timeout = chronos.milliseconds(200)))
    startAndDeferStop(@[hub, leaf])
    await connect(hub, leaf)

    let leafId = leaf.switch.peerInfo.peerId
    await leaf.stop()
    await leaf.switch.stop()

    # Fresh insert times: within grace, so no probe and no eviction.
    await hub.probeAndEvictPeers(hub.rtable)
    check hub.hasKey(leafId.toKey())

  asyncTest "probeAndEvictPeers removes peers with no known addresses":
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let orphan = randomPeerId()
    check kad.rtable.insert(orphan)
    # No AddressBook entry.

    agePeerPastLivenessGrace(kad.rtable, orphan.toKey())

    await kad.probeAndEvictPeers(kad.rtable)
    check not kad.hasKey(orphan.toKey())

  asyncTest "probeAndEvictPeers keeps useful peer even with no addresses":
    ## Re-check after the candidate snapshot: a peer that is still within grace
    ## (or was markUseful'd) must not be removed on the no-addrs path.
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let peer = randomPeerId()
    check kad.rtable.insert(peer)
    # Fresh insert: within grace, and no AddressBook entry.
    await kad.probeAndEvictPeers(kad.rtable)
    check kad.hasKey(peer.toKey())

  asyncTest "probeAndEvictPeers skips peer refreshed after aging":
    ## Age past grace then markUseful before the maintenance pass: candidate
    ## selection (and the post-acquire re-check) must leave the peer in place.
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let peer = randomPeerId()
    check kad.rtable.insert(peer)
    agePeerPastLivenessGrace(kad.rtable, peer.toKey())
    kad.rtable.markUseful(peer)

    await kad.probeAndEvictPeers(kad.rtable)
    check kad.hasKey(peer.toKey())

  asyncTest "refreshTable does not probe or evict aged peers":
    ## Liveness is owned by maintainLiveness, not bucket refresh.
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let orphan = randomPeerId()
    check kad.rtable.insert(orphan)
    agePeerPastLivenessGrace(kad.rtable, orphan.toKey())

    await kad.refreshTable(kad.rtable, forceRefresh = true)
    check kad.hasKey(orphan.toKey())

  asyncTest "liveness loop starts with KadDHT and clears on stop":
    let kad = setupKad(
      config = testKadConfig(
        disableBootstrapping = true, livenessIdleInterval = chronos.hours(1)
      )
    )
    await kad.switch.start()
    defer:
      await kad.switch.stop()

    await kad.start()
    check not kad.livenessLoop.isNil
    await kad.stop()
    check:
      kad.livenessLoop.isNil
      kad.livenessProbes.len == 0

  asyncTest "liveness loop evicts aged peer without refreshTable":
    let grace = chronos.milliseconds(50)
    let hub = setupKad(
      config = testKadConfig(
        timeout = chronos.milliseconds(200),
        livenessGracePeriod = grace,
        livenessIdleInterval = chronos.milliseconds(20),
        disableBootstrapping = true,
      )
    )
    let leaf = setupKad(
      config =
        testKadConfig(timeout = chronos.milliseconds(200), disableBootstrapping = true)
    )
    startAndDeferStop(@[hub, leaf])
    await connect(hub, leaf)

    let leafId = leaf.switch.peerInfo.peerId
    check hub.hasKey(leafId.toKey())

    await leaf.stop()
    await leaf.switch.stop()
    agePeerPastLivenessGrace(hub.rtable, leafId.toKey(), grace)

    # Wait for the continuous loop (initial idle + probe), not refreshTable.
    checkUntilTimeoutCustom(5.seconds, chronos.milliseconds(20)):
      not hub.hasKey(leafId.toKey())

  asyncTest "liveness probe is de-duplicated while in flight":
    ## An in-flight entry must be awaited by a concurrent batch instead of
    ## launching a second probe (and acquiring another livenessSem slot).
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let peer = randomPeerId()
    check kad.rtable.insert(peer)
    agePeerPastLivenessGrace(kad.rtable, peer.toKey())

    let hang = newFuture[void]("liveness-probe-dedup-hang")
    kad.livenessProbes[peer] = hang

    let batch = kad.probeAndEvictPeers(kad.rtable)

    check:
      not batch.finished()
      kad.livenessProbes.len == 1

    hang.complete()
    await batch
    # Hang stood in for the real probe body, so the peer was not removed.
    # Manual inject has no track callback; drop the finished entry ourselves.
    kad.livenessProbes.del(peer)
    check:
      kad.hasKey(peer.toKey())
      kad.livenessProbes.len == 0

  asyncTest "failed liveness probe keeps a peer marked useful mid-flight":
    let config =
      testKadConfig(timeout = chronos.milliseconds(200), disableBootstrapping = true)
    let hub = setupKad(config = config)
    let leaf = setupKad(config = config)
    startAndDeferStop(@[hub, leaf])
    await connect(hub, leaf)

    let leafId = leaf.switch.peerInfo.peerId
    await leaf.stop()
    await leaf.switch.stop()
    agePeerPastLivenessGrace(hub.rtable, leafId.toKey())

    let batch = hub.probeAndEvictPeers(hub.rtable)
    check not batch.finished()
    hub.rtable.markUseful(leafId)
    await batch

    check hub.hasKey(leafId.toKey())

  asyncTest "cancelling a liveness batch cancels its in-flight probes":
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let peer = randomPeerId()
    check kad.rtable.insert(peer)
    agePeerPastLivenessGrace(kad.rtable, peer.toKey())

    let hang = newFuture[void]("liveness-probe-cancel-hang")
    kad.livenessProbes[peer] = hang

    let batch = kad.probeAndEvictPeers(kad.rtable)
    await batch.cancelAndWait()
    kad.livenessProbes.del(peer)

    check:
      batch.cancelled()
      hang.cancelled()
      kad.hasKey(peer.toKey())

  asyncTest "stop ends a liveness loop parked on an in-flight probe":
    let kad = setupKad(
      config = testKadConfig(
        disableBootstrapping = true, livenessIdleInterval = chronos.milliseconds(20)
      )
    )
    await kad.switch.start()
    defer:
      await kad.switch.stop()

    await kad.start()
    let hang = newFuture[void]("liveness-loop-stop-hang")
    kad.livenessProbes[randomPeerId()] = hang
    # Several idle intervals, so the loop parks on the in-flight probe.
    await sleepAsync(chronos.milliseconds(100))

    await kad.stop()
    check:
      hang.cancelled()
      kad.livenessLoop.isNil
      kad.livenessProbes.len == 0
