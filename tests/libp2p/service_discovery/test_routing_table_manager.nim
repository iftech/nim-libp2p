# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sets, tables, sequtils
import
  ../../../libp2p/[peerinfo, peerid],
  ../../../libp2p/protocols/kademlia,
  ../../../libp2p/protocols/service_discovery,
  ../../../libp2p/protocols/service_discovery/[types, routing_table_manager]
import ../../tools/[lifecycle, multiaddress, unittest]
import ../kademlia/[mock_kademlia, utils]
import ./utils

proc makeKey(x: byte): Key =
  var buf: array[IdLength, byte]
  buf[31] = x
  return @buf

proc makeServiceId(x: byte): ServiceId =
  return makeKey(x)

# Heap-allocated recorder so a closure capturing it stays GC-safe (mirrors how
# the production callback captures the disco ref rather than a stack local).
type HitRecorder = ref object
  ids: seq[ServiceId]

proc makeMainTable(selfId: Key, peers: seq[Key]): RoutingTable =
  var rt = RoutingTable.new(selfId)
  for p in peers:
    discard rt.insert(p)
  rt

suite "ServiceRoutingTableManager":
  test "new creates empty manager":
    let manager = ServiceRoutingTableManager.new()
    check:
      manager.count() == 0
      manager.serviceIds().len == 0

  test "addService returns true and adds table":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check:
      manager.addService(
        serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
      )
      manager.count() == 1
      manager.hasService(serviceId)

  test "addService with same service and same status returns false":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    let addedAgain = manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )

    check:
      addedAgain == false
      manager.serviceStatus[serviceId] == {Interest}

  test "addService with same service but different status merges and returns true":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    let upgraded = manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )

    check:
      upgraded == true
      manager.serviceStatus[serviceId] == {Interest, Provided}

  test "addService fires onServiceTableCreated only for brand-new tables":
    let manager = ServiceRoutingTableManager.new()
    let mainRt = RoutingTable.new(makeKey(0))

    let hits = HitRecorder()
    manager.onServiceTableCreated = proc(sid: ServiceId) =
      hits.ids.add(sid)

    let serviceId = makeServiceId(1)

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check:
      hits.ids.len == 1
      hits.ids[0] == serviceId

    discard manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check hits.ids.len == 1

    discard manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )
    check:
      hits.ids.len == 1
      manager.serviceStatus[serviceId] == {Interest, Provided}

    let otherId = makeServiceId(2)
    check manager.addService(
      otherId, mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )
    check:
      hits.ids.len == 2
      otherId in hits.ids

  asyncTest "a new service table bootstraps when bootstrapping is enabled":
    let disco = setupServiceDiscoveryNode(
      kadConfig = KadDHTConfig.new(
        ExtEntryValidator(), ExtEntrySelector(), disableBootstrapping = false
      )
    )
    let serviceId = makeServiceId(1)

    check disco.rtManager.addService(
      serviceId, disco.rtable, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check serviceId in disco.serviceBootstrapFuts

    await disco.serviceBootstrapFuts[serviceId]

  test "addService with no callback set does not crash":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check manager.hasService(serviceId)

  test "addService pre-populates table from main routing table":
    let selfId = makeKey(0)
    let peer1 = makeKey(1)
    let peer2 = makeKey(2)
    let mainRt = makeMainTable(selfId, @[peer1, peer2])

    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(3)
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )

    let table = manager.getTable(serviceId).get()

    let peers = table.allKeys()

    check:
      peer1 in peers
      peer2 in peers

  test "addService shares registry with main table (no peer-row copies)":
    let selfId = makeKey(0)
    let peer1 = makeKey(1)
    let peer2 = makeKey(2)
    let mainRt = makeMainTable(selfId, @[peer1, peer2])
    let registryLenBefore = mainRt.registry.len

    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(3)
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )

    let serviceTable = manager.getTable(serviceId).get()
    check:
      serviceTable.registry == mainRt.registry
      mainRt.registry.len == registryLenBefore
      mainRt.registry.tableIds(peer1).len == 2
      mainRt.registry.tableIds(peer2).len == 2

    mainRt.markUseful(peer1)
    check serviceTable.registry.get(peer1).get().lastUsefulAt.isSome()

  test "removeService detaches table memberships from shared registry":
    let selfId = makeKey(0)
    let peer1 = makeKey(1)
    let mainRt = makeMainTable(selfId, @[peer1])
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(3)
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check mainRt.registry.tableIds(peer1).len == 2

    manager.removeService(serviceId, Interest)
    check:
      not manager.hasService(serviceId)
      peer1 in mainRt
      peer1 in mainRt.registry
      mainRt.registry.tableIds(peer1).len == 1
      serviceId notin mainRt.registry.tableIds(peer1)

  test "clear detaches all service tables from shared registry":
    let selfId = makeKey(0)
    let peer1 = makeKey(1)
    let mainRt = makeMainTable(selfId, @[peer1])
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(3)
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    manager.clear()
    check:
      manager.count() == 0
      peer1 in mainRt.registry
      mainRt.registry.tableIds(peer1).len == 1

  test "removeService removes entry when status matches":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    manager.removeService(serviceId, Interest)

    check:
      not manager.hasService(serviceId)
      manager.count() == 0

  test "removeService of Interest leaves Provided":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )
    check manager.serviceStatus[serviceId] == {Interest, Provided}

    manager.removeService(serviceId, Interest)

    check:
      manager.hasService(serviceId)
      manager.serviceStatus[serviceId] == {Provided}

  test "removeService of Provided leaves Interest":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )
    check manager.serviceStatus[serviceId] == {Interest, Provided}

    manager.removeService(serviceId, Provided)

    check:
      manager.hasService(serviceId)
      manager.serviceStatus[serviceId] == {Interest}

  test "removeService keeps the table until every status is removed":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    let removed = HitRecorder()
    manager.onServiceTableRemoved = proc(sid: ServiceId) =
      removed.ids.add(sid)

    for status in ServiceStatus:
      check manager.addService(
        serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, status
      )

    manager.removeService(serviceId, Registered)
    manager.removeService(serviceId, Interest)
    check:
      manager.serviceStatus[serviceId] == {Provided}
      removed.ids.len == 0

    manager.removeService(serviceId, Provided)
    check:
      not manager.hasService(serviceId)
      serviceId notin manager.serviceStatus
      removed.ids == @[serviceId]

  test "removeService on non-existent service is a no-op":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)

    manager.removeService(serviceId, Interest)
    check manager.count() == 0

  test "getTable returns Some for existing service":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )

    check manager.getTable(serviceId).isSome()

  test "getTable returns None for non-existing service":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)

    check manager.getTable(serviceId).isNone()

  test "insertPeer admits a peer with a valid address to the service routing table":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId(1)
    check disco.rtManager.addService(
      serviceId, disco.rtable, DefaultReplication, DefaultMaxBuckets, Interest
    )

    let peerInfo = makePeerInfo(addrs = @[makeMultiAddress("10.0.0.1")])
    check disco.insertPeer(serviceId, peerInfo)
    check disco.hasPeerInServiceTable(serviceId, peerInfo.peerId)

  test "insertPeer rejects a peer with no addresses":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId(1)
    check disco.rtManager.addService(
      serviceId, disco.rtable, DefaultReplication, DefaultMaxBuckets, Interest
    )

    let peerInfo = makePeerInfo()
    check not disco.insertPeer(serviceId, peerInfo)
    check not disco.hasPeerInServiceTable(serviceId, peerInfo.peerId)

  test "insertPeer rejects an undialable address unless the switch allows it":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId(1)
    check disco.rtManager.addService(
      serviceId, disco.rtable, DefaultReplication, DefaultMaxBuckets, Interest
    )

    let peerInfo = makePeerInfo(addrs = @[ma("/ip4/0.0.0.0/tcp/60000")])
    check not disco.insertPeer(serviceId, peerInfo)
    check not disco.hasPeerInServiceTable(serviceId, peerInfo.peerId)

    disco.switch.peerStore.allowUndialableAddrs = true
    check disco.insertPeer(serviceId, peerInfo)
    check disco.hasPeerInServiceTable(serviceId, peerInfo.peerId)

    disco.switch.peerStore.allowUndialableAddrs = false
    let otherPeerInfo = makePeerInfo(addrs = @[ma("/ip4/0.0.0.0/tcp/60001")])
    check not disco.insertPeer(serviceId, otherPeerInfo)
    check not disco.hasPeerInServiceTable(serviceId, otherPeerInfo.peerId)

  test "insertPeer rejects a second peer on a full public IP":
    let disco = setupServiceDiscoveryNode()
    disco.config.limits.maxPeersPerIp = 1
    let serviceId = makeServiceId(1)
    check disco.rtManager.addService(
      serviceId, disco.rtable, DefaultReplication, DefaultMaxBuckets, Interest
    )

    let first = makePeerInfo(addrs = @[makeMultiAddress("1.2.3.4")])
    let second = makePeerInfo(addrs = @[makeMultiAddress("1.2.3.4")])

    check:
      disco.insertPeer(serviceId, first)
      not disco.insertPeer(serviceId, second)
      not disco.hasPeerInServiceTable(serviceId, second.peerId)

  test "insertPeer on non-existent service is a no-op":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId(1)
    let peerInfo = makePeerInfo(addrs = @[makeMultiAddress("10.0.0.1")])

    check not disco.insertPeer(serviceId, peerInfo)
    check disco.rtManager.count() == 0

  test "hasService returns false for unknown service":
    let manager = ServiceRoutingTableManager.new()
    check not manager.hasService(makeKey(1))

  test "count reflects number of tracked services":
    let manager = ServiceRoutingTableManager.new()
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      makeKey(1), mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check manager.addService(
      makeKey(2), mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )
    check manager.addService(
      makeKey(3), mainRt, DefaultReplication, DefaultMaxBuckets, Registered
    )

    check manager.count() == 3

  test "serviceIds returns all service IDs":
    let manager = ServiceRoutingTableManager.new()
    let mainRt = RoutingTable.new(makeKey(0))
    let ids = @[makeKey(1), makeKey(2), makeKey(3)]

    for id in ids:
      check manager.addService(
        id, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
      )

    check manager.serviceIds().toHashSet() == ids.toHashSet()

  test "clear removes all service tables":
    let manager = ServiceRoutingTableManager.new()
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      makeKey(1), mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check manager.addService(
      makeKey(2), mainRt, DefaultReplication, DefaultMaxBuckets, Provided
    )

    manager.clear()

    check:
      manager.count() == 0
      not manager.hasService(makeKey(1))
      not manager.hasService(makeKey(2))

  test "manager has selfIdPreHashed set to true":
    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(1)
    let mainRt = RoutingTable.new(makeKey(0))

    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )

    check:
      manager.getTable(serviceId).get().config.selfIdPreHashed

suite "ServiceRoutingTableManager - refreshAllTables":
  teardown:
    checkTrackers()

  asyncTest "does nothing when no tables are registered":
    let manager = ServiceRoutingTableManager.new()
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    await manager.refreshAllTables(kad)

    # only call it once
    check kad.findNodeCalls.len == 1

  asyncTest "walks toward the center of a single service table":
    let manager = ServiceRoutingTableManager.new()
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let serviceId = makeServiceId(1)
    let mainRt = makeMainTable(makeKey(2), @[makeKey(3), makeKey(4), makeKey(5)])
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    let serviceTable = manager.getTable(serviceId).get()

    await manager.refreshAllTables(kad)

    # One self-lookup per service table, plus the main table's own from `start`.
    check:
      kad.findNodeCalls.len == 2
      kad.findNodeCalls[1] in serviceTable.allKeys()
      kad.findNodeCalls[1] != serviceId
      kad.findNodeTables[1] == serviceTable

  asyncTest "calls findNode once per registered service table":
    let manager = ServiceRoutingTableManager.new()
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let mainRt = makeMainTable(makeKey(0), @[makeKey(4), makeKey(5), makeKey(6)])
    let serviceIds = @[makeKey(1), makeKey(2), makeKey(3)]
    for id in serviceIds:
      check manager.addService(
        id, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
      )

    await manager.refreshAllTables(kad)

    # One self-lookup per service table, plus the main table's own from `start`.
    check kad.findNodeCalls.len == serviceIds.len + 1
    for id in serviceIds:
      check manager.getTable(id).get() in kad.findNodeTables

  asyncTest "does not call findNode for a removed service table":
    let manager = ServiceRoutingTableManager.new()
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let mainRt = makeMainTable(makeKey(0), @[makeKey(3), makeKey(4), makeKey(5)])
    let kept = makeKey(1)
    let removed = makeKey(2)
    check manager.addService(
      kept, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    check manager.addService(
      removed, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )
    let keptTable = manager.getTable(kept).get()
    manager.removeService(removed, Interest)

    await manager.refreshAllTables(kad)

    # One self-lookup per service table, plus the main table's own from `start`.
    check:
      kad.findNodeCalls.len == 2
      kad.findNodeTables[1] == keptTable

  asyncTest "an empty service table walks toward the main table's peers":
    let manager = ServiceRoutingTableManager.new()
    let kad = setupMockKad()
    startAndDeferStop(@[kad])

    let serviceId = makeServiceId(1)
    check manager.addService(
      serviceId,
      makeMainTable(makeKey(2), @[]),
      DefaultReplication,
      DefaultMaxBuckets,
      Interest,
    )
    let serviceTable = manager.getTable(serviceId).get()
    for i in 3'u8 .. 5'u8:
      discard kad.rtable.insert(makeKey(i))
    let callsBefore = kad.findNodeCalls.len

    await manager.refreshAllTables(kad)

    check:
      serviceTable.allKeys().len == 0
      kad.findNodeCalls.len == callsBefore + 1
      kad.findNodeCalls[^1] in kad.rtable.allKeys()
      kad.findNodeTables[^1] == serviceTable

  test "addService rejects local node insertion into service table":
    let selfId = makeKey(0)
    let peer1 = makeKey(1)
    let peer2 = makeKey(2)
    let mainRt = makeMainTable(selfId, @[peer1, peer2])

    let manager = ServiceRoutingTableManager.new()
    let serviceId = makeServiceId(3)
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )

    let table = manager.getTable(serviceId).get()
    check not table.insert(selfId) # local node must be rejected

    let peers = table.allKeys()

    check:
      selfId notin peers
      peer1 in peers
      peer2 in peers

suite "ServiceRoutingTableManager - service id hashing":
  test "service table buckets peers by the service id, not its re-hash":
    let
      serviceId = hashServiceId("/logos/service-discovery/1.0.0")
      peer = makeKey(1)
      manager = ServiceRoutingTableManager.new()
      mainRt = RoutingTable.new(makeKey(0))
    check manager.addService(serviceId, mainRt, 100, DefaultMaxBuckets, Interest)

    let serviceTable = manager.getTable(serviceId).get()
    check serviceTable.insert(peer)

    let preHashBucket = serviceTable.bucketIndex(peer)

    var nonServiceTable = serviceTable

    # Service table always have this set to true
    nonServiceTable.config.selfIdPreHashed = false

    let doubleHashBucket = nonServiceTable.bucketIndex(peer)

    check:
      preHashBucket != doubleHashBucket
      serviceTable.buckets[preHashBucket].peers.len == 1
      serviceTable.buckets[preHashBucket].peers[0] == peer

  test "service table hashes peers with the main table's hasher":
    let
      serviceId = makeServiceId(1)
      peer = makeKey(3)
      manager = ServiceRoutingTableManager.new()
      mainRt = RoutingTable.new(
        makeKey(0), RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
      )
    check manager.addService(
      serviceId, mainRt, DefaultReplication, DefaultMaxBuckets, Interest
    )

    proc bucketWith(hasher: Opt[XorDHasher]): int =
      RoutingTable
        .new(
          serviceId,
          RoutingTableConfig.new(
            hasher = hasher, maxBuckets = DefaultMaxBuckets, selfIdPreHashed = true
          ),
        )
        .bucketIndex(peer)

    # With `noOpHasher` the peer differs from the service id in one bit, so the
    # default hasher puts it in a different bucket.
    check:
      bucketWith(Opt.some(noOpHasher)) != bucketWith(Opt.none(XorDHasher))
      manager.getTable(serviceId).get().bucketIndex(peer) ==
        bucketWith(Opt.some(noOpHasher))

  test "service table with small bucketsCount uses scaled bucket mapping":
    let
      serviceId = hashServiceId("scaled-buckets-test")
      peer = makeKey(42)
      manager = ServiceRoutingTableManager.new()
      mainRt = RoutingTable.new(makeKey(0))
    check manager.addService(serviceId, mainRt, 20, 16, Interest)

    let table = manager.getTable(serviceId).get()
    check table.insert(peer)

    let expectedScaled = table.bucketIndex(peer)

    check:
      peer in table.allKeys()
      expectedScaled < 16

    var actual = -1
    for i, b in table.buckets:
      if peer in b.peers:
        actual = i
        break
    check actual == expectedScaled

suite "ServiceDiscovery liveness over service tables":
  asyncTest "maintainableTables includes service tables":
    let disco = setupServiceDiscoveryNode()
    startAndDeferStop(@[disco])

    let serviceId = makeServiceId(1)
    check disco.rtManager.addService(
      serviceId, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
      Interest,
    )

    let tables = disco.maintainableTables()
    check:
      tables.len == 2
      tables.anyIt(it.selfId == disco.rtable.selfId)
      tables.anyIt(it.selfId == serviceId)

  asyncTest "probeAndEvictPeers removes aged peer from service table":
    ## Dynamic dispatch through maintainableTables must cover per-service indexes.
    let grace = 50.milliseconds
    let disco = setupServiceDiscoveryNode(
      kadConfig = KadDHTConfig.new(
        ExtEntryValidator(),
        ExtEntrySelector(),
        timeout = 200.milliseconds,
        livenessGracePeriod = grace,
        livenessIdleInterval = 1.hours,
        disableBootstrapping = true,
      )
    )
    startAndDeferStop(@[disco])

    let serviceId = makeServiceId(7)
    check disco.rtManager.addService(
      serviceId, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
      Interest,
    )
    let serviceTable = disco.rtManager.getTable(serviceId).get()

    let peer = randomPeerId()
    check serviceTable.insert(peer)
    # No addresses → liveness path evicts without dialling.
    agePeerPastLivenessGrace(serviceTable, peer.toKey(), grace)

    check peer.toKey() in serviceTable
    await disco.probeAndEvictPeers(serviceTable)
    check peer.toKey() notin serviceTable
