# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sets
import chronos, results
import ../../../libp2p/[peerid, protocols/kademlia, crypto/crypto]
import ../../tools/[unittest, crypto]

proc testKey*(x: byte): Key =
  var buf: array[IdLength, byte]
  buf[31] = x
  return Key(@buf)

suite "KadDHT PeerRegistry":
  test "new registry is empty":
    let registry = PeerRegistry.new()
    check:
      registry.len == 0
      testKey(1) notin registry
      registry.get(testKey(1)).isNone()
      registry.membership(testKey(1), testKey(0)).isNone()
      registry.tableIds(testKey(1)).len == 0

  test "upsert inserts a new peer row":
    let registry = PeerRegistry.new()
    let now = Moment.now()
    let nodeId = testKey(1)

    let record = registry.upsert(nodeId, now)
    check:
      registry.len == 1
      nodeId in registry
      record.nodeId == nodeId
      record.lastSeen == now
      record.lastUsefulAt.isNone()
      registry.get(nodeId).get().lastSeen == now
      # Upsert alone does not create table membership.
      registry.membership(nodeId, testKey(0)).isNone()
      registry.tableIds(nodeId).len == 0

  test "upsert refreshes lastSeen on existing peer":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let first = Moment.now() - 1.hours
    let second = Moment.now()

    discard registry.upsert(nodeId, first)
    let refreshed = registry.upsert(nodeId, second)

    check:
      registry.len == 1
      refreshed.lastSeen == second
      registry.get(nodeId).get().lastSeen == second
      refreshed.lastUsefulAt.isNone()

  test "markUseful sets lastUsefulAt and refreshes lastSeen":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let seenAt = Moment.now() - 1.hours
    let usefulAt = Moment.now()

    discard registry.upsert(nodeId, seenAt)
    registry.markUseful(nodeId, usefulAt)

    let record = registry.get(nodeId).get()
    check:
      record.lastUsefulAt == usefulAt
      record.lastSeen == usefulAt

  test "markUseful is a no-op for unknown peers":
    let registry = PeerRegistry.new()
    registry.markUseful(testKey(1), Moment.now())
    check:
      registry.len == 0
      testKey(1) notin registry

  test "markUseful accepts PeerId":
    let registry = PeerRegistry.new()
    let peerId = PeerId.init(KeyPair.random(ECDSA, rng()).get().pubkey).get()
    let nodeId = peerId.toKey()
    let usefulAt = Moment.now()

    discard registry.upsert(nodeId, usefulAt - 1.hours)
    registry.markUseful(peerId, usefulAt)

    let record = registry.get(nodeId).get()
    check:
      record.lastUsefulAt == usefulAt
      record.lastSeen == usefulAt

  test "addMembership records per-table membership":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableA = testKey(10)
    let tableB = testKey(20)
    let now = Moment.now()

    discard registry.upsert(nodeId, now)
    registry.addMembership(nodeId, tableA, now)
    registry.addMembership(nodeId, tableB, now + 1.seconds)

    check:
      registry.membership(nodeId, tableA).get().addedAt == now
      registry.membership(nodeId, tableB).get().addedAt == now + 1.seconds
      registry.tableIds(nodeId) == [tableA, tableB].toHashSet()

  test "addMembership is a no-op when membership already exists":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableId = testKey(10)
    let first = Moment.now() - 1.hours
    let second = Moment.now()

    discard registry.upsert(nodeId, first)
    registry.addMembership(nodeId, tableId, first)
    registry.addMembership(nodeId, tableId, second)

    check:
      registry.membership(nodeId, tableId).get().addedAt == first
      registry.tableIds(nodeId).len == 1

  test "removeMembership drops one table reference and keeps the peer row":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableA = testKey(10)
    let tableB = testKey(20)
    let now = Moment.now()

    discard registry.upsert(nodeId, now)
    registry.addMembership(nodeId, tableA, now)
    registry.addMembership(nodeId, tableB, now)

    registry.removeMembership(nodeId, tableA)
    check:
      nodeId in registry
      registry.membership(nodeId, tableA).isNone()
      registry.membership(nodeId, tableB).isSome()
      registry.tableIds(nodeId) == [tableB].toHashSet()

  test "removeMembership deletes peer row when last table reference is gone":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableId = testKey(10)
    let now = Moment.now()

    discard registry.upsert(nodeId, now)
    registry.addMembership(nodeId, tableId, now)
    registry.removeMembership(nodeId, tableId)

    check:
      nodeId notin registry
      registry.len == 0
      registry.get(nodeId).isNone()
      registry.membership(nodeId, tableId).isNone()
      registry.tableIds(nodeId).len == 0

  test "removeMembership cleans orphan peer rows without membership map":
    ## Membership missing but a peer row still exists (failed insert path).
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    discard registry.upsert(nodeId)

    check nodeId notin registry.tablesByPeer
    registry.removeMembership(nodeId, testKey(10))

    check:
      nodeId notin registry
      registry.len == 0

  test "removeMembership is a no-op for completely unknown peers":
    let registry = PeerRegistry.new()
    registry.removeMembership(testKey(1), testKey(10))
    check registry.len == 0

  test "dropTable removes memberships and orphaned peer rows":
    let registry = PeerRegistry.new()
    let peerA = testKey(1)
    let peerB = testKey(2)
    let peerC = testKey(3)
    let tableA = testKey(10)
    let tableB = testKey(20)
    let now = Moment.now()

    for peer in [peerA, peerB, peerC]:
      discard registry.upsert(peer, now)

    # peerA only in tableA → should be deleted
    registry.addMembership(peerA, tableA, now)
    # peerB in tableA and tableB → should keep tableB membership
    registry.addMembership(peerB, tableA, now)
    registry.addMembership(peerB, tableB, now)
    # peerC only in tableB → untouched
    registry.addMembership(peerC, tableB, now)

    registry.dropTable(tableA)

    check:
      peerA notin registry
      peerB in registry
      peerC in registry
      registry.len == 2
      registry.membership(peerB, tableA).isNone()
      registry.membership(peerB, tableB).isSome()
      registry.membership(peerC, tableB).isSome()
      registry.tableIds(peerB) == [tableB].toHashSet()
      registry.tableIds(peerC) == [tableB].toHashSet()

  test "dropTable is a no-op for unknown table ids":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableId = testKey(10)
    discard registry.upsert(nodeId)
    registry.addMembership(nodeId, tableId)

    registry.dropTable(testKey(99))
    check:
      nodeId in registry
      registry.membership(nodeId, tableId).isSome()

  test "dropPeer removes row and all membership tracking":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableA = testKey(10)
    let tableB = testKey(20)
    let now = Moment.now()

    discard registry.upsert(nodeId, now)
    registry.addMembership(nodeId, tableA, now)
    registry.addMembership(nodeId, tableB, now)

    registry.dropPeer(nodeId)
    check:
      nodeId notin registry
      registry.len == 0
      registry.tableIds(nodeId).len == 0
      registry.membership(nodeId, tableA).isNone()
      registry.membership(nodeId, tableB).isNone()

  test "dropPeer is a no-op for unknown peers":
    let registry = PeerRegistry.new()
    registry.dropPeer(testKey(1))
    check registry.len == 0

  test "lastActivity prefers lastUsefulAt over membership addedAt":
    let now = Moment.now()
    let membership = Membership(addedAt: now - 2.hours)
    let withoutUseful =
      PeerRecord(nodeId: testKey(1), lastSeen: now, lastUsefulAt: Opt.none(Moment))
    let withUseful = PeerRecord(
      nodeId: testKey(1), lastSeen: now, lastUsefulAt: Opt.some(now - 30.minutes)
    )

    check:
      withoutUseful.lastActivity(membership) == membership.addedAt
      withUseful.lastActivity(membership) == now - 30.minutes

  test "isReplaceable uses membership grace, not first global sighting":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableA = testKey(10)
    let tableB = testKey(20)
    let now = Moment.now()
    let grace = 1.hours

    # Peer was first seen long ago and is past grace in tableA.
    discard registry.upsert(nodeId, now - 3.hours)
    registry.addMembership(nodeId, tableA, now - 2.hours)
    # Fresh membership in tableB still has grace remaining.
    registry.addMembership(nodeId, tableB, now - 10.minutes)

    check:
      registry.isReplaceable(nodeId, tableA, grace, now)
      not registry.isReplaceable(nodeId, tableB, grace, now)

  test "isReplaceable becomes false after markUseful":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableId = testKey(10)
    let now = Moment.now()
    let grace = 1.hours

    discard registry.upsert(nodeId, now - 2.hours)
    registry.addMembership(nodeId, tableId, now - 2.hours)
    check registry.isReplaceable(nodeId, tableId, grace, now)

    registry.markUseful(nodeId, now - 10.minutes)
    check not registry.isReplaceable(nodeId, tableId, grace, now)

  test "isReplaceable is true for missing membership or peer row":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableId = testKey(10)
    let now = Moment.now()
    let grace = 1.hours

    # Completely unknown peer.
    check registry.isReplaceable(nodeId, tableId, grace, now)

    # Row exists but no membership for this table (orphan index entry).
    discard registry.upsert(nodeId, now)
    check registry.isReplaceable(nodeId, tableId, grace, now)

  test "isReplaceable accepts PeerId":
    let registry = PeerRegistry.new()
    let peerId = PeerId.init(KeyPair.random(ECDSA, rng()).get().pubkey).get()
    let nodeId = peerId.toKey()
    let tableId = testKey(10)
    let now = Moment.now()
    let grace = 1.hours

    discard registry.upsert(nodeId, now - 2.hours)
    registry.addMembership(nodeId, tableId, now - 2.hours)

    check registry.isReplaceable(peerId, tableId, grace, now)

  test "record-level isReplaceable matches lastActivity grace rule":
    let now = Moment.now()
    let membership = Membership(addedAt: now - 2.hours)
    let stale =
      PeerRecord(nodeId: testKey(1), lastSeen: now, lastUsefulAt: Opt.none(Moment))
    let useful = PeerRecord(
      nodeId: testKey(1), lastSeen: now, lastUsefulAt: Opt.some(now - 30.minutes)
    )

    check:
      stale.isReplaceable(membership, 1.hours, now)
      not useful.isReplaceable(membership, 1.hours, now)
      not stale.isReplaceable(membership, 3.hours, now)

  test "items and pairs iterate all peer rows":
    let registry = PeerRegistry.new()
    let a = testKey(1)
    let b = testKey(2)
    let now = Moment.now()

    discard registry.upsert(a, now)
    discard registry.upsert(b, now)

    var fromItems = initHashSet[Key]()
    for record in registry.items:
      fromItems.incl(record.nodeId)

    var fromPairs = initHashSet[Key]()
    for nodeId, record in registry.pairs:
      check nodeId == record.nodeId
      fromPairs.incl(nodeId)

    check:
      fromItems == [a, b].toHashSet()
      fromPairs == [a, b].toHashSet()

  test "withRecord mutates the stored peer row":
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let now = Moment.now()
    discard registry.upsert(nodeId, now)

    registry.withRecord(nodeId, record):
      record[].lastUsefulAt = Opt.some(now)
      record[].lastSeen = now + 1.seconds

    let stored = registry.get(nodeId).get()
    check:
      stored.lastUsefulAt == now
      stored.lastSeen == now + 1.seconds

  test "shared row: usefulness is global across table memberships":
    ## One successful answer refreshes usefulness for every table that indexes
    ## the peer, even though each table keeps its own membership addedAt.
    let registry = PeerRegistry.new()
    let nodeId = testKey(1)
    let tableA = testKey(10)
    let tableB = testKey(20)
    let now = Moment.now()
    let grace = 1.hours

    discard registry.upsert(nodeId, now - 3.hours)
    registry.addMembership(nodeId, tableA, now - 2.hours)
    registry.addMembership(nodeId, tableB, now - 90.minutes)

    check:
      registry.isReplaceable(nodeId, tableA, grace, now)
      registry.isReplaceable(nodeId, tableB, grace, now)

    registry.markUseful(nodeId, now - 5.minutes)

    check:
      not registry.isReplaceable(nodeId, tableA, grace, now)
      not registry.isReplaceable(nodeId, tableB, grace, now)
      registry.membership(nodeId, tableA).get().addedAt == now - 2.hours
      registry.membership(nodeId, tableB).get().addedAt == now - 90.minutes
      registry.len == 1
