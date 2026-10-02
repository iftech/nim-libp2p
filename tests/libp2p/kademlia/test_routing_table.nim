# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, algorithm, sets
import ../../../libp2p/[protocols/kademlia, crypto/crypto]
import ../../tools/[unittest, crypto]

proc testKey*(x: byte): Key =
  var buf: array[IdLength, byte]
  buf[31] = x
  return Key(@buf)

proc randomTestKey(): Key =
  var buf = newSeqUninit[byte](IdLength)
  rng().generate(buf)
  Key(buf)

proc keyWithLeadingZeros(n: int): Key =
  ## Key whose XOR distance to an all-zero selfId under `noOpHasher` has
  ## exactly `n` leading zero bits.
  doAssert n < IdLength * 8, "an all-zero key has no first set bit"
  var buf: array[IdLength, byte]
  buf[n div 8] = 0x80'u8 shr (n mod 8)
  return Key(@buf)

suite "KadDHT Routing Table":
  const TargetBucket = 6

  proc keyInBucket(rt: RoutingTable, bucket: int): Key =
    randomKeyInBucket(rt, bucket, rng()).expect("bucket is reachable")

  proc agePastGrace(rt: RoutingTable, bucketIdx: int) =
    ## Push every peer past the usefulness grace period so eviction can act.
    let past = Moment.now() - 2.hours
    for nodeId in rt.buckets[bucketIdx].peers:
      rt.registry.withRecord(nodeId, record):
        record[].lastUsefulAt = Opt.none(Moment)
        record[].lastSeen = past
      rt.registry.tablesByPeer.withValue(nodeId, tables):
        tables[].withValue(rt.selfId, m):
          m[].addedAt = past

  test "inserts single key in correct bucket":
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId)
    let other = testKey(0b10000000)
    discard rt.insert(other)

    let idx = rt.bucketIndex(other)
    check:
      rt.buckets.len > idx
      rt.buckets[idx].peers.len == 1
      rt.buckets[idx].peers[0] == other
      other in rt.registry

  test "does not insert self":
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId)

    check not rt.insert(selfId)

  test "samples peers closest to a target instead of closest to self":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for bucket in [1, 3, TargetBucket]:
      check rt.insert(rt.keyInBucket(bucket))

    # With `noOpHasher` a key is its own hash, so a peer is at distance 0 from
    # itself and lands in the last bucket of a view centred on it.
    let target = rt.buckets[1].peers[0]
    check rt.randomPeersClosestFirst(target, rng(), 1) == @[target]

    # Centred on self, the same table starts from its own closest bucket.
    check rt.randomPeersClosestFirst(rng(), 1) == @[rt.buckets[TargetBucket].peers[0]]

  test "a view centred on a target clamps deep peers into its last bucket":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for bucket in [0, 1, 3, TargetBucket]:
      check rt.insert(rt.keyInBucket(bucket))

    # Seen from the bucket-1 peer, the bucket-0 peer shares no prefix bit, and
    # the peer itself and the bucket-3 and bucket-6 peers share at least one. A
    # 2-bucket view puts those three together in its last bucket.
    let target = rt.buckets[1].peers[0]
    let farPeer = rt.buckets[0].peers[0]
    let nearPeers = [target, rt.buckets[3].peers[0], rt.buckets[TargetBucket].peers[0]]

    let all = rt.randomPeersClosestFirst(target, rng(), 4, maxBuckets = 2)
    check:
      all.len == 4
      all[0 .. 2].toHashSet() == nearPeers.toHashSet()
      all[3] == farPeer

    let capped =
      rt.randomPeersClosestFirst(target, rng(), 4, maxPerBucket = 1, maxBuckets = 2)
    check:
      capped.len == 2
      capped[0] in nearPeers
      capped[1] == farPeer

    check rt.randomPeersClosestFirst(target, rng(), 0, maxBuckets = 2).len == 0

  test "sampling drops every excluded key":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for bucket in [1, 3, TargetBucket]:
      check rt.insert(rt.keyInBucket(bucket))

    let kept = rt.buckets[3].peers[0]
    let skipped = [rt.buckets[1].peers[0], rt.buckets[TargetBucket].peers[0]]

    # Dropped before sampling, so they cannot take a slot from their buckets.
    check rt.randomPeersClosestFirst(rng(), 3, exclude = skipped) == @[kept]

    # The same in a view centred on a target, here one of the excluded keys.
    check rt.randomPeersClosestFirst(skipped[0], rng(), 3, exclude = skipped) == @[kept]

  test "does not insert beyond capacity":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication + 5:
      let kid = rt.keyInBucket(TargetBucket)
      discard rt.insert(kid)

    check TargetBucket < rt.buckets.len
    let bucket = rt.buckets[TargetBucket]
    check bucket.peers.len <= config.replication

  test "evicts oldest replaceable key at max capacity":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication + 10:
      let kid = rt.keyInBucket(TargetBucket)
      discard rt.insert(kid)

    check rt.buckets[TargetBucket].peers.len == config.replication

    # Age fresh peers past the grace period so they become evictable.
    rt.agePastGrace(TargetBucket)

    let (oldest, _) = rt.oldestPeer(TargetBucket)

    check rt.insert(rt.keyInBucket(TargetBucket))

    check:
      rt.buckets[TargetBucket].peers.len == config.replication
      not rt.buckets[TargetBucket].allKeys().contains(oldest)

  test "retains peers still within the usefulness grace period":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication:
      discard rt.insert(rt.keyInBucket(TargetBucket))

    let before = rt.buckets[TargetBucket].allKeys()
    let newcomer = rt.keyInBucket(TargetBucket)

    # Full of fresh, unproven peers: the newcomer is rejected, none evicted.
    check:
      not rt.insert(newcomer)
      rt.buckets[TargetBucket].allKeys() == before
      not rt.buckets[TargetBucket].allKeys().contains(newcomer)

  test "probed newcomer rotates out the least-recently-seen peer of the newer half":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication:
      discard rt.insert(rt.keyInBucket(TargetBucket))
    for nodeId in rt.buckets[TargetBucket].peers:
      rt.markUseful(nodeId)

    let longestHeld = rt.buckets[TargetBucket].peers[0]
    let victim = rt.buckets[TargetBucket].peers[^1]
    rt.registry.withRecord(longestHeld, record):
      record[].lastSeen = Moment.now() - 2.hours
    rt.registry.withRecord(victim, record):
      record[].lastSeen = Moment.now() - 1.hours
    let newcomer = rt.keyInBucket(TargetBucket)

    check:
      rt.insert(newcomer, probed = true)
      rt.buckets[TargetBucket].peers.len == config.replication
      rt.buckets[TargetBucket].allKeys().contains(newcomer)
      rt.buckets[TargetBucket].allKeys().contains(longestHeld)
      not rt.buckets[TargetBucket].allKeys().contains(victim)

  test "rotation never evicts the longest-held half of a bucket":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication:
      discard rt.insert(rt.keyInBucket(TargetBucket))
    let stable = rt.buckets[TargetBucket].peers[0 ..< config.replication div 2]

    for _ in 0 ..< config.replication:
      rt.buckets[TargetBucket].lastRotation = Opt.none(Moment)
      check rt.insert(rt.keyInBucket(TargetBucket), probed = true)

    for nodeId in stable:
      check rt.buckets[TargetBucket].allKeys().contains(nodeId)

  test "rotation admits one probed newcomer per interval":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication:
      discard rt.insert(rt.keyInBucket(TargetBucket))

    check rt.insert(rt.keyInBucket(TargetBucket), probed = true)

    let before = rt.buckets[TargetBucket].allKeys()
    check:
      not rt.insert(rt.keyInBucket(TargetBucket), probed = true)
      rt.buckets[TargetBucket].allKeys() == before

    rt.buckets[TargetBucket].lastRotation =
      Opt.some(Moment.now() - BucketRotationInterval)
    check rt.insert(rt.keyInBucket(TargetBucket), probed = true)

  test "markUseful protects a peer from eviction":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication:
      discard rt.insert(rt.keyInBucket(TargetBucket))

    rt.agePastGrace(TargetBucket)

    # Marking the oldest-seen peer useful spares it and evicts a different one.
    let (oldest, _) = rt.oldestPeer(TargetBucket)
    rt.markUseful(oldest)

    check rt.insert(rt.keyInBucket(TargetBucket))
    check rt.buckets[TargetBucket].allKeys().contains(oldest)

  test "re-insert existing key updates lastSeen":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)

    let key1 = rt.keyInBucket(TargetBucket)
    let key2 = rt.keyInBucket(TargetBucket)
    let key3 = rt.keyInBucket(TargetBucket)

    discard rt.insert(key1)
    discard rt.insert(key2)
    discard rt.insert(key3)

    check rt.buckets[TargetBucket].peers[0] == key1

    let previousLastSeen = rt.registry.get(key1).get().lastSeen

    discard rt.insert(key1)

    # Re-inserting existing key updates lastSeen without changing bucket position
    check:
      rt.buckets[TargetBucket].peers[0] == key1
      rt.registry.get(key1).get().lastSeen > previousLastSeen

  test "findClosest returns sorted keys":
    let selfId = testKey(0)
    var rt = RoutingTable.new(
      selfId, config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    )
    let ids = @[testKey(1), testKey(2), testKey(3), testKey(4), testKey(5)]
    for id in ids:
      discard rt.insert(id)

    const peerCount = 3
    let res = rt.findClosest(testKey(1), peerCount)

    check:
      res.len == peerCount
      res == @[testKey(1), testKey(3), testKey(2)]

  test "findClosest returns all keys if less than n available":
    let selfId = testKey(0)
    var rt = RoutingTable.new(
      selfId, config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    )
    let ids = @[testKey(1), testKey(2), testKey(3)]
    for id in ids:
      discard rt.insert(id)

    let res = rt.findClosest(testKey(1), 5) # n > ids.len

    check:
      res.len == ids.len
      res == @[testKey(1), testKey(3), testKey(2)]

  test "findClosest hashes the target on a selfIdPreHashed table too":
    # Only selfId is pre-hashed, so a raw target key is hashed like the peers are.
    let selfId = testKey(0)
    let config =
      RoutingTableConfig.new(hasher = Opt.none(XorDHasher), selfIdPreHashed = true)
    var rt = RoutingTable.new(selfId, config)
    let p1 = testKey(1)
    let p2 = testKey(2)
    let p3 = testKey(3)
    for p in [p1, p2, p3]:
      discard rt.insert(p)

    let target = testKey(0x10)
    let res = rt.findClosest(target, 3)

    var expected = @[p1, p2, p3]
    let hasher = config.hasher
    expected.sort(
      proc(a, b: Key): int =
        cmp(
          xorDistance(
            Key.fromBytes(a.hashFor(hasher)), Key.fromBytes(target.hashFor(hasher))
          ),
          xorDistance(
            Key.fromBytes(b.hashFor(hasher)), Key.fromBytes(target.hashFor(hasher))
          ),
        )
    )
    check res == expected

  test "isStale returns true for empty or old keys":
    let registry = PeerRegistry.new()
    var bucket: Bucket
    check isStale(bucket, registry) == true

    let oldKey = testKey(1)
    discard registry.upsert(oldKey)
    registry.peers.withValue(oldKey, record):
      record[].lastSeen = Moment.now() - 40.minutes
    bucket.peers = @[oldKey]
    check isStale(bucket, registry) == true

    let freshKey = testKey(2)
    discard registry.upsert(freshKey)
    bucket.peers = @[freshKey]
    check isStale(bucket, registry) == false

  test "removePeer removes an existing entry":
    let selfId = testKey(0)
    var rt = RoutingTable.new(
      selfId, config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    )
    let key = rt.keyInBucket(TargetBucket)
    check:
      rt.insert(key)
      key in rt
      key in rt.registry

    check:
      rt.removePeer(key)
      key notin rt
      key notin rt.registry

    check not rt.removePeer(key) # already gone

  test "removePeer rejects self and localNodeId":
    let selfId = testKey(0)
    let localNodeId = testKey(99)
    var rt = RoutingTable.new(selfId, localNodeId = Opt.some(localNodeId))
    check:
      not rt.removePeer(selfId)
      not rt.removePeer(localNodeId)

  test "isReplaceable follows grace period from membership addedAt":
    let now = Moment.now()
    let record =
      PeerRecord(nodeId: testKey(1), lastSeen: now, lastUsefulAt: Opt.none(Moment))
    let oldMembership = Membership(addedAt: now - 2.hours)
    check record.isReplaceable(oldMembership, 1.hours, now)

    let useful = PeerRecord(
      nodeId: testKey(1), lastSeen: now, lastUsefulAt: Opt.some(now - 30.minutes)
    )
    check not useful.isReplaceable(oldMembership, 1.hours, now)

  test "shared registry: one peer row across two tables":
    let registry = PeerRegistry.new()
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var mainRt = RoutingTable.new(testKey(0), config, registry = registry)
    var serviceRt = RoutingTable.new(
      testKey(0xFF),
      RoutingTableConfig.new(
        hasher = Opt.some(noOpHasher), maxBuckets = 16, selfIdPreHashed = true
      ),
      localNodeId = Opt.some(mainRt.localNodeId),
      registry = registry,
    )

    let peer = testKey(1)
    check mainRt.insert(peer)
    check serviceRt.insert(peer)

    check:
      registry.len == 1
      peer in mainRt
      peer in serviceRt
      registry.tableIds(peer).len == 2

    mainRt.markUseful(peer)
    check registry.get(peer).get().lastUsefulAt.isSome()

    check serviceRt.removePeer(peer)
    check:
      peer in mainRt
      peer notin serviceRt
      peer in registry
      registry.tableIds(peer).len == 1

    check mainRt.removePeer(peer)
    check:
      peer notin registry
      registry.len == 0

  test "seeded service membership gets fresh grace window":
    ## An aged main-table peer must not be immediately replaceable in a new
    ## service table that just indexed it.
    let registry = PeerRegistry.new()
    let config = RoutingTableConfig.new(
      hasher = Opt.some(noOpHasher), usefulnessGracePeriod = 1.hours
    )
    var mainRt = RoutingTable.new(testKey(0), config, registry = registry)
    let peer = testKey(1)
    check mainRt.insert(peer)

    let past = Moment.now() - 2.hours
    registry.withRecord(peer, record):
      record[].lastUsefulAt = Opt.none(Moment)
      record[].lastSeen = past
    registry.tablesByPeer.withValue(peer, tables):
      tables[].withValue(mainRt.selfId, m):
        m[].addedAt = past

    check mainRt.isReplaceable(peer, 1.hours, Moment.now())

    var serviceRt = RoutingTable.new(
      testKey(0xFF),
      RoutingTableConfig.new(
        hasher = Opt.some(noOpHasher),
        maxBuckets = 16,
        selfIdPreHashed = true,
        usefulnessGracePeriod = 1.hours,
      ),
      localNodeId = Opt.some(mainRt.localNodeId),
      registry = registry,
    )
    check serviceRt.insert(peer)
    check not serviceRt.isReplaceable(peer, 1.hours, Moment.now())

  test "orphan bucket key is replaceable and preferred for eviction":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    for _ in 0 ..< config.replication:
      discard rt.insert(rt.keyInBucket(TargetBucket))

    # Corrupt: leave a key in the bucket but drop its registry row.
    let orphan = rt.buckets[TargetBucket].peers[0]
    rt.registry.dropPeer(orphan)
    check rt.registry.isReplaceable(
      orphan, rt.selfId, config.usefulnessGracePeriod, Moment.now()
    )

    let newcomer = rt.keyInBucket(TargetBucket)
    check rt.insert(newcomer)
    check:
      newcomer in rt.buckets[TargetBucket].peers
      orphan notin rt.buckets[TargetBucket].peers

  test "detachAll drops memberships and blocks further inserts":
    let registry = PeerRegistry.new()
    var rt = RoutingTable.new(testKey(0), registry = registry)
    let peer = testKey(1)
    check rt.insert(peer)
    check peer in registry

    rt.detachAll()
    check:
      rt.detached
      peer notin registry
      rt.buckets.len == 0
      not rt.insert(testKey(2))

  test "randomKeyInBucket returns id at correct distance":
    let selfId = testKey(0)
    var rt =
      RoutingTable.new(selfId, RoutingTableConfig.new(hasher = Opt.some(noOpHasher)))
    let rid = randomKeyInBucket(rt, TargetBucket, rng()).expect("bucket is reachable")
    let idx = rt.bucketIndex(rid)
    check:
      idx == TargetBucket
      rid != selfId

  test "bucketIndex is the prefix length, not a rescale of it":
    let selfId = testKey(0)
    var rt =
      RoutingTable.new(selfId, RoutingTableConfig.new(hasher = Opt.some(noOpHasher)))

    for lz in 0 .. 8:
      check rt.bucketIndex(keyWithLeadingZeros(lz)) == lz

  test "small maxBuckets keeps prefix resolution and saturates the last bucket":
    let selfId = testKey(0)
    const MaxBuckets = 16
    var rt = RoutingTable.new(
      selfId,
      RoutingTableConfig.new(hasher = Opt.some(noOpHasher), maxBuckets = MaxBuckets),
    )

    # Prefix lengths below the cap each get their own bucket.
    for lz in 0 ..< MaxBuckets - 1:
      check rt.bucketIndex(keyWithLeadingZeros(lz)) == lz

    # Deeper prefixes all fall into the last bucket.
    for lz in MaxBuckets - 1 .. MaxBuckets + 8:
      check rt.bucketIndex(keyWithLeadingZeros(lz)) == MaxBuckets - 1

  test "randomKeyInBucket targets the bucket under the default (hashing) hasher":
    # The bucket of a key is decided by its *hash*, so a target built by
    # manipulating selfId's bits lands in an unrelated bucket once hashed.
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId, RoutingTableConfig.new())

    for bucket in [0, 1, TargetBucket, MaxRefreshLeadingZeros]:
      for _ in 0 ..< 5:
        let rid = randomKeyInBucket(rt, bucket, rng()).expect("bucket is reachable")
        check rt.bucketIndex(rid) == bucket

  test "randomKeyInBucket returns none for buckets too near to search for":
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId, RoutingTableConfig.new())

    check randomKeyInBucket(rt, MaxRefreshLeadingZeros + 1, rng()).isNone()

  test "randomKeyInBucket respects a narrow bucket split":
    # Service-discovery tables split the id space into few buckets.
    const MaxBuckets = 16
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId, RoutingTableConfig.new(maxBuckets = MaxBuckets))

    for bucket in 0 .. MaxRefreshLeadingZeros:
      let rid = randomKeyInBucket(rt, bucket, rng()).expect("bucket is reachable")
      check rt.bucketIndex(rid) == bucket

    # The last bucket needs 15 shared prefix bits — beyond the cap.
    check randomKeyInBucket(rt, MaxBuckets - 1, rng()).isNone()

  test "refreshTarget falls back to a peer of a bucket too near to search for":
    # Buckets past the cap share too long a prefix with selfId to draw at random.
    const NearBucket = MaxRefreshLeadingZeros + 1
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId, RoutingTableConfig.new())

    var inserted: seq[Key]
    while inserted.len < 3:
      let key = randomTestKey()
      if rt.bucketIndex(key) != NearBucket:
        continue
      discard rt.insert(key)
      inserted.add(key)

    check randomKeyInBucket(rt, NearBucket, rng()).isNone()

    let target = rt.refreshTarget(NearBucket, rng()).expect("bucket holds peers")
    check:
      target in inserted
      rt.bucketIndex(target) == NearBucket

  test "refreshTarget returns none for an unreachable empty bucket":
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId, RoutingTableConfig.new())

    check rt.refreshTarget(MaxRefreshLeadingZeros + 1, rng()).isNone()

  test "refreshTarget prefers a random key when the bucket is reachable":
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId, RoutingTableConfig.new())
    let peer = rt.keyInBucket(TargetBucket)
    discard rt.insert(peer)

    let target = rt.refreshTarget(TargetBucket, rng()).expect("bucket is reachable")
    check:
      target != peer
      rt.bucketIndex(target) == TargetBucket

  proc checkNearestToCenter(rt: RoutingTable, target: Key, candidates: seq[Key]) =
    let targetDist =
      xorDistance(rt.selfId, Key.fromBytes(target.hashFor(rt.config.hasher)))
    for candidate in candidates:
      check targetDist <=
        xorDistance(rt.selfId, Key.fromBytes(candidate.hashFor(rt.config.hasher)))

  test "refreshSelfTarget is selfId when the table centers on a raw key":
    let selfId = testKey(0)
    var rt = RoutingTable.new(selfId, RoutingTableConfig.new())
    discard rt.insert(testKey(1))

    check rt.refreshSelfTarget() == Opt.some(selfId)

  test "refreshSelfTarget stands in for a pre-hashed selfId with the nearest key":
    let serviceId = testKey(0)
    var rt = RoutingTable.new(serviceId, RoutingTableConfig.new(selfIdPreHashed = true))

    var peers: seq[Key]
    for i in 1'u8 .. 8'u8:
      let peer = testKey(i)
      discard rt.insert(peer)
      peers.add(peer)

    let target = rt.refreshSelfTarget().expect("table holds peers")
    check target in peers
    rt.checkNearestToCenter(target, peers)

  test "refreshSelfTarget of an empty pre-hashed table falls back to the main table":
    let serviceId = testKey(0)
    var rt = RoutingTable.new(serviceId, RoutingTableConfig.new(selfIdPreHashed = true))

    check rt.refreshSelfTarget().isNone()

    var mainRt = RoutingTable.new(testKey(0xFF))
    let candidates = @[testKey(1), testKey(2), testKey(3)]
    for candidate in candidates:
      check mainRt.insert(candidate)

    let target =
      rt.nearestToCenter(mainRt.allKeys()).expect("the main table holds peers")
    rt.checkNearestToCenter(target, candidates)

  test "randomKey returns none for empty bucket":
    var bucket: Bucket
    check randomKey(bucket, rng()).isNone()

  test "randomKey returns the only peer in a single-peer bucket":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    let key = rt.keyInBucket(TargetBucket)
    discard rt.insert(key)

    let picked = randomKey(rt.buckets[TargetBucket], rng())
    check:
      picked.isSome()
      picked.get() == key

  test "randomKey returns a peer from the bucket":
    let selfId = testKey(0)
    let config = RoutingTableConfig.new(hasher = Opt.some(noOpHasher))
    var rt = RoutingTable.new(selfId, config)
    var keys: seq[Key]
    for _ in 0 ..< config.replication:
      let k = rt.keyInBucket(TargetBucket)
      keys.add(k)
      discard rt.insert(k)

    let picked = randomKey(rt.buckets[TargetBucket], rng())
    check:
      picked.isSome()
      keys.contains(picked.get())

  test "insert rejects localNodeId even when it differs from selfId":
    let selfId = testKey(0)
    let localNodeId = testKey(99)
    let peer = testKey(1)
    var rt = RoutingTable.new(selfId, localNodeId = Opt.some(localNodeId))

    check:
      not rt.insert(localNodeId) # localNodeId is rejected
      not rt.insert(selfId) # selfId is rejected
      rt.insert(peer) # other peers are accepted

  test "an empty table has no peer to replace or remove and its buckets are stale":
    let rt = RoutingTable.new(testKey(0))
    let peer = testKey(1)

    check:
      not rt.isReplaceable(peer, 1.hours, Moment.now())
      not rt.removePeer(peer)
      rt.isStale(rt.bucketIndex(peer))

  test "a detached table no longer marks peers useful":
    let registry = PeerRegistry.new()
    let peer = testKey(1)
    let mainRt = RoutingTable.new(testKey(0), registry = registry)
    let serviceRt = RoutingTable.new(testKey(0xFF), registry = registry)
    check:
      mainRt.insert(peer)
      serviceRt.insert(peer)

    serviceRt.detachAll()
    serviceRt.markUseful(peer)

    check registry.get(peer).expect("mainRt holds the peer").lastUsefulAt.isNone()

  test "randomPeersClosestFirst returns nothing for a non-positive count":
    let rt = RoutingTable.new(testKey(0))
    check rt.insert(testKey(1))

    check:
      rt.randomPeersClosestFirst(rng(), 0).len == 0
      rt.randomPeersClosestFirst(testKey(1), rng(), 0).len == 0
