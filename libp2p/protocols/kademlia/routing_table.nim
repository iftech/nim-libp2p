# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Routing tables are virtual indexes over a shared ``PeerRegistry``.
## Buckets hold peer ``Key`` references only; liveness state lives on the
## registry row. Multiple tables (main Kad + per-service) share one registry.

import algorithm, sequtils
import chronos, chronicles, results
import ./types
import ./peer_registry
import ./kademlia_metrics
import ../../peerid
import ../../crypto/crypto

logScope:
  topics = "kad-dht rtable"

const NoneHasher = Opt.none(XorDHasher)

proc new*(
    T: typedesc[RoutingTableConfig],
    replication = DefaultReplication,
    hasher: Opt[XorDHasher] = NoneHasher,
    maxBuckets: int = DefaultMaxBuckets,
    selfIdPreHashed = false,
    usefulnessGracePeriod: Duration = DefaultUsefulnessGracePeriod,
    bucketStaleTime: Duration = DefaultBucketStaleTime,
): T =
  doAssert maxBuckets > 0 and maxBuckets <= MaxBucketsLimit,
    "maxBuckets must be in 1 .. " & $MaxBucketsLimit
  RoutingTableConfig(
    replication: replication,
    hasher: hasher,
    maxBuckets: maxBuckets,
    selfIdPreHashed: selfIdPreHashed,
    usefulnessGracePeriod: usefulnessGracePeriod,
    bucketStaleTime: bucketStaleTime,
  )

proc `$`*(rt: RoutingTable): string =
  "selfId(" & $rt.selfId & ") buckets(" & $rt.buckets & ")"

proc new*(
    T: typedesc[RoutingTable],
    selfId: Key,
    config: RoutingTableConfig = RoutingTableConfig.new(),
    localNodeId: Opt[Key] = Opt.none(Key),
    registry: PeerRegistry = PeerRegistry.new(),
): T =
  ## ``registry`` is shared across tables on the same node. Unit tests may omit
  ## it and get a private registry for a single-table setup.
  RoutingTable(
    selfId: selfId,
    localNodeId: localNodeId.get(selfId),
    buckets: @[],
    config: config,
    registry: registry,
  )

func bucketCount(maxBuckets: int): int =
  clamp(maxBuckets, 1, MaxBucketsLimit)

func selfHash(rtable: RoutingTable): Key =
  if rtable.config.selfIdPreHashed:
    rtable.selfId
  else:
    Key.fromBytes(rtable.selfId.hashFor(rtable.config.hasher))

func bucketIndexFor(rtable: RoutingTable, selfHash: Key, key: Key): int =
  let lz = xorDistance(selfHash, Key.fromBytes(key.hashFor(rtable.config.hasher)))
    .leadingZeros()

  min(lz, bucketCount(rtable.config.maxBuckets) - 1)

func bucketIndex*(rtable: RoutingTable, key: Key): int =
  rtable.bucketIndexFor(rtable.selfHash(), key)

func commonPrefixLen*(rtable: RoutingTable, key: Key): int =
  ## Leading bits `key` shares with self: the bucket index before clamping.
  xorDistance(rtable.selfHash(), Key.fromBytes(key.hashFor(rtable.config.hasher)))
    .leadingZeros()

func nPeersForCpl*(rtable: RoutingTable, cpl: int): int =
  ## Fullness of the bucket holding the peers that share `cpl` bits with self.
  var count = 0
  for bucket in rtable.buckets:
    count += bucket.peers.countIt(rtable.commonPrefixLen(it) == cpl)
  count

func peerCount*(rtable: RoutingTable): int =
  var count = 0
  for bucket in rtable.buckets:
    count += bucket.peers.len
  count

proc peerIndexInBucket(bucket: Bucket, nodeId: Key): Opt[int] =
  let i = bucket.peers.find(nodeId)
  if i < 0:
    return Opt.none(int)
  Opt.some(i)

proc oldestPeer*(bucket: Bucket, registry: PeerRegistry): (Key, int) =
  ## Least-recently-seen peer key in the bucket (by registry ``lastSeen``).
  ## Orphan keys (no registry row) sort as oldest so they are preferred for eviction.
  var oldestIdx = 0
  var oldestKey = bucket.peers[0]
  var oldestSeen = Moment.low
  var found = false
  for i, p in bucket.peers:
    var seen = Moment.low
    registry.get(p).withValue(record):
      seen = record.lastSeen
    if not found or seen < oldestSeen:
      oldestKey = p
      oldestIdx = i
      oldestSeen = seen
      found = true
  (oldestKey, oldestIdx)

proc oldestPeer*(rtable: RoutingTable, bucketIndex: int): (Key, int) =
  rtable.buckets[bucketIndex].oldestPeer(rtable.registry)

proc isReplaceable*(
    rtable: RoutingTable, peerId: PeerId, gracePeriod: Duration, now: Moment
): bool =
  ## Live-index check: false when the peer is missing from this table; true when
  ## past this table's usefulness grace (membership ``addedAt``) or an orphan.
  let nodeId = peerId.toKey()
  let idx = rtable.bucketIndex(nodeId)
  if idx >= rtable.buckets.len:
    return false
  if peerIndexInBucket(rtable.buckets[idx], nodeId).isNone():
    return false
  rtable.registry.isReplaceable(nodeId, rtable.selfId, gracePeriod, now)

proc isReplaceable*(
    rtable: RoutingTable, nodeId: Key, gracePeriod: Duration, now: Moment
): bool =
  let idx = rtable.bucketIndex(nodeId)
  if idx >= rtable.buckets.len:
    return false
  if peerIndexInBucket(rtable.buckets[idx], nodeId).isNone():
    return false
  rtable.registry.isReplaceable(nodeId, rtable.selfId, gracePeriod, now)

proc replaceableCandidate(
    rtable: RoutingTable, bucket: Bucket, gracePeriod: Duration
): Opt[int] =
  ## Least-recently-seen peer past the grace period for this table. Orphan keys
  ## (missing registry row/membership) are always eligible. ``Opt.none`` when
  ## every peer is still useful/fresh.
  let now = Moment.now()
  var candidateIdx = -1
  var oldestSeen: Moment
  for i, nodeId in bucket.peers:
    if not rtable.registry.isReplaceable(nodeId, rtable.selfId, gracePeriod, now):
      continue
    var seen = Moment.low
    rtable.registry.get(nodeId).withValue(record):
      seen = record.lastSeen
    if candidateIdx == -1 or seen < oldestSeen:
      candidateIdx = i
      oldestSeen = seen
  if candidateIdx == -1:
    return Opt.none(int)
  Opt.some(candidateIdx)

func canRotate(bucket: Bucket, now: Moment): bool =
  let last = bucket.lastRotation.valueOr:
    return true
  now - last >= BucketRotationInterval

func joinedAt(rtable: RoutingTable, nodeId: Key): Moment =
  let membership = rtable.registry.membership(nodeId, rtable.selfId).valueOr:
    return Moment.low
  membership.addedAt

proc rotationVictim(rtable: RoutingTable, bucket: Bucket): int =
  ## The longest-held half never rotates, so a flood owns at most half a bucket.
  let byAge = bucket.peers.sortedByIt(rtable.joinedAt(it))
  let (victim, _) =
    Bucket(peers: byAge[byAge.len div 2 .. ^1]).oldestPeer(rtable.registry)
  bucket.peers.find(victim)

proc tryReplacePeer(
    rtable: RoutingTable, bucket: var Bucket, newNodeId: Key, probed: bool
): bool =
  if bucket.peers.len < rtable.config.replication:
    trace "Skipping replace: bucket is not full", newNodeId = newNodeId
    return false

  let now = Moment.now()
  let idx = rtable.replaceableCandidate(bucket, rtable.config.usefulnessGracePeriod).valueOr:
    if not probed or not bucket.canRotate(now):
      trace "Skipping replace: no peer past usefulness grace period",
        newNodeId = newNodeId, probed = probed
      return false
    bucket.lastRotation = Opt.some(now)
    kad_routing_table_evictions.inc(labelValues = ["rotation"])
    rtable.rotationVictim(bucket)

  let oldId = bucket.peers[idx]
  bucket.peers[idx] = newNodeId
  rtable.registry.removeMembership(oldId, rtable.selfId)
  true

proc updateRoutingTableMetrics*(rtable: RoutingTable) =
  ## Update routing table gauge metrics
  var total = 0
  for i, b in rtable.buckets:
    total += b.peers.len
    # Only track non-empty buckets to reduce cardinality
    if b.peers.len > 0:
      kad_routing_table_bucket_size.set(b.peers.len.float64, labelValues = [$i])
  kad_routing_table_peers.set(total.float64)
  kad_routing_table_buckets.set(rtable.buckets.len.float64)

proc insert*(rtable: RoutingTable, nodeId: Key, probed = false): bool =
  ## Only a ``probed`` peer evicts a useful one, at most once per ``BucketRotationInterval``.
  if rtable.detached:
    debug "Cannot insert into detached routing table", nodeId = nodeId
    return false
  if nodeId == rtable.selfId or nodeId == rtable.localNodeId:
    debug "Cannot insert self in routing table", nodeId = nodeId
    return false # No self insertion

  let idx = rtable.bucketIndex(nodeId)

  if idx >= rtable.buckets.len:
    # expand buckets lazily if needed
    rtable.buckets.setLen(idx + 1)

  var bucket = rtable.buckets[idx]
  let keyx = peerIndexInBucket(bucket, nodeId)
  if keyx.isSome:
    discard rtable.registry.upsert(nodeId)
    return true
  elif bucket.peers.len < rtable.config.replication:
    discard rtable.registry.upsert(nodeId)
    bucket.peers.add(nodeId)
    rtable.registry.addMembership(nodeId, rtable.selfId)
    kad_routing_table_insertions.inc()
  else:
    # Leave any pre-existing registry row alone; do not create a row without membership.
    if not rtable.tryReplacePeer(bucket, nodeId, probed):
      debug "Cannot insert, no replaceable peer in bucket",
        bucket = idx, nodeId = nodeId
      return false
    discard rtable.registry.upsert(nodeId)
    rtable.registry.addMembership(nodeId, rtable.selfId)
    kad_routing_table_replacements.inc()

  rtable.buckets[idx] = bucket
  updateRoutingTableMetrics(rtable)
  return true

proc insert*(rtable: RoutingTable, peerId: PeerId, probed = false): bool =
  insert(rtable, peerId.toKey(), probed)

proc removePeer*(rtable: RoutingTable, nodeId: Key, reason = "remove"): bool =
  ## Removes ``nodeId`` from this index. Returns true if it was present.
  ## Drops the registry row when no other table still references the peer.
  ## ``reason`` labels the ``kad_routing_table_evictions`` metric
  ## (e.g. ``"liveness"``, ``"remove"``).
  if nodeId == rtable.selfId or nodeId == rtable.localNodeId:
    return false

  let idx = rtable.bucketIndex(nodeId)
  if idx >= rtable.buckets.len:
    return false

  let pos = peerIndexInBucket(rtable.buckets[idx], nodeId).valueOr:
    return false

  rtable.buckets[idx].peers.delete(pos)
  rtable.registry.removeMembership(nodeId, rtable.selfId)
  kad_routing_table_evictions.inc(labelValues = [reason])
  updateRoutingTableMetrics(rtable)
  true

proc removePeer*(rtable: RoutingTable, peerId: PeerId, reason = "remove"): bool =
  removePeer(rtable, peerId.toKey(), reason)

proc detachAll*(rtable: RoutingTable) =
  ## Drop this table's memberships from the shared registry and empty buckets.
  ## Call when the table is destroyed (e.g. service uninterest).
  rtable.detached = true
  rtable.registry.dropTable(rtable.selfId)
  rtable.buckets = @[]
  updateRoutingTableMetrics(rtable)

proc contains*(rtable: RoutingTable, nodeId: Key): bool =
  ## Scans only the node's bucket, not the whole table.
  let idx = rtable.bucketIndex(nodeId)
  if idx >= rtable.buckets.len:
    return false
  peerIndexInBucket(rtable.buckets[idx], nodeId).isSome()

proc markUseful*(rtable: RoutingTable, nodeId: Key) =
  ## Records that ``nodeId`` answered a query. Updates the shared registry row
  ## so every index that references the peer sees the new usefulness. No-op when
  ## the table is detached or the peer has no registry row (not in any table).
  if rtable.detached:
    return
  rtable.registry.markUseful(nodeId)

proc markUseful*(rtable: RoutingTable, peerId: PeerId) =
  rtable.markUseful(peerId.toKey())

proc findClosest*(rtable: RoutingTable, targetId: Key, count: int): seq[Key] =
  ## Up to `count` nodes closest to `targetId`, which is hashed like every other key.
  var allNodes: seq[Key] = @[]

  for bucket in rtable.buckets:
    for p in bucket.peers:
      allNodes.add(p)

  let hasher = rtable.config.hasher
  let targetHash = Key.fromBytes(targetId.hashFor(hasher))

  allNodes.sort(
    proc(a, b: Key): int =
      cmp(
        xorDistance(Key.fromBytes(a.hashFor(hasher)), targetHash),
        xorDistance(Key.fromBytes(b.hashFor(hasher)), targetHash),
      )
  )

  return allNodes[0 ..< min(count, allNodes.len)]

proc findClosestPeerIds*(rtable: RoutingTable, targetId: Key, count: int): seq[PeerId] =
  findClosest(rtable, targetId, count).toPeerIds()

proc randomPeersClosestFirst*(
    rtable: RoutingTable, rng: Rng, count: int, maxPerBucket = high(int)
): seq[Key] =
  ## Returns up to `count` peers sampled randomly from the routing table's
  ## buckets, starting from the closest buckets (highest indices) and moving
  ## to farther buckets (lower indices).

  if count <= 0:
    return @[]

  var selected: seq[Key] = @[]
  var remaining = count

  for i in countdown(rtable.buckets.high, 0):
    if remaining <= 0:
      break
    let bucket = rtable.buckets[i]
    if bucket.peers.len == 0:
      continue

    let take = min(remaining, min(maxPerBucket, bucket.peers.len))
    let picked = rng.pick(bucket.peers, take).valueOr(@[])
    for nodeId in picked:
      selected.add(nodeId)
      remaining.dec
      if remaining <= 0:
        break

  return selected

proc randomPeersClosestFirstPeerIds*(
    rtable: RoutingTable, rng: Rng, count: int, maxPerBucket = high(int)
): seq[PeerId] =
  randomPeersClosestFirst(rtable, rng, count, maxPerBucket).toPeerIds()

proc isStale*(
    bucket: Bucket, registry: PeerRegistry, staleTime: Duration = DefaultBucketStaleTime
): bool =
  ## True when the bucket is empty or any peer has not been seen for longer than
  ## ``staleTime``. Used only to decide whether to refresh the bucket, not to
  ## remove peers.
  if bucket.peers.len == 0:
    return true
  for nodeId in bucket.peers:
    let record = registry.get(nodeId).valueOr:
      return true
    if Moment.now() - record.lastSeen > staleTime:
      return true
  return false

proc isStale*(rtable: RoutingTable, bucketIndex: int): bool =
  if bucketIndex notin 0 ..< rtable.buckets.len:
    return true
  rtable.buckets[bucketIndex].isStale(rtable.registry, rtable.config.bucketStaleTime)

proc randomKeyInBucket*(rtable: RoutingTable, bucketIndex: int, rng: Rng): Opt[Key] =
  let lz = clamp(bucketIndex, 0, bucketCount(rtable.config.maxBuckets) - 1)
  if lz > MaxRefreshLeadingZeros:
    return Opt.none(Key)

  # A draw hits the bucket with probability ~2^-(lz+1); overshooting is free.
  let maxAttempts = 32 shl lz
  let selfHash = rtable.selfHash()
  var key = newSeqUninit[byte](IdLength)

  for _ in 0 ..< maxAttempts:
    rng.generate(key)
    if rtable.bucketIndexFor(selfHash, Key.fromBytes(key)) == lz:
      return Opt.some(Key.fromBytes(key))

  Opt.none(Key)

proc allKeys*(bucket: Bucket): seq[Key] =
  return bucket.peers

proc allKeys*(rtable: RoutingTable): seq[Key] =
  rtable.buckets.mapIt(it.allKeys()).concat()

proc randomKey*(bucket: Bucket, rng: Rng): Opt[Key] =
  rng.pickOne(bucket.peers)

proc nearestToCenter*(
    rtable: RoutingTable, candidates: openArray[Key]
): Opt[Key] {.raises: [].} =
  ## The candidate whose hash lands closest to this table's own center.
  if candidates.len == 0:
    return Opt.none(Key)

  let selfHash = rtable.selfHash()
  var nearest = candidates[0]
  var nearestDist =
    xorDistance(selfHash, Key.fromBytes(nearest.hashFor(rtable.config.hasher)))
  for key in candidates.toOpenArray(1, candidates.high):
    let dist = xorDistance(selfHash, Key.fromBytes(key.hashFor(rtable.config.hasher)))
    if dist < nearestDist:
      nearest = key
      nearestDist = dist
  Opt.some(nearest)

proc refreshSelfTarget*(rtable: RoutingTable): Opt[Key] {.raises: [].} =
  ## Key to run a findNode against in order to refresh the table's own center.
  if not rtable.config.selfIdPreHashed:
    return Opt.some(rtable.selfId)

  # A pre-hashed selfId has no pre-image a peer could hash back to it.
  rtable.nearestToCenter(rtable.allKeys())

proc refreshTarget*(rtable: RoutingTable, bucketIndex: int, rng: Rng): Opt[Key] =
  ## Key to run a findNode against in order to refresh `bucketIndex`.
  let random = randomKeyInBucket(rtable, bucketIndex, rng)
  if random.isSome():
    return random

  # Buckets near self need a shared prefix too long to draw at random. A peer
  # the bucket already holds has that prefix by construction.
  if bucketIndex notin 0 ..< rtable.buckets.len:
    return Opt.none(Key)
  rtable.buckets[bucketIndex].randomKey(rng)
