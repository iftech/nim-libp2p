# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[tables, sequtils, sets, heapqueue, hashes]
from std/times import format, getTime, parse, toTime, toUnix, utc
import chronos, chronicles, results, sugar, stew/arrayOps, nimcrypto/sha2
import ../../[peerid, switch, multihash, cid, multicodec, peeraddrpolicy, multiaddress]
import ../../utils/[opt, shortlog]
import ../protocol
import ./[key_value, protobuf, message_sender]

export tables, sets, heapqueue, key_value, message_sender

logScope:
  topics = "libp2p kademlia"

const
  MaxBucketsLimit* = IdLength * 8
    ## a bucket per shared prefix bit; deeper prefixes than the key is long cannot exist
  MaxRegionBits* = IdLength * 8
    ## a region prefix bit per key bit; a longer prefix narrows nothing further
  DefaultMaxBuckets* = MaxBucketsLimit
  MaxRefreshLeadingZeros* = 12
  DefaultTimeout* = 5.seconds
  DefaultBucketRefreshTime* = 10.minutes
  DefaultBucketStaleTime* = 30.minutes
    ## Peer not seen for this duration marks the bucket stale (refresh trigger).
  DefaultUsefulnessGracePeriod* = 1.hours
    ## New peers resist eviction until in the table this long without proving
  BucketRotationInterval* = 1.minutes
    ## Minimum time between two evictions of useful peers from one bucket.
  DefaultLivenessGracePeriod* = 1.hours
    ## Peers with no successful outbound DHT activity within this window are
    ## probed for liveness by the background liveness loop; failures are
    ## removed from the routing table.
  DefaultLivenessIdleInterval* = 30.seconds
    ## Maximum sleep between liveness-loop iterations when no peer needs a
    ## probe. Bound so a newly replaceable peer is noticed without waiting
    ## for the next bucket-refresh tick.
  DefaultProbeBackoffMax* = 5.minutes
    ## Cap of the re-probe backoff after a failed admission probe.
  DefaultFixLowPeersInterval* = 1.minutes ## How often to check the table size.
  DefaultMinRoutingTableSize* = 10
    ## Fewer peers than this triggers a re-seed. Zero turns the re-seed off.
  DefaultRetries* = 5
  DefaultReplication* = 20 ## aka `k` in the spec
  DefaultAlpha* = 10 # concurrency parameter
  DefaultBeta* = 3 ## core lookup convergence threshold
  DefaultQuorum* = 5 # number of GetValue responses needed to decide
  DefaultProviderRecordCapacity* = 500
    # maximum number of provider records to store at once
  DefaultProvidedKeyCapacity* = 500 # maximum number of provided keys to store at once
  DefaultRepublishInterval* = 10.minutes # same as bootstrap
  DefaultCleanupProvidersInterval* = 10.minutes # same as bootstrap
  DefaultProviderExpirationInterval* = 48.hours
  DefaultRecordExpirationInterval* = 24.hours
    # KV entries older than this are considered stale and will be evicted
  DefaultCleanupDataEntriesInterval* = 1.hours # how often to scan for stale KV entries

  MaxMsgSize* = 1 shl 22 # 4 MiB

  DefaultMaxProvidersPerKey* = 20 ## upper bound on providers stored per key
  DefaultMaxShortlistSize* = DefaultReplication * 2
    ## upper bound on iterative-lookup shortlist
  DefaultMaxReceivedSize* = DefaultReplication
    ## upper bound on per-query ``ReceivedTable``
  DefaultMaxValueSize* = 3072
    ## upper bound (bytes) on a stored record value. Kept much lower than the
    ## RPC frame cap so PUT_VALUE/GET_VALUE records stay independently bounded.
  DefaultMaxLocalRecords* = 500 ## upper bound on locally stored value records
  DefaultMaxConcurrentRpcs* = 100
    ## upper bound on in-flight outbound RPCs across find/get/put/provider
  DefaultMaxConcurrentProbes* = 50
    ## upper bound on concurrent routing-table admission probes (lookupCheck)
  DefaultMaxConcurrentLivenessProbes* = 20
    ## upper bound on concurrent routing-table liveness/eviction probes
  DefaultMaxProbeFailures* = 1024 ## upper bound on cached admission-probe failures
  DefaultMaxPeersPerIp* = 4
    ## upper bound on Kademlia routing-table peers sharing one exact IP
  DefaultMaxPeersPerSubnet* = 10
    ## upper bound on Kademlia routing-table peers sharing one IP subnet
  DefaultMaxPeersPerIpPerBucket* = 2
    ## upper bound on peers of one bucket sharing one exact IP
  DefaultMaxPeersPerSubnetPerBucket* = 3
    ## upper bound on peers of one bucket sharing one IP subnet

  MaxProviderKeyLen* = 80 ## Upper bound (bytes) on an ADD_PROVIDER key

proc toCid*(k: Key): Cid =
  let cidRes = Cid.init(k.toBytes())
  if cidRes.isOk:
    cidRes.get()
  else:
    debug "Kademlia key wrapped as CID", key = k
    Cid
      .init(
        CIDv1, multiCodec("dag-pb"), MultiHash.digest("sha2-256", k.toBytes()).get()
      )
      .get()

template toKey*(mh: MultiHash): Key =
  Key.fromBytes(mh.data.buffer)

proc toKey*(c: Cid): Key =
  c.mhash().get().toKey()

proc toKey*(p: PeerId): Key =
  MultiHash.init(p.data).get().toKey()

proc toPeerId*(k: Key): Result[PeerId, string] =
  PeerId.init(k.toBytes()).mapErr(x => $x)

proc toPeer*(k: Key, switch: Switch): Result[Peer, string] =
  let peer = ?k.toPeerId()
  let addrs = switch.peerStore[AddressBook][peer]
  if addrs.len == 0:
    return err("Could not find peer addresses in address book")

  ok(
    Peer(
      id: Opt.some(peer.getBytes()),
      addrs: addrs,
      connection: Opt.none(ConnectionStatus),
    )
  )

proc toPeer*(peerInfo: PeerInfo): Peer =
  Peer(
    id: Opt.some(peerInfo.peerId.getBytes()),
    addrs: peerInfo.addrs,
    connection: Opt.none(ConnectionStatus),
  )

proc toPeers*(switch: Switch, keys: seq[Key]): seq[Peer] =
  var peers: seq[Peer]

  for p in keys:
    p.toPeer(switch).ifValue(peer):
      peers.add(peer)

  return peers

proc toPeerIds*(peers: seq[Peer]): seq[PeerId] =
  var peerIds: seq[PeerId]

  for p in peers:
    let raw = p.id.valueOr:
      continue
    let pid = PeerId.init(raw).valueOr:
      continue
    peerIds.add(pid)

  return peerIds

type XorDistance* = array[IdLength, byte]
type XorDHasher* = proc(input: seq[byte]): array[IdLength, byte] {.
  raises: [], nimcall, noSideEffect, gcsafe
.}

proc defaultHasher(
    input: seq[byte]
): array[IdLength, byte] {.raises: [], nimcall, noSideEffect, gcsafe.} =
  return sha256.digest(input).data

# useful for testing purposes
proc noOpHasher*(
    input: seq[byte]
): array[IdLength, byte] {.raises: [], nimcall, noSideEffect, gcsafe.} =
  var data: array[IdLength, byte]
  discard data.copyFrom(input)
  return data

proc countLeadingZeroBits*(b: byte): int =
  for i in 0 .. 7:
    if (b and (0x80'u8 shr i)) != 0:
      return i
  return 8

proc leadingZeros*(dist: XorDistance): int =
  for i in 0 ..< dist.len:
    if dist[i] != 0:
      return i * 8 + countLeadingZeroBits(dist[i])
  return dist.len * 8

proc cmp*(a, b: XorDistance): int =
  for i in 0 ..< IdLength:
    if a[i] < b[i]:
      return -1
    elif a[i] > b[i]:
      return 1
  return 0

proc `<`*(a, b: XorDistance): bool =
  cmp(a, b) < 0

proc `<=`*(a, b: XorDistance): bool =
  cmp(a, b) <= 0

proc hashFor*(k: Key, hasher: Opt[XorDHasher]): seq[byte] =
  return @(hasher.get(defaultHasher)(k.toBytes()))

proc xorDistance*(a, b: Key): XorDistance =
  doAssert a.len == IdLength and b.len == IdLength,
    "both keys must be " & $IdLength & " bytes"

  var response: XorDistance
  for i in 0 ..< a.len:
    response[i] = a[i] xor b[i]
  return response

proc xorDistance*(a, b: Key, hasher: Opt[XorDHasher]): XorDistance =
  xorDistance(Key.fromBytes(a.hashFor(hasher)), Key.fromBytes(b.hashFor(hasher)))

proc xorDistance*(a: PeerId, b: Key, hasher: Opt[XorDHasher]): XorDistance =
  xorDistance(a.toKey(), b, hasher)

proc xorDistance*(a: Key, b: PeerId, hasher: Opt[XorDHasher]): XorDistance =
  xorDistance(a, b.toKey(), hasher)

proc xorDistance*(a, b: PeerId, hasher: Opt[XorDHasher]): XorDistance =
  xorDistance(a.toKey(), b.toKey(), hasher)

type
  ## Per-table index membership. ``addedAt`` is when *this* table indexed the
  ## peer and starts that table's usefulness grace window.
  Membership* = object
    addedAt*: Moment

  ## DHT peer row: liveness/usefulness state lives once, independent of which
  ## routing tables index the peer. Tables only store ``Key`` references.
  PeerRecord* = object
    nodeId*: Key
    lastSeen*: Moment
    lastUsefulAt*: Opt[Moment]
      ## Set when the peer answers a query. Global: one successful answer
      ## refreshes usefulness for every table that indexes the peer.
      ## ``Opt.none`` until then; grace then uses membership ``addedAt``.

  ## Shared store of peer rows plus reverse membership (which table selfIds
  ## index each peer). Owned by ``KadDHT``; every ``RoutingTable`` shares it.
  PeerRegistry* = ref object
    peers*: Table[Key, PeerRecord]
    tablesByPeer*: Table[Key, Table[Key, Membership]]
      ## peer key → table selfId → membership (with per-table addedAt).

  ## A k-bucket is an index partition: keys only, ordered for eviction by
  ## looking up ``PeerRecord`` timestamps in the shared registry.
  Bucket* = object
    peers*: seq[Key]
    lastRotation*: Opt[Moment]

  RoutingTableConfig* = ref object
    replication*: int
    hasher*: Opt[XorDHasher]
    maxBuckets*: int
    selfIdPreHashed*: bool
    usefulnessGracePeriod*: Duration
    bucketStaleTime*: Duration

  ## Virtual routing table: k-bucket index over a shared ``PeerRegistry``.
  ## Peers are not owned by the table; membership is a reference into the registry.
  RoutingTable* = ref object
    selfId*: Key
    localNodeId*: Key
    buckets*: seq[Bucket]
    config*: RoutingTableConfig
    registry*: PeerRegistry
    detached*: bool
      ## Set by ``detachAll`` when the table is destroyed. Blocks further inserts
      ## so late admission probes cannot resurrect memberships.

  Provider* = Peer

  ProviderRecord* = object
    provider*: Provider
    expiresAt*: chronos.Moment
    key*: Key

  ProviderRecords* = ref object
    records*: HeapQueue[ProviderRecord]
    capacity*: int

  ProvidedKeys* = ref object
    provided*: Table[Key, chronos.Moment]
    capacity*: int

  ProviderManager* = ref object
    providerRecords*: ProviderRecords
    providedKeys*: ProvidedKeys
    knownKeys*: Table[Key, HashSet[Provider]]

func len*(bucket: Bucket): int =
  bucket.peers.len

func contains*(bucket: Bucket, nodeId: Key): bool =
  nodeId in bucket.peers

iterator items*(bucket: Bucket): Key =
  for nodeId in bucket.peers:
    yield nodeId

iterator items*(registry: PeerRegistry): PeerRecord =
  for record in registry.peers.values:
    yield record

iterator pairs*(registry: PeerRegistry): (Key, PeerRecord) =
  for nodeId, record in registry.peers:
    yield (nodeId, record)

template withRecord*(registry: PeerRegistry, nodeId: Key, record, body: untyped) =
  ## Mutable access to one row. ``record`` is a ``ptr PeerRecord``; body uses ``record[]``.
  registry.peers.withValue(nodeId, record):
    body

proc new*(
    T: typedesc[ProviderManager], providerRecordCapacity: int, providedKeyCapacity: int
): T =
  let pm = T()

  pm.providerRecords = ProviderRecords(capacity: providerRecordCapacity)
  pm.providedKeys = ProvidedKeys(capacity: providedKeyCapacity)

  return pm

type
  NetSizeMeasurement* = object
    distance*: float64 ## normalized XOR distance to a lookup target, in ``[0, 1]``
    weight*: float64
    timestamp*: Moment

  NetworkSizeEstimator* = ref object
    ## Network size from the distances of the closest peers seen across lookups.
    ## See ``netsize.nim`` for the math.
    bucketSize*: int
    measurements*: seq[seq[NetSizeMeasurement]] ## one bucket per closest-peer index

proc toPeerIds*(keys: seq[Key]): seq[PeerId] =
  var peerIds = newSeqOfCap[PeerId](keys.len)
  for k in keys:
    let peerId = k.toPeerId().valueOr:
      trace "Kademlia key conversion failed",
        err = error, operation = "convert key to peer ID"
      continue
    peerIds.add(peerId)
  return peerIds

## Currently a string, because for some reason, that's what is chosen at the protobuf level
## TODO: convert between RFC3339 strings and use of integers (i.e. the _correct_ way)
type Timestamp* = string

const TimestampFormat* = "yyyy-MM-dd'T'HH:mm:ss'Z'"

proc now*(T: typedesc[Timestamp]): Timestamp {.gcsafe, raises: [].} =
  T(getTime().utc.format(TimestampFormat))

proc toUnixSeconds*(
    time: Timestamp
): Result[int64, ref CatchableError] {.gcsafe, raises: [].} =
  catch:
    parse(time, TimestampFormat, utc()).toTime().toUnix()

proc nowUnixSeconds*(): int64 {.gcsafe, raises: [].} =
  getTime().toUnix()

type EntryRecord* = object
  value*: Value
  time*: Timestamp

proc init*(
    T: typedesc[EntryRecord], value: Value, time: Opt[Timestamp]
): EntryRecord {.gcsafe, raises: [].} =
  EntryRecord(value: value, time: time.get(Timestamp.now()))

type
  ReceivedTable* = TableRef[PeerId, Opt[EntryRecord]]
  CandidatePeers* = ref HashSet[PeerId]
  LocalTable* = Table[Key, EntryRecord]

proc insert*(
    self: var LocalTable, key: Key, value: sink Value, time: Timestamp
) {.raises: [].} =
  trace "Local Kademlia record stored", key, value
  self[key] = EntryRecord(value: value, time: time)

proc get*(self: LocalTable, key: Key): Opt[EntryRecord] {.raises: [].} =
  if not self.hasKey(key):
    return Opt.none(EntryRecord)
  try:
    return Opt.some(self[key])
  except KeyError:
    raiseAssert "checked with hasKey"

type EntryValidator* = ref object of RootObj
method isValid*(
    self: EntryValidator, key: Key, record: EntryRecord
): bool {.base, raises: [], gcsafe.} =
  doAssert(false, "EntryValidator base not implemented")

type EntrySelector* = ref object of RootObj
method select*(
    self: EntrySelector, key: Key, records: seq[EntryRecord]
): Result[int, string] {.base, raises: [], gcsafe.} =
  doAssert(false, "EntrySelection base not implemented")

type DefaultEntryValidator* = ref object of EntryValidator
method isValid*(
    self: DefaultEntryValidator, key: Key, record: EntryRecord
): bool {.raises: [], gcsafe.} =
  return true

type DefaultEntrySelector* = ref object of EntrySelector
method select*(
    self: DefaultEntrySelector, key: Key, records: seq[EntryRecord]
): Result[int, string] {.raises: [], gcsafe.} =
  if records.len == 0:
    return err("No records to choose from")

  # Map value -> (count, firstIndex)
  var counts: Table[Value, (int, int)]
  for i, v in records.mapIt(it.value):
    try:
      let (cnt, idx) = counts[v]
      counts[v] = (cnt + 1, idx)
    except KeyError:
      counts[v] = (1, i)

  # Find the first value with the highest count
  var bestIdx = 0
  var maxCount = -1
  var minFirstIdx = high(int)
  for _, (cnt, idx) in counts.pairs:
    if cnt > maxCount or (cnt == maxCount and idx < minFirstIdx):
      maxCount = cnt
      bestIdx = idx
      minFirstIdx = idx

  return ok(bestIdx)

type KadDHTLimits* = object
  maxProvidersPerKey*: Opt[int]
    ## Maximum number of distinct providers stored per key.
    ## ``Opt.none`` means unlimited; when limits are derived by the
    ## ``KadDHTConfig`` constructor this defaults to ``replication``.
  maxShortlistSize*: int
    ## Maximum number of peers retained in an iterative-lookup shortlist.
    ## When exceeded, farther peers are dropped so the shortlist stays bounded.
  maxReceivedSize*: int
    ## Maximum number of per-peer entries retained in a GET_VALUE
    ## ``ReceivedTable``.
  maxValueSize*: int
    ## Maximum size (bytes) of an individual record value. Enforced on
    ## ``putValue`` and on incoming PUT_VALUE / GET_VALUE records.
  maxLocalRecords*: Opt[int]
    ## Maximum number of records retained in the local value store.
    ## ``Opt.none`` means unlimited; when limits are derived by the
    ## ``KadDHTConfig`` constructor this defaults to ``DefaultMaxLocalRecords``.
  maxConcurrentRpcs*: int
    ## Maximum number of in-flight outbound RPCs (find/get/put/provider)
    ## across the whole node. Excess calls wait on a shared semaphore.
  maxConcurrentProbes*: int ## Maximum number of concurrent FIND_NODE admission probes.
  maxConcurrentLivenessProbes*: int
    ## Maximum number of concurrent liveness/eviction probes. Independent of
    ## ``maxConcurrentProbes`` so admission is never starved by eviction.
  maxProbeFailures*: int
    ## Cache size of failed admission probes; its keys come from remote replies.
  maxPeersPerIp*: int
    ## Maximum number of Kademlia routing-table peers sharing one exact IP.
  maxPeersPerIpv4Subnet*: int
    ## Maximum number of Kademlia routing-table peers sharing one IPv4 /24.
  maxPeersPerIpv6Subnet*: int
    ## Maximum number of Kademlia routing-table peers sharing one IPv6 /64.
  maxPeersPerIpPerBucket*: int
    ## Peers of one bucket sharing one exact IP; 0 or less applies the table cap.
  maxPeersPerIpv4SubnetPerBucket*: int
    ## Peers of one bucket sharing one IPv4 /24; 0 or less applies the table cap.
  maxPeersPerIpv6SubnetPerBucket*: int
    ## Peers of one bucket sharing one IPv6 /64; 0 or less applies the table cap.

type
  DiversityCap* = object
    ## Cap on the peers of one IP group, at both scopes the filter enforces.
    table*: int
    bucket*: int

  DiversityCaps* = object
    perIp*: DiversityCap
    perIpv4Subnet*: DiversityCap
    perIpv6Subnet*: DiversityCap

func diversityCap(table, bucket: int): DiversityCap =
  ## An unset (non-positive) bucket cap leaves the table cap as the only limit.
  DiversityCap(table: table, bucket: if bucket > 0: bucket else: table)

func diversityCaps*(limits: KadDHTLimits): DiversityCaps =
  DiversityCaps(
    perIp: diversityCap(limits.maxPeersPerIp, limits.maxPeersPerIpPerBucket),
    perIpv4Subnet:
      diversityCap(limits.maxPeersPerIpv4Subnet, limits.maxPeersPerIpv4SubnetPerBucket),
    perIpv6Subnet:
      diversityCap(limits.maxPeersPerIpv6Subnet, limits.maxPeersPerIpv6SubnetPerBucket),
  )

proc new*(T: typedesc[KadDHTLimits], replication: int, quorum: int): T {.raises: [].} =
  ## Builds a limits object whose shortlist/received caps and providers-per-key
  ## are sized off the actual ``replication`` and ``quorum`` so the configuration
  ## stays internally consistent (e.g. ``maxShortlistSize >= replication``,
  ## ``maxReceivedSize >= quorum``).
  T(
    maxProvidersPerKey: Opt.some(replication),
    maxShortlistSize: replication * 2,
    maxReceivedSize: max(replication, quorum),
    maxValueSize: DefaultMaxValueSize,
    maxLocalRecords: Opt.some(DefaultMaxLocalRecords),
    maxConcurrentRpcs: DefaultMaxConcurrentRpcs,
    maxConcurrentProbes: DefaultMaxConcurrentProbes,
    maxConcurrentLivenessProbes: DefaultMaxConcurrentLivenessProbes,
    maxProbeFailures: DefaultMaxProbeFailures,
    maxPeersPerIp: DefaultMaxPeersPerIp,
    maxPeersPerIpv4Subnet: DefaultMaxPeersPerSubnet,
    maxPeersPerIpv6Subnet: DefaultMaxPeersPerSubnet,
    maxPeersPerIpPerBucket: DefaultMaxPeersPerIpPerBucket,
    maxPeersPerIpv4SubnetPerBucket: DefaultMaxPeersPerSubnetPerBucket,
    maxPeersPerIpv6SubnetPerBucket: DefaultMaxPeersPerSubnetPerBucket,
  )

type KadDHTConfig* = object
  validator*: EntryValidator
  selector*: EntrySelector
  timeout*: chronos.Duration
  bucketRefreshTime*: chronos.Duration
  bootstrapTimeout*: chronos.Duration
    ## Limit of the background bootstrap that ``start`` launches.
  bucketStaleTime*: chronos.Duration
  usefulnessGracePeriod*: chronos.Duration
  livenessGracePeriod*: chronos.Duration
  livenessIdleInterval*: chronos.Duration
  probeBackoffMax*: chronos.Duration
    ## Cap of the exponential re-probe backoff, which starts at ``timeout``.
  fixLowPeersInterval*: chronos.Duration
  minRoutingTableSize*: int
  retries*: int
  replication*: int
  alpha*: int
  beta*: int
    ## Number of closest peers that must answer for the core lookup to converge.
    ## Must be in ``1 .. replication``.
  ttl*: chronos.Duration
  quorum*: int
  providerRecordCapacity*: int
  providedKeyCapacity*: int
  republishProvidedKeysInterval*: chronos.Duration
  cleanupProvidersInterval*: chronos.Duration
  providerExpirationInterval*: chronos.Duration
  recordExpirationInterval*: chronos.Duration
  cleanupDataEntriesInterval*: chronos.Duration
  addressPolicy*: PeerAddressPolicy
  hideConnectionStatus*: bool
  disableBootstrapping*: bool
  providerRejection*: bool
    ## When true, ADD_PROVIDER receivers reply with accepted/rejected on
    ## field 11; the sender spills over to farther peers when a full batch is
    ## rejected. The per-key cap (``limits.maxProvidersPerKey``) is always
    ## enforced regardless of this flag — this only controls whether
    ## rejections are acknowledged on the wire.
  republishRegionBits*: Opt[int]
    ## Overrides the keyspace prefix length that groups provided keys into
    ## republish regions, one DHT walk each. ``Opt.none`` derives it from the
    ## routing table; too few bits advertise a key to peers that are not its
    ## closest.
  optimisticProvide*: bool
    ## Dispatch ADD_PROVIDER mid-lookup to peers that pass an "in the k-closest
    ## set" probability threshold, and return once a fraction of the RPCs
    ## complete. Provides fall back to the classic path while the estimator has
    ## no network size yet.
  limits*: KadDHTLimits

proc new*(
    K: typedesc[KadDHTConfig],
    validator: EntryValidator = DefaultEntryValidator(),
    selector: EntrySelector = DefaultEntrySelector(),
    timeout: chronos.Duration = DefaultTimeout,
    bucketRefreshTime: chronos.Duration = DefaultBucketRefreshTime,
    bucketStaleTime: chronos.Duration = DefaultBucketStaleTime,
    usefulnessGracePeriod: chronos.Duration = DefaultUsefulnessGracePeriod,
    livenessGracePeriod: chronos.Duration = DefaultLivenessGracePeriod,
    livenessIdleInterval: chronos.Duration = DefaultLivenessIdleInterval,
    probeBackoffMax: chronos.Duration = DefaultProbeBackoffMax,
    fixLowPeersInterval: chronos.Duration = DefaultFixLowPeersInterval,
    minRoutingTableSize: int = DefaultMinRoutingTableSize,
    retries: int = DefaultRetries,
    replication: int = DefaultReplication,
    alpha: int = DefaultAlpha,
    beta: int = DefaultBeta,
    quorum: int = DefaultQuorum,
    providerRecordCapacity = DefaultProviderRecordCapacity,
    providedKeyCapacity = DefaultProvidedKeyCapacity,
    republishProvidedKeysInterval: chronos.Duration = DefaultRepublishInterval,
    cleanupProvidersInterval: chronos.Duration = DefaultCleanupProvidersInterval,
    providerExpirationInterval: chronos.Duration = DefaultProviderExpirationInterval,
    recordExpirationInterval: chronos.Duration = DefaultRecordExpirationInterval,
    cleanupDataEntriesInterval: chronos.Duration = DefaultCleanupDataEntriesInterval,
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
    hideConnectionStatus: bool = true,
    disableBootstrapping: bool = false,
    providerRejection: bool = false,
    republishRegionBits: Opt[int] = Opt.none(int),
    optimisticProvide: bool = true,
    limits: Opt[KadDHTLimits] = Opt.none(KadDHTLimits),
    bootstrapTimeout: chronos.Duration = bucketRefreshTime,
): K {.raises: [].} =
  let actualLimits = limits.valueOr:
    KadDHTLimits.new(replication, quorum)
  doAssert republishRegionBits.isNone or republishRegionBits.get() in 0 .. MaxRegionBits,
    "republishRegionBits must be in 0 .. " & $MaxRegionBits &
      "; use Opt.none(int) to derive it from the routing table"
  doAssert actualLimits.maxProvidersPerKey.isNone or
    actualLimits.maxProvidersPerKey.get() > 0,
    "maxProvidersPerKey must be > 0; use Opt.none(int) for unlimited"
  doAssert beta > 0, "beta must be > 0"
  doAssert beta <= replication,
    "beta must be <= replication, since the follow-up phase never reaches past the k closest peers"
  doAssert actualLimits.maxShortlistSize > 0, "maxShortlistSize must be > 0"
  doAssert actualLimits.maxReceivedSize > 0, "maxReceivedSize must be > 0"
  doAssert actualLimits.maxValueSize > 0, "maxValueSize must be > 0"
  doAssert actualLimits.maxLocalRecords.isNone or actualLimits.maxLocalRecords.get() > 0,
    "maxLocalRecords must be > 0; use Opt.none(int) for unlimited"
  doAssert actualLimits.maxConcurrentRpcs > 0, "maxConcurrentRpcs must be > 0"
  doAssert actualLimits.maxConcurrentProbes > 0, "maxConcurrentProbes must be > 0"
  doAssert actualLimits.maxConcurrentLivenessProbes > 0,
    "maxConcurrentLivenessProbes must be > 0"
  doAssert actualLimits.maxPeersPerIp > 0, "maxPeersPerIp must be > 0"
  doAssert actualLimits.maxPeersPerIpv4Subnet > 0, "maxPeersPerIpv4Subnet must be > 0"
  doAssert actualLimits.maxPeersPerIpv6Subnet > 0, "maxPeersPerIpv6Subnet must be > 0"
  doAssert actualLimits.maxShortlistSize >= replication,
    "maxShortlistSize must be >= replication so the shortlist can hold the target k-bucket"
  doAssert actualLimits.maxReceivedSize >= quorum,
    "maxReceivedSize must be >= quorum so getValue can ever satisfy quorum"
  doAssert livenessIdleInterval > 0.nanoseconds, "livenessIdleInterval must be > 0"
  doAssert actualLimits.maxProbeFailures > 0, "maxProbeFailures must be > 0"
  KadDHTConfig(
    validator: validator,
    selector: selector,
    timeout: timeout,
    bucketRefreshTime: bucketRefreshTime,
    bootstrapTimeout: bootstrapTimeout,
    bucketStaleTime: bucketStaleTime,
    usefulnessGracePeriod: usefulnessGracePeriod,
    livenessGracePeriod: livenessGracePeriod,
    livenessIdleInterval: livenessIdleInterval,
    probeBackoffMax: probeBackoffMax,
    fixLowPeersInterval: fixLowPeersInterval,
    minRoutingTableSize: minRoutingTableSize,
    retries: retries,
    replication: replication,
    alpha: alpha,
    beta: beta,
    quorum: quorum,
    providerRecordCapacity: providerRecordCapacity,
    providedKeyCapacity: providedKeyCapacity,
    republishProvidedKeysInterval: republishProvidedKeysInterval,
    cleanupProvidersInterval: cleanupProvidersInterval,
    providerExpirationInterval: providerExpirationInterval,
    recordExpirationInterval: recordExpirationInterval,
    cleanupDataEntriesInterval: cleanupDataEntriesInterval,
    addressPolicy: addressPolicy,
    hideConnectionStatus: hideConnectionStatus,
    disableBootstrapping: disableBootstrapping,
    providerRejection: providerRejection,
    republishRegionBits: republishRegionBits,
    optimisticProvide: optimisticProvide,
    limits: actualLimits,
  )

type ProbeKey* = tuple[tableId: Key, peerId: PeerId]

type ProbeFailure* = object
  count*: int ## consecutive failed admission probes
  until*: Moment ## no re-probe before this instant
  addrs*: Hash ## digest of the addresses the last failed probe dialed

type AdmitHook* = proc(peerId: PeerId) {.gcsafe, raises: [].}

type KadDHT* = ref object of LPProtocol
  switch*: Switch
  rng*: Rng
  rtable*: RoutingTable
  bootstrapFut*: Future[void]
  maintenanceLoop*: Future[void]
  livenessLoop*: Future[void]
  fixLowPeersLoop*: Future[void]
  republishLoop*: Future[void]
  expiredLoop*: Future[void]
  recordExpirationLoop*: Future[void]
  dataTable*: LocalTable
  providerManager*: ProviderManager
  nsEstimator*: NetworkSizeEstimator
    ## Drives the optimistic-provide distance thresholds.
  provideTasks*: seq[Future[void]]
    ## ADD_PROVIDER RPCs still running after an early ``optimisticProvide``.
  config*: KadDHTConfig
  bootstrapNodes*: seq[PeerInfo]
    ## Configured seed peers, kept for the re-seed in ``fixLowPeers``.
  msgSender*: MessageSender
    ## Reuses one outbound stream per peer across every RPC sent to it.
  rpcSem*: AsyncSemaphore
    ## Bounds in-flight outbound RPCs to ``config.limits.maxConcurrentRpcs``.
  admissionSem*: AsyncSemaphore
    ## Bounds concurrent admission probes to ``config.limits.maxConcurrentProbes``.
  livenessSem*: AsyncSemaphore
    ## Bounds concurrent liveness/eviction probes to
    ## ``config.limits.maxConcurrentLivenessProbes``. Independent of
    ## ``admissionSem`` so eviction never starves routing-table admission.
  admissionProbes*: Table[ProbeKey, Future[void]]
    ## In-flight admission probes, keyed by target table and candidate peer.
  probeFailures*: Table[PeerId, ProbeFailure]
    ## Keyed by peer alone: a dead peer is skipped for every routing table.
  livenessProbes*: Table[PeerId, Future[void]]
    ## In-flight liveness probes, keyed by peer only. A peer shared across
    ## multiple routing tables (main Kad + service tables) is probed once.
  stopping*: bool
    ## Set once ``stop`` begins so racing handlers stop launching new probes,
    ## letting the shutdown drain terminate.
  isServer*: bool ## Whether the node answers inbound queries.
  serverStreams*: HashSet[Stream]
    ## Open inbound server streams, reset when the node stops serving.

template withRpcSlot*(kad: KadDHT) =
  ## Acquire one ``rpcSem`` slot until the enclosing scope exits. The slot is
  ## released whether the scope exits normally, raises, or is cancelled.
  await kad.rpcSem.acquire()
  defer:
    try:
      kad.rpcSem.release()
    except AsyncSemaphoreError:
      raiseAssert "rpcSem released without acquire"
