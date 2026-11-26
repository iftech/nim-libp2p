# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import algorithm, chronos, hashes, results, sequtils, sets, tables
import
  ../../../libp2p/[
    protocols/kademlia, switch, builders, cid, multicodec, multihash, stream/connection
  ]
import ../../../libp2p/protocols/kademlia/memory_store
import ../../../libp2p/varint
import ../../tools/[crypto, unittest, switch_builder, multiaddress, bufferstream]
import std/importutils
import ./mock_kademlia

export crypto

proc makeProvidedCid*(seed: byte): Cid =
  Cid.init(CIDv1, multiCodec("raw"), MultiHash.digest("sha2-256", @[seed]).get()).get()

converter toKey*(bytes: seq[byte]): Key =
  Key.fromBytes(bytes)

converter toValue*(bytes: seq[byte]): Value =
  Value.fromBytes(bytes)

converter toOptKey*(key: Key): Opt[Key] =
  Opt.some(key)

converter toRecordKey*(key: Key): RecordKey =
  RecordKey.init(key).tryGet()

converter peerIdToRecordKey*(peerId: PeerId): RecordKey =
  RecordKey.init(peerId.toKey()).tryGet()

converter toOptValue*(value: Value): Opt[Value] =
  Opt.some(value)

proc hash*(x: seq[byte]): Hash {.inline.} =
  hash(x, 0, x.high)

converter fromKeyToBytes*(k: Key): seq[byte] =
  k.toBytes()

converter fromValueToBytes*(v: Value): seq[byte] =
  v.toBytes()

converter fromKeyToOptBytes*(k: Key): Opt[seq[byte]] =
  Opt.some(k.toBytes())

converter fromValueToOptBytes*(v: Value): Opt[seq[byte]] =
  Opt.some(v.toBytes())

converter toOptSeqByte*(a: seq[byte]): Opt[seq[byte]] =
  Opt.some(a)

converter toOptSeqMultiAddress*(a: seq[MultiAddress]): Opt[seq[MultiAddress]] =
  Opt.some(a)

converter toOptConnectionStatus*(a: ConnectionStatus): Opt[ConnectionStatus] =
  Opt.some(a)

converter toOptRecord*(a: protobuf.Record): Opt[protobuf.Record] =
  Opt.some(a)

converter toOptString*(a: string): Opt[string] =
  Opt.some(a)

converter toOptMessageType*(a: MessageType): Opt[MessageType] =
  Opt.some(a)

type PermissiveValidator* = ref object of EntryValidator
method isValid*(self: PermissiveValidator, key: RecordKey, record: EntryRecord): bool =
  true

type RestrictiveValidator* = ref object of EntryValidator
method isValid(self: RestrictiveValidator, key: RecordKey, record: EntryRecord): bool =
  false

type CandSelector* = ref object of EntrySelector
method select*(
    self: CandSelector, key: RecordKey, values: seq[EntryRecord]
): LPResult[int] =
  return ok(0)

type OthersSelector* = ref object of EntrySelector
method select*(
    self: OthersSelector, key: RecordKey, values: seq[EntryRecord]
): LPResult[int] =
  if values.len == 0:
    return err("no values were given")
  if values.len == 1:
    return ok(0)
  ok(1)

proc makeKeys*(T: typedesc[Key], count: int): seq[Key] =
  ## `count` distinct keys, one per index.
  var keys: seq[Key]
  for i in 0 ..< count:
    keys.add(MultiHash.digest("sha2-256", @[i.byte]).get().toKey())
  keys

proc testKadConfig*(
    validator: EntryValidator = PermissiveValidator(),
    selector: EntrySelector = CandSelector(),
    republishProvidedKeysInterval: Duration = chronos.milliseconds(50),
    replication: int = DefaultReplication,
    alpha: int = DefaultAlpha,
    beta: int = DefaultBeta,
    timeout = 1.seconds,
    retries: int = DefaultRetries,
    providerRejection: bool = false,
    providerExpirationInterval: Duration = 1.seconds,
    recordExpirationInterval: Duration = DefaultRecordExpirationInterval,
    republishRegionBits: Opt[int] = Opt.none(int),
    livenessGracePeriod: Duration = DefaultLivenessGracePeriod,
    livenessIdleInterval: Duration = DefaultLivenessIdleInterval,
    fixLowPeersInterval: Duration = DefaultFixLowPeersInterval,
    minRoutingTableSize: int = DefaultMinRoutingTableSize,
    disableBootstrapping: bool = false,
): KadDHTConfig =
  KadDHTConfig.new(
    validator,
    selector,
    timeout = timeout,
    providerExpirationInterval = providerExpirationInterval,
    republishProvidedKeysInterval = republishProvidedKeysInterval,
    replication = replication,
    alpha = alpha,
    beta = beta,
    retries = retries,
    providerRejection = providerRejection,
    recordExpirationInterval = recordExpirationInterval,
    republishRegionBits = republishRegionBits,
    livenessGracePeriod = livenessGracePeriod,
    livenessIdleInterval = livenessIdleInterval,
    fixLowPeersInterval = fixLowPeersInterval,
    minRoutingTableSize = minRoutingTableSize,
    disableBootstrapping = disableBootstrapping,
  )

proc setupKad*(
    config: KadDHTConfig = testKadConfig(),
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
    isServer: bool = true,
    identifyPush: bool = false,
): KadDHT =
  let switch =
    makeStandardSwitchBuilder(TcpAutoAddress).withIdentifyPusher(identifyPush).build()
  let kad = KadDHT.new(switch, bootstrapNodes, config, rng(), isServer)
  kad.switch.mount(kad)
  kad

proc setupMockKad*(
    config: KadDHTConfig = testKadConfig(),
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
    getValueResponse: Opt[Message] = Opt.none(Message),
    getProvidersResponse: Opt[Message] = Opt.none(Message),
    handleAddProviderMessage: Opt[Message] = Opt.none(Message),
    handleFindNodeDelay: Duration = ZeroDuration,
    handleFindNodeMalformedResponse: bool = false,
): MockKadDHT =
  let switch = makeStandardSwitch(TcpAutoAddress)
  let kad = MockKadDHT.new(switch, bootstrapNodes, config, rng = rng())
  kad.getValueResponse = getValueResponse
  kad.getProvidersResponse = getProvidersResponse
  kad.handleAddProviderMessage = handleAddProviderMessage
  kad.handleFindNodeDelay = handleFindNodeDelay
  kad.handleFindNodeMalformedResponse = handleFindNodeMalformedResponse
  kad.switch.mount(kad)
  kad

proc setupKadSwitches*(
    count: int,
    validator: EntryValidator = PermissiveValidator(),
    selector: EntrySelector = CandSelector(),
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
    republishProvidedKeysInterval: Duration = chronos.milliseconds(50),
    replication: int = DefaultReplication,
    beta: int = DefaultBeta,
    recordExpirationInterval: Duration = DefaultRecordExpirationInterval,
): seq[KadDHT] =
  var kads: seq[KadDHT]
  for i in 0 ..< count:
    let config = testKadConfig(
      validator,
      selector,
      republishProvidedKeysInterval = republishProvidedKeysInterval,
      replication = replication,
      beta = beta,
      recordExpirationInterval = recordExpirationInterval,
    )
    kads.add(setupKad(config, bootstrapNodes))
  kads

proc connect*(kad1, kad2: KadDHT) {.async.} =
  ## Bidirectionally connect two KadDHT instances.
  # Add to routing tables
  discard kad1.rtable.insert(kad2.switch.peerInfo.peerId)
  discard kad2.rtable.insert(kad1.switch.peerInfo.peerId)

  # Store addresses so nodes can dial each other
  kad1.switch.peerStore[AddressBook][kad2.switch.peerInfo.peerId] =
    kad2.switch.peerInfo.addrs
  kad2.switch.peerStore[AddressBook][kad1.switch.peerInfo.peerId] =
    kad1.switch.peerInfo.addrs

proc hasKey*(kad: KadDHT, key: Key): bool =
  key in kad.rtable

proc hasKeys*(kad: KadDHT, keys: seq[Key]): bool =
  keys.allIt(kad.hasKey(it))

proc hasNoKeys*(kad: KadDHT, keys: seq[Key]): bool =
  keys.allIt(not kad.hasKey(it))

proc countBucketEntries*(buckets: seq[Bucket], key: Key): uint32 =
  var res: uint32 = 0
  for b in buckets:
    for nodeId in b.peers:
      if nodeId == key:
        res += 1
  return res

privateAccess(MemoryKadStore)
privateAccess(typeof(MemoryKadStore().values))
privateAccess(typeof(MemoryKadStore().values.byKey.values()))
privateAccess(typeof(MemoryKadStore().providers))
privateAccess(typeof(MemoryKadStore().providers.expiries[0]))
privateAccess(typeof(MemoryKadStore().provided))

func mem(kad: KadDHT): MemoryKadStore =
  doAssert kad.store of MemoryKadStore, "the store of this kad is not a MemoryKadStore"
  MemoryKadStore(kad.store)

proc valueCount*(kad: KadDHT): int =
  let now = UnixTimestamp.now()
  var n = 0
  for value in kad.mem().values.byKey.values():
    if value.expiresAt > now:
      inc n
  n

proc liveProviders(kad: KadDHT, key: Key): seq[StoredProvider] =
  ## The store prunes only on a call that takes `now`, so its tables keep expired records.
  let now = UnixTimestamp.now()
  var live: seq[StoredProvider]
  kad.mem().providers.byKey.withValue(key, stored):
    for p in stored[].values():
      if p.expiresAt > now:
        live.add(p)
  live

proc liveProviders(kad: KadDHT): seq[StoredProvider] =
  var live: seq[StoredProvider]
  for key in kad.mem().providers.byKey.keys():
    live.add(kad.liveProviders(key))
  live

proc providerCount*(kad: KadDHT): int =
  kad.liveProviders().len

proc providerCount*(kad: KadDHT, key: Key): int =
  kad.liveProviders(key).len

proc providerKeyCount*(kad: KadDHT): int =
  var n = 0
  for key in kad.mem().providers.byKey.keys():
    if kad.liveProviders(key).len > 0:
      inc n
  n

proc hasProvider*(kad: KadDHT, key: Key): bool =
  kad.liveProviders(key).len > 0

proc findProvider(kad: KadDHT, key: Key, peerId: PeerId): Opt[StoredProvider] =
  let id = Opt.some(peerId.getBytes())
  for p in kad.liveProviders(key):
    if p.provider.id == id:
      return Opt.some(p)
  Opt.none(StoredProvider)

proc hasProvider*(kad: KadDHT, key: Key, peerId: PeerId): bool =
  kad.findProvider(key, peerId).isSome()

proc providerExpiry*(kad: KadDHT, key: Key, peerId: PeerId): UnixTimestamp =
  ## 0 when no record matches.
  let p = kad.findProvider(key, peerId).valueOr:
    return 0
  p.expiresAt

proc providerAddrs*(kad: KadDHT, key: Key, peerId: PeerId): seq[MultiAddress] =
  let p = kad.findProvider(key, peerId).valueOr:
    return @[]
  p.provider.addrs

proc recordsPerPeer*(kad: KadDHT, peerId: PeerId): int =
  let id = Opt.some(peerId.getBytes())
  kad.liveProviders().countIt(it.provider.id == id)

proc providerRecordsFull*(kad: KadDHT): bool =
  let cap = kad.mem().providers.cap.valueOr:
    return false
  kad.providerCount() >= cap

func providedCount*(kad: KadDHT): int =
  kad.mem().provided.stamps.len

func providedKeysFull*(kad: KadDHT): bool =
  let cap = kad.mem().provided.cap.valueOr:
    return false
  kad.providedCount() >= cap

proc isProvided*(kad: KadDHT, key: Key): bool =
  let provided = ProvidedKey.fromBytes(key.toBytes()).valueOr:
    return false
  provided in kad.mem().provided.stamps

proc markProvided*(kad: KadDHT, key: Key) =
  ## Provides `key` locally without announcing it. A later call counts as provided later.
  let provided = ProvidedKey.fromBytes(key.toBytes()).valueOr:
    raiseAssert "markProvided: " & $error
  let stored = kad.store.addProvided(provided).valueOr:
    raiseAssert "markProvided: " & $error
  if not stored:
    raiseAssert "markProvided: the store refused the key"

proc seedProvider*(
    kad: KadDHT,
    key: Key,
    provider: Provider,
    expiresAt: UnixTimestamp = UnixTimestamp.after(1.hours),
) =
  let stored = StoredProvider(provider: provider, expiresAt: expiresAt)
  let outcome = kad.store.addProvider(key, stored, UnixTimestamp.now(), high(int)).valueOr:
    raiseAssert "seedProvider: " & $error
  if outcome notin {AddProviderOutcome.added, AddProviderOutcome.refreshed}:
    raiseAssert "seedProvider: " & $outcome

proc backdateExpiry*(kad: KadDHT, by: Duration = 1.secs) =
  ## Expiry has one-second resolution, so a same-second refresh must beat an older record.
  let seconds = by.seconds().int
  let providers = kad.mem().providers
  for stored in providers.byKey.mvalues():
    for p in stored.mvalues():
      p.expiresAt -= seconds
  var slots: seq[typeof(providers.expiries[0])]
  while providers.expiries.len > 0:
    var slot = providers.expiries.pop()
    slot.expiresAt -= seconds
    slots.add(slot)
  for slot in slots:
    providers.expiries.push(slot)

proc localValue*(kad: KadDHT, key: RecordKey): Opt[EntryRecord] =
  kad.mem().values.byKey.withValue(key, value):
    if value[].expiresAt > UnixTimestamp.now():
      return Opt.some(value[].record)
  Opt.none(EntryRecord)

proc seedLocalValue*(
    kad: KadDHT, key: RecordKey, value: Value, expiresAt = Opt.none(UnixTimestamp)
): bool =
  let now = UnixTimestamp.now()
  let stored = StoredValue(
    key: key,
    record: EntryRecord(value: value, time: Timestamp.now()),
    expiresAt: expiresAt.get(now + kad.config.recordExpirationInterval.ceilSeconds()),
  )
  kad.store.putValue(stored, now).valueOr:
    raiseAssert "seedLocalValue: " & $error

proc containsData*(kad: KadDHT, key: RecordKey, value: Value): bool =
  let record = kad.localValue(key).valueOr:
    checkpoint("containsData: key not found: " & $key.shortLog())
    return false

  if record.value != value:
    checkpoint(
      "containsData: value mismatch for key:" & $key.shortLog & " - expected value: " &
        $value.shortLog & ", got value: " & $record.value
    )
    return false

  true

proc containsNoData*(kad: KadDHT, key: RecordKey): bool =
  kad.localValue(key).isNone()

proc pluckPeerIds*(kads: seq[KadDHT]): seq[PeerId] =
  kads.mapIt(it.switch.peerInfo.peerId)

proc containsPeer*(providers: HashSet[Peer], node: KadDHT): bool =
  let providerIds = providers.toSeq().filterIt(it.id.isSome).mapIt(it.id.get())
  node.switch.peerInfo.peerId.getBytes() in providerIds

proc toPeer*(node: KadDHT): Peer =
  node.switch.peerInfo.toPeer()

proc randomServiceId*(): Key =
  ## Stands in for a `hashServiceId()` result, a key already in the id space.
  var buf = newSeqUninit[byte](IdLength)
  rng().generate(buf)
  Key.fromBytes(buf)

proc populateRoutingTable*(kad: KadDHT, count: int) =
  for i in 0 ..< count:
    let peerId = PeerId.random()
    if kad.rtable.insert(peerId):
      kad.switch.peerStore[AddressBook][peerId] = @[ma("/ip4/127.0.0.1/tcp/1")]

proc insertRandomPeers*(kad: KadDHT, count: int): seq[PeerId] =
  ## Inserts `count` random peers, each with an address the way admission does.
  const maxRetries = 1000
  let maxAttempts = count + maxRetries
  var peers: seq[PeerId]
  for _ in 0 ..< maxAttempts:
    if peers.len == count:
      break
    let peerId = PeerId.random()
    # A bucket only holds k peers, and which bucket an id lands in is random, so
    # a full bucket rejects the insert and the id is simply redrawn.
    if not kad.rtable.insert(peerId):
      continue
    kad.switch.peerStore[AddressBook][peerId] = @[ma("/ip4/127.0.0.1/tcp/1")]
    peers.add(peerId)

  doAssert peers.len == count,
    "routing table took only " & $peers.len & " of " & $count & " peers in " &
      $maxAttempts & " attempts"
  peers

proc peersWithAddrs*(count: int): seq[PeerInfo] =
  ## `count` fresh peers on distinct ports, so the IP-diversity caps admit them.
  (0 ..< count).mapIt(
    PeerInfo(
      peerId: PeerId.random(), addrs: @[ma("/ip4/127.0.0.1/tcp/" & $(40000 + it))]
    )
  )

proc closerPeer*(id: Key): Peer =
  ## `toPeer` refuses an address-free peer, so no real reply carries one.
  Peer(id: id, addrs: @[ma("/ip4/127.0.0.1/tcp/1")])

proc addPeersWithAddrs*(kad: KadDHT, count: int) =
  ## Adds `count` random peers to the routing table, with an address each so they
  ## survive `toPeers`.
  for peerId in kad.insertRandomPeers(count):
    kad.switch.peerStore[AddressBook][peerId] = @[ma("/ip4/127.0.0.1/tcp/1")]

proc getPeersFromRoutingTable*(kad: KadDHT): seq[PeerId] =
  var peersInTable: seq[PeerId]
  for bucket in kad.rtable.buckets:
    for nodeId in bucket.peers:
      peersInTable.add(nodeId.toPeerId().get())
  peersInTable

proc nonEmptyBuckets*(kad: KadDHT): seq[int] =
  var bucketIndices: seq[int]
  for i, bucket in kad.rtable.buckets:
    if bucket.peers.len > 0:
      bucketIndices.add(i)
  bucketIndices

proc makeBucketStale*(rtable: RoutingTable, bucketIdx: int) =
  let past = Moment.now() - (DefaultBucketStaleTime + 1.minutes)
  for nodeId in rtable.buckets[bucketIdx].peers:
    rtable.registry.withRecord(nodeId, record):
      record[].lastSeen = past

proc agePeerPastLivenessGrace*(
    rtable: RoutingTable, key: Key, gracePeriod: Duration = DefaultLivenessGracePeriod
) =
  ## Age a routing-table membership past the liveness grace so the next
  ## liveness pass / continuous loop will probe it.
  let past = Moment.now() - (gracePeriod + 1.minutes)
  rtable.registry.withRecord(key, record):
    record[].lastUsefulAt = Opt.none(Moment)
    record[].lastSeen = past
  rtable.registry.tablesByPeer.withValue(key, tables):
    tables[].withValue(rtable.selfId, m):
      m[].addedAt = past

proc isPeerUseful*(kad: KadDHT, key: Key): bool =
  let record = kad.rtable.registry.get(key).valueOr:
    return false
  record.lastUsefulAt.isSome()

proc sortPeers*(
    peers: seq[PeerId], targetKey: Key, hasher: Opt[XorDHasher]
): seq[PeerId] =
  peers
    .mapIt((it, xorDistance(it, targetKey, hasher)))
    .sorted(
      proc(a, b: auto): int =
        cmp(a[1], b[1])
    )
    .mapIt(it[0])

proc seedRoutingTable*(kad: KadDHT, count: int, target: Key): seq[PeerId] =
  ## Adds `count` random peers to the routing table and returns them sorted by
  ## distance to `target`, closest first.
  kad.insertRandomPeers(count).sortPeers(target, kad.rtable.config.hasher)

proc seedRoutingTableBelow*(
    kad: KadDHT, count: int, target: Key
): tuple[closest: PeerId, seeded: seq[PeerId]] =
  ## Seeds `count` peers plus a closer one that only a reply can bring into a
  ## lookup, since it is held out of the routing table.
  let drawn = kad.seedRoutingTable(count + 1, target)
  doAssert kad.rtable.removePeer(drawn[0]),
    "the closest drawn peer is missing from the routing table"
  (drawn[0], drawn[1 .. ^1])

proc addRandomPeers*(
    state: LookupState, kad: KadDHT, count: int, target: Key
): seq[PeerId] =
  let hasher = kad.rtable.config.hasher
  let peers = PeerId.random(count)
  for peerId in peers:
    state.shortlist[peerId] = xorDistance(peerId, target, hasher)
    kad.switch.peerStore[AddressBook][peerId] = @[ma("/ip4/127.0.0.1/tcp/1")]
  peers.sortPeers(target, hasher)

proc sendAddProviderAndGetStatus*(
    sender: KadDHT, receiver: KadDHT, key: Key
): Future[LPResult[AddProviderStatus]] {.async: (raises: [CancelledError]).} =
  let streamRes = catch:
    await sender.switch.dial(receiver.switch, sender.codec)
  if streamRes.isErr:
    return err(streamRes.error.msg)
  let stream = streamRes.value()
  defer:
    await stream.close()
  let msg = Message(
    msgType: MessageType.addProvider,
    key: key,
    providerPeers: @[sender.switch.peerInfo.toPeer()],
  )
  let writeRes = catch:
    await stream.writeLp(msg.encode(sender.config.hideConnectionStatus))
  if writeRes.isErr:
    return err(writeRes.error.msg)
  let readFut = stream.readLp(MaxMsgSize)
  if not (await readFut.withTimeout(sender.config.timeout)):
    return ok(AddProviderStatus.accepted)
  let readRes = catch:
    await readFut
  if readRes.isErr:
    return ok(AddProviderStatus.accepted)
  let reply = Message.decode(readRes.value).valueOr:
    return ok(AddProviderStatus.accepted)
  return ok(reply.providerStatus.get(AddProviderStatus.accepted))

proc seedLinearMeasurements*(est: NetworkSizeEstimator, netSize: int) =
  ## Fill every closest-peer index with the profile the estimator models: index
  ## `i` (1-based) at distance `i / (netSize + 1)`, plus a spread so the
  ## regression is well posed.
  let now = Moment.now()
  for i in 0 ..< est.bucketSize:
    let base = float64(i + 1) / float64(netSize + 1)
    for delta in [-2e-4, -1e-4, 0.0, 1e-4, 2e-4]:
      est.measurements[i].add(
        NetSizeMeasurement(distance: base + delta, weight: 1.0, timestamp: now)
      )

type StubStore* = ref object of KadStore
  ## Wraps ``inner`` and fails its reads on ``failReads``.
  inner*: KadStore
  failReads*: bool

method getValue*(
    store: StubStore, key: RecordKey, now: UnixTimestamp
): LPResult[Opt[StoredValue]] {.gcsafe, raises: [].} =
  if store.failReads:
    return err("stub read failed")
  store.inner.getValue(key, now)

method putValue*(
    store: StubStore, value: StoredValue, now: UnixTimestamp
): LPResult[bool] {.gcsafe, raises: [].} =
  store.inner.putValue(value, now)

proc setupStubKad*(store: StubStore): KadDHT =
  var config = testKadConfig()
  config.store = Opt.some(KadStore(store))
  setupKad(config)

proc mountedKad*(switch: Switch): Opt[KadDHT] {.raises: [].} =
  for handler in switch.ms.handlers:
    if KadCodec in handler.protos and handler.protocol of KadDHT:
      return Opt.some(KadDHT(handler.protocol))
  Opt.none(KadDHT)

type RecordingStream* = ref object
  stream*: TestBufferStream
  replies*: seq[seq[byte]]

proc new*(T: typedesc[RecordingStream]): T =
  let recording = T()
  recording.stream = TestBufferStream.new(
    proc(data: sink seq[byte]) {.async: (raises: [CancelledError, LPStreamError]).} =
      recording.replies.add(data)
  )
  recording

proc getMessage*(frame: openArray[byte]): Result[seq[byte], string] =
  var prefixLen: int
  var msgLen: uint64
  if PB.getUVarint(frame, prefixLen, msgLen).isErr():
    return err("invalid length prefix")
  if msgLen != uint64(frame.len - prefixLen):
    return err("length prefix " & $msgLen & " != payload " & $(frame.len - prefixLen))
  ok(@frame[prefixLen ..^ 1])

proc getReply*(frame: openArray[byte]): Result[Message, string] =
  let payload = ?getMessage(frame)
  let reply = Message.decode(payload).valueOr:
    return err("decode: " & $error)
  ok(reply)
