# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The default ``KadStore``: plain tables in memory. A ``none`` capacity means no limit.

import std/[heapqueue, sequtils, tables]
import chronos
import ../../[peerid, results]
import ../../utils/opt
import ./[key_value, protobuf, store, types]

export store

const MinExpirySlack = 16
  ## stale heap slots tolerated before a compaction on a small store

type
  ProviderSlot = object
    key: Key
    peerId: PeerId
    expiresAt: UnixTimestamp

  Values = ref object
    cap: Opt[int]
    byKey: Table[RecordKey, StoredValue]
    keys: seq[RecordKey] ## the keys of ``byKey``, sorted
    nextExpiry: UnixTimestamp ## no value expires before this time

  Providers = ref object
    cap: Opt[int]
    capPerPeer: Opt[int]
    byKey: Table[Key, Table[PeerId, StoredProvider]]
    count: int
    countPerPeer: CountTable[PeerId]
    expiries: HeapQueue[ProviderSlot]
      ## min-heap on ``expiresAt``; a slot whose provider was removed or refreshed is stale

  ProvidedKeys = ref object
    cap: Opt[int]
    stamps: Table[ProvidedKey, uint64] ## a lower stamp is provided less recently
    keys: seq[ProvidedKey] ## the keys of ``stamps``, sorted
    nextStamp: uint64

  MemoryKadStore* = ref object of KadStore
    values: Values
    providers: Providers
    provided: ProvidedKeys

func new*(
    T: typedesc[MemoryKadStore],
    limits = KadStoreLimits(
      maxValues: Opt.some(DefaultMaxLocalRecords),
      maxProviders: Opt.some(DefaultProviderRecordCapacity),
      maxProvided: Opt.some(DefaultProvidedKeyCapacity),
      maxProviderRecordsPerPeer:
        Opt.some(defaultMaxProviderRecordsPerPeer(DefaultProviderRecordCapacity)),
    ),
): T =
  T(
    values: Values(cap: limits.maxValues),
    providers:
      Providers(cap: limits.maxProviders, capPerPeer: limits.maxProviderRecordsPerPeer),
    provided: ProvidedKeys(cap: limits.maxProvided),
  )

func limits*(store: MemoryKadStore): KadStoreLimits =
  KadStoreLimits(
    maxValues: store.values.cap,
    maxProviders: store.providers.cap,
    maxProvided: store.provided.cap,
    maxProviderRecordsPerPeer: store.providers.capPerPeer,
  )

func atCapacity(count: int, cap: Opt[int]): bool =
  cap.isSome() and count >= cap.get()

func upperBound[K](keys: openArray[K], key: K): int =
  var low = 0
  var high = keys.len
  while low < high:
    let mid = low + (high - low) div 2
    if key < keys[mid]:
      high = mid
    else:
      low = mid + 1
  low

func insertKey[K](keys: var seq[K], key: K) =
  keys.insert(key, keys.upperBound(key))

func removeKey[K](keys: var seq[K], key: K) =
  let pos = keys.upperBound(key) - 1
  if pos >= 0 and keys[pos] == key:
    keys.delete(pos)

iterator page[K](keys: seq[K], after: Opt[K], limit: int): K =
  let start =
    if after.isSome():
      keys.upperBound(after.get())
    else:
      0
  for i in start ..< start + min(keys.len - start, max(limit, 0)):
    yield keys[i]

func isLive(expiresAt, now: UnixTimestamp): bool =
  expiresAt > now

func prune(values: Values, now: UnixTimestamp) =
  if values.nextExpiry.isLive(now):
    return

  var dead: seq[RecordKey]
  var nextExpiry = high(UnixTimestamp)
  for key, value in values.byKey:
    if value.expiresAt.isLive(now):
      nextExpiry = min(nextExpiry, value.expiresAt)
    else:
      dead.add(key)
  for key in dead:
    values.byKey.del(key)
  values.keys.keepItIf(it in values.byKey)
  values.nextExpiry = nextExpiry

func get(values: Values, key: RecordKey, now: UnixTimestamp): Opt[StoredValue] =
  values.prune(now)

  values.byKey.withValue(key, value):
    return Opt.some(value[])
  Opt.none(StoredValue)

func put(values: Values, value: StoredValue, now: UnixTimestamp): bool =
  values.prune(now)

  if value.key notin values.byKey:
    if values.byKey.len.atCapacity(values.cap):
      return false
    values.keys.insertKey(value.key)

  values.byKey[value.key] = value
  values.nextExpiry = min(values.nextExpiry, value.expiresAt)
  true

func drop(values: Values, key: RecordKey) =
  values.byKey.del(key)
  values.keys.removeKey(key)

func list(
    values: Values, after: Opt[RecordKey], now: UnixTimestamp, limit: int
): seq[StoredValue] =
  values.prune(now)

  var live: seq[StoredValue]
  for key in values.keys.page(after, limit):
    values.byKey.withValue(key, value):
      live.add(value[])
  live

method getValue*(
    store: MemoryKadStore, key: RecordKey, now: UnixTimestamp
): Future[LPResult[Opt[StoredValue]]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(store.values.get(key, now))

method putValue*(
    store: MemoryKadStore, value: StoredValue, now: UnixTimestamp
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(store.values.put(value, now))

method delValue*(
    store: MemoryKadStore, key: RecordKey
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.values.drop(key)
  ok()

method listValues*(
    store: MemoryKadStore, after: Opt[RecordKey], now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredValue]]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(store.values.list(after, now, limit))

func `<`(a, b: ProviderSlot): bool =
  a.expiresAt < b.expiresAt

func isCurrent(providers: Providers, slot: ProviderSlot): bool =
  providers.byKey.withValue(slot.key, stored):
    stored[].withValue(slot.peerId, p):
      return p[].expiresAt == slot.expiresAt
  false

func compact(providers: Providers) =
  if providers.expiries.len <= 2 * providers.count + MinExpirySlack:
    return

  var fresh = initHeapQueue[ProviderSlot]()
  for key, stored in providers.byKey:
    for peerId, p in stored:
      fresh.push(ProviderSlot(key: key, peerId: peerId, expiresAt: p.expiresAt))
  providers.expiries = fresh

func drop(providers: Providers, key: Key, peerId: PeerId) =
  providers.byKey.withValue(key, stored):
    if peerId notin stored[]:
      return
    stored[].del(peerId)
    providers.count.dec()
    let left = providers.countPerPeer.getOrDefault(peerId) - 1
    if left <= 0:
      providers.countPerPeer.del(peerId)
    else:
      providers.countPerPeer[peerId] = left
    if stored[].len == 0:
      providers.byKey.del(key)

func prune(providers: Providers, now: UnixTimestamp) =
  while providers.expiries.len > 0 and not providers.expiries[0].expiresAt.isLive(now):
    let slot = providers.expiries.pop()
    if providers.isCurrent(slot):
      providers.drop(slot.key, slot.peerId)

func soonest(providers: Providers): Opt[ProviderSlot] =
  while providers.expiries.len > 0:
    let slot = providers.expiries[0]
    if providers.isCurrent(slot):
      return Opt.some(slot)
    discard providers.expiries.pop()
  Opt.none(ProviderSlot)

func makeRoom(providers: Providers, p: StoredProvider): bool =
  if not providers.count.atCapacity(providers.cap):
    return true

  let victim = providers.soonest().valueOr:
    return false
  if victim.expiresAt >= p.expiresAt:
    return false
  providers.drop(victim.key, victim.peerId)
  true

func put(providers: Providers, key: Key, peerId: PeerId, p: StoredProvider) =
  providers.byKey.withValue(key, stored):
    stored[][peerId] = p
  do:
    providers.byKey[key] = {peerId: p}.toTable()
  providers.expiries.push(
    ProviderSlot(key: key, peerId: peerId, expiresAt: p.expiresAt)
  )
  providers.compact()

func countOf(providers: Providers, key: Key): int =
  providers.byKey.withValue(key, stored):
    return stored[].len
  0

func add(
    providers: Providers,
    key: Key,
    peerId: PeerId,
    p: StoredProvider,
    now: UnixTimestamp,
    maxPerKey: int,
): AddProviderOutcome =
  providers.prune(now)

  providers.byKey.withValue(key, stored):
    if peerId in stored[]:
      providers.put(key, peerId, p)
      return AddProviderOutcome.refreshed

  if providers.countOf(key) >= maxPerKey:
    return AddProviderOutcome.keyFull
  if providers.countPerPeer.getOrDefault(peerId).atCapacity(providers.capPerPeer):
    return AddProviderOutcome.peerFull
  if not providers.makeRoom(p):
    return AddProviderOutcome.storeFull

  providers.count.inc()
  providers.countPerPeer.inc(peerId)
  providers.put(key, peerId, p)
  AddProviderOutcome.added

func get(
    providers: Providers, key: Key, now: UnixTimestamp, limit: int
): seq[StoredProvider] =
  providers.prune(now)

  var live: seq[StoredProvider]
  providers.byKey.withValue(key, stored):
    for p in stored[].values():
      if live.len >= limit:
        break
      live.add(p)
  live

method addProvider*(
    store: MemoryKadStore,
    key: Key,
    p: StoredProvider,
    now: UnixTimestamp,
    maxPerKey: int,
): Future[LPResult[AddProviderOutcome]] {.async: (raises: [CancelledError]), gcsafe.} =
  let id = p.provider.id.valueOr:
    return err("provider of key " & $key & " has no id", "provider without id")
  let peerId = PeerId.init(id).valueOr:
    return err("provider of key " & $key & ": " & $error, "invalid provider id")

  ok(store.providers.add(key, peerId, p, now, maxPerKey))

method getProviders*(
    store: MemoryKadStore, key: Key, now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredProvider]]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(store.providers.get(key, now, limit))

method removeProvider*(
    store: MemoryKadStore, key: Key, peerId: PeerId
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.providers.drop(key, peerId)
  ok()

func oldest(provided: ProvidedKeys): Opt[ProvidedKey] =
  var oldest = Opt.none(ProvidedKey)
  var oldestStamp = high(uint64)
  for key, stamp in provided.stamps:
    if stamp < oldestStamp:
      oldest = Opt.some(key)
      oldestStamp = stamp
  oldest

func drop(provided: ProvidedKeys, key: ProvidedKey) =
  provided.stamps.del(key)
  provided.keys.removeKey(key)

func stamp(provided: ProvidedKeys, key: ProvidedKey) =
  if key notin provided.stamps:
    provided.keys.insertKey(key)
  provided.stamps[key] = provided.nextStamp
  provided.nextStamp.inc()

func add(provided: ProvidedKeys, key: ProvidedKey): bool =
  if key notin provided.stamps and provided.stamps.len.atCapacity(provided.cap):
    let oldest = provided.oldest().valueOr:
      return false
    provided.drop(oldest)

  provided.stamp(key)
  true

func contains(provided: ProvidedKeys, key: ProvidedKey): bool =
  key in provided.stamps

func list(
    provided: ProvidedKeys, after: Opt[ProvidedKey], limit: int
): seq[ProvidedKey] =
  toSeq(provided.keys.page(after, limit))

method addProvided*(
    store: MemoryKadStore, key: ProvidedKey
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(store.provided.add(key))

method delProvided*(
    store: MemoryKadStore, key: ProvidedKey
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.provided.drop(key)
  ok()

method hasProvided*(
    store: MemoryKadStore, key: ProvidedKey
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(key in store.provided)

method listProvided*(
    store: MemoryKadStore, after: Opt[ProvidedKey], limit: int
): Future[LPResult[seq[ProvidedKey]]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(store.provided.list(after, limit))
