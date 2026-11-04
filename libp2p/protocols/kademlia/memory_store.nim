# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The default ``KadStore``: plain tables in memory. A ``none`` capacity means no limit.

import std/[heapqueue, sequtils, sets, tables]
import chronos
import ../../[peerid, results]
import ../../utils/opt
import ./[key_value, protobuf, store, types]

const MinExpirySlack = 16
  ## stale heap slots tolerated before a compaction on a small store

type
  KadStoreLimits* = object
    maxValues*: Opt[int]
    maxProviders*: Opt[int]
    maxProvided*: Opt[int]

  ProviderSlot = object
    key: Key
    peerId: PeerId
    expiresAt: UnixTimestamp

  MemoryKadStore* = ref object of KadStore
    values: Table[RecordKey, StoredValue]
    valueKeys: seq[RecordKey] ## the keys of ``values``, sorted
    providers: Table[Key, Table[PeerId, StoredProvider]]
    providerCount: int
    providerExpiries: HeapQueue[ProviderSlot]
      ## min-heap on ``expiresAt``; a slot whose provider was removed or refreshed is stale
    provided: HashSet[Key]
    providedKeys: seq[Key] ## the keys of ``provided``, sorted
    limits: KadStoreLimits
    nextValueExpiry: UnixTimestamp ## no value expires before this time

func new*(
    T: typedesc[MemoryKadStore],
    limits = KadStoreLimits(
      maxValues: Opt.some(DefaultMaxLocalRecords),
      maxProviders: Opt.some(DefaultProviderRecordCapacity),
      maxProvided: Opt.some(DefaultProvidedKeyCapacity),
    ),
): T =
  T(limits: limits)

func limits*(store: MemoryKadStore): KadStoreLimits =
  store.limits

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

proc pruneValues(store: MemoryKadStore, now: UnixTimestamp) =
  if store.nextValueExpiry.isLive(now):
    return

  var dead: seq[RecordKey]
  var nextExpiry = high(UnixTimestamp)
  for key, value in store.values:
    if value.expiresAt.isLive(now):
      nextExpiry = min(nextExpiry, value.expiresAt)
    else:
      dead.add(key)
  for key in dead:
    store.values.del(key)
  store.valueKeys.keepItIf(it in store.values)
  store.nextValueExpiry = nextExpiry

method getValue*(
    store: MemoryKadStore, key: RecordKey, now: UnixTimestamp
): Future[LPResult[Opt[StoredValue]]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.pruneValues(now)

  store.values.withValue(key, value):
    return ok(Opt.some(value[]))
  ok(Opt.none(StoredValue))

method putValue*(
    store: MemoryKadStore, value: StoredValue, now: UnixTimestamp
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.pruneValues(now)

  if value.key notin store.values:
    if store.values.len.atCapacity(store.limits.maxValues):
      return ok(false)
    store.valueKeys.insertKey(value.key)

  store.values[value.key] = value
  store.nextValueExpiry = min(store.nextValueExpiry, value.expiresAt)
  ok(true)

method delValue*(
    store: MemoryKadStore, key: RecordKey
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.values.del(key)
  store.valueKeys.removeKey(key)
  ok()

method listValues*(
    store: MemoryKadStore, after: Opt[RecordKey], now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredValue]]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.pruneValues(now)

  var values: seq[StoredValue]
  for key in store.valueKeys.page(after, limit):
    store.values.withValue(key, value):
      values.add(value[])
  ok(values)

func `<`(a, b: ProviderSlot): bool =
  a.expiresAt < b.expiresAt

func isCurrent(store: MemoryKadStore, slot: ProviderSlot): bool =
  store.providers.withValue(slot.key, stored):
    stored[].withValue(slot.peerId, p):
      return p[].expiresAt == slot.expiresAt
  false

proc compactProviderExpiries(store: MemoryKadStore) =
  if store.providerExpiries.len <= 2 * store.providerCount + MinExpirySlack:
    return

  var fresh = initHeapQueue[ProviderSlot]()
  for key, stored in store.providers:
    for peerId, p in stored:
      fresh.push(ProviderSlot(key: key, peerId: peerId, expiresAt: p.expiresAt))
  store.providerExpiries = fresh

proc dropProvider(store: MemoryKadStore, key: Key, peerId: PeerId) =
  store.providers.withValue(key, stored):
    if peerId notin stored[]:
      return
    stored[].del(peerId)
    store.providerCount.dec()
    if stored[].len == 0:
      store.providers.del(key)

proc pruneProviders(store: MemoryKadStore, now: UnixTimestamp) =
  while store.providerExpiries.len > 0 and
      not store.providerExpiries[0].expiresAt.isLive(now):
    let slot = store.providerExpiries.pop()
    if store.isCurrent(slot):
      store.dropProvider(slot.key, slot.peerId)

proc soonestProvider(store: MemoryKadStore): Opt[ProviderSlot] =
  while store.providerExpiries.len > 0:
    let slot = store.providerExpiries[0]
    if store.isCurrent(slot):
      return Opt.some(slot)
    discard store.providerExpiries.pop()
  Opt.none(ProviderSlot)

proc makeRoom(store: MemoryKadStore, p: StoredProvider): bool =
  if not store.providerCount.atCapacity(store.limits.maxProviders):
    return true

  let victim = store.soonestProvider().valueOr:
    return false
  if victim.expiresAt >= p.expiresAt:
    return false
  store.dropProvider(victim.key, victim.peerId)
  true

proc putProvider(store: MemoryKadStore, key: Key, peerId: PeerId, p: StoredProvider) =
  store.providers.withValue(key, stored):
    stored[][peerId] = p
  do:
    store.providers[key] = {peerId: p}.toTable()
  store.providerExpiries.push(
    ProviderSlot(key: key, peerId: peerId, expiresAt: p.expiresAt)
  )
  store.compactProviderExpiries()

func providersOf(store: MemoryKadStore, key: Key): int =
  store.providers.withValue(key, stored):
    return stored[].len
  0

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

  store.pruneProviders(now)

  store.providers.withValue(key, stored):
    if peerId in stored[]:
      store.putProvider(key, peerId, p)
      return ok(AddProviderOutcome.refreshed)

  if store.providersOf(key) >= maxPerKey:
    return ok(AddProviderOutcome.keyFull)
  if not store.makeRoom(p):
    return ok(AddProviderOutcome.storeFull)

  store.providerCount.inc()
  store.putProvider(key, peerId, p)
  ok(AddProviderOutcome.added)

method getProviders*(
    store: MemoryKadStore, key: Key, now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredProvider]]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.pruneProviders(now)

  var live: seq[StoredProvider]
  store.providers.withValue(key, stored):
    for p in stored[].values():
      if live.len >= limit:
        break
      live.add(p)
  ok(live)

method removeProvider*(
    store: MemoryKadStore, key: Key, peerId: PeerId
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.dropProvider(key, peerId)
  ok()

method addProvided*(
    store: MemoryKadStore, key: Key
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  if key in store.provided:
    return ok(true)
  if store.provided.len.atCapacity(store.limits.maxProvided):
    return ok(false)

  store.provided.incl(key)
  store.providedKeys.insertKey(key)
  ok(true)

method delProvided*(
    store: MemoryKadStore, key: Key
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.provided.excl(key)
  store.providedKeys.removeKey(key)
  ok()

method hasProvided*(
    store: MemoryKadStore, key: Key
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(key in store.provided)

method listProvided*(
    store: MemoryKadStore, after: Opt[Key], limit: int
): Future[LPResult[seq[Key]]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(toSeq(store.providedKeys.page(after, limit)))
