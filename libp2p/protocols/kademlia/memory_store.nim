# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The default ``KadStore``: plain tables in memory. A ``none`` capacity means no limit.

import std/[sequtils, sets, tables]
import chronos
import ../../[peerid, results]
import ../../utils/opt
import ./[key_value, protobuf, store, types]

type
  KadStoreLimits* = object
    maxValues*: Opt[int]
    maxProviders*: Opt[int]
    maxProvided*: Opt[int]

  HeldProvider* = object
    stored: StoredProvider
    order: uint64 ## breaks an ``expiresAt`` tie at eviction: the first added goes first

  MemoryKadStore* = ref object of KadStore
    values: Table[RecordKey, StoredValue]
    valueKeys: seq[RecordKey] ## the keys of ``values``, sorted
    providers: Table[Key, seq[HeldProvider]]
    providerCount: int
    recordsPerPeer: CountTable[seq[byte]]
    nextProviderOrder: uint64
    provided: OrderedSet[Key] ## in provide order
    providedKeys: seq[Key] ## the keys of ``provided``, sorted
    limits: KadStoreLimits
    nextValueExpiry: UnixTimestamp ## no value expires before this time
    nextProviderExpiry: UnixTimestamp ## no provider expires before this time

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
  store.values.withValue(key, value):
    if value[].expiresAt.isLive(now):
      return ok(Opt.some(value[]))
  ok(Opt.none(StoredValue))

method putValue*(
    store: MemoryKadStore, value: StoredValue, now: UnixTimestamp
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  if value.key notin store.values:
    if store.values.len.atCapacity(store.limits.maxValues):
      store.pruneValues(now)
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

proc forgetRecord(store: MemoryKadStore, held: HeldProvider) =
  store.providerCount.dec()
  held.stored.provider.id.ifValue(id):
    store.recordsPerPeer.inc(id, -1)

template dropProvidersIf(
    store: MemoryKadStore, held: var seq[HeldProvider], pred: untyped
) =
  var i = 0
  while i < held.len:
    let it {.inject.} = held[i].stored
    if pred:
      store.forgetRecord(held[i])
      held.delete(i)
    else:
      i.inc()

proc pruneProviders(store: MemoryKadStore, now: UnixTimestamp) =
  if store.nextProviderExpiry.isLive(now):
    return

  var emptied: seq[Key]
  var nextExpiry = high(UnixTimestamp)
  for key, held in store.providers.mpairs():
    store.dropProvidersIf(held, not it.expiresAt.isLive(now))
    for provider in held:
      nextExpiry = min(nextExpiry, provider.stored.expiresAt)
    if held.len == 0:
      emptied.add(key)
  for key in emptied:
    store.providers.del(key)
  store.nextProviderExpiry = nextExpiry

proc evictFirstToExpire(store: MemoryKadStore) =
  var victim = Opt.none(Key)
  var victimIdx = 0
  var victimExpiry = high(UnixTimestamp)
  var victimOrder = high(uint64)
  for key, held in store.providers:
    for i, provider in held:
      let expiry = provider.stored.expiresAt
      if victim.isNone() or expiry < victimExpiry or
          (expiry == victimExpiry and provider.order < victimOrder):
        victim = Opt.some(key)
        victimIdx = i
        victimExpiry = expiry
        victimOrder = provider.order

  victim.ifValue(key):
    var emptied = false
    store.providers.withValue(key, held):
      store.forgetRecord(held[][victimIdx])
      held[].delete(victimIdx)
      emptied = held[].len == 0
    if emptied:
      store.providers.del(key)

func refusal(
    store: MemoryKadStore, key: Key, id: seq[byte], maxPerKey, maxPerPeer: int
): Opt[AddProviderOutcome] =
  var count = 0
  store.providers.withValue(key, held):
    count = held[].len

  if count >= maxPerKey:
    return Opt.some(AddProviderOutcome.keyFull)
  if store.recordsPerPeer.getOrDefault(id) >= maxPerPeer:
    return Opt.some(AddProviderOutcome.peerFull)
  Opt.none(AddProviderOutcome)

proc makeRoom(store: MemoryKadStore, now: UnixTimestamp): bool =
  let cap = store.limits.maxProviders
  if not store.providerCount.atCapacity(cap):
    return true

  store.pruneProviders(now)
  if not store.providerCount.atCapacity(cap):
    return true

  store.evictFirstToExpire()
  not store.providerCount.atCapacity(cap)

method addProvider*(
    store: MemoryKadStore,
    key: Key,
    p: StoredProvider,
    now: UnixTimestamp,
    maxPerKey: int,
    maxPerPeer = high(int),
): Future[LPResult[AddProviderOutcome]] {.async: (raises: [CancelledError]), gcsafe.} =
  let id = p.provider.id.valueOr:
    return err("provider of key " & $key & " has no id", "provider without id")

  store.providers.withValue(key, held):
    for existing in held[].mitems():
      if existing.stored.provider.id == p.provider.id:
        existing.stored = p
        store.nextProviderExpiry = min(store.nextProviderExpiry, p.expiresAt)
        return ok(AddProviderOutcome.refreshed)

  var refused = store.refusal(key, id, maxPerKey, maxPerPeer)
  if refused.isSome():
    let before = store.providerCount
    store.pruneProviders(now)
    if store.providerCount < before:
      refused = store.refusal(key, id, maxPerKey, maxPerPeer)
  if refused.isSome():
    return ok(refused.get())

  if not store.makeRoom(now):
    return ok(AddProviderOutcome.storeFull)

  store.providers.mgetOrPut(key, @[]).add(
    HeldProvider(stored: p, order: store.nextProviderOrder)
  )
  store.nextProviderOrder.inc()
  store.providerCount.inc()
  store.recordsPerPeer.inc(id)
  store.nextProviderExpiry = min(store.nextProviderExpiry, p.expiresAt)
  ok(AddProviderOutcome.added)

method getProviders*(
    store: MemoryKadStore, key: Key, now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredProvider]]] {.async: (raises: [CancelledError]), gcsafe.} =
  var live: seq[StoredProvider]
  store.providers.withValue(key, held):
    for provider in held[]:
      if live.len >= limit:
        break
      if provider.stored.expiresAt.isLive(now):
        live.add(provider.stored)
  ok(live)

method removeProvider*(
    store: MemoryKadStore, key: Key, peerId: PeerId
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  let id = Opt.some(peerId.getBytes())
  var emptied = false
  store.providers.withValue(key, held):
    store.dropProvidersIf(held[], it.provider.id == id)
    emptied = held[].len == 0
  if emptied:
    store.providers.del(key)
  ok()

func evictFirstProvided(store: MemoryKadStore) =
  var first = Opt.none(Key)
  for key in store.provided:
    first = Opt.some(key)
    break
  first.ifValue(key):
    store.provided.excl(key)
    store.providedKeys.removeKey(key)

method addProvided*(
    store: MemoryKadStore, key: Key
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  if key in store.provided:
    store.provided.excl(key)
    store.provided.incl(key)
    return ok(true)

  let cap = store.limits.maxProvided
  if store.provided.len.atCapacity(cap):
    store.evictFirstProvided()
  if store.provided.len.atCapacity(cap):
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

method pruneExpired*(
    store: MemoryKadStore, now: UnixTimestamp
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.pruneValues(now)
  store.pruneProviders(now)
  ok()
