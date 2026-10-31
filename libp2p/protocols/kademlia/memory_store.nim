# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The default ``KadStore``: plain tables in memory. A ``none`` capacity means no limit.

import std/[sequtils, sets, tables]
import chronos
import ../../[peerid, results]
import ./[key_value, protobuf, store, types]

type
  KadStoreLimits* = object
    maxValues*: Opt[int]
    maxProviders*: Opt[int]
    maxProvided*: Opt[int]

  MemoryKadStore* = ref object of KadStore
    values: Table[RecordKey, StoredValue]
    valueKeys: seq[RecordKey] ## the keys of ``values``, sorted
    providers: Table[Key, seq[StoredProvider]]
    providerCount: int
    provided: HashSet[Key]
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

template dropProvidersIf(
    store: MemoryKadStore, stored: var seq[StoredProvider], pred: untyped
) =
  let before = stored.len
  stored.keepItIf(not pred)
  store.providerCount -= before - stored.len

proc pruneProviders(store: MemoryKadStore, now: UnixTimestamp) =
  if store.nextProviderExpiry.isLive(now):
    return

  var emptied: seq[Key]
  var nextExpiry = high(UnixTimestamp)
  for key, stored in store.providers.mpairs():
    store.dropProvidersIf(stored, not it.expiresAt.isLive(now))
    for provider in stored:
      nextExpiry = min(nextExpiry, provider.expiresAt)
    if stored.len == 0:
      emptied.add(key)
  for key in emptied:
    store.providers.del(key)
  store.nextProviderExpiry = nextExpiry

func refusal(store: MemoryKadStore, key: Key, maxPerKey: int): Opt[AddProviderOutcome] =
  var count = 0
  store.providers.withValue(key, stored):
    count = stored[].len

  if count >= maxPerKey:
    return Opt.some(AddProviderOutcome.keyFull)
  if store.providerCount.atCapacity(store.limits.maxProviders):
    return Opt.some(AddProviderOutcome.storeFull)
  Opt.none(AddProviderOutcome)

method addProvider*(
    store: MemoryKadStore,
    key: Key,
    p: StoredProvider,
    now: UnixTimestamp,
    maxPerKey: int,
): Future[LPResult[AddProviderOutcome]] {.async: (raises: [CancelledError]), gcsafe.} =
  if p.provider.id.isNone():
    return err("provider of key " & $key & " has no id", "provider without id")

  store.providers.withValue(key, stored):
    for existing in stored[].mitems():
      if existing.provider.id == p.provider.id:
        existing = p
        store.nextProviderExpiry = min(store.nextProviderExpiry, p.expiresAt)
        return ok(AddProviderOutcome.refreshed)

  var refused = store.refusal(key, maxPerKey)
  if refused.isSome():
    let before = store.providerCount
    store.pruneProviders(now)
    if store.providerCount < before:
      refused = store.refusal(key, maxPerKey)
  if refused.isSome():
    return ok(refused.get())

  store.providers.mgetOrPut(key, @[]).add(p)
  store.providerCount.inc()
  store.nextProviderExpiry = min(store.nextProviderExpiry, p.expiresAt)
  ok(AddProviderOutcome.added)

method getProviders*(
    store: MemoryKadStore, key: Key, now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredProvider]]] {.async: (raises: [CancelledError]), gcsafe.} =
  let live = store.providers.getOrDefault(key).filterIt(it.expiresAt.isLive(now))
  ok(live[0 ..< min(live.len, max(limit, 0))])

method removeProvider*(
    store: MemoryKadStore, key: Key, peerId: PeerId
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  let id = Opt.some(peerId.getBytes())
  var emptied = false
  store.providers.withValue(key, stored):
    store.dropProvidersIf(stored[], it.provider.id == id)
    emptied = stored[].len == 0
  if emptied:
    store.providers.del(key)
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

method pruneExpired*(
    store: MemoryKadStore, now: UnixTimestamp
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.pruneValues(now)
  store.pruneProviders(now)
  ok()
