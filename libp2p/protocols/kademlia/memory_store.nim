# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The default ``KadStore``: plain tables in memory. A ``none`` capacity means no limit.

import std/[algorithm, heapqueue, sequtils, sets, tables]
import chronos
import ../../[peerid, results]
import ./[key_value, protobuf, store, types]

type
  KadStoreLimits* = object
    maxValues*: Opt[int]
    maxProviders*: Opt[int]
    maxProvided*: Opt[int]

  ProviderExpiry = object
    expiresAt: UnixTimestamp
    key: Key
    peerId: PeerId

  MemoryKadStore* = ref object of KadStore
    values: Table[RecordKey, StoredValue]
    providers: Table[Key, Table[PeerId, StoredProvider]]
    providerExpiry: HeapQueue[ProviderExpiry]
      ## Lazy deletion: a refresh or a removal leaves the old entry behind.
    providerCount: int
    provided: HashSet[Key]
    limits: KadStoreLimits

func new*(
    T: typedesc[MemoryKadStore],
    maxValues = Opt.some(DefaultMaxLocalRecords),
    maxProviders = Opt.some(DefaultProviderRecordCapacity),
    maxProvided = Opt.some(DefaultProvidedKeyCapacity),
): T =
  T(
    limits: KadStoreLimits(
      maxValues: maxValues, maxProviders: maxProviders, maxProvided: maxProvided
    )
  )

func limits*(store: MemoryKadStore): KadStoreLimits =
  store.limits

func atCapacity(count: int, cap: Opt[int]): bool =
  cap.isSome() and count >= cap.get()

func cmpBytes(a, b: Key): int =
  for i in 0 ..< min(a.len, b.len):
    if a[i] != b[i]:
      return cmp(a[i], b[i])
  cmp(a.len, b.len)

func cmpBytes(a, b: RecordKey): int =
  cmpBytes(a.toKey(), b.toKey())

func page[K: Key | RecordKey](keys: seq[K], after: Opt[K], limit: int): seq[K] =
  var sorted = keys.filterIt(after.isNone() or cmpBytes(it, after.get()) > 0)
  sorted.sort(cmpBytes)

  var page: seq[K]
  for key in sorted:
    if page.len >= limit:
      break
    page.add(key)
  page

func isLive(expiresAt, now: UnixTimestamp): bool =
  expiresAt > now

method getValue*(
    store: MemoryKadStore, key: RecordKey, now: UnixTimestamp
): Future[LPResult[Opt[StoredValue]]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.values.withValue(key, value):
    if value[].expiresAt.isLive(now):
      return ok(Opt.some(value[]))
  ok(Opt.none(StoredValue))

method putValue*(
    store: MemoryKadStore, value: StoredValue
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  if value.key notin store.values and store.values.len.atCapacity(
    store.limits.maxValues
  ):
    return ok(false)

  store.values[value.key] = value
  ok(true)

method delValue*(
    store: MemoryKadStore, key: RecordKey
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.values.del(key)
  ok()

method listValues*(
    store: MemoryKadStore, after: Opt[RecordKey], now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredValue]]] {.async: (raises: [CancelledError]), gcsafe.} =
  var live: seq[RecordKey]
  for key, value in store.values:
    if value.expiresAt.isLive(now):
      live.add(key)

  var values: seq[StoredValue]
  for key in live.page(after, limit):
    store.values.withValue(key, value):
      values.add(value[])
  ok(values)

func `<`(a, b: ProviderExpiry): bool =
  a.expiresAt < b.expiresAt

func isCurrent(store: MemoryKadStore, e: ProviderExpiry): bool =
  store.providers.withValue(e.key, stored):
    stored[].withValue(e.peerId, p):
      return p[].expiresAt == e.expiresAt
  false

proc dropProvider(store: MemoryKadStore, key: Key, peerId: PeerId) =
  var emptied = false
  store.providers.withValue(key, stored):
    if peerId notin stored[]:
      return
    stored[].del(peerId)
    store.providerCount.dec()
    emptied = stored[].len == 0
  if emptied:
    store.providers.del(key)

proc compactProviderExpiry(store: MemoryKadStore) =
  if store.providerExpiry.len <= 2 * store.providerCount:
    return

  var live: seq[ProviderExpiry]
  for key, stored in store.providers:
    for peerId, p in stored:
      live.add(ProviderExpiry(expiresAt: p.expiresAt, key: key, peerId: peerId))
  store.providerExpiry = live.toHeapQueue()

proc evictSoonestProvider(store: MemoryKadStore): bool =
  while store.providerExpiry.len > 0:
    let e = store.providerExpiry.pop()
    if store.isCurrent(e):
      store.dropProvider(e.key, e.peerId)
      return true
  false

proc pushProvider(store: MemoryKadStore, key: Key, peerId: PeerId, p: StoredProvider) =
  store.providers.mgetOrPut(key, initTable[PeerId, StoredProvider]())[peerId] = p
  store.providerExpiry.push(
    ProviderExpiry(expiresAt: p.expiresAt, key: key, peerId: peerId)
  )
  store.compactProviderExpiry()

method addProvider*(
    store: MemoryKadStore, key: Key, p: StoredProvider, maxPerKey: int
): Future[LPResult[AddProviderOutcome]] {.async: (raises: [CancelledError]), gcsafe.} =
  let id = p.provider.id.valueOr:
    return err("provider of key " & $key & " has no id", "provider without id")
  let peerId = PeerId.init(id).valueOr:
    return err("provider of key " & $key & ": " & $error, "invalid provider id")

  var known = false
  var count = 0
  store.providers.withValue(key, stored):
    known = peerId in stored[]
    count = stored[].len
  if known:
    store.pushProvider(key, peerId, p)
    return ok(AddProviderOutcome.refreshed)
  if count >= maxPerKey:
    return ok(AddProviderOutcome.keyFull)
  if store.providerCount.atCapacity(store.limits.maxProviders) and
      not store.evictSoonestProvider():
    return ok(AddProviderOutcome.storeFull)

  store.providerCount.inc()
  store.pushProvider(key, peerId, p)
  ok(AddProviderOutcome.added)

method getProviders*(
    store: MemoryKadStore, key: Key, now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredProvider]]] {.async: (raises: [CancelledError]), gcsafe.} =
  var live: seq[StoredProvider]
  store.providers.withValue(key, stored):
    for p in stored[].values():
      if live.len >= limit:
        break
      if p.expiresAt.isLive(now):
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
  ok(true)

method delProvided*(
    store: MemoryKadStore, key: Key
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  store.provided.excl(key)
  ok()

method hasProvided*(
    store: MemoryKadStore, key: Key
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(key in store.provided)

method listProvided*(
    store: MemoryKadStore, after: Opt[Key], limit: int
): Future[LPResult[seq[Key]]] {.async: (raises: [CancelledError]), gcsafe.} =
  ok(store.provided.toSeq().page(after, limit))

method pruneExpired*(
    store: MemoryKadStore, now: UnixTimestamp
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  var deadValues: seq[RecordKey]
  for key, value in store.values:
    if not value.expiresAt.isLive(now):
      deadValues.add(key)
  for key in deadValues:
    store.values.del(key)

  while store.providerExpiry.len > 0 and
      not store.providerExpiry[0].expiresAt.isLive(now):
    let e = store.providerExpiry.pop()
    if store.isCurrent(e):
      store.dropProvider(e.key, e.peerId)
  ok()
