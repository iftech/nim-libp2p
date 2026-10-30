# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The storage backend of Kademlia: value records, provider records and the
## keys this node provides. Subclass ``KadStore`` and override every method.
##
## Contract for every backend:
## - A read never returns an entry with ``expiresAt <= now``. Provided keys do not expire.
## - A full value or provided-key store refuses a new entry with ``ok(false)``.
## - A full provider store evicts the provider with the lowest ``expiresAt``.
## - ``getProviders`` returns the providers of a key in no fixed order.
## - ``err`` means the backend failed. The core logs it and treats the call as "not stored" or "not found".
## - A ``limit`` below 1 returns no entries.
## - A method must not block the chronos event loop. Slow I/O goes through ``await``.
## - A method is atomic: concurrent calls never interleave a check and its write.
## - The application opens and closes the store. ``KadDHT`` does not.

import chronos
import ../../[peerid, results]
import ./[key_value, protobuf, types]

type
  StoredValue* = object
    key*: RecordKey
    record*: EntryRecord
    expiresAt*: UnixTimestamp

  StoredProvider* = object
    provider*: Provider
    expiresAt*: UnixTimestamp

  AddProviderOutcome* {.pure.} = enum
    added
    refreshed ## the provider was already stored for the key; ``expiresAt`` is updated
    keyFull ## the key holds ``maxPerKey`` other providers
    storeFull ## the store holds its total cap and has no provider to evict

  KadStore* = ref object of RootObj

method getValue*(
    store: KadStore, key: RecordKey, now: UnixTimestamp
): Future[LPResult[Opt[StoredValue]]] {.
    async: (raises: [CancelledError]), base, gcsafe
.} =
  raiseAssert "[KadStore.getValue] abstract method not implemented!"

method putValue*(
    store: KadStore, value: StoredValue
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  ## Inserts or replaces the value of ``value.key``. ``false`` when the store is full.
  raiseAssert "[KadStore.putValue] abstract method not implemented!"

method delValue*(
    store: KadStore, key: RecordKey
): Future[LPResult[void]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  raiseAssert "[KadStore.delValue] abstract method not implemented!"

method listValues*(
    store: KadStore, after: Opt[RecordKey], now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredValue]]] {.
    async: (raises: [CancelledError]), base, gcsafe
.} =
  ## Keyset paging in ``Key`` byte order. ``after`` is exclusive.
  raiseAssert "[KadStore.listValues] abstract method not implemented!"

method addProvider*(
    store: KadStore, key: Key, p: StoredProvider, maxPerKey: int
): Future[LPResult[AddProviderOutcome]] {.
    async: (raises: [CancelledError]), base, gcsafe
.} =
  ## Matches by ``provider.id``. A match is ``refreshed`` even at ``maxPerKey`` or the total cap.
  ## An id that is missing or is not a ``PeerId`` is ``err``.
  raiseAssert "[KadStore.addProvider] abstract method not implemented!"

method getProviders*(
    store: KadStore, key: Key, now: UnixTimestamp, limit: int
): Future[LPResult[seq[StoredProvider]]] {.
    async: (raises: [CancelledError]), base, gcsafe
.} =
  raiseAssert "[KadStore.getProviders] abstract method not implemented!"

method removeProvider*(
    store: KadStore, key: Key, peerId: PeerId
): Future[LPResult[void]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  raiseAssert "[KadStore.removeProvider] abstract method not implemented!"

method addProvided*(
    store: KadStore, key: Key
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  ## Idempotent: ``true`` for a key already provided. ``false`` when a new key finds the store full.
  raiseAssert "[KadStore.addProvided] abstract method not implemented!"

method delProvided*(
    store: KadStore, key: Key
): Future[LPResult[void]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  raiseAssert "[KadStore.delProvided] abstract method not implemented!"

method hasProvided*(
    store: KadStore, key: Key
): Future[LPResult[bool]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  raiseAssert "[KadStore.hasProvided] abstract method not implemented!"

method listProvided*(
    store: KadStore, after: Opt[Key], limit: int
): Future[LPResult[seq[Key]]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  ## Keyset paging in ``Key`` byte order. ``after`` is exclusive.
  raiseAssert "[KadStore.listProvided] abstract method not implemented!"

method pruneExpired*(
    store: KadStore, now: UnixTimestamp
): Future[LPResult[void]] {.async: (raises: [CancelledError]), base, gcsafe.} =
  ## Deletes every value and provider with ``expiresAt <= now``. The core calls it from its heartbeats.
  raiseAssert "[KadStore.pruneExpired] abstract method not implemented!"
