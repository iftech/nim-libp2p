# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import algorithm, sequtils, sets
import chronos
import ./protobuf, ../../peerid

type
  RegistrationId* = uint64

  RegisteredData* = object
    expiration*: Moment
    peerId*: PeerId
    data*: Register

  RegistrationEntry* = object
    id*: RegistrationId
    registration*: RegisteredData

  RegistrationStore* = object
    ## Registrations in insertion order, each with an id that only grows.
    entries: seq[RegistrationEntry]
    nextId: RegistrationId

func cmpId(entry: RegistrationEntry, id: RegistrationId): int =
  cmp(entry.id, id)

func lowerBound(store: RegistrationStore, id: RegistrationId): int =
  store.entries.lowerBound(id, cmpId)

func position(store: RegistrationStore, id: RegistrationId): int =
  let pos = store.lowerBound(id)
  if pos < store.entries.len and store.entries[pos].id == id: pos else: -1

func add*(store: var RegistrationStore, registration: RegisteredData): RegistrationId =
  let id = store.nextId
  store.entries.add(RegistrationEntry(id: id, registration: registration))
  store.nextId.inc()
  id

func remove*(store: var RegistrationStore, id: RegistrationId) =
  let pos = store.position(id)
  if pos >= 0:
    store.entries.delete(pos)

func len*(store: RegistrationStore): int =
  store.entries.len

func contains*(store: RegistrationStore, id: RegistrationId): bool =
  store.position(id) >= 0

func `[]`*(store: var RegistrationStore, id: RegistrationId): var RegisteredData =
  let pos = store.position(id)
  doAssert pos >= 0, "unknown registration id " & $id
  store.entries[pos].registration

func firstId*(store: RegistrationStore): RegistrationId =
  ## Id of the oldest stored registration, or `nextId` when the store is empty.
  if store.entries.len == 0:
    store.nextId
  else:
    store.entries[0].id

func nextId*(store: RegistrationStore): RegistrationId =
  store.nextId

func dropExpired*(store: var RegistrationStore, now: Moment): HashSet[RegistrationId] =
  var dropped = initHashSet[RegistrationId]()
  for entry in store.entries:
    if entry.registration.expiration < now:
      dropped.incl(entry.id)

  store.entries.keepItIf(it.registration.expiration >= now)
  dropped

iterator items*(store: RegistrationStore): lent RegistrationEntry =
  for entry in store.entries:
    yield entry

iterator mitems*(store: var RegistrationStore): var RegisteredData =
  for entry in store.entries.mitems():
    yield entry.registration

iterator entriesFrom*(
    store: RegistrationStore, firstId: RegistrationId
): lent RegistrationEntry =
  for i in store.lowerBound(firstId) ..< store.entries.len:
    yield store.entries[i]
