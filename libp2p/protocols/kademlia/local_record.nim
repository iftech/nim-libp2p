# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The value records of this node in ``KadDHT.store``. Internal to Kademlia: ``kademlia.nim`` does not export it.

import chronos, chronicles
import ../../results
import ../../utils/[lock, opt]
import ./[key_value, protobuf, store, types]

logScope:
  topics = "libp2p kademlia"

proc getLocalRecord*(
    kad: KadDHT, key: RecordKey
): Future[Opt[EntryRecord]] {.async: (raises: [CancelledError]).} =
  let stored = (await kad.store.getValue(key, nowUnixSeconds())).valueOr:
    warn "Local record read failed", err = error
    return Opt.none(EntryRecord)
  let value = stored.valueOr:
    return Opt.none(EntryRecord)
  Opt.some(value.record)

proc getLocalRecord*(
    kad: KadDHT, key: Key
): Future[Opt[EntryRecord]] {.async: (raises: [CancelledError]).} =
  let recordKey = RecordKey.init(key).valueOr:
    return Opt.none(EntryRecord)
  await kad.getLocalRecord(recordKey)

proc putLocalRecord(
    kad: KadDHT, key: RecordKey, record: EntryRecord
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Logs why the store refused the record, so the caller does not log it again.
  let value =
    StoredValue(key: key, record: record, ttl: kad.config.recordExpirationInterval)
  let stored = (await kad.store.putValue(value, nowUnixSeconds())).valueOr:
    warn "Local record not stored: store failed", err = error
    return false
  if not stored:
    debug "Local record not stored: store is full", key
  stored

proc isBestValue*(
    kad: KadDHT, key: RecordKey, record: EntryRecord
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Returns whether `value` is a better value than what we have locally
  ## Always returns `true` if we don't have the value locally

  (await kad.getLocalRecord(key)).ifValue(existing):
    kad.config.selector.select(key, @[record, existing]).ifValue(selectedIdx):
      return selectedIdx == 0
  return true

proc putBestLocalRecord*(
    kad: KadDHT, key: RecordKey, record: EntryRecord
): Future[bool] {.async: (raises: [CancelledError]).} =
  withLock(kad.valueLock):
    if not await kad.isBestValue(key, record):
      trace "Local record not stored: a better one is stored", key
      return false
    return await kad.putLocalRecord(key, record)
