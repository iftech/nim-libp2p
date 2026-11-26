# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The value records of this node in ``KadDHT.store``. Internal to Kademlia: ``kademlia.nim`` does not export it.

import chronicles
import ../../results
import ../../utils/opt
import ./[key_value, protobuf, store, types, kademlia_metrics]

logScope:
  topics = "libp2p kademlia"

proc getLocalRecord*(kad: KadDHT, key: RecordKey): LPResult[Opt[EntryRecord]] =
  let stored = kad.store.getValue(key, UnixTimestamp.now()).valueOr:
    kad_store_errors.inc(labelValues = ["getValue"])
    return err(error, "local record read failed")
  let value = stored.valueOr:
    return ok(Opt.none(EntryRecord))
  ok(Opt.some(value.record))

proc getLocalRecord*(kad: KadDHT, key: Key): LPResult[Opt[EntryRecord]] =
  let recordKey = RecordKey.init(key).valueOr:
    return ok(Opt.none(EntryRecord))
  kad.getLocalRecord(recordKey)

proc putLocalRecord(kad: KadDHT, key: RecordKey, record: EntryRecord): bool =
  ## Logs why the store refused the record, so the caller does not log it again.
  let now = UnixTimestamp.now()
  let value = StoredValue(
    key: key,
    record: record,
    expiresAt: now + kad.config.recordExpirationInterval.ceilSeconds(),
  )
  let stored = kad.store.putValue(value, now).valueOr:
    kad_store_errors.inc(labelValues = ["putValue"])
    warn "Local record not stored: store failed", err = error
    return false
  if not stored:
    debug "Local record not stored: store is full", key
  stored

proc isBestValue*(kad: KadDHT, key: RecordKey, record: EntryRecord): LPResult[bool] =
  ## Returns whether `record` is better than the local record, or ``true`` with no local record.
  let local = ?kad.getLocalRecord(key)
  local.ifValue(existing):
    kad.config.selector.select(key, @[record, existing]).ifValue(selectedIdx):
      return ok(selectedIdx == 0)
  ok(true)

proc putBestLocalRecord*(kad: KadDHT, key: RecordKey, record: EntryRecord): bool =
  ## A failed read of the local record aborts the write, so a store error never overwrites a better record.
  let isBest = kad.isBestValue(key, record).valueOr:
    warn "Local record not stored: local read failed", err = error
    return false
  if not isBest:
    trace "Local record not stored: a better one is stored", key
    return false
  kad.putLocalRecord(key, record)
