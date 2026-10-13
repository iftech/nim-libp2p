# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sequtils, strformat, tables]
import chronos, chronicles, results
import ../../[peerid, switch, multihash]
import ../../utils/[heartbeat, future]
import ../protocol
import ./[protobuf, types, find, rpc, kademlia_metrics]

logScope:
  topics = "libp2p kademlia"

proc isBestValue(kad: KadDHT, key: Key, record: EntryRecord): bool =
  ## Returns whether `value` is a better value than what we have locally
  ## Always returns `true` if we don't have the value locally

  kad.dataTable.get(key).ifValue(existing):
    kad.config.selector.select(key, @[record, existing]).ifValue(selectedIdx):
      return selectedIdx == 0
  return true

proc isExpired*(
    record: EntryRecord,
    interval: chronos.Duration,
    currentUnixSeconds = nowUnixSeconds(),
): bool {.gcsafe, raises: [].} =
  ## Returns true when the record's stored timestamp is older than `interval`.
  ## Records whose timestamp cannot be parsed are treated as expired.
  let storedUnix = record.time.toUnixSeconds().valueOr:
    trace "Failed to parse record timestamp, treating as expired", time = record.time
    return true

  (currentUnixSeconds - storedUnix).seconds > interval

proc manageExpiredRecords*(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  ## Periodically scans `dataTable` and evicts entries that are older than
  ## `config.recordExpirationInterval`. Runs indefinitely as a heartbeat
  ## loop until cancelled (e.g. via `cancelSoon` or `cancelAndWait`).
  heartbeat "cleanup expired data entries", kad.config.cleanupDataEntriesInterval:
    let currentUnixSeconds = nowUnixSeconds()
    var toRemove: seq[Key]
    for key, record in kad.dataTable:
      if record.isExpired(kad.config.recordExpirationInterval, currentUnixSeconds):
        toRemove.add(key)
    for key in toRemove:
      kad.dataTable.del(key)
      trace "Expired record removed", key

proc dispatchPutVal*(
    kad: KadDHT, peer: PeerId, key: Key, value: Value
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let msg = Message(
    msgType: Opt.some(MessageType.putValue),
    key: Opt.some(key),
    record: Opt.some(Record(key: Opt.some(key), value: Opt.some(value))),
  )
  let reply = ?await kad.dispatchRpc(peer, msg)

  trace "Kademlia put-value RPC completed",
    peerId = peer, messageType = "putValue", replyType = $reply.msgType

  if reply != msg:
    trace "Kademlia put-value RPC reply rejected",
      peerId = peer, messageType = "putValue", replyType = $reply.msgType

  ok()

proc canStoreLocalRecord*(kad: KadDHT, key: Key): bool {.raises: [].} =
  if kad.dataTable.hasKey(key):
    return true
  kad.config.limits.maxLocalRecords.ifValue(limit):
    return kad.dataTable.len < limit
  true

proc putValue*(
    kad: KadDHT, key: Key, value: Value
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  if value.len > kad.config.limits.maxValueSize:
    return err(
      fmt"{value.len} > {kad.config.limits.maxValueSize}", "value exceeds maxValueSize"
    )

  let record = EntryRecord(value: value, time: Timestamp.now())

  if not kad.config.validator.isValid(key, record):
    return err("invalid key/value pair")

  if not kad.isBestValue(key, record):
    return err("Value rejected, we have a better one")

  let peers = await kad.findNode(key)

  let storedLocally = kad.canStoreLocalRecord(key)
  if storedLocally:
    kad.dataTable.insert(key, value, Timestamp.now())
  else:
    trace "PutValue: local record limit reached", current = kad.dataTable.len

  var attempted, succeeded, failed, cancelled, pending: int
  var outcome = "cancelled"
  defer:
    debug "Put-value replication finished",
      key,
      outcome,
      storedLocally,
      peers = peers.len,
      attempted,
      succeeded,
      failed,
      cancelled,
      pending

  for chunk in peers.toChunks(kad.config.alpha):
    let batch = chunk.mapIt(kad.dispatchPutVal(it, key, value))
    attempted += batch.len
    try:
      await batch.allFuturesWaitOrTimeout(kad.config.timeout)
    finally:
      let results = countFutureOutcomes(batch)
      var rejected: int
      for fut in batch:
        if fut.completed() and fut.value().isErr():
          rejected.inc()
      succeeded += results.succeeded - rejected
      failed += results.failed + rejected
      cancelled += results.cancelled
      pending += results.pending
  outcome = "completed"
  ok()

proc handlePutValue*(
    kad: KadDHT, stream: Stream, msg: Message
) {.async: (raises: [CancelledError]).} =
  let record = msg.record.valueOr:
    trace "Put-value request rejected",
      reason = "missingRecord", messageType = "putValue", stream
    return

  let msgKey = msg.key.valueOr:
    trace "Put-value request rejected",
      reason = "missingKey", messageType = "putValue", stream
    return

  if record.key.isNone or record.key.get() != msgKey:
    trace "Put-value request rejected",
      reason = "keyMismatch", messageType = "putValue", stream
    return

  let value = record.value.valueOr:
    trace "Put-value request rejected",
      reason = "missingValue", messageType = "putValue", stream
    return

  if value.len > kad.config.limits.maxValueSize:
    trace "PUT_VALUE dropped: value exceeds maxValueSize",
      stream, size = value.len, cap = kad.config.limits.maxValueSize
    await stream.reset()
    return

  let entryRecord = EntryRecord(value: value, time: Timestamp.now())

  # Value sanitisation done. Start insertion process
  if not kad.config.validator.isValid(msgKey, entryRecord):
    trace "Put-value request rejected",
      reason = "invalidRecord", messageType = "putValue", stream
    return

  if not kad.isBestValue(msgKey, entryRecord):
    trace "Dropping received value, we have a better one"
    await stream.reset()
    return

  if not kad.canStoreLocalRecord(msgKey):
    debug "PutValue: local record limit reached", stream, current = kad.dataTable.len
    await stream.reset()
    return

  kad.dataTable.insert(msgKey, entryRecord.value, Timestamp.now())
  # consistent with following link, echo message without change
  # https://github.com/libp2p/js-libp2p/blob/cf9aab5c841ec08bc023b9f49083c95ad78a7a07/packages/kad-dht/src/rpc/handlers/put-value.ts#L22
  let encoded = msg.encode(kad.config.hideConnectionStatus)
  kad_message_bytes_sent.inc(encoded.len.int64, labelValues = [$MessageType.putValue])
  try:
    await stream.writeLp(encoded)
  except LPStreamError as exc:
    trace "Kademlia put-value RPC reply write failed",
      err = exc.msg, stream, messageType = $MessageType.putValue
    return
