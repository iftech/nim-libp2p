# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sequtils, strformat]
import chronos, chronicles, results
import ../../[peerid, switch, multihash]
import ../../utils/[heartbeat, future]
import ../protocol
import ./[protobuf, store, types, find, rpc, kademlia_metrics]

logScope:
  topics = "libp2p kademlia"

proc localRecord*(
    kad: KadDHT, key: RecordKey
): Future[Opt[EntryRecord]] {.async: (raises: [CancelledError]).} =
  let stored = (await kad.store.getValue(key, nowUnixSeconds())).valueOr:
    debug "Failed to read local record", key, err = error
    return Opt.none(EntryRecord)
  let value = stored.valueOr:
    return Opt.none(EntryRecord)
  Opt.some(value.record)

proc storeLocalRecord*(
    kad: KadDHT, key: RecordKey, value: Value, time: Timestamp = Timestamp.now()
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## A record lives through its whole ``recordExpirationInterval``. An unparseable time is expired on arrival.
  let storedAt = time.toUnixSeconds().valueOr(0)
  let stored = StoredValue(
    key: key,
    record: EntryRecord(value: value, time: time),
    expiresAt: storedAt + kad.config.recordExpirationInterval.seconds + 1,
  )
  (await kad.store.putValue(stored, nowUnixSeconds())).valueOr:
    debug "Failed to store local record", key, err = error
    return false

proc isBestValue(
    kad: KadDHT, key: RecordKey, record: EntryRecord
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Returns whether `value` is a better value than what we have locally
  ## Always returns `true` if we don't have the value locally

  (await kad.localRecord(key)).ifValue(existing):
    kad.config.selector.select(key, @[record, existing]).ifValue(selectedIdx):
      return selectedIdx == 0
  return true

proc manageExpiredRecords*(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  ## Periodically deletes the entries that ``recordExpirationInterval`` expired.
  ## Runs indefinitely as a heartbeat loop until cancelled (e.g. via
  ## `cancelSoon` or `cancelAndWait`).
  heartbeat "cleanup expired data entries", kad.config.cleanupDataEntriesInterval:
    (await kad.store.pruneExpired(nowUnixSeconds())).isOkOr:
      debug "Failed to prune expired records", err = error

proc dispatchPutVal*(
    kad: KadDHT, peer: PeerId, key: RecordKey, value: Value
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let msg = Message(
    msgType: Opt.some(MessageType.putValue),
    key: Opt.some(key.toKey()),
    record: Opt.some(Record(key: Opt.some(key.toKey()), value: Opt.some(value))),
  )
  let reply = ?await kad.dispatchRpc(peer, msg)

  trace "Kademlia put-value RPC completed",
    peerId = peer, messageType = "putValue", replyType = $reply.msgType

  if reply != msg:
    trace "Kademlia put-value RPC reply rejected",
      peerId = peer, messageType = "putValue", replyType = $reply.msgType

  ok()

proc putValue*(
    kad: KadDHT, key: RecordKey, value: Value
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  if value.len > kad.config.limits.maxValueSize:
    return err(
      fmt"{value.len} > {kad.config.limits.maxValueSize}", "value exceeds maxValueSize"
    )

  let record = EntryRecord(value: value, time: Timestamp.now())

  if not kad.config.validator.isValid(key, record):
    return err("invalid key/value pair")

  if not await kad.isBestValue(key, record):
    return err("Value rejected, we have a better one")

  let peers = await kad.findNode(key.toKey())

  let storedLocally = await kad.storeLocalRecord(key, value)
  if not storedLocally:
    trace "PutValue: local record limit reached"

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

  let key = RecordKey.init(msgKey).valueOr:
    trace "Put-value request rejected",
      reason = "invalidKeyLength", messageType = "putValue", stream, err = error
    return

  if record.key != msgKey:
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
  if not kad.config.validator.isValid(key, entryRecord):
    trace "Put-value request rejected",
      reason = "invalidRecord", messageType = "putValue", stream
    return

  if not await kad.isBestValue(key, entryRecord):
    trace "Dropping received value, we have a better one"
    await stream.reset()
    return

  if not await kad.storeLocalRecord(key, entryRecord.value):
    debug "PutValue: local record limit reached", stream
    await stream.reset()
    return

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
