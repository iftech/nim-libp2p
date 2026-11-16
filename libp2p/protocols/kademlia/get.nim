# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/tables
import chronos, chronicles, results
import ../../[peerid, switch, multihash]
import ../../utils/future
import ../protocol
import ./[protobuf, types, find, put, rpc, kademlia_metrics]

logScope:
  topics = "kad-dht get"

proc dispatchGetVal*(
    kad: KadDHT, peer: PeerId, key: Key
): Future[Result[Message, string]] {.async: (raises: [CancelledError]), gcsafe.} =
  let msg = Message(msgType: Opt.some(MessageType.getValue), key: Opt.some(key))
  await kad.dispatchRpc(peer, msg)

proc bestValidRecord(
    kad: KadDHT, key: Key, received: ReceivedTable
): Result[EntryRecord, string] =
  var validRecords: seq[EntryRecord]
  for r in received.values():
    let record = r.valueOr:
      continue
    validRecords.add(record)

  if validRecords.len() == 0:
    return err("No valid records found")

  let selectedIdx = kad.config.selector.select(key, validRecords).valueOr:
    return err("Could not select best value")

  ok(validRecords[selectedIdx])

proc getValue*(
    kad: KadDHT, key: Key, quorumOverride: Opt[int] = Opt.none(int)
): Future[Result[EntryRecord, string]] {.async: (raises: [CancelledError]), gcsafe.} =
  ## Quorum counts valid records for early stopping. An exhausted search returns
  ## the best valid record found, or an error if none was found.
  # Some entries have passed validation; None entries are kept for repair.
  let received = ReceivedTable()
  var validCount = 0

  # if locally present and not expired, include our own copy
  kad.dataTable.get(key).withValue(localRecord):
    if not localRecord.isExpired(kad.config.recordExpirationInterval):
      if kad.config.validator.isValid(key, localRecord):
        received[kad.switch.peerInfo.peerId] = Opt.some(localRecord)
        validCount.inc()
      else:
        received[kad.switch.peerInfo.peerId] = Opt.none(EntryRecord)
    else:
      kad.dataTable.del(key)
      debug "Local record expired on read", key = key

  let quorum = quorumOverride.valueOr:
    kad.config.quorum

  let onReply = proc(
      peer: PeerId, msgOpt: Opt[Message], state: LookupState
  ): Future[void] {.async: (raises: []), gcsafe.} =
    if received.getOrDefault(peer).isSome():
      return
    if received.len < kad.config.limits.maxReceivedSize:
      received[peer] = Opt.none(EntryRecord)

    let reply = msgOpt.valueOr:
      debug "Empty reply"
      return

    let record = reply.record.valueOr:
      debug "GetValue returned empty record", reply = reply
      return

    if record.key.isNone or record.key.get() != key:
      debug "GetValue returned record with mismatched key",
        expected = key, got = record.key
      return

    let value = record.value.valueOr:
      debug "GetValue returned record with no value", reply = reply
      return

    if value.len > kad.config.limits.maxValueSize:
      debug "GetValue dropped: value exceeds maxValueSize",
        peer = peer, size = value.len, cap = kad.config.limits.maxValueSize
      return

    let time = record.timeReceived.valueOr:
      debug "GetValue returned record with no timeReceived, using current time instead",
        reply = reply
      Timestamp.now()

    let entry = EntryRecord(value: value, time: time)
    if not kad.config.validator.isValid(key, entry):
      debug "GetValue dropped: record failed validation", peer
      return

    if not received.hasKey(peer) and received.len >= kad.config.limits.maxReceivedSize:
      var replacePeer = Opt.none(PeerId)
      for p, r in received:
        if r.isNone():
          replacePeer = Opt.some(p)
          break
      let p = replacePeer.valueOr:
        debug "GetValue: ReceivedTable cap reached, dropping reply",
          peer = peer, cap = kad.config.limits.maxReceivedSize
        return
      received.del(p)

    received[peer] = Opt.some(entry)
    validCount.inc()

  let quorumReached = proc(state: LookupState): bool {.gcsafe.} =
    validCount > 0 and validCount >= quorum

  discard await kad.iterativeLookup(key, dispatchGetVal, onReply, quorumReached)

  let best = ?kad.bestValidRecord(key, received)

  # insert value to our localtable
  if kad.canStoreLocalRecord(key):
    kad.dataTable.insert(key, best.value, Timestamp.now())
  else:
    debug "GetValue: local record limit reached", key = key, current = kad.dataTable.len

  # update peers that
  # - don't have best value
  # - don't have valid records
  # - don't have the values at all
  var rpcBatch: seq[Future[Result[void, string]]]
  for p, r in received:
    let record = r.valueOr:
      # peer doesn't have value
      rpcBatch.add(kad.dispatchPutVal(p, key, best.value))
      continue
    if record.value != best.value:
      # value is invalid or not best
      rpcBatch.add(kad.dispatchPutVal(p, key, best.value))

  await rpcBatch.allFuturesWaitOrTimeout(kad.config.timeout)

  ok(best)

method handleGetValue*(
    kad: KadDHT, stream: Stream, msg: Message
) {.base, async: (raises: [CancelledError]).} =
  let key = msg.key.valueOr:
    error "Key not set: handleGetValue", msg = msg, stream = stream
    return

  # Evict the entry eagerly if it has expired so the `valueOr` below treats it
  # as absent and sends the standard "no record found" response.
  var entryRecordOpt = kad.dataTable.get(key)
  entryRecordOpt.withValue(record):
    if record.isExpired(kad.config.recordExpirationInterval):
      debug "record expired, dropping", key = key
      kad.dataTable.del(key)
      entryRecordOpt = Opt.none(EntryRecord)

  let entryRecord = entryRecordOpt.valueOr:
    let response = Message(
      msgType: Opt.some(MessageType.getValue),
      key: Opt.some(key),
      closerPeers: kad.findClosestPeers(key, stream.peerId),
    )
    let encoded = response.encode(kad.config.hideConnectionStatus)
    kad_message_bytes_sent.inc(encoded.len.int64, labelValues = [$MessageType.getValue])
    try:
      await stream.writeLp(encoded)
    except LPStreamError as exc:
      debug "Failed to send get-value RPC reply", stream = stream, err = exc.msg
    return

  let response = Message(
    msgType: Opt.some(MessageType.getValue),
    key: Opt.some(key),
    record: Opt.some(
      Record(
        key: Opt.some(key),
        value: Opt.some(entryRecord.value),
        timeReceived: Opt.some(entryRecord.time),
      )
    ),
    closerPeers: kad.findClosestPeers(key, stream.peerId),
  )
  let encoded = response.encode(kad.config.hideConnectionStatus)
  kad_message_bytes_sent.inc(encoded.len.int64, labelValues = [$MessageType.getValue])
  try:
    await stream.writeLp(encoded)
  except LPStreamError as exc:
    debug "Failed to send get-value RPC reply", stream = stream, err = exc.msg
    return
