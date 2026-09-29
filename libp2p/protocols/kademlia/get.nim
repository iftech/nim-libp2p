# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/tables
import chronos, chronicles, results
import ../../[peerid, switch, multihash]
import ../../utils/future
import ../protocol
import ./[protobuf, types, find, put, rpc, kademlia_metrics]

logScope:
  topics = "libp2p kademlia"

proc dispatchGetVal*(
    kad: KadDHT, peer: PeerId, key: Key
): Future[LPResult[Message]] {.async: (raises: [CancelledError]), gcsafe.} =
  let msg = Message(msgType: Opt.some(MessageType.getValue), key: Opt.some(key))
  await kad.dispatchRpc(peer, msg)

proc bestValidRecord(
    kad: KadDHT, key: Key, received: ReceivedTable, quorum: int
): LPResult[EntryRecord] =
  var validRecords: seq[EntryRecord]
  for r in received.values():
    let record = r.valueOr:
      continue
    if kad.config.validator.isValid(key, record):
      validRecords.add(record)

  if validRecords.len() < quorum:
    return err(
      "Not enough valid records to achieve quorum, needed " & $quorum & " got " &
        $validRecords.len()
    )

  let selectedIdx = kad.config.selector.select(key, validRecords).valueOr:
    return err("Could not select best value")

  ok(validRecords[selectedIdx])

proc getValue*(
    kad: KadDHT, key: Key, quorumOverride: Opt[int] = Opt.none(int)
): Future[LPResult[EntryRecord]] {.async: (raises: [CancelledError]), gcsafe.} =
  let received = ReceivedTable()

  # if locally present and not expired, include our own copy
  kad.dataTable.get(key).ifValue(localRecord):
    if not localRecord.isExpired(kad.config.recordExpirationInterval):
      received[kad.switch.peerInfo.peerId] = Opt.some(localRecord)
    else:
      kad.dataTable.del(key)
      trace "Local record expired on read", key = key

  let quorum = quorumOverride.valueOr:
    kad.config.quorum

  let onReply = proc(
      peer: PeerId, msgOpt: Opt[Message], state: LookupState
  ): Future[void] {.async: (raises: []), gcsafe.} =
    if not received.hasKey(peer) and received.len >= kad.config.limits.maxReceivedSize:
      trace "GetValue: ReceivedTable cap reached, dropping reply",
        peer = peer, cap = kad.config.limits.maxReceivedSize
      return

    received[peer] = Opt.none(EntryRecord)

    let reply = msgOpt.valueOr:
      trace "Empty reply"
      return

    let record = reply.record.valueOr:
      trace "Get-value reply has no record", messageType = "getValue"
      return

    if record.key.isNone or record.key.get() != key:
      trace "GetValue returned record with mismatched key",
        expected = key, got = record.key
      return

    let value = record.value.valueOr:
      trace "Get-value reply has no value", messageType = "getValue"
      return

    if value.len > kad.config.limits.maxValueSize:
      trace "GetValue dropped: value exceeds maxValueSize",
        peer = peer, size = value.len, cap = kad.config.limits.maxValueSize
      return

    let time = record.timeReceived.valueOr:
      trace "GetValue returned record with no timeReceived, using current time instead",
        reply = reply
      Timestamp.now()

    received[peer] = Opt.some(EntryRecord(value: value, time: time))

  let quorumReached = proc(state: LookupState): bool {.gcsafe.} =
    received.len >= quorum

  discard await kad.iterativeLookup(key, dispatchGetVal, onReply, quorumReached)

  let best = ?kad.bestValidRecord(key, received, quorum)

  # insert value to our localtable
  if kad.canStoreLocalRecord(key):
    kad.dataTable.insert(key, best.value, Timestamp.now())
  else:
    debug "GetValue: local record limit reached", key = key, current = kad.dataTable.len

  # update peers that
  # - don't have best value
  # - don't have valid records
  # - don't have the values at all
  var rpcBatch: seq[Future[LPResult[void]]]
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
    trace "Get-value request rejected",
      reason = "missingKey", messageType = "getValue", stream
    return

  # Evict the entry eagerly if it has expired so the response below treats it as
  # absent and sends the standard "no record found" response.
  var entryRecordOpt = kad.dataTable.get(key)
  entryRecordOpt.ifValue(record):
    if record.isExpired(kad.config.recordExpirationInterval):
      trace "Record expired, dropping", key = key
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
      debug "Failed to send get-value RPC reply", err = exc.msg, stream
    return

  let response = Message(
    msgType: Opt.some(MessageType.getValue),
    key: Opt.some(key),
    closerPeers: kad.findClosestPeers(key, stream.peerId),
    record: Opt.some(
      Record(
        key: Opt.some(key),
        value: Opt.some(entryRecord.value),
        timeReceived: Opt.some(entryRecord.time),
      )
    ),
  )
  let encoded = response.encode(kad.config.hideConnectionStatus)
  kad_message_bytes_sent.inc(encoded.len.int64, labelValues = [$MessageType.getValue])
  try:
    await stream.writeLp(encoded)
  except LPStreamError as exc:
    trace "Failed to send get-value RPC reply", err = exc.msg, stream
    return
