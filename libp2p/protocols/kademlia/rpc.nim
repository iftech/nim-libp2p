# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The outbound path every Kademlia request/response RPC shares: take an RPC
## slot, encode, send on the peer's reused stream, count the message metrics and
## decode the reply.

import chronos, results
import ../../[multiaddress, peerid, switch]
import ./[protobuf, types, kademlia_metrics]

proc countSent*[T](
    res: Result[T, SendError], msgType: MessageType, sentBytes: int64
) {.gcsafe, raises: [].} =
  ## Count what left the node: a send that gave up at the dial sent nothing.
  if res.isErr() and res.error().stage in {waitStage, dialStage, refusedStage}:
    return
  kad_messages_sent.inc(labelValues = [$msgType])
  kad_message_bytes_sent.inc(sentBytes, labelValues = [$msgType])

proc dialAddrs*(kad: KadDHT, peer: PeerId): seq[MultiAddress] {.raises: [].} =
  ## The addresses an RPC to `peer` dials when its caller names none.
  kad.switch.peerStore[AddressBook][peer]

proc dispatchRpc*(
    kad: KadDHT,
    peer: PeerId,
    msg: Message,
    addrs: Opt[seq[MultiAddress]] = Opt.none(seq[MultiAddress]),
): Future[LPResult[Message]] {.async: (raises: [CancelledError]), gcsafe.} =
  ## Addresses default to the peer store; `addrs` overrides them for a peer the
  ## caller learned about elsewhere.
  let msgType = msg.msgType.valueOr:
    return err("outbound RPC without a message type")

  withRpcSlot(kad)
  var encoded = msg.encode(kad.config.hideConnectionStatus)
  let sentBytes = encoded.len.int64

  var sendRes: Result[seq[byte], SendError]
  kad_message_duration_ms.time(labelValues = [$msgType]):
    sendRes = await kad.msgSender.sendRequest(
      peer, addrs.valueOr(kad.dialAddrs(peer)), move encoded, kad.config.timeout
    )
  sendRes.countSent(msgType, sentBytes)

  let replyBuf = sendRes.valueOr:
    return err(error.msg, $error.stage)

  kad_message_bytes_received.inc(replyBuf.len.int64, labelValues = [$msgType])

  let reply = Message.decode(replyBuf).valueOr:
    return err($msgType & " reply decode fail")

  # Peers share one stream and the wire format carries no request ids, so a reply
  # of another type means the stream desynced. Taking it would answer this RPC
  # with the response to a different one.
  if reply.msgType.valueOr(msgType) != msgType:
    return err($msgType & " reply type mismatch")

  if reply.closerPeers.len > 0:
    kad_responses_with_closer_peers.inc(labelValues = [$msgType])

  ok(reply)
