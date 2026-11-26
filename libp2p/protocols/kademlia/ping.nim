# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, results
import ../../[peerid, peerinfo, switch, multihash]
import ../protocol
import ./[protobuf, types, kademlia_metrics, rpc]

logScope:
  topics = "libp2p kademlia"

proc ping*(
    kad: KadDHT, peerId: PeerId, addrs: seq[MultiAddress]
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let request = Message(msgType: Opt.some(MessageType.ping))
  let reply = (await kad.dispatchRpc(peerId, request, Opt.some(addrs))).valueOr:
    return err(error, "ping failed")

  if reply != request:
    return err("ping reply differs from the request")

  ok()

proc ping*(
    kad: KadDHT, peerInfo: PeerInfo
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  await kad.ping(peerInfo.peerId, peerInfo.addrs)

proc handlePing*(
    kad: KadDHT, stream: Stream, msg: Message
) {.async: (raises: [CancelledError]).} =
  let encoded = msg.encode(kad.config.hideConnectionStatus)
  kad_message_bytes_sent.inc(encoded.len.int64, labelValues = [$MessageType.ping])
  try:
    await stream.writeLp(encoded)
  except LPStreamError as exc:
    debug "Kademlia ping RPC reply write failed",
      err = exc.msg, stream, messageType = $MessageType.ping
    return
