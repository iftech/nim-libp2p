# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, results
import ../../[peerid, peerinfo, switch, multihash]
import ../protocol
import ./[protobuf, types, kademlia_metrics]

logScope:
  topics = "libp2p kademlia"

proc exchange(
    stream: Stream, encoded: seq[byte]
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
  await stream.writeLp(encoded)
  await stream.readLp(MaxMsgSize)

proc ping*(
    kad: KadDHT, peerId: PeerId, addrs: seq[MultiAddress]
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let stream =
    try:
      await noCancel kad.switch.dial(peerId, addrs, kad.codec)
    except DialFailedError as e:
      return err(e, "ping dial failed")
  defer:
    await noCancel stream.close()

  let request = Message(msgType: Opt.some(MessageType.ping))
  let encoded = request.encode(kad.config.hideConnectionStatus)

  kad_messages_sent.inc(labelValues = [$MessageType.ping])
  kad_message_bytes_sent.inc(encoded.len.int64, labelValues = [$MessageType.ping])

  var replyBuf: seq[byte]
  try:
    kad_message_duration_ms.time(labelValues = [$MessageType.ping]):
      replyBuf = await stream.exchange(encoded).wait(kad.config.timeout)
  except AsyncTimeoutError:
    return err("ping timed out")
  except LPStreamError as e:
    return err(e, "ping stream failed")

  kad_message_bytes_received.inc(replyBuf.len.int64, labelValues = [$MessageType.ping])

  let reply = Message.decode(replyBuf).valueOr:
    return err(error, "ping reply decode failed")

  if reply != request:
    return err(
      "expected " & $MessageType.ping & ", got " &
        $reply.msgType.valueOr(MessageType.ping),
      "ping reply does not match the request",
    )

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
