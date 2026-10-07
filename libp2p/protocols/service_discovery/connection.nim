# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/net
import chronos, chronicles, results
import ../../[peerid, switch, multiaddress, extended_peer_record]
import ../kademlia
import ../kademlia/types
import
  ./[types, service_discovery_metrics, registrar, dial_backoff, routing_table_manager]

logScope:
  topics = "libp2p service-discovery"

proc observedIps*(stream: Stream): seq[IpAddress] {.raises: [].} =
  ## Remote endpoint IP(s) from the transport connection, if known.
  var ips: seq[IpAddress]
  stream.observedAddr.ifValue(ma):
    ma.getIp().ifValue(ip):
      ips.add(ip)
  ips

func isRemoteReset(e: ref CatchableError): bool =
  ## A reset during the negotiate arrives as the parent of `DialFailedError`.
  e of LPStreamResetError or (not e.parent.isNil() and e.parent of LPStreamResetError)

proc evictOnReset(disco: ServiceDiscovery, peerId: PeerId, e: ref CatchableError) =
  ## A peer that resets a fresh stream mounts the codec but does not serve it.
  if not e.isRemoteReset():
    return

  let tables = disco.removePeer(peerId, reason = "reset")
  if tables > 0:
    trace "Evicted peer that reset a discovery request", peerId, tables, err = e.msg

proc send*(
    disco: ServiceDiscovery, peerId: PeerId, msg: Message
): Future[LPResult[Message]] {.async: (raises: [CancelledError]), gcsafe.} =
  let addrs = disco.switch.peerStore[AddressBook][peerId]
  if addrs.len == 0:
    return err("no address found for peer: " & $peerId)

  if disco.dialBackedOff(peerId, addrs):
    return err(makeDialBackoffError(peerId))

  let stream =
    try:
      await disco.switch.dial(peerId, addrs, disco.codec)
    except DialFailedError as e:
      disco.recordDialFailure(peerId, addrs)
      disco.evictOnReset(peerId, e)
      return err("dialing peer failed: " & e.msg)

  var replyRead = false
  defer:
    # Closing only half-closes the channel: an abandoned RPC leaves its unread
    # reply in the read buffer, which blocks the muxer for every other channel
    # on that connection. Only a reset drops it.
    if replyRead:
      await noCancel stream.close()
    else:
      await noCancel stream.reset()

  let encodedMsg = msg.encode()

  cd_messages_sent.inc(labelValues = [$msg.msgType])
  cd_message_bytes_sent.inc(encodedMsg.len.float64, labelValues = [$msg.msgType])

  var replyBuf: seq[byte]
  cd_message_duration_ms.time(labelValues = [$msg.msgType]):
    try:
      await stream.writeLp(encodedMsg)
    except LPStreamError as e:
      disco.recordDialFailure(peerId, addrs)
      disco.evictOnReset(peerId, e)
      return err("connection writing failed: " & e.msg)
    try:
      replyBuf = await stream.readLp(ServiceDiscoveryMaxMsgSize)
    except LPStreamError as e:
      disco.recordDialFailure(peerId, addrs)
      disco.evictOnReset(peerId, e)
      return err("connection reading failed: " & e.msg)
  replyRead = true

  cd_messages_received.inc(labelValues = [$msg.msgType])
  cd_message_bytes_received.inc(replyBuf.len.float64, labelValues = [$msg.msgType])

  let reply = Message.decode(replyBuf).valueOr:
    disco.recordDialFailure(peerId, addrs)
    return err(error, "failed to decode message response")

  disco.clearDialFailures(peerId)
  return ok(reply)

proc handleMessage*(
    disco: ServiceDiscovery, stream: Stream, msg: Message
) {.async: (raises: [CancelledError]).} =
  cd_messages_received.inc(labelValues = [$msg.msgType])

  let peerId = stream.peerId

  let response =
    if msg.msgType.get() == MessageType.register:
      # Prefer the wire address of this stream for IP-tree scoring.
      disco.registration(peerId, msg, stream.observedIps())
    else:
      disco.getAdvertisements(peerId, msg)

  let bytes = response.encode()

  cd_messages_sent.inc(labelValues = [$msg.msgType])
  cd_message_bytes_sent.inc(bytes.len.float64, labelValues = [$msg.msgType])

  let writeRes = catch:
    await stream.writeLp(bytes)
  if writeRes.isErr:
    trace "Failed to send message response", err = writeRes.error.msg
