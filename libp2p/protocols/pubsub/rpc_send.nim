# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sequtils, sets]
import chronicles
import ./pubsub, ./pubsubpeer, ./rpc/[messages, protobuf]

logScope:
  topics = "libp2p pubsub"

## This file implements methods for sending protocol messages aka responses. 
## They are intentionally implemented in separated file to avoid exporting
## it to downstream dependencies.

proc sendResponse*(
    p: PubSub,
    peer: PubSubPeer,
    msg: RPCMsg,
    priority: MessagePriority,
    useCustomStream: bool = false,
    relayedSaltedId: Opt[SaltedId] = Opt.none(SaltedId),
) {.raises: [].} =
  ## Sends a protocol response `msg` (of type `RPCMsg`) to the specified remote
  ## peer. This is an internal, protocol-facing send path - messages that
  ## together exceed `maxMessageSize` are split and sent individually.
  ##
  ## This should not be used for application-published messages; use `send`
  ## instead.

  trace "sending pubsub response to peer", peer, rpcMsg = msg
  peer.sendResponse(msg, p.anonymize, priority, useCustomStream, relayedSaltedId)

proc broadcastResponse*(
    p: PubSub,
    sendPeers: seq[PubSubPeer] | HashSet[PubSubPeer],
    msg: RPCMsg,
    priority: MessagePriority,
    useCustomStream: bool = false,
    relayedSaltedId: Opt[SaltedId] = Opt.none(SaltedId),
) {.raises: [].} =
  ## Sends a protocol response `msg` (of type `RPCMsg`) to a specified group of
  ## peers. This is an internal, protocol-facing broadcast path - messages that
  ## together exceed `maxMessageSize` are split and sent individually.
  ##
  ## This should not be used for application-published messages; use `broadcast`
  ## instead.

  countBroadcastMetrics(p, sendPeers, msg)

  trace "broadcasting responses to peers", peers = sendPeers.len, rpcMsg = msg

  # Multiple messages need per-peer splitting on the legacy transport.
  if msg.messages.len > 1 or anyIt(sendPeers, it.hasObservers):
    for peer in sendPeers:
      p.sendResponse(peer, msg, priority, useCustomStream, relayedSaltedId)
  else:
    # Lazily encode each wire format and reuse it across recipients.
    var encoded: seq[byte]
    var topicRPC: PreparedTopicRPC
    for peer in sendPeers:
      if (msg.messages.len > 0 or msg.partialMessageExtension.isSome) and
          peer.extensionsState.peerHasTopicStreams(peer.peerId):
        if topicRPC.isZero():
          topicRPC = makePreparedTopicRPC(msg, p.anonymize)
        peer.sendTopicRPC(topicRPC, priority)
      else:
        if encoded.len == 0:
          encoded = msg.encode(p.anonymize)
        var peerEncoded = encoded
        peer.trackSend(
          peer.sendEncoded(
            move(peerEncoded), priority, useCustomStream, relayedSaltedId
          )
        )
