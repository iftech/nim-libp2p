# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, hashes, tables, sequtils]
import chronos, chronicles, metrics
import
  ./pubsub,
  ./rpc_send,
  ./pubsubpeer,
  ./timedcache,
  ./peertable,
  ./rpc/[message, messages, protobuf],
  nimcrypto/sha2,
  ../../crypto/crypto,
  ../../stream/connection,
  ../../peerid,
  ../../peerinfo,
  ../../utils/opt

## Simple flood-based publishing.

logScope:
  topics = "libp2p floodsub"

const
  FloodSubCodec* = "/floodsub/1.0.0"
  FloodSubSeenMaxSize* = 1_000_000 # ~112 bytes per entry, so a ~120 MB ceiling

type FloodSub* = ref object of PubSub
  floodsub*: PeerTable # topic to remote peer map
  seen*: TimedCache[SaltedId]
    # salted: these ids are unvalidated, so a plain key lets an attacker poison the table
  seenSalt: array[32, byte] # random data used as salt
  # gossipsub rejects these two at init and reads GossipSubParams instead
  overheadRateLimit*: Opt[RateLimit]
  disconnectPeerAboveRateLimit*: bool

proc salt*(f: FloodSub, msgId: MessageId): SaltedId =
  var hash: sha256
  hash.init()
  hash.update(f.seenSalt)
  hash.update(msgId)
  SaltedId(data: hash.finish())

proc hasSeen*(f: FloodSub, saltedId: SaltedId): bool =
  saltedId in f.seen

proc addSeen*(f: FloodSub, saltedId: SaltedId): bool =
  # Return true if the message has already been seen
  f.seen.put(saltedId)

proc firstSeen*(f: FloodSub, saltedId: SaltedId): Moment =
  f.seen.addedAt(saltedId)

proc handleSubscribe(f: FloodSub, peer: PubSubPeer, topic: string, subscribe: bool) =
  logScope:
    peer
    topic

  # this is a workaround for a race condition
  # that can happen if we disconnect the peer very early
  # in the future we might use this as a test case
  # and eventually remove this workaround
  if subscribe and peer.peerId notin f.peers:
    trace "ignoring unknown peer"
    return

  if subscribe and not (isNil(f.subscriptionValidator)) and
      not (f.subscriptionValidator(topic)):
    # this is a violation, so warn should be in order
    trace "ignoring invalid topic subscription"
    return

  if subscribe:
    if peer.subscribedTopics >= f.topicsHigh and not f.floodsub.hasPeer(topic, peer):
      trace "ignoring subscription over topicsHigh limit", limit = f.topicsHigh
      return

    if f.floodsub.addPeer(topic, peer):
      peer.subscribedTopics.inc()
      debug "peer subscribed to topic"
  else:
    if f.floodsub.hasPeer(topic, peer):
      f.floodsub.removePeer(topic, peer)
      peer.subscribedTopics.dec()
      debug "peer unsubscribed from topic"

method unsubscribePeer*(f: FloodSub, peer: PeerId) =
  ## handle peer disconnects
  ##
  trace "unsubscribing floodsub peer", peer
  let pubSubPeer = f.peers.getOrDefault(peer)
  if pubSubPeer.isNil:
    return

  for t in toSeq(f.floodsub.keys):
    f.floodsub.removePeer(t, pubSubPeer)

  procCall PubSub(f).unsubscribePeer(peer)

template chargeOverhead(f: FloodSub, peer: PubSubPeer, overhead: int) =
  # a template, so that a peer within its budget allocates no future
  if not peer.tryCharge(overhead):
    f.punishOverBudget(peer, overhead, f.disconnectPeerAboveRateLimit)

method rpcHandler*(
    f: FloodSub, peer: PubSubPeer, data: sink seq[byte]
) {.async: (raises: [CancelledError, PeerMessageDecodeError, PeerRateLimitError]).} =
  let msgSize = data.len
  var rpcMsg = RPCMsg.decode(move(data)).valueOr:
    trace "PubSub RPC decode failed",
      err = error, peerId = peer.peerId, messageType = "rpc", messageSize = msgSize
    f.chargeOverhead(peer, msgSize)
    raise newException(PeerMessageDecodeError, "Peer msg couldn't be decoded")

  trace "PubSub RPC decoded",
    peerId = peer.peerId, messageType = "rpc", messageSize = msgSize
  # trigger hooks
  peer.recvObservers(rpcMsg)

  for i in 0 ..< min(f.topicsHigh, rpcMsg.subscriptions.len):
    template sub(): untyped =
      rpcMsg.subscriptions[i]

    f.handleSubscribe(peer, sub.topic.get(), sub.isSubscribe)

  for msg in rpcMsg.messages: # for every message
    let msgIdResult = f.msgIdProvider(msg)
    if msgIdResult.isErr:
      trace "Message dropped after ID generation failed", err = msgIdResult.error
      f.chargeOverhead(peer, msg.byteSize())
      continue

    let
      msgId = msgIdResult.get
      saltedId = f.salt(msgId)
      topic = msg.topic

    if topic notin f.topics:
      trace "Dropping message due to topic not in floodsub topics", topic, msgId, peer
      continue

    if (msg.signature.len > 0 or f.verifySignature) and not msg.verify():
      # always validate if signature is present or required
      trace "Dropping message due to failed signature verification", msgId, peer
      f.chargeOverhead(peer, msg.byteSize())
      continue

    if msg.seqno.len > 0 and msg.seqno.len != 8:
      # if we have seqno should be 8 bytes long
      trace "Dropping message due to invalid seqno length", msgId, peer
      f.chargeOverhead(peer, msg.byteSize())
      continue

    if f.addSeen(saltedId):
      trace "Dropping already-seen message", msgId, peer
      continue

    # g.anonymize needs no evaluation when receiving messages
    # as we have a "lax" policy and allow signed messages

    let validation = await f.validate(msg)
    case validation
    of ValidationResult.Reject:
      trace "Dropping message after validation, reason: reject", msgId, peer
      continue
    of ValidationResult.Ignore:
      trace "Dropping message after validation, reason: ignore", msgId, peer
      continue
    of ValidationResult.Accept:
      discard

    var toSendPeers = initHashSet[PubSubPeer]()

    f.floodsub.withValue(topic, peers):
      toSendPeers.incl(peers[])

    await handleData(f, topic, msg.data)

    # In theory, if topics are the same in all messages, we could batch - we'd
    # also have to be careful to only include validated messages
    f.broadcastResponse(toSendPeers, RPCMsg.withMessages(msg), MessagePriority.Low)
    trace "Forwared message to peers", peers = toSendPeers.len

  f.updateMetrics(rpcMsg)

method init*(f: FloodSub) =
  proc handler(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    ## main protocol handler that gets triggered on every
    ## connection for a protocol string
    ## e.g. ``/floodsub/1.0.0``, etc...
    ##
    try:
      await f.handleConn(stream, proto)
    except CancelledError as exc:
      trace "floodsub handler cancelled", stream
      raise exc

  f.handler = handler
  f.codec = FloodSubCodec

method publish*(
    f: FloodSub,
    topic: string,
    data: sink seq[byte],
    publishParams: Opt[PublishParams] = Opt.none(PublishParams),
): Future[int] {.async: (raises: []).} =
  trace "Publishing message", messageSize = data.len, topic

  if topic.len <= 0: # data could be 0/empty
    debug "Empty topic, skipping publish", topic
    return 0

  let msg =
    if f.anonymize:
      Message.init(Opt.none(PeerInfo), data, topic, Opt.none(uint64), false)
    else:
      inc f.msgSeqno
      Message.init(Opt.some(f.peerInfo), data, topic, Opt.some(f.msgSeqno), f.sign)

  # Application-published messages are never split - reject oversized messages
  # up front so the caller can handle the error before any dedup side effects
  # occur.
  let messageSize = RPCMsg.withMessages(msg).encodedSize()
  if messageSize > f.maxMessageSize:
    warn "message exceeds maximum message size; message will not be published",
      messageSize, maxMessageSize = f.maxMessageSize
    return 0

  f.handleSelfPublishing(topic, data)

  let peers = f.floodsub.getOrDefault(topic)

  if peers.len == 0:
    debug "No peers for topic, skipping publish", topic
    return 0

  let msgId = f.msgIdProvider(msg).valueOr:
    trace "Publish skipped after message ID generation failed", err = error
    return 0

  trace "Message created",
    messageType = "publish",
    messageSize = messageSize,
    peerCount = peers.len,
    topic,
    msgId

  if f.addSeen(f.salt(msgId)):
    # custom msgid providers might cause this
    trace "Dropping already-seen message", msgId, topic
    return 0

  # Try to send to all peers that are known to be interested
  f.broadcast(peers, RPCMsg.withMessages(msg), MessagePriority.Medium)

  when defined(libp2p_expensive_metrics):
    libp2p_pubsub_messages_published.inc(labelValues = [topic])

  trace "Published message to peers", msgId, topic

  return peers.len

func validateOverheadRateLimit(f: FloodSub): Result[void, cstring] =
  let limit = f.overheadRateLimit.valueOr:
    if f.disconnectPeerAboveRateLimit:
      return err(
        "floodsub: disconnectPeerAboveRateLimit parameter error, Requires overheadRateLimit"
      )
    return ok()
  if limit.bytes <= 0:
    return err("floodsub: overheadRateLimit.bytes parameter error, Must be > 0")
  if limit.interval <= ZeroDuration:
    return err("floodsub: overheadRateLimit.interval parameter error, Must be > 0")
  ok()

method getOrCreatePeer*(
    f: FloodSub, peerId: PeerId, protosToDial: seq[string], protoNegotiated: string = ""
): PubSubPeer =
  let peer = procCall PubSub(f).getOrCreatePeer(peerId, protosToDial, protoNegotiated)
  # a returning peer keeps its bucket, so a new stream is no way to refill it
  if peer.overheadRateLimitOpt.isNone():
    peer.overheadRateLimitOpt = newOverheadBucket(f.overheadRateLimit)

  peer

method initPubSub*(f: FloodSub) {.raises: [InitializationError].} =
  procCall PubSub(f).initPubSub()

  f.validateOverheadRateLimit().onErrorRaise(InitializationError)

  f.seen = TimedCache[SaltedId].init(2.minutes, maxSize = FloodSubSeenMaxSize)
  f.rng.generate(f.seenSalt)

  f.init()
