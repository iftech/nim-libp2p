# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Gossip based publishing

{.push raises: [].}

import std/[sets, sequtils]
import chronos, chronicles, metrics, results
import chronos/ratelimit
import
  ./pubsub,
  ./floodsub,
  ./gossipsub/partial_message,
  ./pubsubpeer,
  ./peertable,
  ./mcache,
  ./timedcache,
  ./rpc_send,
  ./rpc/[messages, message, protobuf],
  ../protocol,
  ../../stream/connection,
  ../../peerinfo,
  ../../peerid,
  ../../utils/[opt, shortlog, collections],
  ../../switch
import
  ./gossipsub/[types, scoring, behavior, preamblestore, extensions],
  ../../utils/heartbeat,
  ../../utils/future

export types, scoring, behavior, pubsub, results

when defined(libp2p_testing):
  export sendResponse, broadcastResponse

logScope:
  topics = "libp2p gossipsub"

declareCounter(libp2p_gossipsub_failed_publish, "number of failed publish")
declareCounter(
  libp2p_gossipsub_invalid_topic_subscription,
  "number of invalid topic subscriptions that happened",
)
declareCounter(
  libp2p_gossipsub_over_topics_high_subscription,
  "number of subscriptions rejected for exceeding topicsHigh",
)
declareCounter(
  libp2p_gossipsub_duplicate_during_validation,
  "number of duplicates received during message validation",
)
declareCounter(
  libp2p_gossipsub_idontwant_saved_messages, "number of duplicates avoided by idontwant"
)
declareCounter(
  libp2p_gossipsub_saved_bytes,
  "bytes saved by gossipsub optimizations",
  labels = ["kind"],
)
declareCounter(libp2p_gossipsub_duplicate, "number of duplicates received")
declareCounter(libp2p_gossipsub_received, "number of messages received (deduplicated)")
declarePublicGauge(
  libp2p_gossipsub_rpc_overhead_bytes_max,
  "maximum RPC overhead bytes observed in the current one-minute window",
)
declarePublicGauge(
  libp2p_gossipsub_peer_overhead_bytes_per_second_max,
  "maximum per-peer overhead bytes observed in a one-second window during the current one-minute window",
)

const SubscriptionFloodPenalty = 0.1 ## behaviour penalty for subscription abuse

when defined(libp2p_expensive_metrics):
  declarePublicHistogram(
    libp2p_gossipsub_rpc_overhead_bytes,
    "RPC overhead bytes",
    buckets = [1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0],
  )
  declarePublicHistogram(
    libp2p_gossipsub_peer_overhead_bytes_per_second,
    "per-peer overhead bytes observed in one-second windows",
    buckets = [1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0],
  )
  declareCounter(
    libp2p_pubsub_received_messages,
    "number of messages received",
    labels = ["id", "topic"],
  )

proc gossipExtensionsSupported(proto: string): bool =
  return proto == GossipSubCodec_13

proc init*(
    _: type[GossipSubParams],
    pruneBackoff = 1.minutes,
    unsubscribeBackoff = 5.seconds,
    floodPublish = true,
    gossipFactor: float64 = 0.25,
    d = GossipSubD,
    dLow = GossipSubDlo,
    dHigh = GossipSubDhi,
    dScore = GossipSubDlo,
    dOut = GossipSubDlo - 1, # DLow - 1
    dLazy = GossipSubD, # Like D,
    heartbeatInterval = GossipSubHeartbeatInterval,
    historyLength = GossipSubHistoryLength,
    historyGossip = GossipSubHistoryGossip,
    fanoutTTL = GossipSubFanoutTTL,
    seenTTL = 2.minutes,
    seenMaxSize = GossipSubSeenMaxSize,
    gossipThreshold = -100.0,
    publishThreshold = -1000.0,
    graylistThreshold = -10000.0,
    opportunisticGraftThreshold = 0.0,
    decayInterval = 1.seconds,
    decayToZero = 0.01,
    retainScore = 2.minutes,
    appSpecificWeight = 0.0,
    ipColocationFactorWeight = 0.0,
    ipColocationFactorThreshold = 1.0,
    slowPeerPenaltyWeight = 0.0,
    slowPeerPenaltyThreshold = 2.0,
    slowPeerPenaltyDecay = 0.2,
    behaviourPenaltyWeight = -1.0,
    behaviourPenaltyDecay = 0.999,
    directPeers = initTable[PeerId, seq[MultiAddress]](),
    disconnectBadPeers = false,
    enablePX = false,
    bandwidthEstimatebps = 100_000_000, # 100 Mbps or 12.5 MBps
    overheadRateLimit = Opt.none(RateLimit),
    disconnectPeerAboveRateLimit = false,
    maxHighPriorityQueueLen = DefaultMaxHighPriorityQueueLen,
    maxMediumPriorityQueueLen = DefaultMaxMediumPriorityQueueLen,
    maxLowPriorityQueueLen = DefaultMaxLowPriorityQueueLen,
    sendIDontWantOnPublish = false,
    testExtensionConfig = Opt.none(TestExtensionConfig),
    partialMessageExtensionConfig = Opt.none(PartialMessageExtensionConfig),
    pingpongExtensionConfig = Opt.none(PingPongExtensionConfig),
): GossipSubParams =
  GossipSubParams(
    explicit: true,
    pruneBackoff: pruneBackoff,
    unsubscribeBackoff: unsubscribeBackoff,
    floodPublish: floodPublish,
    gossipFactor: gossipFactor,
    d: d,
    dLow: dLow,
    dHigh: dHigh,
    dScore: dScore,
    dOut: dOut,
    dLazy: dLazy,
    heartbeatInterval: heartbeatInterval,
    historyLength: historyLength,
    historyGossip: historyGossip,
    fanoutTTL: fanoutTTL,
    seenTTL: seenTTL,
    seenMaxSize: seenMaxSize,
    gossipThreshold: gossipThreshold,
    publishThreshold: publishThreshold,
    graylistThreshold: graylistThreshold,
    opportunisticGraftThreshold: opportunisticGraftThreshold,
    decayInterval: decayInterval,
    decayToZero: decayToZero,
    retainScore: retainScore,
    appSpecificWeight: appSpecificWeight,
    ipColocationFactorWeight: ipColocationFactorWeight,
    ipColocationFactorThreshold: ipColocationFactorThreshold,
    slowPeerPenaltyWeight: slowPeerPenaltyWeight,
    slowPeerPenaltyThreshold: slowPeerPenaltyThreshold,
    slowPeerPenaltyDecay: slowPeerPenaltyDecay,
    behaviourPenaltyWeight: behaviourPenaltyWeight,
    behaviourPenaltyDecay: behaviourPenaltyDecay,
    directPeers: directPeers,
    disconnectBadPeers: disconnectBadPeers,
    enablePX: enablePX,
    bandwidthEstimatebps: bandwidthEstimatebps,
    overheadRateLimit: overheadRateLimit,
    disconnectPeerAboveRateLimit: disconnectPeerAboveRateLimit,
    maxHighPriorityQueueLen: maxHighPriorityQueueLen,
    maxMediumPriorityQueueLen: maxMediumPriorityQueueLen,
    maxLowPriorityQueueLen: maxLowPriorityQueueLen,
    sendIDontWantOnPublish: sendIDontWantOnPublish,
    testExtensionConfig: testExtensionConfig,
    partialMessageExtensionConfig: partialMessageExtensionConfig,
    pingpongExtensionConfig: pingpongExtensionConfig,
  )

func validateOverheadRateLimit(parameters: GossipSubParams): Result[void, cstring] =
  let limit = parameters.overheadRateLimit.valueOr:
    if parameters.disconnectPeerAboveRateLimit:
      return err(
        "gossipsub: disconnectPeerAboveRateLimit parameter error, Requires overheadRateLimit"
      )
    return ok()
  if limit.bytes <= 0:
    return err("gossipsub: overheadRateLimit.bytes parameter error, Must be > 0")
  if limit.interval <= ZeroDuration:
    return err("gossipsub: overheadRateLimit.interval parameter error, Must be > 0")
  ok()

proc validateParameters*(parameters: GossipSubParams): Result[void, cstring] =
  if (parameters.dOut >= parameters.dLow) or (parameters.dOut > (parameters.d div 2)):
    err(
      "gossipsub: dOut parameter error, Number of outbound connections to keep in the mesh. Must be less than D_lo and at most D/2"
    )
  elif parameters.gossipThreshold >= 0:
    err("gossipsub: gossipThreshold parameter error, Must be < 0")
  elif parameters.unsubscribeBackoff.seconds <= 0:
    err("gossipsub: unsubscribeBackoff parameter error, Must be > 0 seconds")
  elif parameters.historyLength <= 0:
    err("gossipsub: historyLength parameter error, Must be > 0")
  elif parameters.historyGossip < 0:
    err("gossipsub: historyGossip parameter error, Must be >= 0")
  elif parameters.seenMaxSize <= 0:
    err("gossipsub: seenMaxSize parameter error, Must be > 0")
  elif parameters.publishThreshold >= parameters.gossipThreshold:
    err("gossipsub: publishThreshold parameter error, Must be < gossipThreshold")
  elif parameters.graylistThreshold >= parameters.publishThreshold:
    err("gossipsub: graylistThreshold parameter error, Must be < publishThreshold")
  elif parameters.acceptPXThreshold < 0:
    err("gossipsub: acceptPXThreshold parameter error, Must be >= 0")
  elif parameters.opportunisticGraftThreshold < 0:
    err("gossipsub: opportunisticGraftThreshold parameter error, Must be >= 0")
  elif parameters.decayToZero > 0.5 or parameters.decayToZero <= 0.0:
    err("gossipsub: decayToZero parameter error, Should be close to 0.0")
  elif parameters.appSpecificWeight < 0:
    err("gossipsub: appSpecificWeight parameter error, Must be positive")
  elif parameters.ipColocationFactorWeight > 0:
    err("gossipsub: ipColocationFactorWeight parameter error, Must be negative or 0")
  elif parameters.ipColocationFactorThreshold < 1.0:
    err("gossipsub: ipColocationFactorThreshold parameter error, Must be at least 1")
  elif parameters.slowPeerPenaltyWeight > 0:
    err("gossipsub: slowPeerPenaltyWeight parameter error, Must be negative or 0")
  elif parameters.slowPeerPenaltyThreshold < 0:
    err("gossipsub: slowPeerPenaltyThreshold parameter error, Must be positive or 0")
  elif parameters.slowPeerPenaltyDecay <= 0 or parameters.slowPeerPenaltyDecay >= 1:
    err(
      "gossipsub: slowPeerPenaltyDecay parameter error, Must be between 0 and 1 (exclusive)"
    )
  elif parameters.behaviourPenaltyWeight >= 0:
    err("gossipsub: behaviourPenaltyWeight parameter error, Must be negative")
  elif parameters.behaviourPenaltyDecay < 0 or parameters.behaviourPenaltyDecay >= 1:
    err("gossipsub: behaviourPenaltyDecay parameter error, Must be between 0 and 1")
  elif parameters.maxHighPriorityQueueLen <= 0:
    err("gossipsub: maxHighPriorityQueueLen parameter error, Must be > 0")
  elif parameters.maxMediumPriorityQueueLen <= 0:
    err("gossipsub: maxMediumPriorityQueueLen parameter error, Must be > 0")
  elif parameters.maxLowPriorityQueueLen <= 0:
    err("gossipsub: maxLowPriorityQueueLen parameter error, Must be > 0")
  else:
    validateOverheadRateLimit(parameters)

proc validateParameters*(parameters: TopicParams): Result[void, cstring] =
  if parameters.timeInMeshWeight <= 0.0 or parameters.timeInMeshWeight > 1.0:
    err("gossipsub: timeInMeshWeight parameter error, Must be a small positive value")
  elif parameters.timeInMeshCap <= 0.0:
    err("gossipsub: timeInMeshCap parameter error, Should be a positive value")
  elif parameters.firstMessageDeliveriesWeight <= 0.0:
    err(
      "gossipsub: firstMessageDeliveriesWeight parameter error, Should be a positive value"
    )
  elif parameters.meshMessageDeliveriesWeight >= 0.0:
    err(
      "gossipsub: meshMessageDeliveriesWeight parameter error, Should be a negative value"
    )
  elif parameters.meshMessageDeliveriesThreshold <= 0.0:
    err(
      "gossipsub: meshMessageDeliveriesThreshold parameter error, Should be a positive value"
    )
  elif parameters.meshMessageDeliveriesCap < parameters.meshMessageDeliveriesThreshold:
    err(
      "gossipsub: meshMessageDeliveriesCap parameter error, Should be >= meshMessageDeliveriesThreshold"
    )
  elif parameters.meshFailurePenaltyWeight >= 0.0:
    err(
      "gossipsub: meshFailurePenaltyWeight parameter error, Should be a negative value"
    )
  elif parameters.invalidMessageDeliveriesWeight >= 0.0:
    err(
      "gossipsub: invalidMessageDeliveriesWeight parameter error, Should be a negative value"
    )
  else:
    ok()

method init*(g: GossipSub) =
  proc handler(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    ## main protocol handler that gets triggered on every
    ## connection for a protocol string
    ## e.g. ``/floodsub/1.0.0``, etc...
    ##
    try:
      await g.handleConn(stream, proto)
    except CancelledError as exc:
      trace "gossipsub handler cancelled", stream
      raise exc

  g.handler = handler

  g.codecs &= GossipSubCodec_13
  g.codecs &= GossipSubCodec_12
  g.codecs &= GossipSubCodec_11
  g.codecs &= GossipSubCodec_10

proc usesExtensions(g: GossipSub): bool =
  return
    g.parameters.testExtensionConfig.isSome() or
    g.parameters.partialMessageExtensionConfig.isSome() or
    g.parameters.pingpongExtensionConfig.isSome() or
    g.parameters.preambleExtensionConfig.isSome()

proc sendExtensionsControl(g: GossipSub, peer: PubSubPeer) =
  # Called from StreamOpened where codec is always set from the negotiated connection.
  doAssert peer.codec != "", "sendExtensionsControl requires codec to be negotiated"

  if not gossipExtensionsSupported(peer.codec):
    return

  if g.extensionsState.isControlSent(peer.peerId):
    return

  g.extensionsState.addPeer(peer.peerId)
  g.sendResponse(
    peer,
    RPCMsg.withControl(
      ControlMessage.withExtensions(g.extensionsState.makeControlExtensions())
    ),
    MessagePriority.High, # must be the first message on the stream
  )

method onNewPeer*(g: GossipSub, peer: PubSubPeer) =
  g.withPeerStats(peer.peerId) do(stats: var PeerStats):
    # Make sure stats and peer information match, even when reloading peer stats
    # from a previous connection
    peer.score = stats.score
    peer.appScore = stats.appScore
    peer.slowPeerPenalty = stats.slowPeerPenalty
    peer.behaviourPenalty = stats.behaviourPenalty

    # Check if the score is below the threshold and disconnect the peer if necessary
    g.disconnectIfBadScorePeer(peer, stats.score)

  peer.iHaveBudget = IHavePeerBudget

method onPubSubPeerEvent*(
    p: GossipSub, peer: PubSubPeer, event: PubSubPeerEvent
) {.gcsafe.} =
  case event.kind
  of PubSubPeerEventKind.StreamOpened:
    if p.usesExtensions():
      p.sendExtensionsControl(peer)
  of PubSubPeerEventKind.StreamClosed:
    # If a send stream is lost, it's better to remove peer from the mesh -
    # if it gets reestablished, the peer will be readded to the mesh, and if it
    # doesn't, well.. then we hope the peer is going away!
    for topic, peers in p.mesh.mpairs():
      p.pruned(peer, topic)
      peers.excl(peer)
    for _, peers in p.fanout.mpairs():
      peers.excl(peer)
  of PubSubPeerEventKind.DisconnectionRequested:
    p.pendingTasks.trackFut(p.disconnectPeer(peer)) # disconnectPeer also unsubscribes

  procCall FloodSub(p).onPubSubPeerEvent(peer, event)

method unsubscribePeer*(g: GossipSub, peer: PeerId) =
  ## handle peer disconnects
  ##

  trace "unsubscribing gossipsub peer", peer
  let pubSubPeer = g.peers.getOrDefault(peer)
  if pubSubPeer.isNil:
    trace "no peer to unsubscribe", peer
    return

  # remove from peer IPs collection too
  pubSubPeer.address.ifValue(address):
    g.peersInIP.withValue(address, s):
      s[].excl(pubSubPeer.peerId)
      if s[].len == 0:
        g.peersInIP.del(address)

  for t in toSeq(g.mesh.keys):
    trace "pruning unsubscribing peer", pubSubPeer, score = pubSubPeer.score
    g.pruned(pubSubPeer, t)
    g.mesh.removePeer(t, pubSubPeer)

  for t in toSeq(g.gossipsub.keys):
    g.gossipsub.removePeer(t, pubSubPeer)
    # also try to remove from direct peers table here
    g.subscribedDirectPeers.removePeer(t, pubSubPeer)

  for t in toSeq(g.fanout.keys):
    g.fanout.removePeer(t, pubSubPeer)

  g.peerStats.withValue(peer, stats):
    for topic, info in stats[].topicInfos.mpairs:
      info.firstMessageDeliveries = 0

  g.extensionsState.removePeer(peer)

  procCall FloodSub(g).unsubscribePeer(peer)

proc handleSubscribe(
    g: GossipSub, peer: PubSubPeer, topic: string, subscribe: bool
): bool =
  logScope:
    peer
    topic

  if subscribe:
    # this is a workaround for a race condition
    # that can happen if we disconnect the peer very early
    # in the future we might use this as a test case
    # and eventually remove this workaround
    if peer.peerId notin g.peers:
      trace "ignoring unknown peer"
      return false

    if not (isNil(g.subscriptionValidator)) and not (g.subscriptionValidator(topic)):
      # this is a violation, so warn should be in order
      trace "ignoring invalid topic subscription"
      libp2p_gossipsub_invalid_topic_subscription.inc()
      return false

    if peer.subscribedTopics >= g.topicsHigh and not g.gossipsub.hasPeer(topic, peer):
      trace "ignoring subscription over topicsHigh limit", limit = g.topicsHigh
      libp2p_gossipsub_over_topics_high_subscription.inc()
      peer.behaviourPenalty += SubscriptionFloodPenalty
      return false

    if g.gossipsub.addPeer(topic, peer):
      peer.subscribedTopics.inc()
      debug "peer subscribed to topic"
    if peer.peerId in g.parameters.directPeers:
      discard g.subscribedDirectPeers.addPeer(topic, peer)
  else:
    if g.mesh.hasPeer(topic, peer):
      #against spec
      g.mesh.removePeer(topic, peer)
      g.pruned(peer, topic)

    # unsubscribe remote peer from the topic
    let wasSubscribed = g.gossipsub.hasPeer(topic, peer)
    if wasSubscribed:
      peer.subscribedTopics.dec()
    g.gossipsub.removePeer(topic, peer)

    g.fanout.removePeer(topic, peer)
    if peer.peerId in g.parameters.directPeers:
      g.subscribedDirectPeers.removePeer(topic, peer)

    if wasSubscribed:
      debug "peer unsubscribed from topic"

  true

proc handleControl(g: GossipSub, peer: PubSubPeer, control: ControlMessage) =
  g.handlePrune(peer, control.prune)

  var respControl: ControlMessage
  g.handleIDontWant(peer, control.idontwant)
  let iwant = g.handleIHave(peer, control.ihave)
  if iwant.messageIDs.len > 0:
    respControl.iwant.add(iwant)
  respControl.prune.add(g.handleGraft(peer, control.graft))
  let (messages, msgIDs {.used.}) = g.handleIWant(peer, control.iwant)

  let
    isPruneNotEmpty = respControl.prune.len > 0
    isIWantNotEmpty = respControl.iwant.len > 0

  if isPruneNotEmpty or isIWantNotEmpty:
    if isIWantNotEmpty:
      libp2p_pubsub_broadcast_iwant.inc(respControl.iwant.len.int64)

    if isPruneNotEmpty:
      for prune in respControl.prune:
        libp2p_pubsub_broadcast_prune.inc(labelValues = [g.topicLabel(prune.topicID)])

    trace "sending control message", control = respControl, peer
    g.sendResponse(peer, RPCMsg.withControl(respControl), MessagePriority.High)

  if messages.len > 0:
    for i, smsg in messages:
      libp2p_pubsub_broadcast_messages.inc(labelValues = [g.topicLabel(smsg.topic)])

    # should we send preamble here? (Not in specs so far)
    # So receiver will send IMReciving only for preambles received from mesh members
    g.extensionsState.preambleBroadcast(
      RPCMsg.withPreamble(messages, msgIDs), @[peer.peerId]
    )

    # iwant replies have lower priority
    trace "sending iwant reply messages", peer
    g.sendResponse(peer, RPCMsg.withMessages(messages), MessagePriority.Low)

proc sendIDontWant(
    g: GossipSub,
    topic: string,
    msgId: MessageId,
    peersToSendIDontWant: HashSet[PubSubPeer],
) =
  # If the message is "large enough", let the mesh know that we do not want
  # any more copies of it, regardless if it is valid or not.
  #
  # In the case that it is not valid, this leads to some redundancy
  # (since the other peer should not send us an invalid message regardless),
  # but the expectation is that this is rare (due to such peers getting
  # descored) and that the savings from honest peers are greater than the
  # cost a dishonest peer can incur in short time (since the IDONTWANT is
  # small).

  let peers = peersToSendIDontWant.filterIt(
    (it.codec != GossipSubCodec_10 and it.codec != GossipSubCodec_11) and
      #
      # IDONTWANT is only supported by >= GossipSubCodec_12
    (not g.extensionsState.peerRequestsPartial(it.peerId, topic))
      #
      # skip sending IDONTWANT if peer has requested partial for topic
  )

  g.broadcastResponse(
    peers, RPCMsg.withControl(ControlMessage.withIDontWant(msgId)), MessagePriority.High
  )

const iDontWantMessageSizeThreshold* = 512

proc isLargeMessage(dataLen: int, msgId: MessageId): bool =
  dataLen > max(iDontWantMessageSizeThreshold, msgId.len * 10)

proc validateAndRelay(
    g: GossipSub, msg: Message, msgId: MessageId, saltedId: SaltedId, peer: PubSubPeer
) {.async: (raises: []).} =
  defer:
    g.validationSeen.del(saltedId) # drop bookkeeping even if cancelled mid-task
  try:
    let topic = msg.topic

    proc addToSendPeers(toSendPeers: var HashSet[PubSubPeer]) =
      g.floodsub.withValue(topic, peers):
        toSendPeers.incl(peers[])
      g.mesh.withValue(topic, peers):
        toSendPeers.incl(peers[])
      g.subscribedDirectPeers.withValue(topic, peers):
        toSendPeers.incl(peers[])
      toSendPeers.excl(peer)

    if isLargeMessage(msg.data.len, msgId):
      var peersToSendIDontWant = HashSet[PubSubPeer]()
      addToSendPeers(peersToSendIDontWant)
      # Also exclude the original message publisher so we don't send IDontWant
      # to a peer we won't relay to after the fix below.
      g.peers.withValue(msg.fromPeer, sourcePeer):
        peersToSendIDontWant.excl(sourcePeer[])
      g.sendIDontWant(topic, msgId, peersToSendIDontWant)

    let validation = await g.validate(msg)

    let seenPeers = g.validationSeen.getOrDefault(saltedId)
    libp2p_gossipsub_duplicate_during_validation.inc(seenPeers.len.int64)
    libp2p_gossipsub_saved_bytes.inc(
      (msg.data.len * seenPeers.len).int64, labelValues = ["validation_duplicate"]
    )

    case validation
    of ValidationResult.Reject:
      trace "Dropping message after validation, reason: reject",
        msgId = shortLog(msgId), peer
      await g.punishInvalidMessage(peer, msg)
      return
    of ValidationResult.Ignore:
      trace "Dropping message after validation, reason: ignore",
        msgId = shortLog(msgId), peer
      return
    of ValidationResult.Accept:
      discard

    if topic notin g.topics:
      return # Topic was unsubscribed while validating

    # store in cache only after validation
    g.mcache.put(msgId, msg)

    g.rewardDelivered(peer, topic, true)

    # trigger hooks
    peer.validatedObservers(msg, msgId)

    # The send list typically matches the idontwant list from above, but
    # might differ if validation takes time
    var toSendPeers = HashSet[PubSubPeer]()
    addToSendPeers(toSendPeers)
    # Don't send it to peers that sent it during validation
    toSendPeers.excl(seenPeers)
    # Also exclude the original message publisher to prevent relaying back to
    # them. This handles the case where the message arrived via an intermediate
    # relay node (e.g., A→B→C: when C relays, it should not send back to A).
    g.peers.withValue(msg.fromPeer, sourcePeer):
      toSendPeers.excl(sourcePeer[])

    proc isMsgInIdontWant(it: PubSubPeer): bool =
      for iDontWant in it.iDontWants:
        if saltedId in iDontWant:
          libp2p_gossipsub_idontwant_saved_messages.inc
          libp2p_gossipsub_saved_bytes.inc(
            msg.data.len.int64, labelValues = ["idontwant"]
          )
          return true
      return false

    toSendPeers.exclIfIt(isMsgInIdontWant(it))

    g.extensionsState.preambleBroadcastIfNotReceiving(
      RPCMsg.withPreamble(topic, msgId, msg.data.len), toSendPeers.mapIt(it.peerId)
    )

    # In theory, if topics are the same in all messages, we could batch - we'd
    # also have to be careful to only include validated messages
    g.broadcastResponse(toSendPeers, RPCMsg.withMessages(msg), MessagePriority.Low)
    trace "forwarded message to peers", peers = toSendPeers.len, msgId, peer

    libp2p_pubsub_messages_rebroadcasted.inc(
      toSendPeers.len.int64, labelValues = [g.topicLabel(topic)]
    )

    await handleData(g, topic, msg.data)
  except CancelledError:
    trace "validateAndRelay cancelled"
  except PeerRateLimitError as exc:
    trace "validateAndRelay failed", err = exc.msg

proc dataAndTopicsIdSize(msgs: seq[Message]): int =
  msgs.mapIt(it.data.len + it.topic.len).foldl(a + b, 0)

proc messageOverhead(g: GossipSub, msg: RPCMsg, msgSize: int): int =
  # In this way we count even ignored fields by protobuf
  let
    payloadSize =
      if g.verifySignature:
        byteSize(msg.messages)
      else:
        dataAndTopicsIdSize(msg.messages)
    controlSize = msg.control.ifValue(control):
      byteSize(control.ihave) + byteSize(control.iwant)
    do:
      0

  msgSize - payloadSize - controlSize

proc recordOverheadMetrics(g: GossipSub, peer: PubSubPeer, overhead: int) =
  let now = Moment.now()

  if now - g.overheadMetricsWindowStart >= 1.minutes:
    g.overheadMetricsWindowStart = now
    g.rpcOverheadBytesMax = 0
    g.peerOverheadBytesPerSecondMax = 0
    libp2p_gossipsub_rpc_overhead_bytes_max.set(0)
    libp2p_gossipsub_peer_overhead_bytes_per_second_max.set(0)

  if overhead > g.rpcOverheadBytesMax:
    g.rpcOverheadBytesMax = overhead
    libp2p_gossipsub_rpc_overhead_bytes_max.set(overhead.int64)

  when defined(libp2p_expensive_metrics):
    libp2p_gossipsub_rpc_overhead_bytes.observe(overhead.int64)

  if now - peer.overheadSecondWindowStart >= 1.seconds:
    when defined(libp2p_expensive_metrics):
      if peer.overheadBytesInSecondWindow > 0:
        libp2p_gossipsub_peer_overhead_bytes_per_second.observe(
          peer.overheadBytesInSecondWindow.int64
        )
    peer.overheadSecondWindowStart = now
    peer.overheadBytesInSecondWindow = 0

  peer.overheadBytesInSecondWindow += overhead
  if peer.overheadBytesInSecondWindow > g.peerOverheadBytesPerSecondMax:
    g.peerOverheadBytesPerSecondMax = peer.overheadBytesInSecondWindow
    libp2p_gossipsub_peer_overhead_bytes_per_second_max.set(
      peer.overheadBytesInSecondWindow.int64
    )

proc rateLimit*(
    g: GossipSub, peer: PubSubPeer, overhead: int
) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
  g.recordOverheadMetrics(peer, overhead)
  if peer.tryCharge(overhead):
    return

  # counted before the disconnect below, which raises
  libp2p_gossipsub_peers_rate_limit_hits.inc(labelValues = [peer.getAgent()])
  g.punishOverBudget(peer, overhead, g.parameters.disconnectPeerAboveRateLimit)

method rpcHandler*(
    g: GossipSub, peer: PubSubPeer, data: sink seq[byte]
) {.async: (raises: [CancelledError, PeerMessageDecodeError, PeerRateLimitError]).} =
  let msgSize = data.len

  if g.isGraylisted(peer, peer.score):
    await rateLimit(g, peer, msgSize)
    trace "PubSub RPC ignored",
      peerId = peer.peerId, reason = "graylisted", score = peer.score
    libp2p_gossipsub_graylisted_rpcs.inc(labelValues = [peer.getAgent()])
    return

  var rpcMsg = RPCMsg.decode(move(data)).valueOr:
    trace "PubSub RPC decode failed",
      err = error, peerId = peer.peerId, messageType = "rpc", messageSize = msgSize
    await rateLimit(g, peer, msgSize)
    # Raising in the handler closes the gossipsub connection (but doesn't
    # disconnect the peer!)
    # TODO evaluate behaviour penalty values
    peer.behaviourPenalty += 0.1

    raise newException(PeerMessageDecodeError, "Peer msg couldn't be decoded")

  when defined(libp2p_expensive_metrics):
    for m in rpcMsg.messages:
      libp2p_pubsub_received_messages.inc(labelValues = [$peer.peerId, m.topic])

  trace "PubSub RPC decoded",
    peerId = peer.peerId, messageType = "rpc", messageSize = msgSize
  await rateLimit(g, peer, g.messageOverhead(rpcMsg, msgSize))

  # trigger hooks - these may modify the message
  peer.recvObservers(rpcMsg)

  var extensionsRpcMsg = rpcMsg
  extensionsRpcMsg.subscriptions = @[]
  for i in 0 ..< min(g.topicsHigh, rpcMsg.subscriptions.len):
    template sub(): untyped =
      rpcMsg.subscriptions[i]

    if g.handleSubscribe(peer, sub.topic.get(), sub.isSubscribe):
      extensionsRpcMsg.subscriptions.add(sub)

  g.extensionsState.handleRPC(peer.peerId, extensionsRpcMsg)

  # the above call applied limits to subs number
  # in gossipsub we want to apply scoring as well
  if rpcMsg.subscriptions.len > g.topicsHigh:
    trace "received an rpc message with an oversized amount of subscriptions",
      peer, size = rpcMsg.subscriptions.len, limit = g.topicsHigh
    peer.behaviourPenalty += SubscriptionFloodPenalty

  for i in 0 ..< rpcMsg.messages.len(): # for every message
    template msg(): untyped =
      rpcMsg.messages[i]

    template topic(): string =
      msg.topic

    let msgIdResult = g.msgIdProvider(msg)

    if msgIdResult.isErr:
      trace "Message dropped after ID generation failed", err = msgIdResult.error
      await g.punishInvalidMessage(peer, msg)
      continue

    let
      msgId = msgIdResult.get
      msgIdSalted = g.salt(msgId)

    # avoid processing messages we are not interested in
    if topic notin g.topics:
      trace "Dropping message of topic without subscription",
        msgId = shortLog(msgId), peer
      continue

    if (msg.signature.len > 0 or g.verifySignature) and not msg.verify():
      trace "Message dropped",
        peerId = peer.peerId, reason = "signatureVerificationFailed"

      await g.punishInvalidMessage(peer, msg)
      continue

    if msg.seqno.len > 0 and msg.seqno.len != 8:
      # if we have seqno should be 8 bytes long
      trace "Dropping message due to invalid seqno length",
        msgId = shortLog(msgId), peer
      await g.punishInvalidMessage(peer, msg)
      continue

    g.extensionsState.preambleMsgReceived(peer.peerId, msgId, msg.data.len)

    if g.addSeen(msgIdSalted):
      trace "Dropping already-seen message", msgId = shortLog(msgId), peer

      var alreadyReceived = false
      g.validationSeen.withValue(msgIdSalted, seen):
        if seen[].containsOrIncl(peer):
          # peer sent us this message twice
          alreadyReceived = true

      if not alreadyReceived:
        let delay = Moment.now() - g.firstSeen(msgIdSalted)
        g.rewardDelivered(peer, topic, false, delay)

      libp2p_gossipsub_duplicate.inc()

      # onto the next message
      continue

    libp2p_gossipsub_received.inc()

    # g.anonymize needs no evaluation when receiving messages
    # as we have a "lax" policy and allow signed messages

    # Be careful not to fill the validationSeen table
    # (eg, pop everything you put in it)
    g.validationSeen[msgIdSalted] = initHashSet[PubSubPeer]()

    g.pendingTasks.trackFut(g.validateAndRelay(msg, msgId, msgIdSalted, peer))

  if rpcMsg.control.isSome():
    g.handleControl(peer, rpcMsg.control.unsafeGet())

  # Now, check subscription to update the meshes if required
  for i in 0 ..< min(g.topicsHigh, rpcMsg.subscriptions.len):
    let topic = rpcMsg.subscriptions[i].topic.get()
    if topic in g.topics and g.mesh.peers(topic) < g.parameters.dLow:
      # rebalance but don't update metrics here, we do that only in the heartbeat
      g.rebalanceMesh(topic, metrics = nil)

  g.updateMetrics(rpcMsg)

method onTopicSubscription*(g: GossipSub, topic: string, subscribed: bool) =
  if subscribed:
    procCall PubSub(g).onTopicSubscription(topic, subscribed)

    # if we have a fanout on this topic break it
    if topic in g.fanout:
      g.fanout.del(topic)

    # rebalance but don't update metrics here, we do that only in the heartbeat
    g.rebalanceMesh(topic, metrics = nil)
  else:
    let mpeers = g.mesh.getOrDefault(topic)

    # Remove peers from the mesh since we're no longer both interested
    # in the topic
    let msg = RPCMsg.withControl(
      ControlMessage.withPrune(
        topic, g.parameters.unsubscribeBackoff.seconds.uint64, g.peerExchangeList(topic)
      )
    )
    g.broadcastResponse(mpeers, msg, MessagePriority.High)

    for peer in mpeers:
      g.pruned(peer, topic, backoff = Opt.some(g.parameters.unsubscribeBackoff))

    g.mesh.del(topic)

    # Send unsubscribe (in reverse order to sub/graft)
    procCall PubSub(g).onTopicSubscription(topic, subscribed)

proc makePeersForPublishUsingCustomStream(
    g: GossipSub, topic: string
): HashSet[PubSubPeer] =
  assert g.customStreamCallbacks.isSome,
    "GossipSub misconfiguration: useCustomStream was true, but no customStreamCallbacks provided"

  trace "Selecting peers via custom stream callback"

  return g.customStreamCallbacks.get().customPeerSelectionCB(
      g.gossipsub.getOrDefault(topic),
      g.subscribedDirectPeers.getOrDefault(topic),
      g.mesh.getOrDefault(topic),
      g.fanout.getOrDefault(topic),
    )

proc makePeersForPublishDefault(
    g: GossipSub, topic: string, dataLen: int = 0
): HashSet[PubSubPeer] =
  var peers: HashSet[PubSubPeer]

  # Always include direct peers
  peers.incl(g.subscribedDirectPeers.getOrDefault(topic))

  if topic in g.topics: # if we're subscribed use the mesh
    peers.incl(g.mesh.getOrDefault(topic))

  if g.parameters.floodPublish:
    # With flood publishing enabled, the mesh is used when propagating messages from other peers,
    # but a peer's own messages will always be published to all known peers in the topic, limited
    # to the amount of peers we can send it to in one heartbeat

    let maxPeersToFlood =
      if g.parameters.bandwidthEstimatebps > 0:
        let
          bandwidth = (g.parameters.bandwidthEstimatebps) div 8 div 1000
            # Divisions are to convert it to Bytes per ms TODO replace with bandwidth estimate
          msToTransmit = max(dataLen div bandwidth, 1)
        max(
          g.parameters.heartbeatInterval.milliseconds div msToTransmit,
          g.parameters.dLow,
        )
      else:
        int.high() # unlimited

    for peer in g.gossipsub.getOrDefault(topic):
      if peers.len >= maxPeersToFlood:
        break

      if peer.score >= g.parameters.publishThreshold:
        trace "publish: including flood/high score peer", peer
        peers.incl(peer)
  elif peers.len < g.parameters.dLow:
    # not subscribed or bad mesh, send to fanout peers
    # when flood-publishing, fanout won't help since all potential peers have
    # already been added

    g.replenishFanout(topic) # Make sure fanout is populated

    var fanoutPeers = g.fanout.getOrDefault(topic).toSeq()
    g.rng.shuffle(fanoutPeers)

    for fanPeer in fanoutPeers:
      peers.incl(fanPeer)
      if peers.len > g.parameters.d:
        break

    # Attempting to publish counts as fanout send (even if the message
    # ultimately is not sent)
    g.lastFanoutPubSub[topic] = Moment.fromNow(g.parameters.fanoutTTL)

  return peers

method publish*(
    g: GossipSub,
    topic: string,
    data: sink seq[byte],
    publishParams: Opt[PublishParams] = Opt.none(PublishParams),
): Future[int] {.async: (raises: []).} =
  logScope:
    topic

  if topic.len <= 0: # data could be 0/empty
    warn "Empty topic, skipping publish"
    return 0

  let msg =
    if g.anonymize:
      Message.init(Opt.none(PeerInfo), data, topic, Opt.none(uint64), false)
    else:
      inc g.msgSeqno
      Message.init(Opt.some(g.peerInfo), data, topic, Opt.some(g.msgSeqno), g.sign)

  # Application-published messages are never split - reject oversized messages
  # up front so the caller can handle the error before any dedup/cache side
  # effects occur.
  let messageSize = RPCMsg.withMessages(msg).encodedSize()
  if messageSize > g.maxMessageSize:
    warn "message exceeds maximum message size; message will not be published",
      messageSize, maxMessageSize = g.maxMessageSize
    return 0

  g.handleSelfPublishing(topic, data)

  trace "Publishing message", messageSize = data.len

  let pubParams = publishParams.get(PublishParams())

  var peers =
    if pubParams.useCustomStream:
      g.makePeersForPublishUsingCustomStream(topic)
    else:
      g.makePeersForPublishDefault(topic, data.len)

  peers = peers.filterIt(
    (not g.extensionsState.peerRequestsPartial(it.peerId, topic))
      #
      # skip sending *full message* if peer has requested partial for topic
  )

  if peers.len == 0:
    let topicPeers = g.gossipsub.getOrDefault(topic).toSeq()
    trace "No peers for topic, skipping publish",
      peersOnTopic = topicPeers.len,
      connectedPeers = topicPeers.filterIt(it.connected).len,
      topic
    libp2p_gossipsub_failed_publish.inc()
    return 0

  let msgId = g.msgIdProvider(msg).valueOr:
    trace "Publish skipped after message ID generation failed", err = error
    libp2p_gossipsub_failed_publish.inc()
    return 0

  logScope:
    msgId = shortLog(msgId)

  trace "Message created",
    messageType = "publish", messageSize = messageSize, peerCount = peers.len

  if g.addSeen(g.salt(msgId)):
    # If the message was received or published recently, don't re-publish it -
    # this might happen when not using sequence id:s and / or with a custom
    # message id provider
    trace "Dropping already-seen message"
    return 0

  if not pubParams.skipMCache:
    g.mcache.put(msgId, msg)

  if g.parameters.sendIDontWantOnPublish:
    if not pubParams.skipIDontWant and isLargeMessage(msg.data.len, msgId):
      g.sendIDontWant(topic, msgId, peers)

    if not pubParams.skipPreamble:
      g.extensionsState.preambleBroadcast(
        RPCMsg.withPreamble(topic, msgId, msg.data.len), peers.mapIt(it.peerId)
      )

  g.broadcast(
    peers,
    RPCMsg.withMessages(msg),
    MessagePriority.Medium,
    useCustomStream = pubParams.useCustomStream,
  )

  libp2p_pubsub_messages_published.inc(
    peers.len.int64, labelValues = [g.topicLabel(topic)]
  )

  trace "Published message to peers", count = peers.len

  return peers.len

proc publishPartial*(
    g: GossipSub,
    topic: string,
    groupId: GroupId,
    partsMetadata: PartsMetadata,
    peers: seq[PeerId] = @[],
): Future[void] {.async: (raises: []).} =
  let count = g.extensionsState.publishPartial(topic, groupId, partsMetadata, peers)

  libp2p_pubsub_messages_published_partial.inc(
    count.int64, labelValues = [g.topicLabel(topic)]
  )

  trace "Published partial message to peers", count = count

proc maintainDirectPeer(
    g: GossipSub, id: PeerId, addrs: seq[MultiAddress]
) {.async: (raises: [CancelledError]).} =
  if g.switch.isStopping:
    return
  if id notin g.peers:
    trace "Attempting to dial a direct peer", peerId = id
    if g.switch.isConnected(id):
      warn "We are connected to a direct peer, but it isn't a GossipSub peer!", id
      return
    try:
      await g.switch.connect(id, addrs, forceDial = true)
      # populate the peer after it's connected
      if not g.switch.isStopping:
        discard g.getOrCreatePeer(id, g.codecs)
    except CancelledError as exc:
      trace "Direct peer dial canceled"
      raise exc
    except DialFailedError as exc:
      trace "Direct peer error dialing", err = exc.msg

proc addDirectPeer*(
    g: GossipSub, id: PeerId, addrs: seq[MultiAddress]
) {.async: (raises: [CancelledError]).} =
  g.parameters.directPeers[id] = addrs
  await g.maintainDirectPeer(id, addrs)

proc maintainDirectPeers(g: GossipSub) {.async: (raises: [CancelledError]).} =
  heartbeat "GossipSub DirectPeers", 1.minutes:
    for id, addrs in g.parameters.directPeers:
      await g.addDirectPeer(id, addrs)

proc createExtensionsState(g: GossipSub): ExtensionsState =
  if not g.usesExtensions():
    # use noop state when no extensions are used
    return ExtensionsState.new(g.rng)

  proc updatePeerBehaviorPenalty(id: PeerId, delta: float64) {.gcsafe, raises: [].} =
    g.peers.withValue(id, peer):
      peer[].behaviourPenalty += delta

  # when extension config is not set then that extension is disabled.
  # config params (callbacks) are set with default gossipsub behavior only if 
  # these params are not set. they can be set with non default behaviour in
  # unit tests.

  g.parameters.testExtensionConfig.ifValue(c):
    var cfg = c

    if cfg.onNegotiated.isNil:
      cfg.onNegotiated = proc(peerId: PeerId) {.gcsafe, raises: [].} =
        g.peers.withValue(peerId, peer):
          g.sendResponse(
            peer[],
            RPCMsg(testExtension: Opt.some(TestExtensionRPC())),
            MessagePriority.High,
          )

    g.parameters.testExtensionConfig = Opt.some(cfg)

  g.parameters.partialMessageExtensionConfig.ifValue(c):
    var cfg = c

    if cfg.sendRPC.isNil:
      cfg.sendRPC = proc(
          peerId: PeerId, rpc: PartialMessageExtensionRPC
      ) {.gcsafe, raises: [].} =
        g.peers.withValue(peerId, peer):
          g.sendResponse(
            peer[], RPCMsg(partialMessageExtension: Opt.some(rpc)), MessagePriority.Low
          )

    if cfg.publishToPeers.isNil:
      cfg.publishToPeers = proc(topic: string): seq[PeerId] {.gcsafe, raises: [].} =
        let peers = g.makePeersForPublishDefault(topic)
        return peers.mapIt(it.peerId)

    if cfg.nodeTopicOpts.isNil:
      cfg.nodeTopicOpts = proc(topic: string): TopicOpts {.gcsafe, raises: [].} =
        g.topics.withValue(topic, topicData):
          return TopicOpts(
            requestsPartial: topicData[].requestsPartial,
            supportsSendingPartial: topicData[].supportsSendingPartial,
          )
        return TopicOpts()

    g.parameters.partialMessageExtensionConfig = Opt.some(cfg)

  g.parameters.pingpongExtensionConfig.ifValue(c):
    var cfg = c

    if cfg.sendPong.isNil:
      cfg.sendPong = proc(peerId: PeerId, pong: seq[byte]) {.gcsafe, raises: [].} =
        g.peers.withValue(peerId, peer):
          g.sendResponse(peer[], RPCMsg.withPong(pong), MessagePriority.High)

    g.parameters.pingpongExtensionConfig = Opt.some(cfg)

  g.parameters.preambleExtensionConfig.ifValue(c):
    var cfg = c

    if cfg.broadcastRPC.isNil:
      cfg.broadcastRPC = proc(msg: RPCMsg, peers: seq[PeerId]) {.gcsafe, raises: [].} =
        let peersToBroadcast =
          peers.filterIt(it in g.peers).mapIt(g.peers.getOrDefault(it))
        g.broadcastResponse(peersToBroadcast, msg, MessagePriority.High)
    if cfg.hasSeen.isNil:
      cfg.hasSeen = proc(mid: MessageId): bool {.gcsafe, raises: [].} =
        return g.hasSeen(g.salt(mid))
    if cfg.meshAndDirectPeersForTopic.isNil:
      cfg.meshAndDirectPeersForTopic = proc(
          topic: string
      ): seq[PeerId] {.gcsafe, raises: [].} =
        var peers = HashSet[PubSubPeer]()
        g.mesh.withValue(topic, meshPeers):
          peers.incl(meshPeers[])
        peers.incl(g.subscribedDirectPeers.getOrDefault(topic))
        return peers.toSeq().mapIt(it.peerId)

    g.parameters.preambleExtensionConfig = Opt.some(cfg)

  return ExtensionsState.new(
    g.rng, updatePeerBehaviorPenalty, g.parameters.testExtensionConfig,
    g.parameters.partialMessageExtensionConfig, g.parameters.pingpongExtensionConfig,
    g.parameters.preambleExtensionConfig,
  )

method start*(g: GossipSub): Future[void] {.async: (raises: [CancelledError]).} =
  if g.started:
    warn "Starting gossipsub twice"
    return

  await procCall PubSub(g).start()
  info "gossipsub start"

  g.heartbeatFut = g.heartbeat()
  g.scoringHeartbeatFut = g.scoringHeartbeat()
  g.directPeersLoop = g.maintainDirectPeers()
  reportBackgroundFailure(g.heartbeatFut, "gossipsub heartbeat")
  reportBackgroundFailure(g.scoringHeartbeatFut, "gossipsub scoring")
  reportBackgroundFailure(g.directPeersLoop, "gossipsub direct peer maintenance")

method stop*(g: GossipSub): Future[void] {.async: (raw: true, raises: []).} =
  if not g.started:
    warn "Stopping gossipsub without starting it"
  if not g.stopFut.isNil and not g.stopFut.finished:
    return g.stopFut

  info "gossipsub stop"
  let peersStopped = procCall PubSub(g).stop()
  var pending = move g.pendingTasks
  for fut in [move g.directPeersLoop, move g.scoringHeartbeatFut, move g.heartbeatFut]:
    if not fut.isNil:
      pending.add(fut)
  g.stopFut = noCancel allFutures(peersStopped, chronos.cancelAndWait(pending))
  return g.stopFut

method initPubSub*(g: GossipSub) {.raises: [InitializationError].} =
  procCall FloodSub(g).initPubSub()

  if not g.parameters.explicit:
    g.parameters = GossipSubParams.init()

  if g.overheadRateLimit.isSome() or g.disconnectPeerAboveRateLimit:
    raise newException(
      InitializationError,
      "gossipsub: set the overhead rate limit through GossipSubParams, not the inherited FloodSub fields",
    )

  g.parameters.validateParameters().onErrorRaise(InitializationError)

  # init the floodsub stuff here, we customize timedcache in gossip!
  g.seen =
    TimedCache[SaltedId].init(g.parameters.seenTTL, maxSize = g.parameters.seenMaxSize)
  g.overheadMetricsWindowStart = Moment.now()

  # init gossip stuff
  g.mcache = MCache.init(g.parameters.historyGossip, g.parameters.historyLength)
  g.extensionsState = g.createExtensionsState()

method getOrCreatePeer*(
    g: GossipSub,
    peerId: PeerId,
    protosToDial: seq[string],
    protoNegotiated: string = "",
): PubSubPeer =
  let peer = procCall PubSub(g).getOrCreatePeer(peerId, protosToDial, protoNegotiated)
  # a returning peer keeps its bucket, so a new stream is no way to refill it
  if peer.overheadRateLimitOpt.isNone():
    peer.overheadRateLimitOpt = newOverheadBucket(g.parameters.overheadRateLimit)
  peer.maxHighPriorityQueueLen = g.parameters.maxHighPriorityQueueLen
  peer.maxMediumPriorityQueueLen = g.parameters.maxMediumPriorityQueueLen
  peer.maxLowPriorityQueueLen = g.parameters.maxLowPriorityQueueLen

  return peer
