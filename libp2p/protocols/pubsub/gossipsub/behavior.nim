# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[tables, sequtils, sets, algorithm, deques]
import chronos, chronicles, metrics
import ./[types, scoring, extensions]
import ../[pubsubpeer, peertable, mcache, floodsub, pubsub, rpc_send, timedcache]
import ../rpc/[messages]
import
  "../../.."/[
    peerid,
    multiaddress,
    utils/opt,
    switch,
    routing_record,
    signed_envelope,
    utils/heartbeat,
  ]

logScope:
  topics = "libp2p gossipsub"

declareGauge(libp2p_gossipsub_cache_window_size, "the number of messages in the cache")
declarePublicGauge(
  libp2p_gossipsub_seen_cache_size, "number of message IDs retained in the seen cache"
)
declareGauge(
  libp2p_gossipsub_peers_without_send_stream, "gossipsub peers with no open send stream"
)
declareGauge(
  libp2p_gossipsub_peers_per_topic_mesh,
  "gossipsub peers per topic in mesh",
  labels = ["topic"],
)
declareGauge(
  libp2p_gossipsub_peers_per_topic_fanout,
  "gossipsub peers per topic in fanout",
  labels = ["topic"],
)
declareGauge(
  libp2p_gossipsub_peers_per_topic_gossipsub,
  "gossipsub peers per topic in gossipsub",
  labels = ["topic"],
)
declareGauge(libp2p_gossipsub_under_dout_topics, "number of topics below dout")
declareGauge(libp2p_gossipsub_no_peers_topics, "number of topics in mesh with no peers")
declareGauge(
  libp2p_gossipsub_low_peers_topics,
  "number of topics in mesh with at least one but below dlow peers",
)
declareGauge(
  libp2p_gossipsub_healthy_peers_topics,
  "number of topics in mesh with at least dlow peers (but below dhigh)",
)
declareCounter(
  libp2p_gossipsub_above_dhigh_condition,
  "number of above dhigh pruning branches ran",
  labels = ["topic"],
)
declareGauge(libp2p_gossipsub_received_iwants, "received iwants", labels = ["kind"])
declareCounter(
  libp2p_gossipsub_preamble_saved_iwants,
  "number of iwant requests avoided by preamble",
  labels = ["topic"],
)

proc grafted*(g: GossipSub, p: PubSubPeer, topic: string) =
  g.withPeerStats(p.peerId) do(stats: var PeerStats):
    var info = stats.topicInfos.getOrDefault(topic)
    info.graftTime = Moment.now()
    info.meshTime = 0.seconds
    info.inMesh = true
    info.meshMessageDeliveriesActive = false

    stats.topicInfos[topic] = info

    trace "grafted", peerId = p, topic

proc pruned*(
    g: GossipSub,
    p: PubSubPeer,
    topic: string,
    setBackoff: bool = true,
    backoff = Opt.none(Duration),
) =
  if setBackoff:
    let
      backoffDuration = backoff.get(g.parameters.pruneBackoff)
      backoffMoment = Moment.fromNow(backoffDuration)

    g.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[p.peerId] = backoffMoment

  g.peerStats.withValue(p.peerId, stats):
    stats.topicInfos.withValue(topic, info):
      g.topicParams.withValue(topic, topicParams):
        # penalize a peer that delivered no message
        let threshold = topicParams[].meshMessageDeliveriesThreshold
        if info[].inMesh and info[].meshMessageDeliveriesActive and
            info[].meshMessageDeliveries < threshold:
          let deficit = threshold - info.meshMessageDeliveries
          info[].meshFailurePenalty += deficit * deficit

      info.inMesh = false

      trace "pruned", peerId = p, topic

proc handleBackingOff*(t: var BackoffTable, topic: string) =
  let now = Moment.now()
  var expired = toSeq(t.getOrDefault(topic).pairs())
  expired.keepIf do(pair: tuple[peer: PeerId, expire: Moment]) -> bool:
    now >= pair.expire
  for (peer, _) in expired:
    t.withValue(topic, v):
      v[].del(peer)

proc peerExchangeList*(g: GossipSub, topic: string): seq[PeerInfoMsg] =
  if not g.parameters.enablePX:
    return @[]
  var peers = g.gossipsub.getOrDefault(topic, initHashSet[PubSubPeer]()).toSeq()
  peers.keepIf do(x: PubSubPeer) -> bool:
    x.score >= 0.0
  # by spec, larger then Dhi, but let's put some hard caps
  peers.setLen(min(peers.len, g.parameters.dHigh * 2))
  let sprBook = g.switch.peerStore[SPRBook]
  peers.map do(x: PubSubPeer) -> PeerInfoMsg:
    PeerInfoMsg(
      peerId: Opt.some(x.peerId),
      signedPeerRecord:
        if x.peerId in sprBook:
          Opt.some(sprBook[x.peerId].encode())
        else:
          Opt.none(seq[byte]),
    )

proc handleGraft*(
    g: GossipSub, peer: PubSubPeer, grafts: seq[ControlGraft]
): seq[ControlPrune] =
  var prunes: seq[ControlPrune]
  for graft in grafts:
    let topic = graft.topicID

    trace "peer grafted topicID", peer, topic

    # It is an error to GRAFT on a direct peer
    if peer.peerId in g.parameters.directPeers:
      # receiving a graft from a direct peer should yield a more prominent warning (protocol violation)
      # we are trusting direct peer not to abuse this
      trace "a direct peer attempted to graft us, peering agreements should be reciprocal",
        peer, topic
      # and such an attempt should be logged and rejected with a PRUNE
      prunes.add(
        ControlPrune(
          topicID: topic,
          peers: @[],
            # omitting heavy computation here as the remote did something illegal
          backoff: g.parameters.pruneBackoff.seconds.uint64,
        )
      )

      let backoff = Moment.fromNow(g.parameters.pruneBackoff)

      g.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[peer.peerId] = backoff

      peer.behaviourPenalty += 0.1

      continue

    if g.mesh.hasPeer(topic, peer):
      trace "peer already in mesh", peer, topic
      continue

    # Check backingOff
    # Ignore BackoffSlackTime here, since this only for outbound activity
    # and subtract a second time to avoid race conditions
    # (peers may wait to graft us as the exact instant they're allowed to)
    if g.backingOff.getOrDefault(topic).getOrDefault(peer.peerId) -
        (BackoffSlackTime * 2).seconds > Moment.now():
      debug "a backingOff peer attempted to graft us", peer, topic
      # and such an attempt should be logged and rejected with a PRUNE
      prunes.add(
        ControlPrune(
          topicID: topic,
          peers: @[],
            # omitting heavy computation here as the remote did something illegal
          backoff: g.parameters.pruneBackoff.seconds.uint64,
        )
      )

      let backoff = Moment.fromNow(g.parameters.pruneBackoff)

      g.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[peer.peerId] = backoff

      peer.behaviourPenalty += 0.1

      continue

    # not in the spec exactly, but let's avoid way too low score peers
    # other clients do it too also was an audit recommendation
    if peer.score < g.parameters.publishThreshold:
      continue

    # If they send us a graft before they send us a subscribe, what should
    # we do? For now, we add them to mesh but don't add them to gossipsub.
    if topic in g.topics:
      if g.mesh.peers(topic) < g.parameters.dHigh or
          (peer.outbound and g.mesh.outboundPeers(topic) < g.parameters.dOut):
        # In the spec, there's no mention of DHi here, but implicitly, a
        # peer will be removed from the mesh on next rebalance, so we don't want
        # this peer to push someone else out
        if g.mesh.addPeer(topic, peer):
          g.grafted(peer, topic)
          g.fanout.removePeer(topic, peer)
        else:
          trace "peer already in mesh", peer, topic
      else:
        trace "pruning grafting peer, mesh full",
          peer, topic, score = peer.score, meshSize = g.mesh.peers(topic)
        prunes.add(
          ControlPrune(
            topicID: topic,
            peers: g.peerExchangeList(topic),
            backoff: g.parameters.pruneBackoff.seconds.uint64,
          )
        )

        let backoff = Moment.fromNow(g.parameters.pruneBackoff)

        g.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[peer.peerId] =
          backoff
    else:
      trace "peer grafting topic we're not interested in", peer, topic
      # gossip 1.1, we do not send a control message prune anymore

  return prunes

proc getPeers(prune: ControlPrune, peer: PubSubPeer): seq[(PeerId, Opt[PeerRecord])] =
  var routingRecords: seq[(PeerId, Opt[PeerRecord])]
  for record in prune.peers:
    if record.peerId.isNone:
      continue

    var peerRecord = Opt.none(PeerRecord)
    if record.signedPeerRecord.isSome:
      SignedPeerRecord.decode(record.signedPeerRecord.get()).toOpt().ifValue(spr):
        if record.peerId.isSome and record.peerId.get() != spr.data.peerId:
          trace "peer sent envelope with wrong public key", peer
        else:
          peerRecord = Opt.some(spr.data)
      else:
        trace "peer sent invalid SPR", peer

    routingRecords.add((record.peerId.get(), peerRecord))

  routingRecords

proc handlePrune*(g: GossipSub, peer: PubSubPeer, prunes: seq[ControlPrune]) =
  for prune in prunes:
    let topic = prune.topicID

    trace "peer pruned topicID", peer, topic

    if topic notin g.topics:
      trace "ignoring prune for unsubscribed topic", peer, topic
      continue

    if not g.mesh.hasPeer(topic, peer):
      trace "ignoring prune for peer outside mesh", peer, topic
      continue

    # add peer backoff
    if prune.backoff > 0:
      let
        # avoid overflows and clamp to reasonable value
        backoffSeconds =
          clamp(prune.backoff + BackoffSlackTime, 0'u64, 1.days.seconds.uint64)
        backoff = Moment.fromNow(backoffSeconds.int64.seconds)
        current = g.backingOff.getOrDefault(topic).getOrDefault(peer.peerId)
      if backoff > current:
        g.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[peer.peerId] =
          backoff

    trace "pruning rpc received peer", peer, score = peer.score
    g.pruned(peer, topic, setBackoff = false)
    g.mesh.removePeer(topic, peer)

    if peer.score > g.parameters.gossipThreshold and prune.peers.len > 0 and
        g.routingRecordsHandler.len > 0:
      let routingRecords = prune.getPeers(peer)

      for handler in g.routingRecordsHandler:
        handler(peer.peerId, topic, routingRecords)

proc handleIHave*(
    g: GossipSub, peer: PubSubPeer, ihaves: seq[ControlIHave]
): ControlIWant =
  var res: ControlIWant
  if peer.score < g.parameters.gossipThreshold:
    trace "ihave: ignoring low score peer", peer, score = peer.score
  elif peer.iHaveBudget <= 0:
    trace "ihave: ignoring out of budget peer", peer, score = peer.score
  else:
    for ihave in ihaves:
      let topic = ihave.topicID
      if topic.len == 0:
        trace "topic not set: ihave", peer
        continue
      trace "peer sent ihave", peer, topic, messageCount = ihave.messageIDs.len
      if topic in g.topics:
        for msgId in ihave.messageIDs:
          if not g.hasSeen(g.salt(msgId)):
            if peer.iHaveBudget <= 0:
              break
            elif msgId notin res.messageIDs:
              if g.extensionsState.preambleHandleIHave(peer.peerId, msgId):
                libp2p_gossipsub_preamble_saved_iwants.inc(labelValues = [topic])
                continue
              res.messageIDs.add(msgId)
              dec peer.iHaveBudget
              trace "requested message via ihave", peer, messageID = msgId
    # shuffling res.messageIDs before sending it out to increase the likelihood
    # of getting an answer if the peer truncates the list due to internal size restrictions.
    g.rng.shuffle(res.messageIDs)
    return res

proc handleIDontWant*(g: GossipSub, peer: PubSubPeer, iDontWants: seq[ControlIWant]) =
  for dontWant in iDontWants:
    for messageId in dontWant.messageIDs:
      if peer.iDontWants[0].len >= IDontWantMaxCount:
        break
      peer.iDontWants[0].incl(g.salt(messageId))

proc handleIWant*(
    g: GossipSub, peer: PubSubPeer, iwants: seq[ControlIWant]
): tuple[messages: seq[Message], ids: seq[MessageId]] =
  var response: tuple[messages: seq[Message], ids: seq[MessageId]]
  var invalidRequests = 0
  if peer.score < g.parameters.gossipThreshold:
    trace "iwant: ignoring low score peer", peer, score = peer.score
  else:
    for iwant in iwants:
      for mid in iwant.messageIDs:
        trace "peer sent iwant", peer, messageID = mid
        # canAskIWant will only return true once for a specific message
        if not peer.canAskIWant(mid):
          libp2p_gossipsub_received_iwants.inc(1, labelValues = ["notsent"])

          invalidRequests.inc()
          if invalidRequests > 20:
            libp2p_gossipsub_received_iwants.inc(1, labelValues = ["skipped"])
            return response
          continue
        let msg = g.mcache.get(mid).valueOr:
          libp2p_gossipsub_received_iwants.inc(1, labelValues = ["unknown"])
          continue
        libp2p_gossipsub_received_iwants.inc(1, labelValues = ["correct"])
        response.messages.add(msg)
        response.ids.add(mid)
  return response

proc commitMetrics(metrics: var MeshMetrics) =
  libp2p_gossipsub_low_peers_topics.set(metrics.lowPeersTopics)
  libp2p_gossipsub_no_peers_topics.set(metrics.noPeersTopics)
  libp2p_gossipsub_under_dout_topics.set(metrics.underDoutTopics)
  libp2p_gossipsub_healthy_peers_topics.set(metrics.healthyPeersTopics)
  libp2p_gossipsub_peers_per_topic_gossipsub.set(
    metrics.otherPeersPerTopicGossipsub, labelValues = ["other"]
  )
  libp2p_gossipsub_peers_per_topic_fanout.set(
    metrics.otherPeersPerTopicFanout, labelValues = ["other"]
  )
  libp2p_gossipsub_peers_per_topic_mesh.set(
    metrics.otherPeersPerTopicMesh, labelValues = ["other"]
  )

proc rebalanceMesh*(g: GossipSub, topic: string, metrics: ptr MeshMetrics = nil) =
  logScope:
    topic
    meshSize = g.mesh.peers(topic)
    gossipsubSize = g.gossipsub.peers(topic)

  # create a mesh topic that we're subscribing to

  var
    prunes, grafts: seq[PubSubPeer]
    npeers = g.mesh.peers(topic)
    nOutPeers = g.mesh.outboundPeers(topic)
    defaultMesh: HashSet[PubSubPeer]
    backingOff = g.backingOff.getOrDefault(topic)

  if npeers < g.parameters.dLow:
    trace "replenishing mesh", peers = npeers
    # replenish the mesh if we're below Dlo

    var
      candidates: seq[PubSubPeer]
      currentMesh = addr defaultMesh
    g.mesh.withValue(topic, v):
      currentMesh = v
    g.gossipsub.withValue(topic, peerList):
      for it in peerList[]:
        if it.connected and
            # avoid negative score peers
            it.score >= 0.0 and it notin currentMesh[] and
            # don't pick direct peers
            it.peerId notin g.parameters.directPeers and
            # and avoid peers we are backing off
            it.peerId notin backingOff:
          candidates.add(it)

    # shuffle anyway, score might be not used
    g.rng.shuffle(candidates)

    # sort peers by score, high score first since we graft
    candidates.sort(byScore, SortOrder.Descending)

    # Graft peers so we reach a count of D
    candidates.setLen(min(candidates.len, g.parameters.d - npeers))

    trace "grafting", grafting = candidates.len

    if candidates.len > 0:
      for peer in candidates:
        if g.mesh.addPeer(topic, peer):
          g.grafted(peer, topic)
          g.fanout.removePeer(topic, peer)
          grafts &= peer
  elif nOutPeers < g.parameters.dOut:
    trace "replenishing mesh outbound quota", peers = g.mesh.peers(topic)

    var
      candidates: seq[PubSubPeer]
      currentMesh = addr defaultMesh
    g.mesh.withValue(topic, v):
      currentMesh = v
    g.gossipsub.withValue(topic, peerList):
      for it in peerList[]:
        if it.connected and
        # get only outbound ones
        it.outbound and it notin currentMesh[] and
            # avoid negative score peers
            it.score >= 0.0 and
            # don't pick direct peers
            it.peerId notin g.parameters.directPeers and
            # and avoid peers we are backing off
            it.peerId notin backingOff:
          candidates.add(it)

    # shuffle anyway, score might be not used
    g.rng.shuffle(candidates)

    # sort peers by score, high score first, we are grafting
    candidates.sort(byScore, SortOrder.Descending)

    # Graft outgoing peers so we reach a count of dOut
    candidates.setLen(min(candidates.len, g.parameters.dOut - nOutPeers))

    trace "grafting outbound peers", topic, peersCount = candidates.len

    for peer in candidates:
      if g.mesh.addPeer(topic, peer):
        g.grafted(peer, topic)
        g.fanout.removePeer(topic, peer)
        grafts &= peer

  # get again npeers after possible grafts
  npeers = g.mesh.peers(topic)
  if npeers > g.parameters.dHigh:
    if not isNil(metrics):
      if g.knownTopics.contains(topic):
        libp2p_gossipsub_above_dhigh_condition.inc(labelValues = [topic])
      else:
        libp2p_gossipsub_above_dhigh_condition.inc(labelValues = ["other"])

    # prune peers if we've gone over Dhi
    prunes = toSeq(
      try:
        g.mesh[topic]
      except KeyError as e:
        raiseAssert "have peers: " & e.msg
    )
    # avoid pruning peers we are currently grafting in this heartbeat
    prunes.keepIf do(x: PubSubPeer) -> bool:
      x notin grafts

    # shuffle anyway, score might be not used
    g.rng.shuffle(prunes)

    # sort peers by score (inverted), pruning, so low score peers are on top
    prunes.sort(byScore, SortOrder.Ascending)

    # keep high score peers
    if prunes.len > g.parameters.dScore:
      prunes.setLen(prunes.len - g.parameters.dScore)

      # collect inbound/outbound info
      var outbound: seq[PubSubPeer]
      var inbound: seq[PubSubPeer]
      for peer in prunes:
        if peer.outbound:
          outbound &= peer
        else:
          inbound &= peer

      let
        meshOutbound = prunes.countIt(it.outbound)
        maxOutboundPrunes = meshOutbound - g.parameters.dOut

      # ensure that there are at least D_out peers first and rebalance to g.d after that
      outbound.setLen(min(outbound.len, max(0, maxOutboundPrunes)))

      # concat remaining outbound peers
      prunes = inbound & outbound

      let pruneLen = prunes.len - g.parameters.d
      if pruneLen > 0:
        # Ok we got some peers to prune,
        # for this heartbeat let's prune those
        g.rng.shuffle(prunes)
        prunes.setLen(pruneLen)

      trace "pruning", prunes = prunes.len
      for peer in prunes:
        trace "pruning peer on rebalance", peer, score = peer.score
        g.pruned(peer, topic)
        g.mesh.removePeer(topic, peer)

      backingOff = g.backingOff.getOrDefault(topic)

  # opportunistic grafting, by spec mesh should not be empty...
  if g.mesh.peers(topic) > 1:
    var peers = toSeq(
      try:
        g.mesh[topic]
      except KeyError as e:
        raiseAssert "have peers: " & e.msg
    )
    # grafting so high score has priority
    peers.sort(byScore, SortOrder.Descending)
    let medianIdx = peers.len div 2
    let median = peers[medianIdx]
    if median.score < g.parameters.opportunisticGraftThreshold:
      trace "median score below opportunistic threshold", score = median.score

      var
        avail: seq[PubSubPeer]
        currentMesh = addr defaultMesh
      g.mesh.withValue(topic, v):
        currentMesh = v
      g.gossipsub.withValue(topic, peerList):
        for it in peerList[]:
          if it.score >= median.score and # avoid negative score peers
          it notin currentMesh[] and
              # don't pick direct peers
              it.peerId notin g.parameters.directPeers and
              # and avoid peers we are backing off
              it.peerId notin backingOff:
            avail.add(it)

            # by spec, grab only up to MaxOpportunisticGraftPeers
            if avail.len >= MaxOpportunisticGraftPeers:
              break

      for peer in avail:
        if g.mesh.addPeer(topic, peer):
          g.grafted(peer, topic)
          grafts &= peer
          trace "opportunistic grafting", peer

  if not isNil(metrics):
    npeers = g.mesh.peers(topic)
    if npeers == 0:
      inc metrics[].noPeersTopics
    elif npeers < g.parameters.dLow:
      inc metrics[].lowPeersTopics
    else:
      inc metrics[].healthyPeersTopics

    var meshPeers = toSeq(g.mesh.getOrDefault(topic, initHashSet[PubSubPeer]()))
    meshPeers.keepIf do(x: PubSubPeer) -> bool:
      x.outbound
    if meshPeers.len < g.parameters.dOut:
      inc metrics[].underDoutTopics

    if g.knownTopics.contains(topic):
      libp2p_gossipsub_peers_per_topic_gossipsub.set(
        g.gossipsub.peers(topic).int64, labelValues = [topic]
      )

      libp2p_gossipsub_peers_per_topic_fanout.set(
        g.fanout.peers(topic).int64, labelValues = [topic]
      )

      libp2p_gossipsub_peers_per_topic_mesh.set(
        g.mesh.peers(topic).int64, labelValues = [topic]
      )
    else:
      metrics[].otherPeersPerTopicGossipsub += g.gossipsub.peers(topic).int64
      metrics[].otherPeersPerTopicFanout += g.fanout.peers(topic).int64
      metrics[].otherPeersPerTopicMesh += g.mesh.peers(topic).int64

  # Send changes to peers after table updates to avoid stale state
  if grafts.len > 0:
    let graft = RPCMsg.withControl(ControlMessage.withGraft(topic))
    g.broadcastResponse(grafts, graft, MessagePriority.High)
  if prunes.len > 0:
    let prune = RPCMsg.withControl(
      ControlMessage.withPrune(
        topic, g.parameters.pruneBackoff.seconds.uint64, g.peerExchangeList(topic)
      )
    )
    g.broadcastResponse(prunes, prune, MessagePriority.High)

proc dropFanoutPeers*(g: GossipSub) =
  # drop peers that we haven't published to in
  # GossipSubFanoutTTL seconds
  let now = Moment.now()
  var drops: seq[string]
  for topic, val in g.lastFanoutPubSub:
    if now > val:
      g.fanout.del(topic)
      drops.add topic
      trace "dropping fanout topic", topic
  for topic in drops:
    g.lastFanoutPubSub.del topic

proc replenishFanout*(g: GossipSub, topic: string) =
  ## get fanout peers for a topic
  if g.fanout.peers(topic) < g.parameters.dLow:
    let currentMesh = g.mesh.getOrDefault(topic)
    trace "replenishing fanout", topic, peersCount = g.fanout.peers(topic)
    for peer in g.gossipsub.getOrDefault(topic):
      if peer in currentMesh:
        continue
      if g.fanout.addPeer(topic, peer):
        if g.fanout.peers(topic) == g.parameters.d:
          break

  trace "fanout replenished with peers", topic, peersCount = g.fanout.peers(topic)

proc makeGossipControlMessages*(g: GossipSub): Table[PubSubPeer, ControlMessage] =
  ## gossip iHave messages to peers
  ##

  var cacheWindowSize = 0
  var control: Table[PubSubPeer, ControlMessage]

  let topics = toHashSet(toSeq(g.mesh.keys)) + toHashSet(toSeq(g.fanout.keys))
  trace "getting gossip peers (iHave)", ntopics = topics.len
  for topic in topics:
    if topic notin g.gossipsub:
      trace "topic not in gossip array, skipping", topic
      continue

    let mids = g.mcache.window(topic)
    if not (mids.len > 0):
      trace "no messages to emit"
      continue

    var midsSeq = toSeq(mids)

    cacheWindowSize += midsSeq.len

    trace "got messages to emit", size = midsSeq.len

    # not in spec
    # similar to rust: https://github.com/sigp/rust-libp2p/blob/f53d02bc873fef2bf52cd31e3d5ce366a41d8a8c/protocols/gossipsub/src/behaviour.rs#L2101
    # and go https://github.com/libp2p/go-libp2p-pubsub/blob/08c17398fb11b2ab06ca141dddc8ec97272eb772/gossipsub.go#L582
    if midsSeq.len > IHaveMaxLength:
      g.rng.shuffle(midsSeq)
      midsSeq.setLen(IHaveMaxLength)

    let
      ihave = ControlIHave(topicID: topic, messageIDs: midsSeq)
      mesh = g.mesh.getOrDefault(topic)
      fanout = g.fanout.getOrDefault(topic)
      gossipPeers = mesh + fanout
    var allPeers = toSeq(g.gossipsub.getOrDefault(topic))

    allPeers.keepIf do(x: PubSubPeer) -> bool:
      x.peerId notin g.parameters.directPeers and x notin gossipPeers and
        x.score >= g.parameters.gossipThreshold

    # https://github.com/libp2p/specs/blob/98c5aa9421703fc31b0833ad8860a55db15be063/pubsub/gossipsub/gossipsub-v1.1.md#adaptive-gossip-dissemination
    let
      factor = (g.parameters.gossipFactor.float * allPeers.len.float).int
      target = max(g.parameters.dLazy, factor)

    if target < allPeers.len:
      g.rng.shuffle(allPeers)
      allPeers.setLen(target)

    for peer in allPeers:
      if g.extensionsState.peerRequestsPartial(peer.peerId, topic):
        # add IHAVE only if peer has not requested partial for topic.
        # these peers will receive gossip of partial metadata via extension.
        continue

      control.mgetOrPut(peer, ControlMessage()).ihave.add(ihave)
      for msgId in ihave.messageIDs:
        peer.sentIHaves[0].incl(msgId)

  libp2p_gossipsub_cache_window_size.set(cacheWindowSize.int64)

  return control

proc onHeartbeat(g: GossipSub) =
  libp2p_gossipsub_seen_cache_size.set(g.seen.len.int64)

  # reset IWANT budget
  # reset IHAVE cap
  block:
    var peersWithoutSendStream = 0'i64
    for peer in g.peers.values:
      if not peer.connected():
        inc peersWithoutSendStream
      peer.sentIHaves.addFirst(default(HashSet[MessageId]))
      if peer.sentIHaves.len > g.parameters.historyLength:
        discard peer.sentIHaves.popLast()
      peer.iDontWants.addFirst(default(HashSet[SaltedId]))
      if peer.iDontWants.len > g.parameters.historyLength:
        discard peer.iDontWants.popLast()
      peer.iHaveBudget = IHavePeerBudget
    libp2p_gossipsub_peers_without_send_stream.set(peersWithoutSendStream)

  var meshMetrics = MeshMetrics()

  for t in toSeq(g.topics.keys):
    # remove expired backoffs
    block:
      handleBackingOff(g.backingOff, t)

    # prune every negative score peer
    # do this before relance
    # in order to avoid grafted -> pruned in the same cycle
    let meshPeers = g.mesh.getOrDefault(t)
    var prunes: seq[PubSubPeer]
    for peer in meshPeers:
      if peer.score < 0.0:
        trace "pruning negative score peer", peer, score = peer.score
        g.pruned(peer, t)
        g.mesh.removePeer(t, peer)
        prunes &= peer
    if prunes.len > 0:
      let prune = RPCMsg.withControl(
        ControlMessage.withPrune(
          t, g.parameters.pruneBackoff.seconds.uint64, g.peerExchangeList(t)
        )
      )
      g.broadcastResponse(prunes, prune, MessagePriority.High)

    # pass by ptr in order to both signal we want to update metrics
    # and as well update the struct for each topic during this iteration
    g.rebalanceMesh(t, addr meshMetrics)

  commitMetrics(meshMetrics)

  g.dropFanoutPeers()

  # replenish known topics to the fanout
  for t in toSeq(g.fanout.keys):
    g.replenishFanout(t)

  for peer, control in g.makeGossipControlMessages():
    # only ihave from here
    for ihave in control.ihave:
      libp2p_pubsub_broadcast_ihave.inc(labelValues = [g.topicLabel(ihave.topicID)])
    g.sendResponse(peer, RPCMsg.withControl(control), MessagePriority.High)

  g.mcache.shift() # shift the cache

  g.extensionsState.heartbeat()

proc heartbeat*(g: GossipSub) {.async: (raises: [CancelledError]).} =
  heartbeat "GossipSub", g.parameters.heartbeatInterval:
    g.onHeartbeat()

    for trigger in g.heartbeatEvents:
      trigger.fire()
