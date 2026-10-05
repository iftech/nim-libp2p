# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils, strutils], stew/byteutils
import
  ../../../../libp2p/protocols/pubsub/
    [gossipsub, mcache, peertable, pubsubpeer, rpc/messages]
import ../../../../libp2p/utils/future
import ../../../tools/[lifecycle, topology, unittest, futures]
import ../utils

suite "GossipSub Component - Scoring":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "Flood publish to all peers with score above threshold, regardless of subscription":
    let
      numberOfNodes = 3
      nodes =
        generateNodes(numberOfNodes, gossip = true, floodPublish = true).toGossipSub()

    startAndDeferStop(nodes)

    # Nodes 1 and 2 are connected to node 0
    await connectHub(nodes[0], nodes[1 ..^ 1])

    let (handlerFut1, handler1) = createCompleteHandler()
    let (handlerFut2, handler2) = createCompleteHandler()

    # Nodes are subscribed to the same topic
    nodes[1].subscribe(topic, handler1)
    nodes[2].subscribe(topic, handler2)
    waitSubscribe(nodes[0], nodes[1], topic)
    waitSubscribe(nodes[0], nodes[2], topic)

    # Given node 2's score is below the threshold
    for peer in nodes[0].gossipsub.getOrDefault(topic):
      if peer.peerId == nodes[2].peerInfo.peerId:
        peer.score = (nodes[0].parameters.publishThreshold - 1)

    # When node 0 publishes a message to topic "foo"
    let message = "Hello!".toBytes()
    tryPublish await nodes[0].publish(topic, message), 1

    # Then only node 1 should receive the message
    checkUntilTimeout:
      handlerFut1.finished() == true
      handlerFut2.finished() == false

  asyncTest "Should not rate limit decodable messages below the size allowed":
    let nodes = generateNodes(
        2,
        gossip = true,
        overheadRateLimit = Opt.some(RateLimit(bytes: 20, interval: 1.millis)),
        verifySignature = false,
          # Avoid being disconnected by failing signature verification
      )
      .toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let rateLimitHits = currentRateLimitHits()

    nodes[0].broadcastResponse(
      nodes[0].mesh[topic],
      RPCMsg.withMessages(Message(topic: topic, data: newSeq[byte](10))),
      MessagePriority.High,
    )

    checkUntilTimeout:
      currentRateLimitHits() == rateLimitHits
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == true

    # Disconnect peer when rate limiting is enabled
    nodes[1].parameters.disconnectPeerAboveRateLimit = true
    nodes[0].broadcastResponse(
      nodes[0].mesh[topic],
      RPCMsg.withMessages(Message(topic: topic, data: newSeq[byte](12))),
      MessagePriority.High,
    )

    checkUntilTimeout:
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == true
      currentRateLimitHits() == rateLimitHits

  asyncTest "Should rate limit undecodable messages above the size allowed":
    let nodes = generateNodes(
        2,
        gossip = true,
        overheadRateLimit = Opt.some(RateLimit(bytes: 20, interval: 1.millis)),
        verifySignature = false,
          # Avoid being disconnected by failing signature verification
      )
      .toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let rateLimitHits = currentRateLimitHits()

    # Simulate sending an undecodable message
    await nodes[1].peers[nodes[0].switch.peerInfo.peerId].sendEncoded(
      newSeqWith(33, 1.byte), MessagePriority.High
    )

    checkUntilTimeout:
      currentRateLimitHits() == rateLimitHits + 1
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == true

    # Disconnect peer when rate limiting is enabled
    nodes[1].parameters.disconnectPeerAboveRateLimit = true
    await nodes[0].peers[nodes[1].switch.peerInfo.peerId].sendEncoded(
      newSeqWith(35, 1.byte), MessagePriority.High
    )

    checkUntilTimeout:
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == false
      currentRateLimitHits() == rateLimitHits + 2

  asyncTest "Should rate limit decodable messages above the size allowed":
    let nodes = generateNodes(
        2,
        gossip = true,
        overheadRateLimit = Opt.some(RateLimit(bytes: 40, interval: 1.millis)),
        verifySignature = false,
          # Avoid being disconnected by failing signature verification
      )
      .toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    checkUntilTimeout:
      nodes[0].peers[nodes[1].switch.peerInfo.peerId] in
        nodes[0].mesh.getOrDefault(topic)

    # Let any in-flight rate-limit checks on setup RPCs flush and the token
    # bucket refill before capturing the baseline.
    await sleepAsync(50.milliseconds)
    let rateLimitHits = currentRateLimitHits()

    let msg = RPCMsg.withControl(
      ControlMessage.withPrune(
        topic, 123'u64, @[PeerInfoMsg(peerId: PeerId(data: newSeq[byte](33)))]
      )
    )
    nodes[0].broadcastResponse(nodes[0].mesh[topic], msg, MessagePriority.High)

    checkUntilTimeout:
      currentRateLimitHits() == rateLimitHits + 1
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == true

    # Disconnect peer when rate limiting is enabled
    nodes[1].parameters.disconnectPeerAboveRateLimit = true
    let rateLimitHits2 = currentRateLimitHits()
    let msg2 = RPCMsg.withControl(
      ControlMessage.withPrune(
        topic, 123'u64, @[PeerInfoMsg(peerId: PeerId(data: newSeq[byte](35)))]
      )
    )
    nodes[0].broadcastResponse(nodes[0].mesh[topic], msg2, MessagePriority.High)

    checkUntilTimeout:
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == false
      currentRateLimitHits() == rateLimitHits2 + 1

  asyncTest "Should rate limit invalid messages above the size allowed":
    let nodes = generateNodes(
        2,
        gossip = true,
        overheadRateLimit = Opt.some(RateLimit(bytes: 30, interval: 1.millis)),
        verifySignature = false,
          # Avoid being disconnected by failing signature verification
      )
      .toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    proc execValidator(
        topic: string, message: messages.Message
    ): Future[ValidationResult] {.async.} =
      return ValidationResult.Reject

    nodes[0].addValidator(topic, execValidator)
    nodes[1].addValidator(topic, execValidator)

    checkUntilTimeout:
      nodes[0].peers[nodes[1].switch.peerInfo.peerId] in
        nodes[0].mesh.getOrDefault(topic)

    # Let any in-flight rate-limit checks on setup RPCs flush and the token
    # bucket refill before capturing the baseline.
    await sleepAsync(50.milliseconds)
    let rateLimitHits = currentRateLimitHits()

    let msg = RPCMsg.withMessages(Message(topic: topic, data: newSeq[byte](40)))
    nodes[0].broadcastResponse(nodes[0].mesh[topic], msg, MessagePriority.High)

    checkUntilTimeout:
      currentRateLimitHits() == rateLimitHits + 1
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == true

    # Disconnect peer when rate limiting is enabled
    nodes[1].parameters.disconnectPeerAboveRateLimit = true
    let rateLimitHits2 = currentRateLimitHits()
    nodes[0].broadcastResponse(
      nodes[0].mesh[topic],
      RPCMsg.withMessages(Message(topic: topic, data: newSeq[byte](35))),
      MessagePriority.High,
    )

    checkUntilTimeout:
      nodes[1].switch.isConnected(nodes[0].switch.peerInfo.peerId) == false
      currentRateLimitHits() == rateLimitHits2 + 1

  asyncTest "DirectPeers: don't kick direct peer with low score":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await nodes.addDirectPeerStar()

    nodes[1].parameters.disconnectBadPeers = true
    nodes[1].parameters.graylistThreshold = 100000

    var (handlerFut, handler) = createCompleteHandler()
    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, handler)
    waitSubscribe(nodes[0], nodes[1], topic)

    nodes[1].updateScores()

    # peer shouldn't be in our mesh
    check:
      topic notin nodes[1].mesh
      nodes[1].peerStats[nodes[0].switch.peerInfo.peerId].score <
        nodes[1].parameters.graylistThreshold

    tryPublish await nodes[0].publish(topic, toBytes("hellow")), 1

    # Without directPeers, this would fail
    checkUntilTimeout:
      handlerFut.finished() == true

  asyncTest "Graylisted peers: RPC is ignored":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    let (handlerFut, handler) = createCompleteHandler()
    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, handler)
    waitSubscribeStar(nodes, topic)

    let node0Id = nodes[0].peerInfo.peerId
    checkUntilTimeout:
      nodes[1].mesh.hasPeerId(topic, node0Id)

    # raise the threshold instead of lowering the score, which would also prune the mesh
    nodes[1].parameters.graylistThreshold = 100000.0
    check nodes[1].getPeerScore(node0Id) < nodes[1].parameters.graylistThreshold

    var ignored = currentGraylistedRpcs()
    let peer = nodes[0].getPeerByPeerId(topic, nodes[1].peerInfo.peerId)
    peer.send(
      RPCMsg(control: Opt.some(ControlMessage(prune: @[ControlPrune(topicID: topic)]))),
      false,
      MessagePriority.High,
    )

    checkUntilTimeout:
      currentGraylistedRpcs() > ignored
    check nodes[1].mesh.hasPeerId(topic, node0Id)

    ignored = currentGraylistedRpcs()
    tryPublish await nodes[0].publish(topic, toBytes("hellow")), 1

    checkUntilTimeout:
      currentGraylistedRpcs() > ignored
    check not handlerFut.finished()

  asyncTest "Graylisted peers: RPC of a direct peer is processed":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await nodes.addDirectPeerStar()

    let (handlerFut, handler) = createCompleteHandler()
    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, handler)
    waitSubscribe(nodes[0], nodes[1], topic)

    nodes[1].parameters.graylistThreshold = 100000.0
    check nodes[1].getPeerScore(nodes[0].peerInfo.peerId) <
      nodes[1].parameters.graylistThreshold

    tryPublish await nodes[0].publish(topic, toBytes("hellow")), 1

    # without directPeers, the graylist gate would drop this
    checkUntilTimeout:
      handlerFut.finished() == true

  asyncTest "Slow peer penalty can prune a peer on heartbeat":
    let nodes = generateNodes(
        2,
        gossip = true,
        decayInterval = 20.milliseconds,
        heartbeatInterval = TEST_GOSSIPSUB_HEARTBEAT_INTERVAL,
      )
      .toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    nodes[0].parameters.slowPeerPenaltyWeight = -10.0
    nodes[0].parameters.slowPeerPenaltyThreshold = 0.0
    nodes[0].parameters.slowPeerPenaltyDecay = 0.9

    let peer = nodes[0].getPeerByPeerId(topic, nodes[1].peerInfo.peerId)
    peer.slowPeerPenalty = 2.0

    checkUntilTimeout:
      nodes[0].getPeerScore(peer.peerId) < 0.0
      not nodes[0].mesh.hasPeerId(topic, peer.peerId)

  asyncTest "Peers disconnections mechanics":
    const numberOfNodes = 10
    let nodes =
      generateNodes(numberOfNodes, gossip = true, triggerSelf = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    var seen: Table[string, int]
    var seenFut = newFuture[void]()
    for i in 0 ..< numberOfNodes:
      let dialer = nodes[i]
      var handler: TopicHandler
      closureScope:
        var peerName = $dialer.peerInfo.peerId
        handler = proc(topicName: string, data: seq[byte]) {.async.} =
          seen.mgetOrPut(peerName, 0).inc()
          check topicName == topic
          if seen.len >= numberOfNodes:
            seenFut.completeOnce()

      dialer.subscribe(topic, handler)

    await waitSubGraph(nodes, topic)

    # ensure peer stats are stored properly and kept properly
    check:
      nodes[0].peerStats.len == numberOfNodes - 1 # minus self

    tryPublish await nodes[0].publish(topic, toBytes("hello")), 1

    await seenFut
    check:
      seen.len >= numberOfNodes
    for k, v in seen.pairs:
      check:
        v >= 1

    for node in nodes:
      check:
        topic in node.gossipsub
        node.fanout.len == 0
        node.mesh[topic].len > 0

    # Removing some subscriptions

    for i in 0 ..< numberOfNodes:
      if i mod 3 != 0:
        nodes[i].unsubscribeAll(topic)

    # Waiting 2 heartbeats
    await nodes[0].waitForHeartbeatByEvent(2)

    # ensure peer stats are stored properly and kept properly
    check:
      nodes[0].peerStats.len == numberOfNodes - 1 # minus self

    # Adding again subscriptions
    for i in 0 ..< numberOfNodes:
      if i mod 3 != 0:
        nodes[i].subscribe(topic, voidTopicHandler)

    # Waiting 2 heartbeats
    await nodes[0].waitForHeartbeatByEvent(2)

    # ensure peer stats are stored properly and kept properly
    check:
      nodes[0].peerStats.len == numberOfNodes - 1 # minus self

  asyncTest "DecayInterval":
    const decayInterval = 50.milliseconds
    let nodes =
      generateNodes(2, gossip = true, decayInterval = decayInterval).toGossipSub()

    nodes.setDefaultTopicParams(topic)

    startAndDeferStop(nodes)
    await connectStar(nodes)

    var (handlerFut, handler) = createCompleteHandler()
    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, handler)
    waitSubscribeStar(nodes, topic)

    tryPublish await nodes[0].publish(topic, toBytes("hello")), 1

    checkUntilTimeout:
      handlerFut.finished() == true

    nodes[0].peerStats[nodes[1].peerInfo.peerId].topicInfos[topic].meshMessageDeliveries =
      100
    nodes[0].topicParams[topic].meshMessageDeliveriesDecay = 0.9

    # Wait for exactly 5 scoring heartbeats to ensure precise decay count
    await nodes[0].waitForScoringHeartbeatByEvent(5)
    # After exactly 5 decays: 100 * 0.9^5 = 59.049
    check:
      nodes[0].peerStats[nodes[1].peerInfo.peerId].topicInfos[topic].meshMessageDeliveries in
        57.0 .. 62.0

  asyncTest "Nodes publishing invalid messages are penalised and disconnected":
    # Given GossipSub nodes with Topic Params
    const numberOfNodes = 3

    let
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          verifySignature = false,
            # Disable signature verification to isolate validation penalties
          decayInterval = 200.milliseconds, # scoring heartbeat interval
          heartbeatInterval = 5.seconds,
            # heartbeatInterval >>> decayInterval to prevent prunning peers with bad score
          publishThreshold = -150.0,
          graylistThreshold = -200.0,
          disconnectBadPeers = false,
        )
        .toGossipSub()
      centerNode = nodes[0]
      node1peerId = nodes[1].peerInfo.peerId
      node2peerId = nodes[2].peerInfo.peerId

    nodes.setDefaultTopicParams(topic)
    # no decay: a scoring heartbeat can run between checkUntilTimeout and the score check
    for node in nodes:
      node.topicParams[topic].invalidMessageDeliveriesWeight = -10.0
      node.topicParams[topic].invalidMessageDeliveriesDecay = 1.0
      node.topicParams[topic].firstMessageDeliveriesDecay = 1.0

    startAndDeferStop(nodes)

    # And Node 0 is center node, connected to others
    await connectHub(nodes[0], nodes[1 ..^ 1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # And center node has message validator: accept from node 1, reject from node 2
    var validatedMessageCount = 0
    proc validationHandler(
        topic: string, message: Message
    ): Future[ValidationResult] {.async.} =
      validatedMessageCount.inc
      if string.fromBytes(message.data).contains("invalid"):
        return ValidationResult.Reject # reject invalid messages
      else:
        return ValidationResult.Accept

    nodes[0].addValidator(topic, validationHandler)

    # 1st scoring heartbeat
    await centerNode.waitForScoringHeartbeatByEvent(1)
    check:
      centerNode.getPeerScore(node1peerId) > 0
      centerNode.getPeerScore(node2peerId) > 0

    # When messages are broadcasted
    const messagesToSend = 5
    for i in 0 ..< messagesToSend:
      nodes[1].broadcastResponse(
        nodes[1].mesh[topic],
        RPCMsg.withMessages(Message(topic: topic, data: ("valid_" & $i).toBytes())),
        MessagePriority.High,
      )
      nodes[2].broadcastResponse(
        nodes[2].mesh[topic],
        RPCMsg.withMessages(Message(topic: topic, data: ("invalid_" & $i).toBytes())),
        MessagePriority.High,
      )

    # And messages are processed
    # Then invalidMessageDeliveries stats are applied
    checkUntilTimeout:
      validatedMessageCount == messagesToSend * (numberOfNodes - 1)
      centerNode.getPeerTopicInfo(node1peerId, topic).invalidMessageDeliveries == 0.0
        # valid messages
      centerNode.getPeerTopicInfo(node2peerId, topic).invalidMessageDeliveries ==
        messagesToSend.float64 # invalid messages

    # When scoring heartbeat occurs (2nd scoring heartbeat)
    # Then peer scores are calculated
    await centerNode.waitForScoringHeartbeatByEvent(1)
    check:
      # node1: p1 (time in mesh) + p2 (first message deliveries)
      centerNode.getPeerScore(node1peerId) > 5.0 and
        centerNode.getPeerScore(node1peerId) < 6.0
      # node2: p1 (time in mesh) - p4 (invalid message deliveries)
      centerNode.getPeerScore(node2peerId) < -249.0 and
        centerNode.getPeerScore(node2peerId) > -250.0
      # all peers are still connected
      centerNode.mesh[topic].toSeq().len == 2

    # When disconnecting peers with bad score (score < graylistThreshold) is enabled
    for node in nodes:
      node.parameters.disconnectBadPeers = true

    # Then peers with bad score are disconnected on scoring heartbeat (3rd scoring heartbeat)
    await centerNode.waitForScoringHeartbeatByEvent(1)
    # disconnects happen independently of scoring heartbeat events, so poll continuously
    checkUntilTimeout:
      centerNode.mesh[topic].toSeq().len == 1

  asyncTest "Nodes not meeting Mesh Message Deliveries Threshold are penalised":
    # Given GossipSub nodes with Topic Params
    const numberOfNodes = 2

    let
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          decayInterval = 200.milliseconds, # scoring heartbeat interval
          heartbeatInterval = 5.seconds,
            # heartbeatInterval >>> decayInterval to prevent prunning peers with bad score
          disconnectBadPeers = false,
        )
        .toGossipSub()
      node1PeerId = nodes[1].peerInfo.peerId

    nodes.setDefaultTopicParams(topic)
    for node in nodes:
      node.topicParams[topic].meshMessageDeliveriesThreshold = 5
      node.topicParams[topic].meshMessageDeliveriesActivation = 1.milliseconds
        # active from the start
      node.topicParams[topic].meshMessageDeliveriesDecay = 0.9
      node.topicParams[topic].meshMessageDeliveriesWeight = -10.0
      node.topicParams[topic].meshFailurePenaltyDecay = 0.9
      node.topicParams[topic].meshFailurePenaltyWeight = -5.0

    startAndDeferStop(nodes)

    # And Nodes are connected and subscribed to the topic
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # When scoring heartbeat occurs
    # Then Peer has negative score due to active meshMessageDeliveries deficit
    await nodes[0].waitForScoringHeartbeatByEvent(1)
    check:
      nodes[0].gossipsub.getOrDefault(topic).len == numberOfNodes - 1
      nodes[0].mesh.getOrDefault(topic).len == numberOfNodes - 1
      # p1 (time in mesh) - p3 (mesh message deliveries)
      nodes[0].getPeerScore(node1PeerId) < -249.0

    # When Peer is unsubscribed
    nodes[1].unsubscribe(topic, voidTopicHandler)

    # Then meshFailurePenalty is applied due to active meshMessageDeliveries deficit
    checkUntilTimeout:
      nodes[0].getPeerTopicInfo(node1PeerId, topic).meshFailurePenalty == 25

    # When next scoring heartbeat occurs
    # Then Peer has negative score
    await nodes[0].waitForScoringHeartbeatByEvent(1)
    check:
      # p3b (mesh failure penalty) [p1 and p3 not calculated when peer was pruned]
      nodes[0].getPeerScore(node1PeerId) == -125.0

    # When Peer subscribes again
    nodes[1].subscribe(topic, voidTopicHandler)

    # Then Peer is not grafted to the mesh due to negative score (score was retained)
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault(topic).len == numberOfNodes - 1
      nodes[0].mesh.getOrDefault(topic).len == 0
