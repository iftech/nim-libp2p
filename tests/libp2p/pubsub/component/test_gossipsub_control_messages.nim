# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils, tables], chronicles
import ../../../../libp2p/protocols/pubsub/[gossipsub, mcache, peertable, pubsubpeer]
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

proc countGrafts(node: GossipSub, topic: string, rejectBackoff: Opt[uint64]): ref int =
  ## With `rejectBackoff`, drop each GRAFT and reply with a PRUNE that carries it.
  let grafts = new int
  node.addOnRecvObserver(
    proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].} =
      if msgs.control.isNone():
        return

      var control = msgs.control.get()
      let received = control.graft.countIt(it.topicID == topic)
      grafts[] += received
      if received == 0 or rejectBackoff.isNone():
        return

      control.graft.keepItIf(it.topicID != topic)
      msgs.control = Opt.some(control)
      node.broadcastResponse(
        @[peer],
        RPCMsg.withControl(ControlMessage.withPrune(topic, rejectBackoff.get(), @[])),
        MessagePriority.High,
      )
  )
  grafts

proc graftsAfterRejection(
    topic: string, rejectBackoff: Opt[uint64]
): Future[int] {.async.} =
  ## Counts the GRAFTs that n1 sends to n0 when n0 rejects each one.
  let
    nodes = generateNodes(2, gossip = true, verifySignature = false).toGossipSub()
    n0 = nodes[0]
    n1 = nodes[1]
    grafts = n0.countGrafts(topic, rejectBackoff)

  # n0 never grafts n1, so only n1 sends GRAFTs
  n0.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[n1.peerInfo.peerId] =
    Moment.fromNow(1.hours)

  startAndDeferStop(nodes)
  await connectStar(nodes)
  subscribeAllNodes(nodes, topic, voidTopicHandler)
  waitSubscribeStar(nodes, topic)

  checkUntilTimeout:
    n0.peerInfo.peerId in n1.backingOff.getOrDefault(topic)

  # without the backoff, n1 re-GRAFTs on the next heartbeat; the third lets it arrive
  await n1.waitForHeartbeatByEvent(3)
  check not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

  grafts[]

suite "GossipSub Component - Control Messages":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "GRAFT messages correctly add peers to mesh":
    let
      graftMessage = ControlMessage.withGraft(topic)
      numberOfNodes = 2
      # First part of the hack: Weird dValues so peers are not GRAFTed automatically
      dValues = DValues(
        dLow: Opt.some(0), dHigh: Opt.some(0), d: Opt.some(0), dOut: Opt.some(-1)
      )
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          verifySignature = false,
          dValues = Opt.some(dValues),
        )
        .toGossipSub()
      n0 = nodes[0]
      n1 = nodes[1]

    startAndDeferStop(nodes)

    # And the nodes are connected
    await connectStar(nodes)

    # And both subscribe to the topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # Because of the hack-ish dValues, the peers are added to gossipsub but not GRAFTed to mesh
    checkUntilTimeout:
      not n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

    # Pause automatic GRAFTs while testing explicit control messages.
    await n0.heartbeatFut.cancelAndWait()
    await n1.heartbeatFut.cancelAndWait()

    # Second part of the hack
    # Set values so peers can be GRAFTed
    let newDValues = Opt.some(
      DValues(dLow: Opt.some(1), dHigh: Opt.some(1), d: Opt.some(1), dOut: Opt.some(1))
    )
    n0.parameters.applyDValues(newDValues)
    n1.parameters.applyDValues(newDValues)

    # When a GRAFT message is sent
    let p0 = n1.getOrCreatePeer(n0.peerInfo.peerId, @[GossipSubCodec_12])
    let p1 = n0.getOrCreatePeer(n1.peerInfo.peerId, @[GossipSubCodec_12])
    n0.broadcastResponse(@[p1], RPCMsg.withControl(graftMessage), MessagePriority.High)
    n1.broadcastResponse(@[p0], RPCMsg.withControl(graftMessage), MessagePriority.High)

    checkUntilTimeout:
      nodes.allIt(it.mesh.getOrDefault(topic).len == 1)

    # Then the peers are GRAFTed
    check:
      n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

  asyncTest "Received GRAFT for non-subscribed topic":
    let
      graftMessage = ControlMessage.withGraft(topic)
      numberOfNodes = 2
      nodes = generateNodes(numberOfNodes, gossip = true, verifySignature = false)
        .toGossipSub()
      n0 = nodes[0]
      n1 = nodes[1]

    startAndDeferStop(nodes)

    # And the nodes are connected
    await connectStar(nodes)

    # And only node0 subscribes to the topic
    nodes[0].subscribe(topic, voidTopicHandler)
    waitSubscribe(n1, n0, topic)

    check:
      n0.topics.hasKey(topic)
      not n1.topics.hasKey(topic)
      not n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      not n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

    # When a GRAFT message is sent
    let p1 = n0.getOrCreatePeer(n1.peerInfo.peerId, @[GossipSubCodec_12])
    n0.broadcastResponse(@[p1], RPCMsg.withControl(graftMessage), MessagePriority.High)

    # Then the peer is not GRAFTed
    checkUntilTimeout:
      n0.topics.hasKey(topic)
      not n1.topics.hasKey(topic)
      not n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      not n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

  asyncTest "PRUNE messages correctly removes peers from mesh":
    let
      backoff = 1
      pruneMessage = ControlMessage.withPrune(topic, uint64(backoff), @[])
      numberOfNodes = 2
      nodes = generateNodes(numberOfNodes, gossip = true, verifySignature = false)
        .toGossipSub()
      n0 = nodes[0]
      n1 = nodes[1]

    startAndDeferStop(nodes)

    # And the nodes are connected
    await connectStar(nodes)

    # And both subscribe to the topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    check:
      n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

    # When a PRUNE message is sent
    let p1 = n0.getOrCreatePeer(n1.peerInfo.peerId, @[GossipSubCodec_12])
    n0.broadcastResponse(@[p1], RPCMsg.withControl(pruneMessage), MessagePriority.High)

    # Then the peer is PRUNEd
    checkUntilTimeout:
      n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

    # When another PRUNE message is sent
    let p0 = n1.getOrCreatePeer(n0.peerInfo.peerId, @[GossipSubCodec_12])
    n1.broadcastResponse(@[p0], RPCMsg.withControl(pruneMessage), MessagePriority.High)

    # Then the peer is PRUNEd
    checkUntilTimeout:
      n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      not n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

  asyncTest "GRAFT rejected by handleGraft is sent once":
    check (await graftsAfterRejection(topic, Opt.none(uint64))) == 1

  asyncTest "GRAFT rejected by a PRUNE without backoff is sent once":
    check (await graftsAfterRejection(topic, Opt.some(0'u64))) == 1

  asyncTest "Received PRUNE for non-subscribed topic":
    let
      pruneMessage = ControlMessage.withPrune(topic, 1, @[])
      numberOfNodes = 2
      nodes = generateNodes(numberOfNodes, gossip = true, verifySignature = false)
        .toGossipSub()
      n0 = nodes[0]
      n1 = nodes[1]

    startAndDeferStop(nodes)

    # And the nodes are connected
    await connectStar(nodes)

    # And only node0 subscribes to the topic 
    n0.subscribe(topic, voidTopicHandler)
    waitSubscribe(n1, n0, topic)

    check:
      n0.topics.hasKey(topic)
      not n1.topics.hasKey(topic)
      not n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      not n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

    # When a PRUNE message is sent
    let p1 = n0.getOrCreatePeer(n1.peerInfo.peerId, @[GossipSubCodec_12])
    n0.broadcastResponse(@[p1], RPCMsg.withControl(pruneMessage), MessagePriority.High)

    # Then the peer is not PRUNEd
    checkUntilTimeout:
      n0.topics.hasKey(topic)
      not n1.topics.hasKey(topic)
      not n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)
      not n0.mesh.hasPeerId(topic, n1.peerInfo.peerId)
      not n1.mesh.hasPeerId(topic, n0.peerInfo.peerId)

  asyncTest "IHAVE messages correctly advertise message ID to peers":
    let
      messageID = @[0'u8, 1, 2, 3]
      ihaveMessage = ControlMessage.withIHave(topic, @[messageID])
      numberOfNodes = 2
      nodes = generateNodes(numberOfNodes, gossip = true, verifySignature = false)
        .toGossipSub()
      n0 = nodes[0]
      n1 = nodes[1]

    startAndDeferStop(nodes)

    # Given node1 has an IHAVE observer
    var (receivedIHaves, checkForIHaves) = createCheckForIHave()
    n1.addOnRecvObserver(checkForIHaves)

    # And the nodes are connected
    await connectStar(nodes)

    # And both subscribe to the topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    check:
      n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)

    # When an IHAVE message is sent
    let p1 = n0.getOrCreatePeer(n1.peerInfo.peerId, @[GossipSubCodec_12])
    n0.broadcastResponse(@[p1], RPCMsg.withControl(ihaveMessage), MessagePriority.High)

    # Wait until IHAVE response is received
    # Then the peer has exactly one IHAVE message with the correct message ID
    checkUntilTimeout:
      receivedIHaves[].len == 1 and
        receivedIHaves[0] == ControlIHave(topicID: topic, messageIDs: @[messageID])

  asyncTest "IWANT messages correctly request messages by their IDs":
    let
      messageID = @[0'u8, 1, 2, 3]
      iwantMessage = ControlMessage.withIWant(@[messageID])
      numberOfNodes = 2
      nodes = generateNodes(numberOfNodes, gossip = true, verifySignature = false)
        .toGossipSub()
      n0 = nodes[0]
      n1 = nodes[1]

    startAndDeferStop(nodes)

    # Given node1 has an IWANT observer
    var (receivedIWants, checkForIWants) = createCheckForIWant()
    n1.addOnRecvObserver(checkForIWants)

    # And the nodes are connected   
    await connectStar(nodes)

    # And both subscribe to the topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    check:
      n0.gossipsub.hasPeerId(topic, n1.peerInfo.peerId)
      n1.gossipsub.hasPeerId(topic, n0.peerInfo.peerId)

    # When an IWANT message is sent
    let p1 = n0.getOrCreatePeer(n1.peerInfo.peerId, @[GossipSubCodec_12])
    n0.broadcastResponse(@[p1], RPCMsg.withControl(iwantMessage), MessagePriority.High)

    # Wait until IWANT response is received
    # Then the peer has exactly one IWANT message with the correct message ID
    checkUntilTimeout:
      receivedIWants[].len == 1 and
        receivedIWants[0] == ControlIWant(messageIDs: @[messageID])

  asyncTest "IHAVE for message not held by peer triggers IWANT response to sender":
    let
      messageID = @[0'u8, 1, 2, 3]
      ihaveMessage = ControlMessage.withIHave(topic, @[messageID])
      numberOfNodes = 2
      nodes = generateNodes(numberOfNodes, gossip = true, verifySignature = false)
        .toGossipSub()
      n0 = nodes[0]
      n1 = nodes[1]

    startAndDeferStop(nodes)

    # Given node1 has an IWANT observer
    var (receivedIWants, checkForIWants) = createCheckForIWant()
    n0.addOnRecvObserver(checkForIWants)

    # And the nodes are connected
    await connectStar(nodes)

    # And both nodes subscribe to the topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # When an IHAVE message is sent from node0
    let p1 = n0.getOrCreatePeer(n1.peerInfo.peerId, @[GossipSubCodec_12])
    n0.broadcastResponse(@[p1], RPCMsg.withControl(ihaveMessage), MessagePriority.High)

    # Wait until IWANT response is received
    # Then node0 should receive exactly one IWANT message from node1
    checkUntilTimeout:
      receivedIWants[].len == 1 and
        receivedIWants[0] == ControlIWant(messageIDs: @[messageID])

  asyncTest "IDONTWANT":
    let nodes = generateNodes(3, gossip = true).toGossipSub()

    startAndDeferStop(nodes)

    # Nodes in chain connection
    await connectChain(nodes)

    let (bFinished, handlerB) = createCompleteHandler()

    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, handlerB)
    nodes[2].subscribe(topic, voidTopicHandler)
    waitSubscribeChain(nodes, topic)

    check:
      nodes[2].mesh.peers(topic) == 1

    # When we pre-emptively send a dontwant from C to B,
    nodes[2].broadcastResponse(
      nodes[2].mesh[topic],
      RPCMsg.withControl(ControlMessage.withIDontWant(newSeq[byte](10))),
      MessagePriority.High,
    )

    # Then B doesn't relay the message to C.
    checkUntilTimeout:
      nodes[1].mesh.getOrDefault(topic).anyIt(it.iDontWants.anyIt(it.len == 1))

    # When A sends a message to the topic
    tryPublish await nodes[0].publish(topic, newSeq[byte](10000)), 1

    discard await bFinished

    # Then B sends IDONTWANT to C, but not A
    checkUntilTimeout:
      toSeq(nodes[2].mesh.getOrDefault(topic)).anyIt(it.iDontWants.anyIt(it.len == 1))
    check:
      toSeq(nodes[0].mesh.getOrDefault(topic)).allIt(it.iDontWants.allIt(it.len == 0))

  asyncTest "IDONTWANT is broadcasted on publish":
    let nodes =
      generateNodes(2, gossip = true, sendIDontWantOnPublish = true).toGossipSub()

    startAndDeferStop(nodes)

    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # When A sends a message to the topic
    tryPublish await nodes[0].publish(topic, newSeq[byte](10000)), 1

    # Then IDONTWANT is sent to B on publish
    checkUntilTimeout:
      nodes[1].mesh.getOrDefault(topic).anyIt(it.iDontWants.anyIt(it.len == 1))
