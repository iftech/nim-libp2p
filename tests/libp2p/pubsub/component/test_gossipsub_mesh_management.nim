# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils]
import ../../../../libp2p/protocols/pubsub/[gossipsub, mcache, peertable, pubsubpeer]
import ../../../tools/[lifecycle, topology, unittest, futures]
import ../utils

suite "GossipSub Component - Mesh Management":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "Nodes graft peers according to DValues - numberOfNodes < dHigh":
    let
      numberOfNodes = 5
      nodes = generateNodes(numberOfNodes, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)

    let expectedNumberOfPeers = numberOfNodes - 1

    for i in 0 ..< numberOfNodes:
      let node = nodes[i]
      checkUntilTimeout:
        node.gossipsub.getOrDefault(topic).len == expectedNumberOfPeers
        node.mesh.getOrDefault(topic).len == expectedNumberOfPeers
        node.fanout.len == 0

  asyncTest "Nodes graft peers according to DValues - numberOfNodes > dHigh":
    let
      numberOfNodes = 8
      nodes = generateNodes(numberOfNodes, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)

    let
      expectedNumberOfPeers = numberOfNodes - 1
      dHigh = 7
      dLow = 4

    for i in 0 ..< numberOfNodes:
      let node = nodes[i]
      checkUntilTimeout:
        node.fanout.len == 0
        node.gossipsub.getOrDefault(topic).len == expectedNumberOfPeers
        (
          node.mesh.getOrDefault(topic).len >= dLow and
          node.mesh.getOrDefault(topic).len <= dHigh
        )

  asyncTest "GossipSub should add remote peer topic subscriptions":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[1].subscribe(topic, voidTopicHandler)

    checkUntilTimeout:
      topic in nodes[1].topics
      topic in nodes[0].gossipsub
      nodes[0].gossipsub.hasPeerId(topic, nodes[1].peerInfo.peerId)

  asyncTest "GossipSub should add remote peer topic subscriptions if both peers are subscribed":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    check:
      topic in nodes[0].topics
      topic in nodes[1].topics

      topic in nodes[0].gossipsub
      topic in nodes[1].gossipsub

      nodes[0].gossipsub.hasPeerId(topic, nodes[1].peerInfo.peerId) or
        nodes[0].mesh.hasPeerId(topic, nodes[1].peerInfo.peerId)

      nodes[1].gossipsub.hasPeerId(topic, nodes[0].peerInfo.peerId) or
        nodes[1].mesh.hasPeerId(topic, nodes[0].peerInfo.peerId)

  asyncTest "GossipSub invalid topic subscription":
    var handlerFut = newFuture[bool]()
    proc handler(handlerTopic: string, data: seq[byte]) {.async.} =
      check handlerTopic == topic
      handlerFut.complete(true)

    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)

    # We must subscribe before setting the validator
    nodes[0].subscribe(topic, handler)

    let invalidDetected = newFuture[void]()
    nodes[0].subscriptionValidator = proc(subTopic: string): bool =
      if subTopic == topic:
        try:
          invalidDetected.complete()
        except:
          raise newException(Defect, "Exception during subscriptionValidator")
        false
      else:
        true

    await connectStar(nodes)

    nodes[1].subscribe(topic, handler)

    await invalidDetected

  asyncTest "GossipSub test directPeers":
    let nodes = generateNodes(2, gossip = true).toGossipSub()
    startAndDeferStop(nodes)

    await nodes[0].addDirectPeer(nodes[1])

    let invalidDetected = newFuture[void]()
    nodes[0].subscriptionValidator = proc(subTopic: string): bool =
      if subTopic == topic:
        try:
          invalidDetected.complete()
        except:
          raise newException(Defect, "Exception during subscriptionValidator")
        false
      else:
        true

    # DO NOT SUBSCRIBE, CONNECTION SHOULD HAPPEN
    ### await connectStar(nodes)

    nodes[1].subscribe(topic, voidTopicHandler)

    await invalidDetected

  asyncTest "mesh and gossipsub updated when topic subscribed and unsubscribed":
    let
      numberOfNodes = 5
      nodes = generateNodes(numberOfNodes, gossip = true).toGossipSub()

    startAndDeferStop(nodes)

    # When all of them are connected and subscribed to the same topic
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # Then mesh and gossipsub should be populated
    for node in nodes:
      check:
        node.topics.contains(topic)
        node.gossipsub.hasKey(topic)
        node.gossipsub[topic].len() == numberOfNodes - 1
        node.mesh.hasKey(topic)
        node.mesh[topic].len() == numberOfNodes - 1

    # When all nodes unsubscribe from the topic
    unsubscribeAllNodes(nodes, topic, voidTopicHandler)

    # Then the topic should be removed from mesh and gossipsub
    for node in nodes:
      check:
        topic notin node.topics
        topic notin node.mesh
        topic notin node.gossipsub

  asyncTest "handle subscribe and unsubscribe for multiple topics":
    let
      numberOfNodes = 3
      topics = @["foobar1", "foobar2", "foobar3"]
      nodes = generateNodes(numberOfNodes, gossip = true).toGossipSub()

    startAndDeferStop(nodes)

    await connectStar(nodes)

    # When nodes subscribe to multiple topics
    for t in topics:
      let topic = t
      subscribeAllNodes(nodes, topic, voidTopicHandler)

    # Then all nodes should be subscribed to the topics initially
    for t in topics:
      let topic = t
      waitSubscribeStar(nodes, topic)

    # When they unsubscribe from all topics
    for t in topics:
      let topic = t
      unsubscribeAllNodes(nodes, topic, voidTopicHandler)

    # Then topics should be removed from mesh and gossipsub
    for topic in topics:
      check:
        nodes.allIt(not it.topics.contains(topic))
        nodes.allIt(topic notin it.gossipsub)
        nodes.allIt(topic notin it.mesh)

  asyncTest "Unsubscribe backoff":
    const
      numberOfNodes = 3
      unsubscribeBackoff = 1.seconds # 1s is the minimum
    let nodes = generateNodes(
        numberOfNodes, gossip = true, unsubscribeBackoff = unsubscribeBackoff
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    # Nodes are connected to Node0
    await connectHub(nodes[0], nodes[1 .. ^1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # When Node0 unsubscribes from the topic
    nodes[0].unsubscribe(topic, voidTopicHandler)

    # And subscribes back straight away
    nodes[0].subscribe(topic, voidTopicHandler)

    # Then its mesh is pruned and peers have applied unsubscribeBackoff
    check not nodes[0].mesh.hasKey(topic)

    # After unsubscribeBackoff period is done
    # Then on the next heartbeat mesh is rebalanced and peers are regrafted
    checkUntilTimeout:
      (nodes[0].mesh.hasKey(topic) and nodes[0].mesh[topic].len == numberOfNodes - 1)

  asyncTest "Prune backoff":
    const
      numberOfNodes = 9
      pruneBackoff = 1.seconds # 1s is the minimum
      dValues = Opt.some(
        DValues(
          dLow: Opt.some(6),
          dHigh: Opt.some(8),
          d: Opt.some(6),
          dLazy: Opt.some(6),
          dScore: Opt.some(4),
          dOut: Opt.some(2),
        )
      )
    let
      nodes = generateNodes(
          numberOfNodes, gossip = true, dValues = dValues, pruneBackoff = pruneBackoff
        )
        .toGossipSub()
      node0 = nodes[0]

    startAndDeferStop(nodes)

    # Nodes are connected to Node0
    await connectHub(nodes[0], nodes[1 .. ^1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # When DValues of Node0 are updated to lower than initial dValues
    const newDValues = Opt.some(
      DValues(
        dLow: Opt.some(2),
        dHigh: Opt.some(4),
        d: Opt.some(3),
        dLazy: Opt.some(3),
        dScore: Opt.some(2),
        dOut: Opt.some(2),
      )
    )
    node0.parameters.applyDValues(newDValues)

    # Then Node0 mesh is pruned to newDValues.dHigh length
    # And pruned peers have applied pruneBackoff
    checkUntilTimeout:
      node0.mesh.getOrDefault(topic).len == newDValues.get.dHigh.get

    # When DValues of Node0 are updated back to the initial dValues
    node0.parameters.applyDValues(dValues)

    # Then on the next heartbeat mesh is rebalanced and peers are regrafted to the initial d value
    checkUntilTimeout:
      node0.mesh.getOrDefault(topic).len == dValues.get.d.get

  asyncTest "Outbound peers are marked correctly":
    let
      numberOfNodes = 4
      nodes = generateNodes(numberOfNodes, gossip = true).toGossipSub()

    startAndDeferStop(nodes)

    await allFuturesRaising(
      connect(nodes[0], nodes[1]), # Out
      connect(nodes[0], nodes[2]), # Out
      connect(nodes[3], nodes[0]), # In
    )

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribe(nodes[0], nodes[1], topic)
    waitSubscribe(nodes[0], nodes[2], topic)
    waitSubscribe(nodes[3], nodes[0], topic)

    checkUntilTimeout:
      nodes[0].mesh.outboundPeers(topic) == 2
      nodes[0].getPeerByPeerId(topic, nodes[1].peerInfo.peerId).outbound == true
      nodes[0].getPeerByPeerId(topic, nodes[2].peerInfo.peerId).outbound == true
      nodes[0].getPeerByPeerId(topic, nodes[3].peerInfo.peerId).outbound == false
