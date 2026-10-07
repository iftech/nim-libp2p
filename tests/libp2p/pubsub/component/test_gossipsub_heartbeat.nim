# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils], stew/byteutils
import ../../../../libp2p/protocols/pubsub/[gossipsub, mcache, peertable]
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

suite "GossipSub Component - Heartbeat":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "Mesh is rebalanced during heartbeat - pruning peers":
    const numberOfNodes = 10
    let
      nodes = generateNodes(
          numberOfNodes, gossip = true, heartbeatInterval = 500.milliseconds
        )
        .toGossipSub()
      node0 = nodes[0]

    startAndDeferStop(nodes)

    # Nodes are connected to Node0
    await connectHub(node0, nodes[1 .. ^1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(node0, nodes[1 .. ^1], topic)

    # When DValues of Node0 are updated to lower than defaults
    const
      newDLow = 2
      newDHigh = 4
      newDValues = Opt.some(
        DValues(
          dLow: Opt.some(newDLow),
          dHigh: Opt.some(newDHigh),
          d: Opt.some(3),
          dLazy: Opt.some(3),
          dScore: Opt.some(2),
          dOut: Opt.some(2),
        )
      )
    node0.parameters.applyDValues(newDValues)

    # Then mesh of Node0 is rebalanced and peers are pruned to adapt to new values
    checkUntilTimeout:
      node0.mesh[topic].len >= newDLow and node0.mesh[topic].len <= newDHigh

  asyncTest "Mesh is rebalanced during heartbeat - grafting new peers":
    const
      numberOfNodes = 10
      dLow = 3
      dHigh = 4
    let
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          dValues = Opt.some(
            DValues(
              dLow: Opt.some(dLow),
              dHigh: Opt.some(dHigh),
              d: Opt.some(3),
              dOut: Opt.some(1),
            )
          ),
          pruneBackoff = 20.milliseconds,
          heartbeatInterval = 500.milliseconds,
        )
        .toGossipSub()
      node0 = nodes[0]

    startAndDeferStop(nodes)

    # Nodes are connected to Node0
    await connectHub(node0, nodes[1 .. ^1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(node0, nodes[1 .. ^1], topic)

    checkUntilTimeout:
      node0.mesh.getOrDefault(topic).len >= dLow and
        node0.mesh.getOrDefault(topic).len <= dHigh

    # When peers of Node0 mesh are disconnected
    let peersToDisconnect = node0.mesh[topic].toSeq()[1 .. ^1].mapIt(it.peerId)
    findAndUnsubscribePeers(nodes, peersToDisconnect, topic, voidTopicHandler)

    checkUntilTimeout:
      node0.mesh[topic].len >= dLow and node0.mesh[topic].len <= dHigh
      node0.mesh[topic].toSeq().allIt(it.peerId notin peersToDisconnect)

  asyncTest "Mesh is rebalanced during heartbeat - opportunistic grafting":
    const numberOfNodes = 10
    let
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          dValues = Opt.some(
            DValues(
              dLow: Opt.some(3),
              dHigh: Opt.some(4),
              d: Opt.some(3),
              dOut: Opt.some(1),
              dLazy: Opt.some(3),
              dScore: Opt.some(2),
            )
          ),
          pruneBackoff = 20.milliseconds,
          opportunisticGraftThreshold = 600,
          heartbeatInterval = 1000.milliseconds,
        )
        .toGossipSub()
      node0 = nodes[0]

    startAndDeferStop(nodes)

    # Nodes are connected to Node0
    await connectHub(node0, nodes[1 .. ^1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(node0, nodes[1 .. ^1], topic)

    # Wait for beginning of the heartbeat to increase chances for
    # peer graft to happen within same heartbeat
    await node0.waitForNextHeartbeat()

    # Keep track of initial mesh of Node0
    let startingMesh = node0.mesh[topic].toSeq()

    # When scores are assigned to Peers of Node0
    var expectedGrafts: seq[PubSubPeer] = @[]
    var score = 100.0
    for peer in node0.gossipsub[topic]:
      if peer in node0.mesh[topic]:
        # Assign scores in starting Mesh
        peer.score = score
        score += 100.0
      else:
        # Assign scores higher than median to Peers not in starting Mesh and expect them to be grafted
        peer.score = 800.0
        expectedGrafts &= peer

    # Then during heartbeat Peers with lower than median scores are pruned and max 2 Peers are grafted

    checkUntilTimeout:
      block:
        let actualGrafts = node0.mesh[topic].toSeq().filterIt(it notin startingMesh)
        actualGrafts.len == MaxOpportunisticGraftPeers and
          actualGrafts.allIt(it in expectedGrafts)

  asyncTest "Fanout maintenance during heartbeat - expired peers are dropped":
    const
      numberOfNodes = 10
      heartbeatInterval = 200.milliseconds
    let
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          fanoutTTL = 60.milliseconds,
          heartbeatInterval = heartbeatInterval,
        )
        .toGossipSub()
      node0 = nodes[0]

    startAndDeferStop(nodes)
    await connectStar(nodes)

    # All nodes but Node0 are subscribed to the topic
    subscribeAllNodes(nodes[1 .. ^1], topic, voidTopicHandler)
    checkUntilTimeout:
      node0.gossipsub.hasKey(topic)
      nodes[1 .. ^1].allIt(it.gossipsub.getOrDefault(topic).len >= 1)

    # Before publishing messages, wait for Node0's next heartbeat so publishing
    # happens right after a heartbeat and the test has a full interval.
    await node0.waitForNextHeartbeat()

    # When Node0 sends a message to the topic
    tryPublish await node0.publish(topic, newSeq[byte](10000)), 3

    # Then Node0 fanout peers are populated
    checkUntilTimeout:
      node0.fanout.hasKey(topic)
      node0.fanout[topic].len > 0

    # And after heartbeat Node0 fanout peers are dropped (because fanoutTTL < heartbeatInterval)
    checkUntilTimeout:
      not node0.fanout.hasKey(topic)

  asyncTest "Fanout maintenance during heartbeat - fanout peers are replenished":
    const
      numberOfNodes = 10
      heartbeatInterval = 200.milliseconds
    let
      nodes = generateNodes(
          numberOfNodes, gossip = true, heartbeatInterval = heartbeatInterval
        )
        .toGossipSub()
      node0 = nodes[0]

    startAndDeferStop(nodes)
    await connectStar(nodes)

    # All nodes but Node0 are subscribed  to the topic
    subscribeAllNodes(nodes[1 .. ^1], topic, voidTopicHandler)
    checkUntilTimeout:
      node0.gossipsub.hasKey(topic)
      nodes[1 .. ^1].allIt(it.gossipsub.getOrDefault(topic).len == numberOfNodes - 2)

    # Before publishing messages, wait for Node0's next heartbeat so publishing
    # happens right after a heartbeat and the test has a full interval.
    await node0.waitForNextHeartbeat()

    # When Node0 sends a message to the topic
    tryPublish await node0.publish(topic, newSeq[byte](10000)), 1

    # Then Node0 fanout peers are populated 
    let maxFanoutPeers = node0.parameters.d
    checkUntilTimeout:
      node0.fanout[topic].len == maxFanoutPeers

    # When all peers but first one of Node0 fanout are disconnected
    let peersToDisconnect = node0.fanout[topic].toSeq()[1 .. ^1].mapIt(it.peerId)
    findAndUnsubscribePeers(nodes, peersToDisconnect, topic, voidTopicHandler)

    # Then Node0 fanout peers are replenished during heartbeat
    # expecting 10[numberOfNodes] - 1[Node0] - (6[maxFanoutPeers] - 1[first peer not disconnected]) = 4
    let expectedLen = numberOfNodes - 1 - (maxFanoutPeers - 1)
    checkUntilTimeout:
      node0.fanout[topic].len == expectedLen
      node0.fanout[topic].toSeq().allIt(it.peerId notin peersToDisconnect)

  asyncTest "iDontWants history - last element is pruned during heartbeat":
    # When Node0 publish larger messages, it will also publish IDontWants, because 
    # message is larger and sendIDontWantOnPublish is set to true.
    # Then Node1 receives messages and IDontWants control messages.
    # Test asserts that with each heartbeat iDontWants history moves and last element is pruned.
    const
      historyLength = 3
      msgCount = 5
    let nodes = generateNodes(
        2,
        gossip = true,
        sendIDontWantOnPublish = true,
        historyLength = historyLength,
        heartbeatInterval = (300 * msgCount).milliseconds,
          # All message publications must be delivered within the same heartbeat.
          # Therefore, the heartbeat interval needs to scale with the number of messages.
          # Node will also send as many iDontWants control messages, which should also 
          # be received within the same heartbeat.
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    await connectChain(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeChain(nodes, topic)

    # Get Node0 as Peer of Node1 
    let peer = nodes[1].mesh[topic].toSeq()[0]

    # Wait for history to populate
    checkUntilTimeout:
      peer.iDontWants.len == historyLength

    # Before publishing messages, wait for beginning of Node1 heartbeat interval
    # to further increase chances of all publications to be received within same heartbeat.
    await nodes[1].waitForNextHeartbeat()

    # When Node0 sends large messages to the topic
    # (it will also send iDontWants control messages)
    let largeMsg = newSeq[byte](iDontWantMessageSizeThreshold * 2)
    for i in 0 ..< msgCount:
      tryPublish await nodes[0].publish(topic, largeMsg), 1

    # Then Node1 receives msgCount messages and iDontWant messages from Node0
    # And with each heartbeat, history moves (new element added at start, last element pruned)
    for i in 0 ..< historyLength:
      checkUntilTimeout:
        peer.iDontWants[i].len == msgCount

      # Assert that new element is added to the start
      for j in 0 ..< i:
        check peer.iDontWants[j].len == 0

    # Finally after historyLength iterations history is cleared
    checkUntilTimeout:
      peer.iDontWants.allIt(it.len == 0)

  asyncTest "sentIHaves history - last element is pruned during heartbeat":
    # 3 Nodes, Node 0 <==> Node 1 and Node 0 <==> Node 2
    # due to DValues: 1 peer in mesh and 1 peer only in gossip of Node 0
    const
      numberOfNodes = 3
      historyLength = 3
      gossipThreshold = -100.0
    let nodes = generateNodes(
        numberOfNodes,
        gossip = true,
        historyLength = historyLength,
        dValues = Opt.some(
          DValues(
            dLow: Opt.some(1), dHigh: Opt.some(1), d: Opt.some(1), dOut: Opt.some(0)
          )
        ),
        heartbeatInterval = 500.milliseconds,
        gossipThreshold = gossipThreshold,
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    await connectHub(nodes[0], nodes[1 .. ^1])
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # Find Peer outside of mesh to which Node 0 will send IHave
    let peerOutsideMesh =
      nodes[0].gossipsub[topic].toSeq().filterIt(it notin nodes[0].mesh[topic])[0]

    # Wait for history to populate
    checkUntilTimeout:
      peerOutsideMesh.sentIHaves.len == historyLength

    # When a nodeOutsideMesh receives an IHave message, it responds with an IWant to request the full message from Node0
    # Setting `peer.score < gossipThreshold` to prevent the nodeOutsideMesh from sending the IWant
    # As when IWant is processed, messages are removed from sentIHaves history 
    let nodeOutsideMesh = nodes.getNodeByPeerId(peerOutsideMesh.peerId)
    for p in nodeOutsideMesh.gossipsub[topic].toSeq():
      p.score = 2 * gossipThreshold

    # Before publish sentIHaves has empty history
    check:
      peerOutsideMesh.sentIHaves.allIt(it.len == 0)

    # When NodeInsideMesh sends a messages to the topic
    let peerInsideMesh = nodes[0].mesh[topic].toSeq()[0]
    let nodeInsideMesh = nodes.getNodeByPeerId(peerInsideMesh.peerId)
    tryPublish await nodeInsideMesh.publish(topic, toBytes("hellow")), 1

    # Then with each heartbeat, history moves (new element added at start, last element pruned)
    for i in 0 ..< historyLength:
      checkUntilTimeout:
        peerOutsideMesh.sentIHaves[i].len == 1

    # Finally after historyLength iterations history is cleared
    checkUntilTimeout:
      peerOutsideMesh.sentIHaves.allIt(it.len == 0)
