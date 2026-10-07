# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils], stew/byteutils
import ../../../../libp2p/protocols/pubsub/[gossipsub, mcache, rpc/message]
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

suite "GossipSub Component - Gossip Protocol":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "messages sent to peers not in the mesh are propagated via gossip":
    let
      numberOfNodes = 5
      dValues = DValues(
        dLow: Opt.some(2), dHigh: Opt.some(3), d: Opt.some(2), dOut: Opt.some(1)
      )
      nodes = generateNodes(numberOfNodes, gossip = true, dValues = Opt.some(dValues))
        .toGossipSub()

    startAndDeferStop(nodes)

    # All nodes are checking for iHave messages
    var messages = addIHaveObservers(nodes)

    # And are interconnected
    await connectStar(nodes)

    # And subscribed to the same topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # When node 0 sends a message
    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 1

    # At least one of the nodes should have received an iHave message
    # The check is made this way because the mesh structure changes from run to run
    checkUntilTimeout:
      messages[].mapIt(it[].len).anyIt(it > 0)

  asyncTest "adaptive gossip dissemination, dLazy and gossipFactor to 0":
    let
      numberOfNodes = 20
      dValues = DValues(
        dLow: Opt.some(2),
        dHigh: Opt.some(3),
        d: Opt.some(2),
        dOut: Opt.some(1),
        dLazy: Opt.some(0),
      )
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          dValues = Opt.some(dValues),
          gossipFactor = Opt.some(0.float),
        )
        .toGossipSub()

    startAndDeferStop(nodes)

    # All nodes are checking for iHave messages
    var messages = addIHaveObservers(nodes)

    # And are connected to node 0
    await connectHub(nodes[0], nodes[1 ..^ 1])

    # And subscribed to the same topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # When node 0 sends a message
    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 3

    # None of the nodes should have received an iHave message
    checkUntilTimeout:
      block:
        let receivedIHaves = messages[].mapIt(it[].len)
        filterIt(receivedIHaves, it > 0).len == 0

  asyncTest "adaptive gossip dissemination, with gossipFactor priority":
    let
      numberOfNodes = 20
      dValues = DValues(
        dLow: Opt.some(2),
        dHigh: Opt.some(3),
        d: Opt.some(2),
        dOut: Opt.some(1),
        dLazy: Opt.some(4),
      )
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          dValues = Opt.some(dValues),
          gossipFactor = Opt.some(0.5),
        )
        .toGossipSub()

    startAndDeferStop(nodes)

    # All nodes are checking for iHave messages
    var messages = addIHaveObservers(nodes)

    # And are connected to node 0
    await connectHub(nodes[0], nodes[1 ..^ 1])

    # And subscribed to the same topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # When node 0 sends a message
    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 3

    # At least 8 of the nodes should have received an iHave message
    # That's because the gossip factor is 0.5 over 16 available nodes
    checkUntilTimeout:
      block:
        let receivedIHaves = messages[].mapIt(it[].len)
        filterIt(receivedIHaves, it > 0).len >= 8

  asyncTest "adaptive gossip dissemination, with dLazy priority":
    let
      numberOfNodes = 20
      dValues = DValues(
        dLow: Opt.some(2),
        dHigh: Opt.some(3),
        d: Opt.some(2),
        dOut: Opt.some(1),
        dLazy: Opt.some(6),
      )
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          dValues = Opt.some(dValues),
          gossipFactor = Opt.some(0.float),
        )
        .toGossipSub()

    startAndDeferStop(nodes)

    # All nodes are checking for iHave messages
    var messages = addIHaveObservers(nodes)

    # And are connected to node 0
    await connectHub(nodes[0], nodes[1 ..^ 1])

    # And subscribed to the same topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # When node 0 sends a message
    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 3

    # At least 6 of the nodes should have received an iHave message
    # That's because the dLazy is 6
    checkUntilTimeout:
      block:
        let receivedIHaves = messages[].mapIt(it[].len)
        filterIt(receivedIHaves, it > 0).len >= dValues.dLazy.get()

  asyncTest "iDontWant messages are broadcast immediately after receiving the first message instance":
    let
      numberOfNodes = 3
      nodes = generateNodes(numberOfNodes, gossip = true).toGossipSub()

    startAndDeferStop(nodes)

    # All nodes are checking for iDontWant messages
    var messages = addIDontWantObservers(nodes)

    # And are connected in a chain
    await connectChain(nodes)

    # And subscribed to the same topic
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeChain(nodes, topic)

    # When node 0 sends a large message
    let largeMsg = newSeq[byte](1000)
    tryPublish await nodes[0].publish(topic, largeMsg), 1

    # Only node 2 should have received the iDontWant message
    checkUntilTimeout:
      messages[].mapIt(it[].len)[2] == 1
      messages[].mapIt(it[].len)[1] == 0
      messages[].mapIt(it[].len)[0] == 0

  asyncTest "GossipSub peer exchange":
    # A, B & C are subscribed to something
    # B unsubcribe from it, it should send
    # PX to A & C
    #
    # C sent his SPR, not A
    let nodes =
      generateNodes(2, gossip = true, enablePX = true).toGossipSub() &
      generateNodes(1, gossip = true, sendSignedPeerRecord = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # Setup record handlers for all nodes
    let
      passed0: Future[void] = newFuture[void]()
      passed2: Future[void] = newFuture[void]()
    nodes[0].routingRecordsHandler.add(
      proc(peer: PeerId, tag: string, peers: seq[RoutingRecordsPair]) =
        check:
          tag == topic
          peers.len == 2
          peers[0].record.isSome() xor peers[1].record.isSome()
        passed0.complete()
    )
    nodes[1].routingRecordsHandler.add(
      proc(peer: PeerId, tag: string, peers: seq[RoutingRecordsPair]) =
        raiseAssert "should not get here"
    )
    nodes[2].routingRecordsHandler.add(
      proc(peer: PeerId, tag: string, peers: seq[RoutingRecordsPair]) =
        check:
          tag == topic
          peers.len == 2
          peers[0].record.isSome() xor peers[1].record.isSome()
        passed2.complete()
    )

    # Unsubscribe from the topic 
    nodes[1].unsubscribe(topic, voidTopicHandler)

    checkUntilTimeout:
      passed0.finished() == true
      passed2.finished() == true
