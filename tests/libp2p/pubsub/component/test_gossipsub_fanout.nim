# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, rpc/messages]
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

suite "GossipSub Component - Fanout Management":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "GossipSub send over fanout A -> B":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    let (passed, handler) = createCompleteHandler()
    nodes[1].subscribe(topic, handler)
    waitSubscribe(nodes[0], nodes[1], topic)

    var observed = 0
    let
      obs1 = PubSubObserver(
        onRecv: proc(peer: PubSubPeer, msgs: var RPCMsg) =
          inc observed
      )
      obs2 = PubSubObserver(
        onSend: proc(peer: PubSubPeer, msgs: var RPCMsg) =
          inc observed
      )

    nodes[1].addObserver(obs1)
    nodes[0].addObserver(obs2)

    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 1

    discard await passed

    check:
      topic in nodes[0].gossipsub
      nodes[0].fanout.hasPeerId(topic, nodes[1].peerInfo.peerId)
      not nodes[0].mesh.hasPeerId(topic, nodes[1].peerInfo.peerId)

    check observed == 2

  asyncTest "GossipSub send over fanout A -> B for subscribed topic":
    let nodes =
      generateNodes(2, gossip = true, unsubscribeBackoff = 10.minutes).toGossipSub()

    nodes[1].parameters.d = 0
    nodes[1].parameters.dHigh = 0
    nodes[1].parameters.dLow = 0

    startAndDeferStop(nodes)
    await connectStar(nodes)

    let (passed, handler) = createCompleteHandler()
    nodes[1].subscribe(topic, handler)
    waitSubscribe(nodes[0], nodes[1], topic)

    checkUntilTimeout:
      nodes[0].mesh.getOrDefault(topic).len == 0
      nodes[1].mesh.getOrDefault(topic).len == 0
      (
        nodes[0].gossipsub.getOrDefault(topic).len == 1 or
        nodes[0].fanout.getOrDefault(topic).len == 1
      )

    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 1

    discard await passed
    check:
      nodes[0].mesh.getOrDefault(topic).len == 0
      nodes[0].fanout.getOrDefault(topic).len == 1
