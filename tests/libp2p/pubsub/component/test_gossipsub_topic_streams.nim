# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, tables, stew/byteutils
import ../../../../libp2p/protocols/pubsub/[gossipsub, pubsubpeer]
import ../../../tools/[lifecycle, unittest]
import ../utils

suite "GossipSub Component - Topic streams":
  teardown:
    checkTrackers()

  asyncTest "signed delivery in both directions and unsubscribe/resubscribe":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)
    var received: array[2, int]
    proc handlerFor(index: int): TopicHandler =
      return proc(topic: string, data: seq[byte]) {.async.} =
        inc received[index]

    for i in 0 .. 1:
      nodes[i].subscribe("topic", handlerFor(i))
    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, "topic")
    checkUntilTimeout:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId) and
        nodes[1].extensionsState.peerHasTopicStreams(nodes[0].peerInfo.peerId)
    discard await nodes[0].publish("topic", "first".toBytes)
    discard await nodes[1].publish("topic", "second".toBytes)
    checkUntilTimeout:
      received == [1, 1]
    nodes[1].unsubscribeAll("topic")
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault("topic").len == 0
    nodes[1].subscribe("topic", handlerFor(1))
    waitSubscribeStar(nodes, "topic")
    discard await nodes[0].publish("topic", "third".toBytes)
    checkUntilTimeout:
      received == [1, 2]
