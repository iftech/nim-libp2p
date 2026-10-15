# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, tables, stew/byteutils
import
  ../../../../libp2p/protocols/pubsub/
    [gossipsub, pubsubpeer, rpc/message]
import ../../../tools/[lifecycle, unittest]
import ../utils

suite "GossipSub Component - Topic streams":
  teardown:
    checkTrackers()

  test "topic stream limits are validated and support is disabled by default":
    check GossipSubParams.init().topicStreamsConfig.isNone
    check GossipSubParams
      .init(topicStreamsConfig = Opt.some(TopicStreamsConfig()))
      .validateParameters().isOk
    for config in [
      TopicStreamsConfig(maxStreams: 2),
      TopicStreamsConfig(maxQueuedBytes: 0),
      TopicStreamsConfig(maxIncomingBytes: 0),
      TopicStreamsConfig(maxQueuedMessages: 0),
    ]:
      check GossipSubParams
        .init(topicStreamsConfig = Opt.some(config))
        .validateParameters().isErr

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
      nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId).usesTopicStreams() and
        nodes[1].peers.getOrDefault(nodes[0].peerInfo.peerId).usesTopicStreams()
    discard await nodes[0].publish("topic", "first".toBytes)
    discard await nodes[1].publish("topic", "second".toBytes)
    checkUntilTimeout:
      received[0] == 1 and received[1] == 1
    nodes[1].unsubscribeAll("topic")
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault("topic").len == 0
    proc topicHandler(topic: string, data: seq[byte]) {.async.} =
      inc received[1]

    nodes[1].subscribe("topic", topicHandler)
    waitSubscribeStar(nodes, "topic")
    discard await nodes[0].publish("topic", "third".toBytes)
    checkUntilTimeout:
      received[1] == 2
