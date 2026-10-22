# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, tables, stew/byteutils, sequtils
import ../../../../libp2p/protocols/pubsub/[gossipsub, pubsubpeer, rpc/message]
import ../../../tools/[lifecycle, unittest]
import ../../../../libp2p/protocols/pubsub/rpc/protobuf
import ../utils
import ../extensions/my_partial_message

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

  asyncTest "mixed capability broadcast and reconnect":
    let nodes = (
      generateNodes(
        2,
        gossip = true,
        floodPublish = true,
        topicStreamsConfig = Opt.some(TopicStreamsConfig()),
      ) & generateNodes(1, gossip = true, floodPublish = true)
    ).toGossipSub()
    startAndDeferStop(nodes)

    var received: array[3, int]

    proc handlerFor(index: int): TopicHandler =
      return proc(topic: string, data: seq[byte]) {.async.} =
        inc received[index]

    for i in 0 .. 2:
      nodes[i].subscribe("mixed", handlerFor(i))

    await connect(nodes[0], nodes[1])
    await connect(nodes[0], nodes[2])
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault("mixed").len == 2 and
        nodes[1].gossipsub.getOrDefault("mixed").len == 1 and
        nodes[2].gossipsub.getOrDefault("mixed").len == 1

    let modern = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
    let legacy = nodes[0].peers.getOrDefault(nodes[2].peerInfo.peerId)
    check modern.extensionsState.peerHasTopicStreams(modern.peerId)
    check not legacy.extensionsState.peerHasTopicStreams(legacy.peerId)

    discard await nodes[0].publish("mixed", "both".toBytes)
    checkUntilTimeout:
      received[1] == 1 and received[2] == 1

    await nodes[0].switch.disconnect(nodes[1].peerInfo.peerId)
    await nodes[1].switch.disconnect(nodes[0].peerInfo.peerId)
    checkUntilTimeout:
      not nodes[0].peers.hasKey(nodes[1].peerInfo.peerId) and
        not nodes[1].peers.hasKey(nodes[0].peerInfo.peerId)

    await connect(nodes[0], nodes[1])
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault("mixed").len == 2 and
        nodes[1].gossipsub.getOrDefault("mixed").len == 1 and
        nodes[2].gossipsub.getOrDefault("mixed").len == 1

    discard await nodes[0].publish("mixed", "again".toBytes)
    checkUntilTimeout:
      received[1] == 2 and received[2] == 2

  asyncTest "partial requests and application data use topic streams":
    let store = MyPartialMessageStore()
    var incoming: seq[PartialMessageExtensionRPC]

    proc validateRPC(
        rpc: PartialMessageExtensionRPC
    ): LPResult[void] {.gcsafe, raises: [].} =
      ok()

    proc onIncomingRPC(
        peer: PeerId, rpc: PartialMessageExtensionRPC
    ) {.gcsafe, raises: [].} =
      incoming.add(rpc)

    let nodes = generateNodes(
        2,
        gossip = true,
        topicStreamsConfig = Opt.some(TopicStreamsConfig()),
        partialMessageExtensionConfig = Opt.some(
          PartialMessageExtensionConfig(
            unionPartsMetadata: unionPartsMetadata,
            materializeParts: store.materializePartsFn(),
            validateRPC: validateRPC,
            onIncomingRPC: onIncomingRPC,
            heartbeatsTillEviction: 100,
          )
        ),
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    for node in nodes:
      node.subscribe("partial", voidTopicHandler, requestsPartial = true)

    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, "partial")

    let request = MyPartialMessage(groupId: "group".toBytes, want: @[1])
    store.messages[request.groupId] = request
    await nodes[1].publishPartial("partial", request.groupId, request.partsMetadata())
    checkUntilTimeout:
      incoming.len == 1
    check incoming[0].topicID.get() == "partial"
    check incoming[0].partialMessage.isNone

    let response =
      MyPartialMessage(groupId: request.groupId, data: {1: "one".toBytes}.toTable)
    store.messages[response.groupId] = response
    await nodes[0].publishPartial("partial", response.groupId, response.partsMetadata())
    checkUntilTimeout:
      incoming.anyIt(it.partialMessage.isSome)
    check incoming[^1].partialMessage.get() == "one".toBytes

  asyncTest "mixed RPC keeps subscription control separate from application response":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    var received = false

    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      received = data == "reply".toBytes

    nodes[0].subscribe("response", voidTopicHandler)
    nodes[1].subscribe("response", onMessage)

    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, "response")

    let msg = Message.init(
      Opt.some(nodes[0].peerInfo), "reply".toBytes, "response", Opt.some(10'u64)
    )
    let peer = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
    nodes[0].sendResponse(
      peer,
      RPCMsg(
        messages: @[msg],
        subscriptions:
          @[SubOpts(topic: Opt.some("additional"), subscribe: Opt.some(true))],
      ),
      MessagePriority.Low,
    )
    checkUntilTimeout:
      received and nodes[1].gossipsub.getOrDefault("additional").len == 1

  asyncTest "application payload on negotiated control stream disconnects peer":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    nodes.subscribeAllNodes("violation", voidTopicHandler)

    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, "violation")

    let peer = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
    check peer.extensionsState.peerHasTopicStreams(peer.peerId)

    let msg = Message.init(
      Opt.some(nodes[0].peerInfo),
      "invalid stream".toBytes,
      "violation",
      Opt.some(20'u64),
    )
    peer.trackSend(
      peer.sendEncoded(RPCMsg.withMessages(msg).encode(false), MessagePriority.High)
    )
    checkUntilTimeout:
      not nodes[1].switch.isConnected(nodes[0].peerInfo.peerId)
