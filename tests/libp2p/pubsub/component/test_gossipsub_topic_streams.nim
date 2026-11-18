# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/ratelimit, tables, stew/byteutils, sequtils
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, pubsubpeer, rpc/message]
import ../../../tools/[lifecycle, switch_builder, topology, unittest]
import ../../../../libp2p/protocols/pubsub/gossipsub/extensions
import ../../../../libp2p/utils/future
import ../utils
import ../extensions/my_partial_message

suite "GossipSub Component - Topic streams":
  const topic = "foobar"

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
      nodes[i].subscribe(topic, handlerFor(i))

    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, topic)
    checkUntilTimeout:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId) and
        nodes[1].extensionsState.peerHasTopicStreams(nodes[0].peerInfo.peerId)

    discard await nodes[0].publish(topic, "first")
    discard await nodes[1].publish(topic, "second")
    checkUntilTimeout:
      received == [1, 1]

    nodes[1].unsubscribeAll(topic)
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault(topic).len == 0

    nodes[1].subscribe(topic, handlerFor(1))
    waitSubscribeStar(nodes, topic)
    discard await nodes[0].publish(topic, "third")
    checkUntilTimeout:
      received == [1, 2]

  asyncTest "full incoming stream budget does not block outgoing delivery":
    const streamLimit = 3
    let nodes = generateNodes(
        2,
        gossip = true,
        floodPublish = true,
        topicStreamsConfig = Opt.some(
          TopicStreamsConfig(
            maxIncomingStreams: streamLimit, maxOutgoingStreams: streamLimit
          )
        ),
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    var received: array[2, int]
    proc handlerFor(index: int): TopicHandler =
      return proc(topic: string, data: seq[byte]) {.async.} =
        inc received[index]

    for i in 0 .. streamLimit:
      for j in 0 .. 1:
        nodes[j].subscribe("topic-" & $i, handlerFor(j))

    await connect(nodes[0], nodes[1])
    for i in 0 .. streamLimit:
      waitSubscribeStar(nodes, "topic-" & $i)
    checkUntilTimeout:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId) and
        nodes[1].extensionsState.peerHasTopicStreams(nodes[0].peerInfo.peerId)

    for i in 0 ..< streamLimit:
      discard await nodes[1].publish("topic-" & $i, "incoming")
    checkUntilTimeout:
      received[0] == streamLimit
    check nodes[0].inboundTopicStreams(nodes[1].peerInfo.peerId).len == streamLimit

    discard await nodes[0].publish("topic-" & $streamLimit, "outgoing")
    checkUntilTimeout:
      received[1] == 1
    check nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId).len == 1

  asyncTest "forwarded message travels on topic streams":
    let nodes = generateNodes(
        3, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let received = newFuture[void]("forwardedMessageReceived")
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      received.completeOnce()

    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, voidTopicHandler)
    nodes[2].subscribe(topic, onMessage)

    await connectChain(nodes)
    waitSubscribeChain(nodes, topic)
    checkUntilTimeout:
      nodes[0].mesh.hasPeerId(topic, nodes[1].peerInfo.peerId)
      nodes[1].mesh.hasPeerId(topic, nodes[2].peerInfo.peerId)

    discard await nodes[0].publish(topic, "forwarded")
    await received
    check nodes[2].inboundTopicStreams(nodes[1].peerInfo.peerId).len == 1

  asyncTest "publish counts a topic stream peer that never receives a message with empty data":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let received = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await received.put(data)

    nodes[1].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    waitSubscribe(nodes[0], nodes[1], topic)

    # TODO: iftech/nim-libp2p#3411
    check (await nodes[0].publish(topic, newSeq[byte]())) == 1
    discard await nodes[0].publish(topic, "data")
    check (await received.popFirst()) == "data"

  asyncTest "publish with useCustomStream runs custom peer selection and stream creation for a topic stream peer":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()

    var
      peerSelectionCalled = false
      streamCreationCalled = false
      customStream: Stream
    nodes[0].customStreamCallbacks = Opt.some(
      CustomStreamCallbacks(
        customStreamCreationCB: proc(
            destAddr: Opt[MultiAddress], destPeerId: PeerId, codec: string
        ): Stream =
          streamCreationCalled = true
          return customStream,
        customPeerSelectionCB: proc(
            allPeers: HashSet[PubSubPeer],
            directPeers: HashSet[PubSubPeer],
            meshPeers: HashSet[PubSubPeer],
            fanoutPeers: HashSet[PubSubPeer],
        ): HashSet[PubSubPeer] =
          peerSelectionCalled = true
          return allPeers,
      )
    )
    startAndDeferStop(nodes)

    let received = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await received.put(data)

    nodes[1].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    waitSubscribe(nodes[0], nodes[1], topic)

    checkUntilTimeout:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)
    customStream = await nodes[0].switch.dial(nodes[1].switch, TopicStreamsCodec)

    const msg = "data"
    discard await nodes[0].publish(
      topic, msg, publishParams = Opt.some(PublishParams(useCustomStream: true))
    )
    check:
      (await received.popFirst()) == msg
      peerSelectionCalled
      streamCreationCalled

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
      nodes[i].subscribe(topic, handlerFor(i))

    await connect(nodes[0], nodes[1])
    await connect(nodes[0], nodes[2])
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault(topic).len == 2 and
        nodes[1].gossipsub.getOrDefault(topic).len == 1 and
        nodes[2].gossipsub.getOrDefault(topic).len == 1

    let modern = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
    let legacy = nodes[0].peers.getOrDefault(nodes[2].peerInfo.peerId)
    check modern.extensionsState.peerHasTopicStreams(modern.peerId)
    check not legacy.extensionsState.peerHasTopicStreams(legacy.peerId)

    discard await nodes[0].publish(topic, "both")
    checkUntilTimeout:
      received[1] == 1 and received[2] == 1

    await nodes[0].switch.disconnect(nodes[1].peerInfo.peerId)
    await nodes[1].switch.disconnect(nodes[0].peerInfo.peerId)
    checkUntilTimeout:
      not nodes[0].peers.hasKey(nodes[1].peerInfo.peerId) and
        not nodes[1].peers.hasKey(nodes[0].peerInfo.peerId)

    await connect(nodes[0], nodes[1])
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault(topic).len == 2 and
        nodes[1].gossipsub.getOrDefault(topic).len == 1 and
        nodes[2].gossipsub.getOrDefault(topic).len == 1

    discard await nodes[0].publish(topic, "again")
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
      node.subscribe(topic, voidTopicHandler, requestsPartial = true)

    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, topic)

    let request = MyPartialMessage(groupId: "group", want: @[1])
    store.messages[request.groupId] = request
    await nodes[1].publishPartial(topic, request.groupId, request.partsMetadata())
    checkUntilTimeout:
      incoming.len == 1
    check:
      incoming[0].topicID == topic
      incoming[0].partialMessage.isNone
      nodes[0].inboundTopicStreams(nodes[1].peerInfo.peerId).len == 1

    let response =
      MyPartialMessage(groupId: request.groupId, data: {1: "one".toBytes}.toTable)
    store.messages[response.groupId] = response
    await nodes[0].publishPartial(topic, response.groupId, response.partsMetadata())
    checkUntilTimeout:
      incoming.anyIt(it.partialMessage.isSome)
    check:
      incoming[^1].partialMessage == "one".toBytes
      nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId).len == 1

  asyncTest "mixed RPC keeps subscription control separate from application response":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    var received = false

    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      received = data == "reply".toBytes

    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, onMessage)

    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, topic)

    let msg = Message.init(nodes[0].peerInfo, "reply", topic, 10'u64)
    let peer = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
    const additionalTopic = "additional"
    nodes[0].sendResponse(
      peer,
      RPCMsg(
        messages: @[msg],
        subscriptions: @[SubOpts(topic: additionalTopic, subscribe: true)],
      ),
      MessagePriority.Low,
    )
    checkUntilTimeout:
      received and nodes[1].gossipsub.getOrDefault(additionalTopic).len == 1
