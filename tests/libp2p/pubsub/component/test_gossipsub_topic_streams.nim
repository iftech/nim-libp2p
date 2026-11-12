# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, tables, stew/byteutils, sequtils
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, pubsubpeer, rpc/message]
import ../../../tools/[lifecycle, topology, unittest]
import ../../../../libp2p/protocols/pubsub/rpc/protobuf
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

  asyncTest "application payload on negotiated control stream disconnects peer":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    nodes.subscribeAllNodes(topic, voidTopicHandler)

    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, topic)

    let peer = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
    check peer.extensionsState.peerHasTopicStreams(peer.peerId)

    let msg = Message.init(nodes[0].peerInfo, "invalid stream", topic, 20'u64)
    peer.trackSend(
      peer.sendEncoded(RPCMsg.withMessages(msg).encode(false), MessagePriority.High)
    )
    checkUntilTimeout:
      not nodes[1].switch.isConnected(nodes[0].switch)

  asyncTest "graylisted peer recovers with subscription before publication":
    let negotiated = newFuture[void]("graylistedTopicStreamsNegotiated")
    var negotiatedPeers = 0
    proc onNegotiated(peer: PeerId) {.gcsafe, raises: [].} =
      inc negotiatedPeers
      if negotiatedPeers == 2:
        negotiated.completeOnce()

    let nodes = generateNodes(
        2,
        gossip = true,
        topicStreamsConfig = Opt.some(TopicStreamsConfig()),
        testExtensionConfig = Opt.some(TestExtensionConfig(onNegotiated: onNegotiated)),
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    var received = 0
    proc handler(topic: string, data: seq[byte]) {.async.} =
      inc received

    nodes[0].subscribe(topic, handler)
    let originalGraylistThreshold = nodes[0].parameters.graylistThreshold
    # nodes[1]'s score is 0, so this graylists it
    nodes[0].parameters.graylistThreshold = 100000.0
    # the agent label stays "unknown" until identify finishes
    let ignored = currentGraylistedRpcs() + currentGraylistedRpcs("unknown")

    # Negotiate capabilities even though ordinary RPC processing is suppressed.
    await connect(nodes[0], nodes[1])
    await negotiated
    check currentGraylistedRpcs() + currentGraylistedRpcs("unknown") > ignored

    nodes[0].parameters.graylistThreshold = originalGraylistThreshold
    nodes[1].subscribe(topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    check:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)
      nodes[1].extensionsState.peerHasTopicStreams(nodes[0].peerInfo.peerId)

    discard await nodes[1].publish(topic, "data")

    checkUntilTimeout:
      received == 1
    check nodes[0].switch.isConnected(nodes[1].switch)

  asyncTest "graylisted peer recovers with publication before subscription":
    let
      negotiated = newFuture[void]("graylistedTopicStreamsNegotiated")
      subscribed = newFuture[void]("topicStreamPeerSubscribed")
    var negotiatedPeers = 0
    proc onNegotiated(peer: PeerId) {.gcsafe, raises: [].} =
      inc negotiatedPeers
      if negotiatedPeers == 2:
        negotiated.completeOnce()

    let nodes = generateNodes(
        2,
        gossip = true,
        topicStreamsConfig = Opt.some(TopicStreamsConfig()),
        testExtensionConfig = Opt.some(TestExtensionConfig(onNegotiated: onNegotiated)),
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let remotePeerId = nodes[0].peerInfo.peerId
    nodes[1].addObserver(
      PubSubObserver(
        onRecv: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          if peer.peerId == remotePeerId:
            for sub in msg.subscriptions:
              if sub.topic.get() == topic and sub.isSubscribe:
                subscribed.completeOnce()
      )
    )

    var received = 0
    proc handler(topic: string, data: seq[byte]) {.async.} =
      inc received

    nodes[0].subscribe(topic, handler)
    let originalGraylistThreshold = nodes[0].parameters.graylistThreshold
    # nodes[1]'s score is 0, so this graylists it
    nodes[0].parameters.graylistThreshold = 100000.0
    # the agent label stays "unknown" until identify finishes
    let ignored = currentGraylistedRpcs() + currentGraylistedRpcs("unknown")

    # Negotiate capabilities even though ordinary RPC processing is suppressed.
    await connect(nodes[0], nodes[1])
    await negotiated
    check currentGraylistedRpcs() + currentGraylistedRpcs("unknown") > ignored

    nodes[0].parameters.graylistThreshold = originalGraylistThreshold
    # The publisher needs the receiver's subscription, but has not subscribed itself.
    await subscribed
    check nodes[1].gossipsub.getOrDefault(topic).len == 1

    check:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)
      nodes[1].extensionsState.peerHasTopicStreams(nodes[0].peerInfo.peerId)

    discard await nodes[1].publish(topic, "data")

    checkUntilTimeout:
      received == 1
    nodes[1].subscribe(topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)
    check nodes[0].switch.isConnected(nodes[1].switch)

  asyncTest "a message on an open topic stream still reaches the topic handler after GossipSub stops":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let firstMessage = "first".toBytes
    let secondMessage = "second".toBytes
    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    nodes[0].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])

    # opened from the switch to force the race with a message in flight as nodes[0] stops
    # GossipSub would close this stream within a round trip
    let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    await stream.writeLp(TopicRPCHeader(topic: topic).encode())
    await stream.writeLp(
      Message.init(nodes[1].peerInfo, firstMessage, topic, 1'u64).topicRPC().encode()
    )
    check (await handled.popFirst()) == firstMessage

    await nodes[0].stop() # the switch keeps running
    var data: byte
    # nodes[0] never writes on this stream, so reading 0 bytes means it closed its side
    check (await stream.readOnce(addr data, 1)) == 0

    # TODO: iftech/nim-libp2p#3404
    await stream.writeLp(
      Message.init(nodes[1].peerInfo, secondMessage, topic, 2'u64).topicRPC().encode()
    )
    check (await handled.popFirst()) == secondMessage

  asyncTest "peer that denied support is disconnected when it opens a topic stream":
    let nodes = (
      generateNodes(
        1, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      ) & generateNodes(1, gossip = true)
    ).toGossipSub()
    startAndDeferStop(nodes)

    # nodes[1] has no topic streams, so its first control RPC denies support
    nodes[1].subscribe(topic, voidTopicHandler)
    # nodes[1] connects, so identify finishes before the dial below, which then does not race nodes[0]'s reset
    await connect(nodes[1], nodes[0])
    waitSubscribe(nodes[0], nodes[1], topic)

    # nodes[0] rejects the stream before reading a header
    let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    checkUntilTimeout:
      not nodes[0].switch.isConnected(nodes[1].switch)

  asyncTest "peer that writes on a topic stream the node opened is disconnected":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let received = newFuture[void]("messageReceived")
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      received.completeOnce()

    nodes[1].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    waitSubscribe(nodes[0], nodes[1], topic)

    discard await nodes[0].publish(topic, "data")
    await received
    # nodes[1]'s end of the topic stream that nodes[0] opened to deliver the message
    let stream = nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId)[0]
    await stream.write(@[1.byte])
    checkUntilTimeout:
      not nodes[0].switch.isConnected(nodes[1].switch)

  asyncTest "peer whose topic stream header or frame exceeds a byte limit gets 0.1 behaviour penalty":
    const maxMessageSize = 1024
    let header = TopicRPCHeader(topic: topic).encode()
    proc checkPenalty(
        topicStreamsConfig: TopicStreamsConfig, writes: seq[seq[byte]]
    ) {.async.} =
      let nodes = generateNodes(
          2,
          gossip = true,
          maxMessageSize = maxMessageSize,
          decayInterval = 1.hours, # the scoring heartbeat decays the behaviour penalty
          topicStreamsConfig = Opt.some(topicStreamsConfig),
        )
        .toGossipSub()
      startAndDeferStop(nodes)

      await connect(nodes[0], nodes[1])
      let peer = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
      check peer.behaviourPenalty == 0.0

      let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
      defer:
        await stream.close()
      for data in writes:
        await stream.writeLp(data)
      var data: byte
      check:
        # nodes[0] ends the stream right after it penalizes nodes[1]
        (await stream.readOnce(addr data, 1)) == 0
        # TODO: iftech/nim-libp2p#3307
        peer.behaviourPenalty == 0.1

    for (topicStreamsConfig, writes) in [
      # header over maxIncomingBytes
      (TopicStreamsConfig(maxIncomingBytes: header.len - 1), @[header]),
      # frame over maxMessageSize
      (TopicStreamsConfig(), @[header, newSeq[byte](maxMessageSize + 1)]),
    ]:
      await checkPenalty(topicStreamsConfig, writes)
