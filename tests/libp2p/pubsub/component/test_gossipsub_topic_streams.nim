# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/ratelimit, tables, stew/byteutils, sequtils
import ../../../../libp2p/multistream
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, pubsubpeer, rpc/message]
import ../../../tools/[lifecycle, padding, switch_builder, sync, topology, unittest]
import ../../../../libp2p/protocols/pubsub/rpc/protobuf
import ../../../../libp2p/protocols/pubsub/gossipsub/extensions
import ../../../../libp2p/utils/future
import ../utils
import ../extensions/[extension_recording, my_partial_message]

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
    let negotiated = newWaitGroup(2)
    let nodes = generateNodes(
        2,
        gossip = true,
        topicStreamsConfig = Opt.some(TopicStreamsConfig()),
        testExtensionConfig = Opt.some(
          TestExtensionConfig(
            onNegotiated: proc(peer: PeerId) {.gcsafe, raises: [].} =
              negotiated.done()
          )
        ),
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
    await negotiated.wait()
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
      negotiated = newWaitGroup(2)
      subscribed = newFuture[void]("topicStreamPeerSubscribed")
    let nodes = generateNodes(
        2,
        gossip = true,
        topicStreamsConfig = Opt.some(TopicStreamsConfig()),
        testExtensionConfig = Opt.some(
          TestExtensionConfig(
            onNegotiated: proc(peer: PeerId) {.gcsafe, raises: [].} =
              negotiated.done()
          )
        ),
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
    await negotiated.wait()
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

  asyncTest "topic stream frames from a graylisted peer are dropped until its score recovers":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    nodes[0].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    # wait for negotiation, so nodes[1]'s ControlExtensions is not counted as a graylisted RPC
    checkUntilTimeout:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId) and
        nodes[1].extensionsState.peerHasTopicStreams(nodes[0].peerInfo.peerId)

    let originalGraylistThreshold = nodes[0].parameters.graylistThreshold
    # nodes[1]'s score is 0, so this graylists it
    nodes[0].parameters.graylistThreshold = 100000.0
    let ignored = currentGraylistedRpcs()

    const firstMsg = "first"
    let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    await stream.writeLp(TopicRPCHeader(topic: topic).encode())
    await stream.writeLp(
      Message.init(nodes[1].peerInfo, firstMsg, topic, 1'u64).topicRPC().encode()
    )
    checkUntilTimeout:
      currentGraylistedRpcs() > ignored

    nodes[0].parameters.graylistThreshold = originalGraylistThreshold
    const secondMsg = "second"
    await stream.writeLp(
      Message.init(nodes[1].peerInfo, secondMsg, topic, 2'u64).topicRPC().encode()
    )
    check (await handled.popFirst()) == secondMsg

  asyncTest "a message on an open topic stream is dropped after GossipSub stops":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let readerDone = newAsyncEvent()
    let protocol = nodes[0].switch.ms.lookupProtocol(TopicStreamsCodec).get()
    let handleTopicStream = protocol.handler
    protocol.handler = proc(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      await handleTopicStream(stream, proto)
      readerDone.fire()

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

    await stream.writeLp(
      Message.init(nodes[1].peerInfo, secondMessage, topic, 2'u64).topicRPC().encode()
    )
    await readerDone.wait()
    await allFutures(nodes[0].pendingTasks)
    check handled.len == 0

  asyncTest "topic stream opened after GossipSub stops ends":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    # nodes[1] connects, so identify finishes before the dial below, which then does not race nodes[0]'s reset
    await connect(nodes[1], nodes[0])
    await nodes[0].stop() # the switch keeps running

    let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    # without this header, an accepted stream would also end at the header timeout
    await stream.writeLp(TopicRPCHeader(topic: topic).encode())
    var data: byte
    # nodes[0] never writes on this stream, so reading 0 bytes means it ended its side
    check (await stream.readOnce(addr data, 1)) == 0

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

  asyncTest "peer that opens a topic stream before its control stream negotiates extensions without penalty":
    let negotiated = newFuture[void]("extensionsNegotiated")
    proc onNegotiated(peer: PeerId) {.gcsafe, raises: [].} =
      negotiated.completeOnce()

    let nodes = generateNodes(
        1,
        gossip = true,
        topicStreamsConfig = Opt.some(TopicStreamsConfig()),
        testExtensionConfig = Opt.some(TestExtensionConfig(onNegotiated: onNegotiated)),
      )
      .toGossipSub()
    # the peer runs no GossipSub; it holds nodes[0]'s control stream, the only stream nodes[0] sends its ControlExtensions on
    let peer = makeStandardSwitch()
    let controlOpened = newFuture[void]("controlStreamOpened")
    let controlProtocol = LPProtocol(codecs: @[GossipSubCodec_13])
    controlProtocol.handler = proc(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      controlOpened.completeOnce()
      await stream.join()
    peer.mount(controlProtocol)
    startAndDeferStop(nodes)
    startAndDeferStop(@[peer])

    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    nodes[0].subscribe(topic, onMessage)
    await peer.connect(nodes[0].switch)
    # a conforming peer publishes only after nodes[0]'s subscription arrives on this control stream
    await controlOpened

    const msg = "data"
    let stream = await peer.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    await stream.writeLp(TopicRPCHeader(topic: topic).encode())
    await stream.writeLp(
      Message.init(peer.peerInfo, msg, topic, 1'u64).topicRPC().encode()
    )
    check (await handled.popFirst()) == msg

    let control = await peer.dial(nodes[0].switch, GossipSubCodec_13)
    defer:
      await control.close()
    # testExtension makes nodes[0] report the negotiation through onNegotiated
    await control.writeLp(
      makeRPC(ControlExtensions(topicStreams: true, testExtension: true)).encode(false)
    )
    await negotiated
    check nodes[0].peers.getOrDefault(peer.peerInfo.peerId).behaviourPenalty == 0.0

  asyncTest "peer whose control stream runs GossipSub 1.2 is disconnected when it opens a topic stream":
    let nodes = (
      generateNodes(
        1, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      ) & generateNodes(1, gossip = true, codecs = @[GossipSubCodec_12])
    ).toGossipSub()
    startAndDeferStop(nodes)

    nodes[0].subscribe(topic, voidTopicHandler)
    # nodes[1] connects, so identify finishes before the dial below, which then does not race nodes[0]'s reset
    await connect(nodes[1], nodes[0])
    # nodes[0]'s control stream to nodes[1] is open, so nodes[0] already knows nodes[1] runs GossipSub 1.2
    waitSubscribe(nodes[1], nodes[0], topic)

    let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    checkUntilTimeout:
      not nodes[0].switch.isConnected(nodes[1].switch)

  asyncTest "peer that opens a topic stream before its GossipSub 1.2 control stream is disconnected at its first control RPC":
    let nodes = generateNodes(
        1, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    # the peer runs no GossipSub, so nodes[0] does not know the peer's control stream protocol when the topic stream arrives
    let peer = makeStandardSwitch()
    startAndDeferStop(nodes)
    startAndDeferStop(@[peer])

    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    nodes[0].subscribe(topic, onMessage)
    await peer.connect(nodes[0].switch)

    const msg = "data"
    let stream = await peer.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    await stream.writeLp(TopicRPCHeader(topic: topic).encode())
    await stream.writeLp(
      Message.init(peer.peerInfo, msg, topic, 1'u64).topicRPC().encode()
    )
    check (await handled.popFirst()) == msg

    let control = await peer.dial(nodes[0].switch, GossipSubCodec_12)
    defer:
      await control.close()
    await control.writeLp(
      RPCMsg.withSubscriptions(@[SubOpts(topic: topic, subscribe: true)]).encode(false)
    )
    checkUntilTimeout:
      not nodes[0].switch.isConnected(peer)

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

  asyncTest "peer that closes a topic stream the node opened gets the next message on a new stream":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let readerDone = newAsyncEvent()
    let protocol = nodes[1].switch.ms.lookupProtocol(TopicStreamsCodec).get()
    let handleTopicStream = protocol.handler
    protocol.handler = proc(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      await handleTopicStream(stream, proto)
      readerDone.fire()

    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    nodes[1].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    waitSubscribe(nodes[0], nodes[1], topic)

    const firstMsg = "first"
    discard await nodes[0].publish(topic, firstMsg)
    check (await handled.popFirst()) == firstMsg
    # nodes[1]'s end of the topic stream that nodes[0] opened to deliver the message
    let stream = nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId)[0]
    await stream.close() # as nodes[1]'s GossipSub does when it unsubscribes
    # nodes[1]'s reader ends once nodes[0] closes its side, so the next message needs a new stream
    await readerDone.wait()

    const secondMsg = "second"
    discard await nodes[0].publish(topic, secondMsg)
    check (await handled.popFirst()) == secondMsg

  asyncTest "topic stream the node opened ends when the node unsubscribes":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let received = newFuture[void]("messageReceived")
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      received.completeOnce()

    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    waitSubscribeStar(nodes, topic)

    discard await nodes[0].publish(topic, "data")
    await received
    # nodes[1]'s end of the topic stream that nodes[0] opened to deliver the message
    let stream = nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId)[0]
    nodes[0].unsubscribeAll(topic)
    # nodes[1] stays subscribed, so only nodes[0] can end the stream
    await stream.join()

  asyncTest "topic stream for another topic stays open when the node unsubscribes":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    const otherTopic = "other"
    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[0].subscribe(otherTopic, onMessage)
    await connect(nodes[0], nodes[1])
    waitSubscribe(nodes[1], nodes[0], otherTopic)

    const firstMsg = "first"
    discard await nodes[1].publish(otherTopic, firstMsg)
    check (await handled.popFirst()) == firstMsg
    let streams = nodes[0].inboundTopicStreams(nodes[1].peerInfo.peerId)
    nodes[0].unsubscribeAll(topic)

    const secondMsg = "second"
    discard await nodes[1].publish(otherTopic, secondMsg)
    check:
      (await handled.popFirst()) == secondMsg
      nodes[0].inboundTopicStreams(nodes[1].peerInfo.peerId) == streams

  asyncTest "topic stream the node opened ends when the peer unsubscribes without closing it":
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
    # nodes[1] announces an unsubscribe but stays subscribed, so only nodes[0] can end the stream
    nodes[1].sendSubs(
      nodes[1].peers.getOrDefault(nodes[0].peerInfo.peerId), [topic], subscribe = false
    )
    await stream.join()

  asyncTest "topic stream the node opened ends when its fanout expires":
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

    # nodes[0] is not subscribed, so it publishes through fanout
    discard await nodes[0].publish(topic, "data")
    await received
    # nodes[1]'s end of the topic stream that nodes[0] opened to deliver the message
    let stream = nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId)[0]
    nodes[0].lastFanoutPubSub[topic] = Moment.now() # expires at the next heartbeat
    await stream.join()

  asyncTest "topic stream stays open when fanout expires for a topic the node subscribed to since":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    startAndDeferStop(nodes)

    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    nodes[1].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    waitSubscribe(nodes[0], nodes[1], topic)

    const firstMsg = "first"
    discard await nodes[0].publish(topic, firstMsg)
    check (await handled.popFirst()) == firstMsg
    let streams = nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId)
    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[0].lastFanoutPubSub[topic] = Moment.now() # expires at the next heartbeat
    checkUntilTimeout:
      not nodes[0].lastFanoutPubSub.hasKey(topic)

    const secondMsg = "second"
    discard await nodes[0].publish(topic, secondMsg)
    check:
      (await handled.popFirst()) == secondMsg
      nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId) == streams

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

  asyncTest "topic stream frames are charged to the overhead rate limit":
    const budget = 1024
    let
      payload = "data".toBytes()
      frame = Message(data: payload, topic: topic).topicRPC().encode().pad(512)
    proc checkCharged(graylistThreshold: float64, charged: int) {.async.} =
      let negotiated = newWaitGroup(2)
      let nodes = generateNodes(
          2,
          gossip = true,
          topicStreamsConfig = Opt.some(TopicStreamsConfig()),
          testExtensionConfig = Opt.some(
            TestExtensionConfig(
              onNegotiated: proc(peer: PeerId) {.gcsafe, raises: [].} =
                negotiated.done()
            )
          ),
        )
        .toGossipSub()
      startAndDeferStop(nodes)

      await connect(nodes[0], nodes[1])
      # wait for negotiation, so only the frame below is charged to the bucket
      await negotiated.wait()
      nodes[0].parameters.graylistThreshold = graylistThreshold
      # never refills, so the spent budget is exactly the charge
      let bucket = TokenBucket.new(budget, ZeroDuration)
      nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId).overheadRateLimitOpt =
        Opt.some(bucket)

      let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
      defer:
        await stream.close()
      await stream.writeLp(TopicRPCHeader(topic: topic).encode())
      await stream.writeLp(frame)
      # nodes[0] charges the frame before it reads the end of the stream and ends its side
      await stream.closeWrite()
      var data: byte
      check:
        (await stream.readOnce(addr data, 1)) == 0
        bucket.getAvailableCapacity() == budget - charged

    for (graylistThreshold, charged) in [
      # below nodes[1]'s score of 0: everything except the payload
      (-10000.0, frame.len - payload.len),
      # above nodes[1]'s score of 0: the whole frame
      (100000.0, frame.len),
    ]:
      await checkCharged(graylistThreshold, charged)
