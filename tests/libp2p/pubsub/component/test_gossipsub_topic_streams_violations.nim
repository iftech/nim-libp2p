# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/ratelimit, tables, stew/byteutils, sequtils
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, pubsubpeer, rpc/message]
import ../../../tools/[lifecycle, protobuf, switch_builder, sync, unittest]
import ../../../../libp2p/protocols/pubsub/rpc/protobuf
import ../../../../libp2p/protocols/pubsub/gossipsub/extensions
import ../../../../libp2p/utils/future
import ../utils
import ../extensions/extension_recording

suite "GossipSub Component - Topic streams violations and penalties":
  const topic = "foobar"

  teardown:
    checkTrackers()

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
    # the peer runs no GossipSub, so it sends no ControlExtensions until the test writes one
    let peer = makeStandardSwitch()
    let controlOpened = newFuture[void]("controlStreamOpened")
    let controlProtocol = LPProtocol(codecs: @[GossipSubCodec_13])
    controlProtocol.handler = proc(
        stream: Stream, proto: ProtoCodec
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
    let topicStream = await peer.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await topicStream.close()
    await topicStream.writeLp(TopicRPCHeader(topic: topic).encode())
    await topicStream.writeLp(
      Message.init(peer.peerInfo, msg, topic, 1'u64).topicRPC().encode()
    )
    check (await handled.popFirst()) == msg

    let controlStream = await peer.dial(nodes[0].switch, GossipSubCodec_13)
    defer:
      await controlStream.close()
    # testExtension makes nodes[0] report the negotiation through onNegotiated
    await controlStream.writeLp(
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

  asyncTest "GossipSub 1.2 peer's topic stream is delivered, then the peer is disconnected at its first RPC":
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

    let handled = newAsyncQueue[seq[byte]]()
    proc onMessage(topic: string, data: seq[byte]) {.async.} =
      await handled.put(data)

    nodes[0].subscribe(topic, onMessage)
    await connect(nodes[0], nodes[1])
    # wait for negotiation, so nodes[1]'s ControlExtensions is not counted as a graylisted RPC
    await negotiated.wait()

    let originalGraylistThreshold = nodes[0].parameters.graylistThreshold
    # nodes[1]'s score is 0, so this graylists it
    nodes[0].parameters.graylistThreshold = 100000.0
    let ignored = currentGraylistedRpcs()

    const firstMsg = "first"
    let graylistedStream =
      await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await graylistedStream.close()
    await graylistedStream.writeLp(TopicRPCHeader(topic: topic).encode())
    await graylistedStream.writeLp(
      Message.init(nodes[1].peerInfo, firstMsg, topic, 1'u64).topicRPC().encode()
    )
    # nodes[0] drops the frame before it reads the end of the stream and ends its side
    await graylistedStream.closeWrite()
    var data: byte
    check:
      (await graylistedStream.readOnce(addr data, 1)) == 0
      currentGraylistedRpcs() == ignored + 1

    nodes[0].parameters.graylistThreshold = originalGraylistThreshold
    const secondMsg = "second"
    let stream = await nodes[1].switch.dial(nodes[0].switch, TopicStreamsCodec)
    defer:
      await stream.close()
    await stream.writeLp(TopicRPCHeader(topic: topic).encode())
    await stream.writeLp(
      Message.init(nodes[1].peerInfo, secondMsg, topic, 2'u64).topicRPC().encode()
    )
    check (await handled.popFirst()) == secondMsg

  asyncTest "peer whose topic stream header or frame exceeds maximum message size gets 0.1 behaviour penalty":
    const maxMessageSize = 1024
    let header = TopicRPCHeader(topic: topic).encode()
    proc checkPenalty(writes: seq[seq[byte]]) {.async.} =
      let nodes = generateNodes(
          2,
          gossip = true,
          maxMessageSize = maxMessageSize,
          decayInterval = 1.hours, # the scoring heartbeat decays the behaviour penalty
          topicStreamsConfig = Opt.some(TopicStreamsConfig()),
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

    for writes in [
      # header over maxMessageSize
      @[newSeq[byte](maxMessageSize + 1)],
      # frame over maxMessageSize
      @[header, newSeq[byte](maxMessageSize + 1)],
    ]:
      await checkPenalty(writes)

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
