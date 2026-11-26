# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/ratelimit, tables, stew/byteutils, sequtils
import ../../../../libp2p/multistream
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, pubsubpeer, rpc/message]
import ../../../tools/[lifecycle, switch_builder, unittest]
import ../../../../libp2p/protocols/pubsub/gossipsub/extensions
import ../../../../libp2p/utils/future
import ../utils

suite "GossipSub Component - Topic streams lifecycle":
  const topic = "foobar"

  teardown:
    checkTrackers()

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
        stream: Stream, proto: ProtoCodec
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
        stream: Stream, proto: ProtoCodec
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
    check nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId).len == 0

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
    check nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId).len == 0

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
    check nodes[1].inboundTopicStreams(nodes[0].peerInfo.peerId).len == 0

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
