# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/tables
import chronos, stew/byteutils
import ../../../../libp2p/stream/connection
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, pubsubpeer, rpc/messages]
import ../../../tools/[lifecycle, topology, unittest]
import ../../../../libp2p/protocols/pubsub/gossipsub/extensions
import ../../../../libp2p/protocols/pubsub/rpc/message
import ../utils

type DummyStream* = ref object of Connection
  data: seq[byte]

method write*(
    self: DummyStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  self.data.add(msg)

suite "GossipSub Component - Custom Stream Support":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "publish with useCustomStream triggers custom stream and peer selection":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    var
      dummyStream = DummyStream()
      peerSelectionCalled = false

    nodes[0].customStreamCallbacks = Opt.some(
      CustomStreamCallbacks(
        customStreamCreationCB: proc(
            destAddr: Opt[MultiAddress], destPeerId: PeerId, codec: ProtoCodec
        ): Stream =
          return dummyStream,
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
    await connectStar(nodes)

    nodes[1].subscribe(topic, voidTopicHandler)
    waitSubscribe(nodes[0], nodes[1], topic)

    tryPublish await nodes[0].publish(
      topic,
      "hello".toBytes(),
      publishParams = Opt.some(PublishParams(useCustomStream: true)),
    ), 1

    check:
      peerSelectionCalled
      dummyStream.data.len > 0

  asyncTest "custom topic streams preserve routing and framing":
    for withObserver in [false, true]:
      checkpoint("running with observer=" & $withObserver)
      let nodes = generateNodes(
          2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
        )
        .toGossipSub()
      let received = newAsyncQueue[string]()
      var
        customStream: Stream
        opened = 0
        requestedCodec: ProtoCodec

      nodes[0].customStreamCallbacks = Opt.some(
        CustomStreamCallbacks(
          customStreamCreationCB: proc(
              destAddr: Opt[MultiAddress], destPeerId: PeerId, codec: ProtoCodec
          ): Stream =
            inc opened
            requestedCodec = codec
            return customStream,
          customPeerSelectionCB: proc(
              allPeers, directPeers, meshPeers, fanoutPeers: HashSet[PubSubPeer]
          ): HashSet[PubSubPeer] =
            return allPeers,
        )
      )
      if withObserver:
        nodes[0].addObserver(
          PubSubObserver(
            onSend: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
              discard
          )
        )
      startAndDeferStop(nodes)
      proc onMessage(topic: string, data: seq[byte]) {.async.} =
        await received.put(string.fromBytes(data))

      nodes[1].subscribe(topic, onMessage)
      await connectStar(nodes)
      waitSubscribe(nodes[0], nodes[1], topic)
      checkUntilTimeout:
        nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)

      check (await nodes[0].publish(topic, "direct")) == 1
      check (await received.popFirst()) == "direct"
      customStream = await nodes[0].switch.dial(nodes[1].switch, TopicStreamsCodec)
      for payload in ["custom-1", "custom-2"]:
        check (
          await nodes[0].publish(
            topic,
            payload,
            publishParams = Opt.some(PublishParams(useCustomStream: true)),
          )
        ) == 1
      for payload in ["custom-1", "custom-2"]:
        check (await received.popFirst()) == payload
      check received.empty()
      check:
        opened == 1
        requestedCodec == TopicStreamsCodec
        nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)

  asyncTest "custom broadcast response recovers after nil stream creation":
    let nodes = generateNodes(
        2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
      )
      .toGossipSub()
    var
      customStream: Stream
      opened = 0
      received: seq[string]
    nodes[0].customStreamCallbacks = Opt.some(
      CustomStreamCallbacks(
        customStreamCreationCB: proc(
            destAddr: Opt[MultiAddress], destPeerId: PeerId, codec: ProtoCodec
        ): Stream =
          inc opened
          return customStream
      )
    )
    startAndDeferStop(nodes)
    nodes[1].subscribe(
      topic,
      proc(topic: string, data: seq[byte]) {.async.} =
        received.add(string.fromBytes(data)),
    )
    await connectStar(nodes)
    waitSubscribe(nodes[0], nodes[1], topic)
    checkUntilTimeout:
      nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)
    let peer = nodes[0].peers.getOrDefault(nodes[1].peerInfo.peerId)
    let rpc =
      RPCMsg(messages: @[Message.init(nodes[0].peerInfo, "reply", topic, 10'u64)])
    nodes[0].broadcastResponse(
      @[peer], rpc, MessagePriority.Low, useCustomStream = true
    )
    check:
      opened == 1
      received.len == 0
    customStream = await nodes[0].switch.dial(nodes[1].switch, TopicStreamsCodec)
    nodes[0].broadcastResponse(
      @[peer], rpc, MessagePriority.Low, useCustomStream = true
    )
    checkUntilTimeout:
      received == @["reply"]
    check opened == 2

  asyncTest "publish with useCustomStream triggers assertion if custom callbacks not set":
    let nodes = generateNodes(2, gossip = true).toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[1].subscribe(topic, voidTopicHandler)
    waitSubscribe(nodes[0], nodes[1], topic)

    expect AssertionDefect:
      discard await nodes[0].publish(
        topic,
        "hello".toBytes(),
        publishParams = Opt.some(PublishParams(useCustomStream: true)),
      )
