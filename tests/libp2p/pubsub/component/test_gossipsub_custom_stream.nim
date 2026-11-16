# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import ../../../../libp2p/stream/connection
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, peertable, pubsubpeer, rpc/messages]
import ../../../tools/[lifecycle, topology, unittest]
import ../../../../libp2p/protocols/pubsub/gossipsub/extensions
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
            destAddr: Opt[MultiAddress], destPeerId: PeerId, codec: string
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

  for withObserver in [false, true]:
    asyncTest "custom topic streams preserve routing and framing, observer=" &
      $withObserver:
      let nodes = generateNodes(
          2, gossip = true, topicStreamsConfig = Opt.some(TopicStreamsConfig())
        )
        .toGossipSub()
      var
        customStream: Stream
        opened = 0
        received: seq[string]
        requestedCodec: string

      nodes[0].customStreamCallbacks = Opt.some(
        CustomStreamCallbacks(
          customStreamCreationCB: proc(
              destAddr: Opt[MultiAddress], destPeerId: PeerId, codec: string
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
      nodes[1].subscribe(
        topic,
        proc(topic: string, data: seq[byte]) {.async.} =
          received.add(string.fromBytes(data)),
      )
      await connectStar(nodes)
      waitSubscribe(nodes[0], nodes[1], topic)
      checkUntilTimeout:
        nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)

      check (await nodes[0].publish(topic, "direct")) == 1
      checkUntilTimeout:
        received == @["direct"]
      customStream = await nodes[0].switch.dial(nodes[1].switch, TopicStreamsCodec)
      for payload in ["custom-1", "custom-2"]:
        check (
          await nodes[0].publish(
            topic,
            payload,
            publishParams = Opt.some(PublishParams(useCustomStream: true)),
          )
        ) == 1
      checkUntilTimeout:
        received == @["direct", "custom-1", "custom-2"]
      check:
        opened == 1
        requestedCodec == TopicStreamsCodec
        nodes[0].extensionsState.peerHasTopicStreams(nodes[1].peerInfo.peerId)

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
