# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, algorithm, stew/byteutils, sequtils, tables
import
  ../../../../libp2p/protocols/pubsub/[
    gossipsub,
    gossipsub/extensions,
    gossipsub/extension_preamble,
    pubsubpeer,
    rpc/message,
  ]
import ../../../../libp2p/utils/future
import ../../../tools/[lifecycle, unittest]
import ../extensions/my_partial_message
import ../utils

# this file tests integration of gossipsub with extensions. 
# tests here do not need to be very comprehensive, because it is enough 
# to test integration with extension and gossipsub. more detailed tests
# should be added to test files of respective extensions.

proc publishPartial(
    node: GossipSub, store: MyPartialMessageStore, topic: string, pm: MyPartialMessage
) {.async: (raises: []).} =
  # stores message so config.materializeParts can serve it, then publishes
  store.messages[pm.groupId] = pm
  await node.publishPartial(topic, pm.groupId, pm.partsMetadata())

suite "GossipSub Component - Extensions":
  teardown:
    checkTrackers()

  asyncTest "Test Extension":
    var negotiatedPeers: seq[PeerId]
    proc onNegotiated(peer: PeerId) {.gcsafe, raises: [].} =
      negotiatedPeers.add(peer)

    let
      numberOfNodes = 2
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          testExtensionConfig =
            Opt.some(TestExtensionConfig(onNegotiated: onNegotiated)),
        )
        .toGossipSub()

    startAndDeferStop(nodes)

    await connect(nodes[0], nodes[1])

    let nodesPeerIdSorted = pluckPeerId(nodes).sorted()
    checkUntilTimeout:
      block:
        let negotiatedPeersSorted = negotiatedPeers.sorted()
        negotiatedPeersSorted == nodesPeerIdSorted

  asyncTest "Extensions control is sent before subscriptions on stream open":
    # If node has pre-existing subscriptions on a dial,
    # then it sends the subscriptions control message before extensions control message on a newly opened stream,
    # which violates the protocol contract.
    const topic = "foobar"
    let
      dialerFirstMsgFut = newFuture[RPCMsg]("dialerFirstMsg")
      receiverFirstMsgFut = newFuture[RPCMsg]("receiverFirstMsg")

    proc onNegotiated(_: PeerId) {.gcsafe, raises: [].} =
      discard

    let
      numberOfNodes = 2
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          testExtensionConfig =
            Opt.some(TestExtensionConfig(onNegotiated: onNegotiated)),
        )
        .toGossipSub()

    # Observe the first outgoing message from each node to the other.
    let receiverPeerId = nodes[0].peerInfo.peerId
    let dialerPeerId = nodes[1].peerInfo.peerId

    nodes[1].addObserver(
      PubSubObserver(
        onSend: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          if peer.peerId == receiverPeerId:
            dialerFirstMsgFut.completeOnce(msg)
      )
    )
    nodes[0].addObserver(
      PubSubObserver(
        onSend: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          if peer.peerId == dialerPeerId:
            receiverFirstMsgFut.completeOnce(msg)
      )
    )

    startAndDeferStop(nodes)

    # Subscribe before connect
    nodes.subscribeAllNodes(topic, voidTopicHandler)

    await connect(nodes[1], nodes[0])

    let
      dialerFirstMsg = await dialerFirstMsgFut
      receiverFirstMsg = await receiverFirstMsgFut

    # First message must be extensions control, no subscriptions.
    check:
      # Dialer side
      dialerFirstMsg.control.isSome()
      dialerFirstMsg.control.get().extensions.isSome()
      dialerFirstMsg.subscriptions.len == 0
      # Receiver side
      receiverFirstMsg.control.isSome()
      receiverFirstMsg.control.get().extensions.isSome()
      receiverFirstMsg.subscriptions.len == 0

  asyncTest "Extensions re-negotiated after disconnect/reconnect with correct ordering":
    const topic = "foobar"

    var negotiatedPeers: seq[PeerId]
    proc onNegotiated(peer: PeerId) {.gcsafe, raises: [].} =
      negotiatedPeers.add(peer)

    let
      numberOfNodes = 2
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          testExtensionConfig =
            Opt.some(TestExtensionConfig(onNegotiated: onNegotiated)),
        )
        .toGossipSub()

    let
      peerId0 = nodes[0].peerInfo.peerId
      peerId1 = nodes[1].peerInfo.peerId

    # Track all outgoing messages per (sender, receiver) pair in send order.
    let
      outgoingMsgs0to1 = newAsyncQueue[RPCMsg]()
      outgoingMsgs1to0 = newAsyncQueue[RPCMsg]()

    # Observe all outgoing messages from both nodes.
    nodes[0].addObserver(
      PubSubObserver(
        onSend: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          discard outgoingMsgs0to1.put(msg)
      )
    )
    nodes[1].addObserver(
      PubSubObserver(
        onSend: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          discard outgoingMsgs1to0.put(msg)
      )
    )

    startAndDeferStop(nodes)

    # Subscribe before connecting — the scenario that triggers the original bug.
    nodes.subscribeAllNodes(topic, voidTopicHandler)

    # First connection
    await connect(nodes[1], nodes[0])

    # Wait for both sides to have sent first message.
    let firstMessage0to1 = await outgoingMsgs0to1.get.wait(1.seconds)
    let firstMessage1to0 = await outgoingMsgs1to0.get.wait(1.seconds)

    # Both sides: first message is extensions control, not subscriptions.
    check:
      firstMessage0to1.control.isSome()
      firstMessage0to1.control.get().extensions.isSome()
      firstMessage0to1.subscriptions.len == 0
      firstMessage1to0.control.isSome()
      firstMessage1to0.control.get().extensions.isSome()
      firstMessage1to0.subscriptions.len == 0

    # Both peers should have negotiated.
    check:
      negotiatedPeers.len == 2

    # Disconnect from both sides to ensure clean state.
    outgoingMsgs0to1.clear()
    outgoingMsgs1to0.clear()
    await nodes[1].switch.disconnect(peerId0)
    await nodes[0].switch.disconnect(peerId1)

    checkUntilTimeout:
      not nodes[1].switch.isConnected(peerId0)
      not nodes[0].switch.isConnected(peerId1)

    # Reconnect
    await connect(nodes[1], nodes[0])

    let secondMessage0to1 = await outgoingMsgs0to1.get.wait(1.seconds)
    let secondMessage1to0 = await outgoingMsgs1to0.get.wait(1.seconds)

    # Both sides: first message is extensions control, not subscriptions.
    check:
      secondMessage0to1.control.isSome()
      secondMessage0to1.control.get().extensions.isSome()
      secondMessage0to1.subscriptions.len == 0
      secondMessage1to0.control.isSome()
      secondMessage1to0.control.get().extensions.isSome()
      secondMessage1to0.subscriptions.len == 0

    # Extensions must have been re-negotiated (new callbacks fired).
    check:
      negotiatedPeers.len == 4

  asyncTest "No extensions control sent when node has no extensions configured":
    const topic = "foobar"
    var outgoingMsgs: seq[RPCMsg]

    let nodes = generateNodes(2, gossip = true).toGossipSub()

    let remotePeerId = nodes[0].peerInfo.peerId
    nodes[1].addObserver(
      PubSubObserver(
        onSend: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          if peer.peerId == remotePeerId:
            outgoingMsgs.add(msg)
      )
    )

    startAndDeferStop(nodes)
    nodes.subscribeAllNodes(topic, voidTopicHandler)
    await connect(nodes[1], nodes[0])

    # Wait for subscriptions to propagate.
    waitSubscribeStar(nodes, topic)

    # None of the sent messages should contain extensions control.
    check:
      outgoingMsgs.len >= 1

    for msg in outgoingMsgs:
      if msg.control.isSome():
        check msg.control.get().extensions.isNone()

  asyncTest "Extensions control sent exactly once per peer per connection":
    # Guard: isControlSent returns true after first send => no duplicates.
    const topic = "foobar"

    proc onNegotiated(_: PeerId) {.gcsafe, raises: [].} =
      discard

    var extControlCount: int = 0

    let nodes = generateNodes(
        2,
        gossip = true,
        testExtensionConfig = Opt.some(TestExtensionConfig(onNegotiated: onNegotiated)),
      )
      .toGossipSub()

    let remotePeerId = nodes[0].peerInfo.peerId
    nodes[1].addObserver(
      PubSubObserver(
        onSend: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          if peer.peerId == remotePeerId and msg.control.isSome():
            if msg.control.get().extensions.isSome():
              extControlCount.inc
      )
    )

    startAndDeferStop(nodes)
    nodes.subscribeAllNodes(topic, voidTopicHandler)
    await connect(nodes[1], nodes[0])

    waitSubscribeStar(nodes, topic)

    # wait some time before asserting that only one extensions control message is received
    await sleepAsync(500.milliseconds)

    check extControlCount == 1

  asyncTest "Partial Message Extension":
    const topic = "logos-partial"
    const groupId = "group-id-1".toBytes
    # nodes share one config, so they share one store; messages are keyed by groupId
    let store = MyPartialMessageStore()

    proc validateRPC(
        rpc: PartialMessageExtensionRPC
    ): LPResult[void] {.gcsafe, raises: [].} =
      checkLen(rpc.partsMetadata)
      return ok()

    var incomingRPC: Table[PeerId, seq[PartialMessageExtensionRPC]]
    proc onIncomingRPC(
        peer: PeerId, rpc: PartialMessageExtensionRPC
    ) {.gcsafe, raises: [].} =
      # peer - who sent RPC (received from)
      incomingRPC.mgetOrPut(peer, newSeq[PartialMessageExtensionRPC]()).add(rpc)

      # note: ideally this is where applications will publish partial messages on requests.
      # but for the sake of tests it is much more easier and intuitive to follow when 
      # rpc are added to table, and testing is done in procedural, like in test below.

    let
      numberOfNodes = 2
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          partialMessageExtensionConfig = Opt.some(
            PartialMessageExtensionConfig(
              unionPartsMetadata: my_partial_message.unionPartsMetadata,
              materializeParts: store.materializePartsFn(),
              validateRPC: validateRPC,
              onIncomingRPC: onIncomingRPC,
              heartbeatsTillEviction: 100,
            )
          ),
        )
        .toGossipSub()

    startAndDeferStop(nodes)

    await connect(nodes[0], nodes[1])

    # subscribe all nodes requesting partial messages and wait for subscribe
    for node in nodes:
      node.subscribe(topic, voidTopicHandler, requestsPartial = true)
    checkUntilTimeout:
      nodes.allIt(it.gossipsub.getOrDefault(topic).len == 1)

    # node 1 seeks for parts 1, 2, 3
    let node1Req = MyPartialMessage(groupID: groupId, want: @[1, 2, 3])
    await nodes[1].publishPartial(store, topic, node1Req)

    # wait for node 0 to receive request
    checkUntilTimeout:
      # to get messages received by node 0, we need to 
      # get messages that are sent by node 1.
      incomingRPC.getOrDefault(nodes[1].peerInfo.peerId, @[]).len == 1

    # assert that node 0 received exactly what node 1 sent
    check:
      incomingRPC[nodes[1].peerInfo.peerId][0] ==
        PartialMessageExtensionRPC(
          topicID: topic,
          groupID: groupId,
          partsMetadata: MyPartsMetadata.want(node1Req.want),
        )

    # then node 0 publishes data
    let pmData = MyPartialMessage(
      groupID: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    await nodes[0].publishPartial(store, topic, pmData)

    # wait for node 1 to receive partial message
    checkUntilTimeout:
      incomingRPC.getOrDefault(nodes[0].peerInfo.peerId, @[]).len == 1

    # assert that node 1 received exactly what node 0 sent
    check:
      incomingRPC[nodes[0].peerInfo.peerId][0] ==
        PartialMessageExtensionRPC(
          topicID: topic,
          groupID: groupId,
          partialMessage: "onetwothree".toBytes,
          partsMetadata: MyPartsMetadata.have(toSeq(pmData.data.keys)),
        )

  asyncTest "Partial Message Extension - fanout publisher":
    # Fanout pattern: publisher node is not subscribed to the topic but
    # pushes partial messages to peers via broadcast publish.
    const topic = "logos-partial"
    const groupId = "group-id-1".toBytes
    # nodes share one config, so they share one store; messages are keyed by groupId
    let store = MyPartialMessageStore()

    proc validateRPC(
        rpc: PartialMessageExtensionRPC
    ): LPResult[void] {.gcsafe, raises: [].} =
      checkLen(rpc.partsMetadata)
      return ok()

    let incomingRPC = newAsyncQueue[(PeerId, PartialMessageExtensionRPC)]()
    proc onIncomingRPC(
        peer: PeerId, rpc: PartialMessageExtensionRPC
    ) {.gcsafe, raises: [].} =
      discard incomingRPC.put((peer, rpc))

    let
      numberOfNodes = 2
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          partialMessageExtensionConfig = Opt.some(
            PartialMessageExtensionConfig(
              unionPartsMetadata: my_partial_message.unionPartsMetadata,
              materializeParts: store.materializePartsFn(),
              validateRPC: validateRPC,
              onIncomingRPC: onIncomingRPC,
              heartbeatsTillEviction: 100,
            )
          ),
        )
        .toGossipSub()

    startAndDeferStop(nodes)

    await connect(nodes[0], nodes[1])

    # Only node 1 subscribes (requesting partials). Node 0 does not subscribe.
    nodes[1].subscribe(topic, voidTopicHandler, requestsPartial = true)

    # Wait for node 0 to learn node 1 is subscribed to the topic with partial.
    checkUntilTimeout:
      nodes[0].gossipsub.getOrDefault(topic).len == 1

    # Node 0 publishes parts via broadcast publish.
    let pmData = MyPartialMessage(
      groupID: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    await nodes[0].publishPartial(store, topic, pmData)

    # Node 1 should receive the announcement even though node 0 never subscribed.
    # Peer has not yet expressed what it wants, so only parts metadata is sent
    # on this first publish.
    let (fromPeer, rpc) = await incomingRPC.get.wait(3.seconds)
    check:
      fromPeer == nodes[0].peerInfo.peerId
      rpc ==
        PartialMessageExtensionRPC(
          topicID: topic,
          groupID: groupId,
          partsMetadata: MyPartsMetadata.have(toSeq(pmData.data.keys)),
        )

  asyncTest "PingPong Extension":
    let
      numberOfNodes = 2
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          pingpongExtensionConfig = Opt.some(PingPongExtensionConfig()),
        )
        .toGossipSub()

    startAndDeferStop(nodes)

    await connect(nodes[0], nodes[1])

    let pingBytes = @[1'u8, 2, 3, 4, 5]
    let receivedPongFut = newFuture[seq[byte]]("wait for pong")

    # observe pong received by nodes[0] after it sends a ping
    nodes[0].addObserver(
      PubSubObserver(
        onRecv: proc(peer: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
          msg.pingpongExtension.ifValue(ppe):
            if ppe.pong.isSome:
              receivedPongFut.complete(ppe.pong.get())
      )
    )

    # send ping from nodes[0] to nodes[1]
    nodes[0].sendResponse(
      nodes[0].peers[nodes[1].peerInfo.peerId],
      RPCMsg.withPing(pingBytes),
      MessagePriority.High,
    )

    # nodes[1] should echo the ping back as a pong
    check (await receivedPongFut) == pingBytes

  asyncTest "Preamble Extension":
    const topic = "preamble-topic"

    let
      numberOfNodes = 2
      nodes = generateNodes(
          numberOfNodes,
          gossip = true,
          preambleExtensionConfig = Opt.some(PreambleExtensionConfig()),
          sendIDontWantOnPublish = true,
        )
        .toGossipSub()

    # Capture IMReceiving messages received by nodes[1] (sent by nodes[0] after processing the preamble)
    var receivedImReceiving: seq[IMReceiving]
    nodes[1].addObserver(
      PubSubObserver(
        onRecv: proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].} =
          msgs.preambleExtension.ifValue(pe):
            for ir in pe.imreceiving:
              receivedImReceiving.add(ir)
      )
    )

    startAndDeferStop(nodes)

    await connect(nodes[0], nodes[1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # publishing large message should publish preamble (nodes[0] will receive preamble as well).
    let msgLength = preambleMessageSizeThreshold + 4 # some large message length
    discard await nodes[1].publish(topic, newSeq[byte](msgLength))

    # nodes[1] should receive IMReceiving right after it broadcasted preamble.
    checkUntilTimeout:
      receivedImReceiving.len == 1
      receivedImReceiving[0].messageLength.get() == msgLength.uint32
