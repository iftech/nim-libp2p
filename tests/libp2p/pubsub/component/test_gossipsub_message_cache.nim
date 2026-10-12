# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils], stew/byteutils
import
  ../../../../libp2p/protocols/pubsub/
    [gossipsub, mcache, peertable, floodsub, pubsubpeer, rpc/messages, rpc/message]
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

suite "GossipSub Component - Message Cache":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "Message cache history shifts on heartbeat and is cleared on shift":
    const
      numberOfNodes = 2
      historyGossip = 3 # mcache window
      historyLength = 5
    let nodes = generateNodes(
        numberOfNodes,
        gossip = true,
        historyGossip = historyGossip,
        historyLength = historyLength,
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # When Node0 publishes a message to the topic
    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 1

    # Then Node1 receives the message and saves it in the cache 
    checkUntilTimeout:
      nodes[1].mcache.window(topic).len == 1

    let messageId = nodes[1].mcache.window(topic).toSeq()[0]

    # When heartbeat happens, circular history shifts to the next position
    # Then history is cleared when the position with the message is reached again
    # And message is removed
    checkUntilTimeout:
      nodes[1].mcache.window(topic).len == 0
      not nodes[1].mcache.contains(messageId)

  asyncTest "IHave propagation capped by history window":
    # 3 Nodes, Node 0 <==> Node 1 and Node 0 <==> Node 2
    # due to DValues: 1 peer in mesh and 1 peer only in gossip of Node 0
    const
      numberOfNodes = 3
      historyGossip = 3 # mcache window
      historyLength = 5
    let nodes = generateNodes(
        numberOfNodes,
        gossip = true,
        historyGossip = historyGossip,
        historyLength = historyLength,
        dValues = Opt.some(
          DValues(
            dLow: Opt.some(1), dHigh: Opt.some(1), d: Opt.some(1), dOut: Opt.some(0)
          )
        ),
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    await connectHub(nodes[0], nodes[1 .. ^1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # Add observer to NodeOutsideMesh for received IHave messages
    var (receivedIHaves, checkForIHaves) = createCheckForIHave()
    let peerOutsideMesh =
      nodes[0].gossipsub[topic].toSeq().filterIt(it notin nodes[0].mesh[topic])[0]
    let nodeOutsideMesh = nodes.getNodeByPeerId(peerOutsideMesh.peerId)
    nodeOutsideMesh.addOnRecvObserver(checkForIHaves)

    # When NodeInsideMesh sends a messages to the topic
    let peerInsideMesh = nodes[0].mesh[topic].toSeq()[0]
    let nodeInsideMesh = nodes.getNodeByPeerId(peerInsideMesh.peerId)
    tryPublish await nodeInsideMesh.publish(topic, newSeq[byte](1000)), 1

    # On each heartbeat, Node0 retrieves messages in its mcache and sends IHave to NodeOutsideMesh
    # On heartbeat, Node0 mcache advances to the next position (rotating the message cache window)
    # Node0 will gossip about messages from the last few positions, depending on the mcache window size (historyGossip)
    # By waiting more than 'historyGossip' (2x3 = 6) heartbeats, we ensure Node0 does not send IHave messages for messages older than the window size

    # Then nodeInsideMesh receives 3 (historyGossip) IHave messages
    checkUntilTimeout:
      receivedIHaves[].len == historyGossip

  asyncTest "Message is retrieved from cache when handling IWant and relayed to a peer outside the mesh":
    # 3 Nodes, Node 0 <==> Node 1 and Node 0 <==> Node 2
    # due to DValues: 1 peer in mesh and 1 peer only in gossip of Node 0
    const numberOfNodes = 3
    let nodes = generateNodes(
        numberOfNodes,
        gossip = true,
        dValues = Opt.some(
          DValues(
            dLow: Opt.some(1), dHigh: Opt.some(1), d: Opt.some(1), dOut: Opt.some(0)
          )
        ),
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    await connectHub(nodes[0], nodes[1 .. ^1])

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeHub(nodes[0], nodes[1 .. ^1], topic)

    # Add observer to Node0 for received IWant messages
    var (receivedIWantsNode0, checkForIWant) = createCheckForIWant()
    nodes[0].addOnRecvObserver(checkForIWant)

    # Find Peer outside of mesh to which Node 0 will relay received message
    let peerOutsideMesh =
      nodes[0].gossipsub[topic].toSeq().filterIt(it notin nodes[0].mesh[topic])[0]
    let nodeOutsideMesh = nodes.getNodeByPeerId(peerOutsideMesh.peerId)

    # Add observer to NodeOutsideMesh for received messages
    var (receivedMessagesNodeOutsideMesh, checkForMessage) = createCheckForMessages()
    nodeOutsideMesh.addOnRecvObserver(checkForMessage)

    # When NodeInsideMesh publishes a message to the topic
    let peerInsideMesh = nodes[0].mesh[topic].toSeq()[0]
    let nodeInsideMesh = nodes.getNodeByPeerId(peerInsideMesh.peerId)
    tryPublish await nodeInsideMesh.publish(topic, "Hello!".toBytes()), 1

    # Then Node0 receives the message from NodeInsideMesh and saves it in its cache
    checkUntilTimeout:
      nodes[0].mcache.window(topic).len == 1
    let messageId = nodes[0].mcache.window(topic).toSeq()[0]

    # When Node0 sends an IHave message to NodeOutsideMesh during a heartbeat.
    # (Happening in the background...)

    # Then NodeOutsideMesh responds with an IWant message to Node0
    checkUntilTimeout:
      receivedIWantsNode0[].anyIt(messageId in it.messageIDs)

    # When Node0 handles the IWant message, it retrieves the message from its message cache using the MessageId
    # Then Node0 relays the original message to NodeOutsideMesh
    checkUntilTimeout:
      block:
        let messages = receivedMessagesNodeOutsideMesh[].mapIt(
          nodeOutsideMesh.msgIdProvider(it).value()
        )
        messageId in messages

  asyncTest "Received messages enter mcache and both peers record them as seen":
    const numberOfNodes = 2
    let nodes = generateNodes(numberOfNodes, gossip = true).toGossipSub()

    startAndDeferStop(nodes)

    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # When Node0 publishes a message to the topic
    tryPublish await nodes[0].publish(topic, "Hello!".toBytes()), 1

    # Then Node1 receives the message 
    # Get messageId from mcache 
    checkUntilTimeout:
      nodes[1].mcache.window(topic).len == 1

    let messageId = nodes[1].mcache.window(topic).toSeq()[0]

    # And both nodes save it in their seen cache
    # Node0 when publish, Node1 when received
    check:
      nodes[0].hasSeen(nodes[0].salt(messageId))
      nodes[1].hasSeen(nodes[1].salt(messageId))

  asyncTest "Received messages are dropped if they are already in seen cache":
    # 3 Nodes, Node 0 <==> Node 1 and Node 2 not connected and not subscribed yet
    const numberOfNodes = 3
    let nodes = generateNodes(
        numberOfNodes,
        gossip = true,
        heartbeatInterval = 300.milliseconds,
          # Becasue default heartbeat interval in tests is small (60ms) and very close to `checkUntilTimeout` 
          # check interval (50ms). It can happen that two heartbeats happen before asserting.
          # To prevent this from happening, `heartbeatInterval` interval is increased here to ensure that only
          # one heartbeat interval is happening before assertion.
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    await connect(nodes[0], nodes[1])
    nodes[0].subscribe(topic, voidTopicHandler)
    nodes[1].subscribe(topic, voidTopicHandler)
    waitSubscribe(nodes[0], nodes[1], topic)
    waitSubscribe(nodes[1], nodes[0], topic)

    # When Node0 publishes two messages to the topic
    tryPublish await nodes[0].publish(topic, "Hello".toBytes()), 1
    tryPublish await nodes[0].publish(topic, "World".toBytes()), 1

    # Then Node1 receives the messages
    # Getting messageIds from mcache 
    checkUntilTimeout:
      nodes[1].mcache.window(topic).len == 2

    let messageId1 = nodes[1].mcache.window(topic).toSeq()[0]
    let messageId2 = nodes[1].mcache.window(topic).toSeq()[1]

    # And Node0 doesn't receive messages
    check:
      nodes[2].mcache.window(topic).len == 0

    # When Node2 connects with Node0 and subscribes to the topic
    await connect(nodes[0], nodes[2])
    nodes[2].subscribe(topic, voidTopicHandler)
    waitSubscribe(nodes[0], nodes[2], topic)
    waitSubscribe(nodes[2], nodes[0], topic)

    # And messageIds are added to node0PeerNode2 sentIHaves to allow processing IWant
    let node0PeerNode2 = nodes[0].getPeerByPeerId(topic, nodes[2].peerInfo.peerId)
    node0PeerNode2.sentIHaves[0].incl(messageId1)
    node0PeerNode2.sentIHaves[0].incl(messageId2)

    # And messageId1 is added to seen messages cache of Node2
    check:
      not nodes[2].addSeen(nodes[2].salt(messageId1))
      not nodes[2].hasSeen(nodes[2].salt(messageId2))

    # And Node2 sends IWant to Node0 requesting both messages
    nodes[2].broadcastResponse(
      @[nodes[2].getPeerByPeerId(topic, nodes[0].peerInfo.peerId)],
      RPCMsg.withControl(ControlMessage.withIWant(@[messageId1, messageId2])),
      MessagePriority.High,
    )

    # Then Node2 receives only messageId2 and messageId1 is dropped
    checkUntilTimeout:
      nodes[2].mcache.window(topic).toSeq() == @[messageId2]

  asyncTest "Published messages are dropped if they are already in seen cache":
    func customMsgIdProvider(m: Message): Result[MessageId, ValidationResult] =
      ok("fixed_message_id_string".toBytes())

    const numberOfNodes = 2
    let nodes = generateNodes(
        numberOfNodes, gossip = true, msgIdProvider = customMsgIdProvider
      )
      .toGossipSub()

    startAndDeferStop(nodes)

    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    # Given Node0 has msgId already in seen cache
    let data = "Hello".toBytes()
    let msg = Message.init(
      Opt.some(nodes[0].peerInfo),
      data,
      topic,
      Opt.some(nodes[0].msgSeqno),
      nodes[0].sign,
    )
    let msgId = nodes[0].msgIdProvider(msg)

    check:
      not nodes[0].addSeen(nodes[0].salt(msgId.value()))

    # When Node0 publishes the message to the topic
    discard await nodes[0].publish(topic, data)

    # wait some time before asserting that messages is not received
    await sleepAsync(300.milliseconds)

    # Then Node1 doesn't receive the message
    check:
      nodes[1].mcache.window(topic).len == 0
