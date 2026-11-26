# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import ./[utils, waggle_node]
import ../../../tools/[unittest, lifecycle, topology]

const topic = @[byte 1]

suite "Waggle switch integration":
  teardown:
    checkTrackers()

  asyncTest "start attaches to the switch and exchanges pieces":
    const objectId = @[byte 2]
    let nodes = setupWaggleNodes(2)
    discard nodes[1].waggle.subscribe(topic).get()
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])
    # wait for the subscription, so publish has a subscriber
    await nodes[0].waitForSubscribers()

    check nodes[0].waggle.publish(topic, BitShard(id: objectId, have: 1)).get() == 1
    let received = await nodes[1].waitForEvent(WaggleEventKind.Received)
    check:
      received.message.objectId == objectId
      received.message.pieces == Opt.some(@[byte 1])

  asyncTest "a publishFanout set with setTopicConfig limits how many subscribers a new object reaches":
    const
      firstId = @[byte 1]
      laterId = @[byte 2]
      publishFanout = 1
    let nodes = setupWaggleNodes(3)
    let subscribers = nodes[1 ..^ 1]
    startAndDeferStop(nodes)
    await connectHub(nodes[0], subscribers)
    for node in subscribers:
      discard node.waggle.subscribe(topic).get()
    # wait for both subscriptions, so publish has two subscribers to choose from
    await nodes[0].waitForSubscribers(subscribers.len)

    var config = WaggleConfig().defaultTopicConfig
    config.publishFanout = publishFanout
    check:
      nodes[0].waggle.setTopicConfig(topic, config).isOk
      nodes[0].waggle.publish(topic, BitShard(id: firstId, have: 1)).get() ==
        publishFanout
    # the later object reaches every subscriber
    config.publishFanout = subscribers.len
    check:
      nodes[0].waggle.setTopicConfig(topic, config).isOk
      nodes[0].waggle.publish(topic, BitShard(id: laterId, have: 1)).get() ==
        subscribers.len

    # a subscription delivers objects in publish order, so a subscriber whose first
    # object is the later one never received the first
    var arrivedFirst: seq[ObjectId]
    for node in subscribers:
      arrivedFirst.add((await node.events.popFirst()).message.objectId)
    check:
      arrivedFirst.countIt(it == firstId) == publishFanout
      arrivedFirst.countIt(it == laterId) == subscribers.len - publishFanout

  asyncTest "an empty snapshot published after discovery brings every piece the holder has":
    const
      objectId = @[byte 1]
      firstPiece = 0b001
      allPieces = 0b011
    let nodes = setupWaggleNodes(3)
    startAndDeferStop(nodes)
    await connectHub(nodes[0], nodes[1 ..^ 1])

    # publish stores the object only when it has a subscriber
    discard nodes[2].waggle.subscribe(topic).get()
    await nodes[0].waitForSubscribers()
    # a first publish sends the object's pieces to its subscribers, so nodes[0]
    # publishes before nodes[1] subscribes
    check nodes[0].waggle.publish(topic, BitShard(id: objectId, have: firstPiece)).get() ==
      1

    # an update skips subscribers whose state is unknown, so nodes[1] gets only metadata
    discard nodes[1].waggle.subscribe(topic).get()
    await nodes[0].waitForSubscribers()
    check nodes[0].waggle.publish(topic, BitShard(id: objectId, have: allPieces)).get() ==
      2
    # wait for the discovery metadata, so nodes[1] learns of the object before it asks
    let discovered = await nodes[1].waitForEvent(WaggleEventKind.Received)
    check:
      discovered.message.pieces.isNone
      discovered.message.piecesMetadata == Opt.some(@[byte allPieces])

    # the empty snapshot tells nodes[0] that nodes[1] needs every piece
    discard nodes[0].waggle.subscribe(topic).get()
    await nodes[1].waitForSubscribers()
    check nodes[1].waggle.publish(topic, BitShard(id: objectId, have: 0)).get() == 1
    let reply = await nodes[1].waitForEvent(WaggleEventKind.Received)
    check:
      reply.message.objectId == objectId
      reply.message.pieces == Opt.some(@[byte allPieces])

  asyncTest "pieces a subscriber already holds are not passed to its application":
    const
      heldId = @[byte 1]
      laterId = @[byte 2]
      piece = 0b001
    let nodes = setupWaggleNodes(3)
    startAndDeferStop(nodes)
    await connectChain(nodes)
    # nodes[0] does not subscribe, so it never learns which pieces nodes[1] holds
    discard nodes[1].waggle.subscribe(topic).get()
    discard nodes[2].waggle.subscribe(topic).get()
    # wait for nodes[2]'s subscription, so nodes[1] has a subscriber to publish to
    await nodes[1].waitForSubscribers()
    # wait for nodes[1]'s subscription, so nodes[0]'s publishes reach nodes[1]
    await nodes[0].waitForSubscribers()
    # nodes[1] holds the object before nodes[0] publishes it
    check nodes[1].waggle.publish(topic, BitShard(id: heldId, have: piece)).get() == 1

    # a first publish sends the object's pieces to its subscribers, so nodes[1]
    # receives a piece it already holds
    check:
      nodes[0].waggle.publish(topic, BitShard(id: heldId, have: piece)).get() == 1
      nodes[0].waggle.publish(topic, BitShard(id: laterId, have: piece)).get() == 1
    # one subscription delivers objects in publish order, so the later object arriving
    # first means the held pieces raised no event
    let received = await nodes[1].waitForEvent(WaggleEventKind.Received)
    check received.message.objectId == laterId

  asyncTest "removing a published object frees capacity for a later subscription":
    const
      publishedTopic = @[byte 2]
      objectId = @[byte 1]
      piece = 0b001
    # the published topic fills nodes[0]'s topic-state limit
    let nodes = @[setupWaggleNode(WaggleConfig(maxTopics: 1)), setupWaggleNode()]
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])
    # nodes[1] subscribes to both topics, so nodes[0] has someone to publish to
    for t in [publishedTopic, topic]:
      discard nodes[1].waggle.subscribe(t).get()
    await nodes[0].waitForSubscribers(2)
    let snapshot = BitShard(id: objectId, have: piece)
    check nodes[0].waggle.publish(publishedTopic, snapshot).get() == 1
    # wait for the delivery, so nodes[1]'s next event is nodes[0]'s subscription
    check (await nodes[1].events.popFirst()).kind == WaggleEventKind.Received
    check nodes[0].waggle.subscribe(topic).isErr
    check:
      # unsubscribe returns false for a topic nodes[0] only publishes to
      not (await nodes[0].waggle.unsubscribe(publishedTopic))
      # removing the only object makes the topic state reclaimable
      nodes[0].waggle.removeObject(publishedTopic, objectId)

    # nodes[0] subscribes to a new topic, and nodes[1] publishes on it
    check nodes[0].waggle.subscribe(topic).get().added
    await nodes[1].waitForSubscribers()
    check nodes[1].waggle.publish(topic, snapshot).get() == 1
    let received = await nodes[0].events.popFirst()
    check:
      received.kind == WaggleEventKind.Received
      received.peerId == nodes[1].switch.peerInfo.peerId
      received.topicId == topic
      received.message.objectId == objectId
      nodes[0].events.len == 0
      nodes[0].waggle.publish(topic, snapshot).isOk

  asyncTest "unsubscribe frees a topic slot":
    const
      subscribedTopic = @[byte 2]
      objectId = @[byte 1]
      piece = 0b001
    # nodes[0]'s topic-state limit holds one topic
    let nodes = @[setupWaggleNode(WaggleConfig(maxTopics: 1)), setupWaggleNode()]
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])
    # nodes[1] subscribes to both topics, so nodes[0] has someone to publish to
    for t in [subscribedTopic, topic]:
      discard nodes[1].waggle.subscribe(t).get()
    await nodes[0].waitForSubscribers(2)
    discard nodes[0].waggle.subscribe(subscribedTopic).get()

    let snapshot = BitShard(id: objectId, have: piece)
    check:
      # the publish gives subscribedTopic state, which fills the limit
      nodes[0].waggle.publish(subscribedTopic, snapshot).get() == 1
      await nodes[0].waggle.unsubscribe(subscribedTopic)
      # the limit has room for topic only once subscribedTopic's state is gone
      nodes[0].waggle.publish(topic, snapshot).get() == 1

  asyncTest "every publish of an object reports invalid data for a peer whose metadata the shard rejects":
    const
      objectId = @[byte 1]
      firstPiece = 0b001
      # BitShard tracks three pieces, so it rejects metadata naming a fourth
      fourthPiece = 0b1000
    let nodes = setupWaggleNodes(2)
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])
    # each node subscribes, so each has the other to publish to
    for node in nodes:
      discard node.waggle.subscribe(topic).get()
    for node in nodes:
      await node.waitForSubscribers()
    # nodes[1]'s snapshot holds the fourth piece, so its metadata names it
    check nodes[1].waggle.publish(topic, BitShard(id: objectId, have: fourthPiece)).get() ==
      1
    # nodes[0] holds no snapshot of the object, so it keeps the metadata unchecked
    let received = await nodes[0].waitForEvent(WaggleEventKind.Received)

    let snapshot = BitShard(id: objectId, have: firstPiece)
    # a first publish, then an unchanged republish, which retries rejected transmissions
    for _ in 0 ..< 2:
      check:
        nodes[0].waggle.publish(topic, snapshot).error ==
          "Message not sent on any connection"
        # publish emits its events before it returns
        nodes[0].events.len == 1
      let rejected = nodes[0].events.popFirstNoWait()
      check:
        rejected.kind == WaggleEventKind.InvalidData
        rejected.peerId == nodes[1].switch.peerInfo.peerId
        rejected.connectionId == received.connectionId
        rejected.topicId == topic
        rejected.message == ObjectPieces(objectId: objectId)
        rejected.reason == "invalid bit metadata"

  asyncTest "after the publisher stops and starts, an object cached before the stop is published as a new object":
    const
      objectId = @[byte 1]
      firstPiece = 0b001
      allPieces = 0b011
    let nodes = setupWaggleNodes(2)
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])
    discard nodes[1].waggle.subscribe(topic).get()
    # wait for the subscription, so publish has a subscriber
    await nodes[0].waitForSubscribers()
    # nodes[0] caches the object holding its first piece
    check nodes[0].waggle.publish(topic, BitShard(id: objectId, have: firstPiece)).get() ==
      1
    # wait for the delivery, so nodes[1]'s next event is the one the update brings
    discard await nodes[1].waitForEvent(WaggleEventKind.Received)

    check await nodes[1].waggle.unsubscribe(topic)
    await nodes[0].waggle.stop()
    # take nodes[0]'s Unsubscribed for the ended subscription off the queue, so its
    # next event is the renewed one
    discard await nodes[0].waitForEvent(WaggleEventKind.Unsubscribed)
    await nodes[0].waggle.start()
    discard nodes[1].waggle.subscribe(topic).get()
    await nodes[0].waitForSubscribers()

    # an update skips peers whose state is unknown, as nodes[1]'s is on the
    # re-registered connection, so the pieces arrive only if the object is new again
    check nodes[0].waggle.publish(topic, BitShard(id: objectId, have: allPieces)).get() ==
      1
    let received = await nodes[1].waitForEvent(WaggleEventKind.Received)
    check:
      received.message.objectId == objectId
      received.message.pieces == Opt.some(@[byte allPieces])

  asyncTest "over QUIC, after the subscriber stops and starts, its reopened subscription is refused as a duplicate":
    # TODO: iftech/nim-libp2p#3518
    let nodes = setupWaggleNodes(2)
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])
    discard nodes[0].waggle.subscribe(topic).get()
    # wait for nodes[0]'s subscription to reach nodes[1]
    await nodes[1].waitForSubscribers()

    # the restart reopens nodes[0]'s receiver on the same connection
    await nodes[0].waggle.stop()
    await nodes[0].waggle.start()
    # the stop's reset reaches nodes[1] as a remote close, which leaves the old
    # subscription open, so nodes[1] refuses the reopened one
    let refused = await nodes[1].waitForEvent(WaggleEventKind.InvalidData)
    check refused.reason == "Duplicate Waggle topic stream"

  asyncTest "peer is wrongly reported as InvalidData when own streams fill the per-peer limit":
    # TODO: iftech/nim-libp2p#3530
    let nodes =
      @[setupWaggleNode(WaggleConfig(maxStreamsPerPeer: 1)), setupWaggleNode()]
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])
    discard nodes[0].waggle.subscribe(topic).get()

    # nodes[0] refuses nodes[1]'s stream at maxStreamsPerPeer before reading its TopicSubscription
    discard nodes[1].waggle.subscribe(topic).get()
    let refused = await nodes[0].waitForEvent(WaggleEventKind.InvalidData)
    check:
      refused.peerId == nodes[1].switch.peerInfo.peerId
      refused.reason == "Waggle stream limit reached"
