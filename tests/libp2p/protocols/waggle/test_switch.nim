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
    let received = await nodes[1].events.popFirst()
    check:
      received.kind == WaggleEventKind.Received
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
    let discovered = await nodes[1].events.popFirst()
    check:
      discovered.kind == WaggleEventKind.Received
      discovered.message.pieces.isNone
      discovered.message.piecesMetadata == Opt.some(@[byte allPieces])

    # the empty snapshot tells nodes[0] that nodes[1] needs every piece
    discard nodes[0].waggle.subscribe(topic).get()
    await nodes[1].waitForSubscribers()
    check nodes[1].waggle.publish(topic, BitShard(id: objectId, have: 0)).get() == 1
    let reply = await nodes[1].events.popFirst()
    check:
      reply.kind == WaggleEventKind.Received
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
    let received = await nodes[1].events.popFirst()
    check:
      received.kind == WaggleEventKind.Received
      received.message.objectId == laterId
