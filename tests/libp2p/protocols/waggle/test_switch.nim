# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import ./utils
import ../../../../libp2p/switch
import ../../../tools/[unittest, lifecycle, topology, waggle_node]

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
    check (await nodes[0].events.popFirst()).kind == WaggleEventKind.Subscribed

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
    check (await nodes[0].popEvents(subscribers.len)).allIt(
      it.kind == WaggleEventKind.Subscribed
    )

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
