# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../../../../libp2p/[switch, protocols/waggle]
import ../../../tools/[crypto, switch_builder]

type WaggleNode* = ref object ## A switch over QUIC with a mounted Waggle.
  switch*: Switch
  waggle*: Waggle
  events*: AsyncQueue[WaggleEvent] # every event Waggle emits, in order

proc setupWaggleNode*(config = WaggleConfig()): WaggleNode =
  let events = newAsyncQueue[WaggleEvent]()
  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    try:
      events.addLastNoWait(event)
    except AsyncQueueFullError:
      raiseAssert "an unbounded queue is never full"

  let switch = makeStandardSwitch()
  let waggle =
    Waggle.new(config = config, onEvent = onEvent, rng = rng(), switch = switch)
  switch.mount(waggle)
  return WaggleNode(switch: switch, waggle: waggle, events: events)

proc setupWaggleNodes*(count: int): seq[WaggleNode] =
  var nodes: seq[WaggleNode]
  for _ in 0 ..< count:
    nodes.add(setupWaggleNode())
  return nodes

proc waitForSubscribers*(node: WaggleNode, count = 1) {.async.} =
  ## Awaits the next `count` events, each a peer's subscription to `node`.
  for _ in 0 ..< count:
    let event = await node.events.popFirst()
    doAssert event.kind == WaggleEventKind.Subscribed, $event.kind

proc connect*(dialer, target: WaggleNode) {.async.} =
  await dialer.switch.connect(target.switch)
