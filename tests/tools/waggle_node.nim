# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../../libp2p/[switch, protocols/waggle]
import ./[crypto, switch_builder]

type WaggleNode* = ref object ## A switch over QUIC with a mounted Waggle.
  switch*: Switch
  waggle*: Waggle
  events*: AsyncQueue[WaggleEvent] # every event Waggle emits, in order

proc setupWaggleNode*(): WaggleNode =
  let events = newAsyncQueue[WaggleEvent]()
  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    try:
      events.addLastNoWait(event)
    except AsyncQueueFullError:
      raiseAssert "an unbounded queue is never full"

  let switch = makeStandardSwitch()
  let waggle = Waggle.new(onEvent = onEvent, rng = rng(), switch = switch)
  switch.mount(waggle)
  return WaggleNode(switch: switch, waggle: waggle, events: events)

proc setupWaggleNodes*(count: int): seq[WaggleNode] =
  var nodes: seq[WaggleNode]
  for _ in 0 ..< count:
    nodes.add(setupWaggleNode())
  return nodes

proc popEvents*(node: WaggleNode, count: int): Future[seq[WaggleEvent]] {.async.} =
  var events: seq[WaggleEvent]
  for _ in 0 ..< count:
    events.add(await node.events.popFirst())
  return events

proc connect*(dialer, target: WaggleNode) {.async.} =
  await dialer.switch.connect(target.switch)
