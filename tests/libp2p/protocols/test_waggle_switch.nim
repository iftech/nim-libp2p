# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./waggle_utils
import ../../../libp2p/switch
import ../../tools/[unittest, switch_builder, multiaddress]

suite "Waggle switch integration":
  teardown:
    checkTrackers()

  asyncTest "constructor attaches to the switch and exchanges pieces":
    let a = makeStandardSwitch(TcpAutoAddress)
    let b = makeStandardSwitch(TcpAutoAddress)
    var received: seq[WaggleEvent]
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.Received:
        received.add(event)

    let wa = Waggle.new(switch = a)
    let wb = Waggle.new(switch = b, onEvent = onEvent)
    a.mount(wa)
    b.mount(wb)
    let topic = @[byte 1]
    discard wa.subscribe(topic).get()
    discard wb.subscribe(topic).get()
    try:
      await a.start()
      await b.start()
      await a.connect(b.peerInfo)
      checkUntilTimeout:
        wa.subscribers(topic).len == 1 and wb.subscribers(topic).len == 1
      check wa.publish(topic, BitShard(id: @[byte 2], have: 1)).get() == 1
      checkUntilTimeout:
        received.len == 1
      check received[0].message.objectId == @[byte 2]
      check received[0].message.pieces == Opt.some(@[byte 1])
    finally:
      await a.stop()
      await b.stop()
