# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/strutils
import chronos
import ../../../../tests/libp2p/protocols/waggle_utils
import ../../../../libp2p/builders

proc networkInterop*(address, mode: string, initial: byte = 1) {.async.} =
  let random = newRng()
  let switch = SwitchBuilder
    .new()
    .withRng(random)
    .withAddress(MultiAddress.init("/ip4/127.0.0.1/tcp/0").get())
    .withTcpTransport()
    .withYamux()
    .withNoise()
    .build()
  var have = initial
  var phase = 0.byte
  var unsubscribed = false
  var confirmed = false
  var started = false
  var fullQueues = 0
  var waggle: Waggle
  let dataTopic = @[byte 0, 255, 1]
  let controlTopic = @[byte 0, 255, 0]
  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    if event.kind == WaggleEventKind.FullQueue and mode == "pressure":
      inc fullQueues
      return
    doAssert event.kind notin {WaggleEventKind.InvalidData, WaggleEventKind.FullQueue}
    if event.kind != WaggleEventKind.Received:
      return
    let msg = event.message
    if event.topic == controlTopic:
      if mode == "pressure":
        doAssert msg.objectId.len == 2 and msg.objectId[0] == byte 'R'
        let ack = msg.objectId[1]
        doAssert msg.pieces == Opt.some(@[ack])
        if ack == 0:
          doAssert not started
          started = true
        else:
          doAssert ack == phase + 1 and ack <= 2
          phase = ack
        return
      if msg.objectId == @[byte 'R', 1]:
        doAssert mode == "topology" and msg.pieces == Opt.some(@[byte 1])
        started = true
      elif msg.objectId == @[byte 'R', 0]:
        doAssert mode == "lifecycle" and phase == 1
        doAssert msg.pieces == Opt.some(@[byte 1])
        unsubscribed = true
      else:
        doAssert mode == "topology" and msg.objectId == @[byte 'R', 255]
        doAssert have == 7 and msg.pieces == Opt.some(@[byte 7])
        confirmed = true
      return
    doAssert event.topic == dataTopic and msg.objectId == @[byte 1]
    if msg.pieces.isNone:
      return
    let pieces = msg.pieces.get()
    doAssert pieces.len == 1
    if mode == "topology":
      doAssert pieces[0] > 0 and pieces[0] <= 7
      doAssert (pieces[0] and not have) != 0
      have = have or pieces[0]
      if started:
        discard waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have))
    else:
      doAssert pieces[0] == phase + 1 and pieces[0] <= 3
      phase = pieces[0]

  waggle = Waggle.new(
    switch = switch,
    rng = random,
    onEvent = onEvent,
    maxQueued = (if mode == "pressure": 1 else: 5000),
  )
  switch.mount(waggle)
  defer:
    await switch.stop()
  doAssert waggle.subscribe(dataTopic).get()
  doAssert waggle.subscribe(controlTopic).get()
  let
    parts = address.rsplit("/p2p/", maxsplit = 1)
    peer = PeerId.init(parts[1]).get()
  await switch.start()
  for epoch in 0 .. (if mode == "lifecycle": 1 else: 0):
    await switch.connect(peer, @[MultiAddress.init(parts[0]).get()])
    try:
      while waggle.subscribers(dataTopic).len != 1 or
          waggle.subscribers(controlTopic).len != 1:
        await sleepAsync(10.milliseconds)
      if mode == "pressure":
        while not started:
          await sleepAsync(10.milliseconds)
        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: 1)).get() == 1
        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 2], have: 1)).isErr
        doAssert fullQueues == 1
        while phase != 1:
          await sleepAsync(10.milliseconds)
        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 2], have: 1)).get() == 1
        while phase != 2:
          await sleepAsync(10.milliseconds)
        doAssert await waggle.send(
          peer,
          controlTopic,
          ObjectPieces(objectId: @[byte 'N', 255], pieces: Opt.some(@[byte 2])),
        )
        while switch.isConnected(peer):
          await sleepAsync(10.milliseconds)
      elif mode == "topology":
        while not started:
          await sleepAsync(10.milliseconds)
        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have)).isOk
        while have != 7:
          await sleepAsync(10.milliseconds)
        doAssert await waggle.send(
          peer,
          controlTopic,
          ObjectPieces(objectId: @[byte 'N', initial], pieces: Opt.some(@[byte 7])),
        )
        while not confirmed:
          await sleepAsync(10.milliseconds)
        doAssert await waggle.send(
          peer,
          controlTopic,
          ObjectPieces(objectId: @[byte 'N', initial, 255], pieces: Opt.some(@[byte 7])),
        )
        while switch.isConnected(peer):
          await sleepAsync(10.milliseconds)
      elif epoch == 0:
        while phase != 1:
          await sleepAsync(10.milliseconds)
        doAssert await waggle.unsubscribe(dataTopic)
        # The pinned Rust writer observes an idle close only when it writes again.
        doAssert await waggle.send(
          peer,
          controlTopic,
          ObjectPieces(objectId: @[byte 'N', 0], pieces: Opt.some(@[byte 1])),
        )
        while not unsubscribed:
          await sleepAsync(10.milliseconds)
        doAssert waggle.subscribe(dataTopic).get()
        while phase != 2:
          await sleepAsync(10.milliseconds)
      else:
        while phase != 3:
          await sleepAsync(10.milliseconds)
        doAssert await waggle.send(
          peer,
          controlTopic,
          ObjectPieces(objectId: @[byte 'N', 255], pieces: Opt.some(@[byte 3])),
        )
        while switch.isConnected(peer):
          await sleepAsync(10.milliseconds)
    finally:
      await switch.disconnect(peer)
    while waggle.subscribers(dataTopic).len > 0 or
        waggle.subscribers(controlTopic).len > 0:
      await sleepAsync(10.milliseconds)
  echo "Nim verified ", mode, " interoperability"
