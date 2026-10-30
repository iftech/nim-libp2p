# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/strutils
import ./constants
import chronos
import ../../../../tests/libp2p/protocols/waggle/utils
import ../../../../libp2p/builders

proc networkInterop*(address, mode: string, initial: byte = 1) {.async.} =
  let
    parts = address.rsplit("/p2p/", maxsplit = 1)
    peer = PeerId.init(parts[1]).get()
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
  let confirmed = Future[void].Raising([CancelledError]).init()
  let started = Future[void].Raising([CancelledError]).init()
  let reconstructed = Future[void].Raising([CancelledError]).init()
  var dataSubscribed = Future[void].Raising([CancelledError]).init()
  var controlSubscribed = Future[void].Raising([CancelledError]).init()
  var disconnected = Future[void].Raising([CancelledError]).init()
  var fullQueues = 0
  var waggle: Waggle
  let dataTopic = @[byte 0, 255, 1]
  let controlTopic = @[byte 0, 255, 0]

  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    if event.kind == WaggleEventKind.FullQueue and mode == PressureScenario:
      inc fullQueues
      return

    doAssert event.kind notin {WaggleEventKind.InvalidData, WaggleEventKind.FullQueue}
    if event.kind == WaggleEventKind.Subscribed and event.peerId == peer:
      if event.topicId == dataTopic and not dataSubscribed.finished:
        dataSubscribed.complete()
      elif event.topicId == controlTopic and not controlSubscribed.finished:
        controlSubscribed.complete()
    if event.kind != WaggleEventKind.Received:
      return

    let msg = event.message
    if event.topicId == controlTopic:
      if mode == PressureScenario:
        doAssert msg.objectId.len == 2 and msg.objectId[0] == RustObjectPrefix
        let ack = msg.objectId[1]
        doAssert msg.pieces == Opt.some(@[ack])

        if ack == 0:
          doAssert not started.finished
          started.complete()
        else:
          doAssert ack == phase + 1 and ack <= 2
          phase = ack
        return

      if msg.objectId == @[RustObjectPrefix, 1]:
        doAssert mode == TopologyScenario and msg.pieces == Opt.some(@[byte 1])
        started.complete()
      elif msg.objectId == @[RustObjectPrefix, 0]:
        doAssert mode == LifecycleScenario and phase == 1
        doAssert msg.pieces == Opt.some(@[byte 1])
        unsubscribed = true
      else:
        doAssert mode == TopologyScenario and msg.objectId == @[RustObjectPrefix, 255]
        doAssert have == 7 and msg.pieces == Opt.some(@[byte 7])
        doAssert not confirmed.finished
        confirmed.complete()
      return

    doAssert event.topicId == dataTopic and msg.objectId == @[byte 1]
    if msg.pieces.isNone:
      return

    let pieces = msg.pieces.get()
    doAssert pieces.len == 1

    if mode == TopologyScenario:
      doAssert pieces[0] > 0 and pieces[0] <= 7
      doAssert (pieces[0] and not have) != 0
      have = have or pieces[0]
      if started.finished:
        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have)).isOk
      if have == 7 and not reconstructed.finished:
        reconstructed.complete()
    else:
      doAssert pieces[0] == phase + 1 and pieces[0] <= 3
      phase = pieces[0]

  waggle = Waggle.new(
    switch = switch,
    rng = random,
    onEvent = onEvent,
    config = WaggleConfig(maxQueued: (if mode == PressureScenario: 1 else: 5000)),
  )
  switch.mount(waggle)

  defer:
    await switch.stop()

  doAssert waggle.subscribe(dataTopic).get().added
  doAssert waggle.subscribe(controlTopic).get().added

  proc onPeerLeft(
      remote: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    if remote == peer and not disconnected.finished:
      disconnected.complete()

  switch.addPeerEventHandler(onPeerLeft, PeerEventKind.Left)
  defer:
    switch.removePeerEventHandler(onPeerLeft, PeerEventKind.Left)

  await switch.start()

  for epoch in 0 .. (if mode == LifecycleScenario: 1 else: 0):
    if epoch > 0:
      dataSubscribed = Future[void].Raising([CancelledError]).init()
      controlSubscribed = Future[void].Raising([CancelledError]).init()
      disconnected = Future[void].Raising([CancelledError]).init()
    await switch.connect(peer, @[MultiAddress.init(parts[0]).get()])
    try:
      doAssert await dataSubscribed.withTimeout(20.seconds),
        "Timed out waiting for Rust data subscription"
      doAssert await controlSubscribed.withTimeout(20.seconds),
        "Timed out waiting for Rust control subscription"

      if mode == PressureScenario:
        doAssert await started.withTimeout(20.seconds),
          "Timed out waiting for Rust readiness"

        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: 1)).get() == 1
        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 2], have: 1)).isErr
        doAssert fullQueues == 1

        while phase != 1:
          await sleepAsync(10.milliseconds)

        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 2], have: 1)).get() == 1

        while phase != 2:
          await sleepAsync(10.milliseconds)

        doAssert (
          await waggle.send(
            peer,
            controlTopic,
            ObjectPieces(objectId: @[NimObjectPrefix, 255], pieces: Opt.some(@[byte 2])),
          )
        ).get()

        doAssert await disconnected.withTimeout(20.seconds),
          "Timed out waiting for Rust disconnect"
      elif mode == TopologyScenario:
        doAssert await started.withTimeout(20.seconds),
          "Timed out waiting for Rust readiness"

        doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have)).isOk

        doAssert await reconstructed.withTimeout(20.seconds),
          "Timed out waiting for all pieces"

        doAssert (
          await waggle.send(
            peer,
            controlTopic,
            ObjectPieces(
              objectId: @[NimObjectPrefix, initial], pieces: Opt.some(@[byte 7])
            ),
          )
        ).get()

        doAssert await confirmed.withTimeout(20.seconds),
          "Timed out waiting for Rust topology acknowledgement"

        doAssert (
          await waggle.send(
            peer,
            controlTopic,
            ObjectPieces(
              objectId: @[NimObjectPrefix, initial, 255], pieces: Opt.some(@[byte 7])
            ),
          )
        ).get()

        doAssert await disconnected.withTimeout(20.seconds),
          "Timed out waiting for Rust disconnect"
      elif epoch == 0:
        while phase != 1:
          await sleepAsync(10.milliseconds)

        doAssert await waggle.unsubscribe(dataTopic)

        # The pinned Rust writer observes an idle close only when it writes again.
        doAssert (
          await waggle.send(
            peer,
            controlTopic,
            ObjectPieces(objectId: @[NimObjectPrefix, 0], pieces: Opt.some(@[byte 1])),
          )
        ).get()

        while not unsubscribed:
          await sleepAsync(10.milliseconds)

        doAssert waggle.subscribe(dataTopic).get().added

        while phase != 2:
          await sleepAsync(10.milliseconds)
      else:
        while phase != 3:
          await sleepAsync(10.milliseconds)

        doAssert (
          await waggle.send(
            peer,
            controlTopic,
            ObjectPieces(objectId: @[NimObjectPrefix, 255], pieces: Opt.some(@[byte 3])),
          )
        ).get()

        doAssert await disconnected.withTimeout(20.seconds),
          "Timed out waiting for Rust disconnect"
    finally:
      await switch.disconnect(peer)

    while waggle.subscribers(dataTopic).len > 0 or
        waggle.subscribers(controlTopic).len > 0:
      await sleepAsync(10.milliseconds)

  echo "Nim verified ", mode, " interoperability"
