# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import ./[constants, common]
import chronos
import ../../../../tests/libp2p/protocols/waggle/utils
import ../../../../libp2p/builders

proc networkInterop*(address, mode: string, initial: byte = 1) {.async.} =
  let
    client = newInteropPeer(address)
    peer = client.peer
    switch = client.switch

  var have = initial
  let confirmed = Future[void].Raising([CancelledError]).init()
  let started = Future[void].Raising([CancelledError]).init()
  let reconstructed = Future[void].Raising([CancelledError]).init()
  let dataSubscribed = Future[void].Raising([CancelledError]).init()
  let controlSubscribed = Future[void].Raising([CancelledError]).init()
  var waggle: Waggle
  let dataTopic = @[byte 0, 255, 1]
  let controlTopic = @[byte 0, 255, 0]

  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
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
      if msg.objectId == @[RustObjectPrefix, 1]:
        doAssert mode == TopologyScenario and msg.pieces == Opt.some(@[byte 1])
        doAssert not started.finished
        started.complete()
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

    doAssert pieces[0] > 0 and pieces[0] <= 7
    doAssert (pieces[0] and not have) != 0
    have = have or pieces[0]
    if started.finished:
      doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have)).isOk
    if have == 7 and not reconstructed.finished:
      reconstructed.complete()

  waggle = client.mountWaggle(onEvent)

  defer:
    await client.stop()

  doAssert waggle.subscribe(dataTopic).get().added
  doAssert waggle.subscribe(controlTopic).get().added

  await switch.start()

  await client.connect()
  doAssert await dataSubscribed.withTimeout(20.seconds),
    "Timed out waiting for Rust data subscription"
  doAssert await controlSubscribed.withTimeout(20.seconds),
    "Timed out waiting for Rust control subscription"
  doAssert await started.withTimeout(20.seconds),
    "Timed out waiting for Rust topology readiness"

  doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have)).isOk

  doAssert await reconstructed.withTimeout(20.seconds),
    "Timed out waiting for all pieces"

  doAssert (
    await waggle.send(
      peer,
      controlTopic,
      ObjectPieces(objectId: @[NimObjectPrefix, initial], pieces: Opt.some(@[byte 7])),
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

  doAssert await client.disconnected.withTimeout(20.seconds),
    "Timed out waiting for Rust disconnect"
  echo "Nim verified ", mode, " interoperability"
