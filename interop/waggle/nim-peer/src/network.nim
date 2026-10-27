# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/strutils
import ./constants
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
  var confirmed = false
  var started = false
  var waggle: Waggle
  let dataTopic = @[byte 0, 255, 1]
  let controlTopic = @[byte 0, 255, 0]

  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    doAssert event.kind notin {WaggleEventKind.InvalidData, WaggleEventKind.FullQueue}
    if event.kind != WaggleEventKind.Received:
      return

    let msg = event.message
    if event.topicId == controlTopic:
      if msg.objectId == @[RustObjectPrefix, 1]:
        doAssert mode == TopologyScenario and msg.pieces == Opt.some(@[byte 1])
        started = true
      else:
        doAssert mode == TopologyScenario and msg.objectId == @[RustObjectPrefix, 255]
        doAssert have == 7 and msg.pieces == Opt.some(@[byte 7])
        confirmed = true
      return

    doAssert event.topicId == dataTopic and msg.objectId == @[byte 1]
    if msg.pieces.isNone:
      return

    let pieces = msg.pieces.get()
    doAssert pieces.len == 1

    doAssert pieces[0] > 0 and pieces[0] <= 7
    doAssert (pieces[0] and not have) != 0
    have = have or pieces[0]
    if started:
      discard waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have))

  waggle = Waggle.new(switch = switch, rng = random, onEvent = onEvent)
  switch.mount(waggle)

  defer:
    await switch.stop()

  doAssert waggle.subscribe(dataTopic).get()
  doAssert waggle.subscribe(controlTopic).get()

  let
    parts = address.rsplit("/p2p/", maxsplit = 1)
    peer = PeerId.init(parts[1]).get()

  await switch.start()

  await switch.connect(peer, @[MultiAddress.init(parts[0]).get()])
  while waggle.subscribers(dataTopic).len != 1 or
      waggle.subscribers(controlTopic).len != 1:
    await sleepAsync(10.milliseconds)
  while not started:
    await sleepAsync(10.milliseconds)

  doAssert waggle.publish(dataTopic, BitShard(id: @[byte 1], have: have)).isOk

  while have != 7:
    await sleepAsync(10.milliseconds)

  doAssert (
    await waggle.send(
      peer,
      controlTopic,
      ObjectPieces(objectId: @[NimObjectPrefix, initial], pieces: Opt.some(@[byte 7])),
    )
  ).get()

  while not confirmed:
    await sleepAsync(10.milliseconds)

  doAssert (
    await waggle.send(
      peer,
      controlTopic,
      ObjectPieces(
        objectId: @[NimObjectPrefix, initial, 255], pieces: Opt.some(@[byte 7])
      ),
    )
  ).get()

  while switch.isConnected(peer):
    await sleepAsync(10.milliseconds)
  echo "Nim verified ", mode, " interoperability"
