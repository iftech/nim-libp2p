# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/strutils
import chronos
import ../../../../tests/libp2p/protocols/waggle_utils
import ../../../../libp2p/builders

const Topic = @[byte 0, 255, 1]

proc managedInterop*(address: string) {.async.} =
  let random = newRng()
  let switch = SwitchBuilder
    .new()
    .withRng(random)
    .withAddress(MultiAddress.init("/ip4/127.0.0.1/tcp/0").get())
    .withTcpTransport()
    .withYamux()
    .withNoise()
    .build()
  var have = 1.byte
  var deliveries = 0
  var waggle: Waggle
  let confirmed = Future[void].Raising([CancelledError]).init()
  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    doAssert event.kind != WaggleEventKind.InvalidData
    doAssert event.kind != WaggleEventKind.FullQueue
    if event.kind != WaggleEventKind.Received:
      return
    doAssert event.topic == Topic
    if event.message.objectId == @[byte 'R', 255]:
      doAssert have == 3 and deliveries == 1
      doAssert event.message.piecesMetadata == Opt.some(@[byte 3])
      doAssert event.message.pieces == Opt.some(@[byte 3])
      doAssert not confirmed.finished
      confirmed.complete()
    else:
      doAssert event.message.objectId == @[byte 1]
      if event.message.pieces.isSome:
        let pieces = event.message.pieces.get()
        doAssert pieces == @[byte 2]
        inc deliveries
        have = have or pieces[0]
        discard waggle.publish(Topic, BitShard(id: @[byte 1], have: have))

  waggle = Waggle.new(switch = switch, rng = random, onEvent = onEvent)
  switch.mount(waggle)
  defer:
    await switch.stop()
  doAssert waggle.subscribe(Topic).get()
  let
    parts = address.rsplit("/p2p/", maxsplit = 1)
    peer = PeerId.init(parts[1]).get()
  await switch.start()
  await switch.connect(peer, @[MultiAddress.init(parts[0]).get()])
  while waggle.subscribers(Topic).len != 1:
    await sleepAsync(10.milliseconds)
  doAssert waggle.publish(Topic, BitShard(id: @[byte 1], have: have)).isOk
  await confirmed
  doAssert have == 3 and deliveries == 1
  doAssert waggle.publish(Topic, BitShard(id: @[byte 1], have: 3)).get() == 0
  doAssert await waggle.send(
    peer,
    Topic,
    ObjectPieces(
      objectId: @[byte 'N', 255],
      piecesMetadata: Opt.some(@[byte 3]),
      pieces: Opt.some(@[byte 3]),
    ),
  )
  while switch.isConnected(peer):
    await sleepAsync(10.milliseconds)
  echo "Nim reconciled complementary pieces with Rust; duplicate payload suppressed"
