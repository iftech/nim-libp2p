# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/strutils
import ./constants
import chronos
import ../../../../tests/libp2p/protocols/waggle/utils
import ../../../../libp2p/builders

const Topic = @[byte 0, 255, 1]

proc managedInterop*(address: string) {.async.} =
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

  var have = 1.byte
  var deliveries = 0
  var waggle: Waggle
  let subscribed = Future[void].Raising([CancelledError]).init()
  let confirmed = Future[void].Raising([CancelledError]).init()

  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    doAssert event.kind != WaggleEventKind.InvalidData
    doAssert event.kind != WaggleEventKind.FullQueue
    if event.kind == WaggleEventKind.Subscribed:
      if event.peerId == peer and event.topicId == Topic and not subscribed.finished:
        subscribed.complete()
    if event.kind != WaggleEventKind.Received:
      return

    doAssert event.topicId == Topic
    if event.message.objectId == @[RustObjectPrefix, 255]:
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
        doAssert waggle.publish(Topic, BitShard(id: @[byte 1], have: have)).isOk

  waggle = Waggle.new(switch = switch, rng = random, onEvent = onEvent)
  switch.mount(waggle)

  defer:
    await switch.stop()

  doAssert waggle.subscribe(Topic).get().added

  let disconnected = Future[void].Raising([CancelledError]).init()
  proc onPeerLeft(
      remote: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    if remote == peer and not disconnected.finished:
      disconnected.complete()

  switch.addPeerEventHandler(onPeerLeft, PeerEventKind.Left)
  defer:
    switch.removePeerEventHandler(onPeerLeft, PeerEventKind.Left)

  await switch.start()
  await switch.connect(peer, @[MultiAddress.init(parts[0]).get()])

  doAssert await subscribed.withTimeout(20.seconds),
    "Timed out waiting for Rust subscription"

  doAssert waggle.publish(Topic, BitShard(id: @[byte 1], have: have)).isOk
  doAssert await confirmed.withTimeout(20.seconds),
    "Timed out waiting for Rust reconciliation acknowledgement"

  doAssert have == 3 and deliveries == 1
  doAssert waggle.publish(Topic, BitShard(id: @[byte 1], have: 3)).get() == 0

  doAssert (
    await waggle.send(
      peer,
      Topic,
      ObjectPieces(
        objectId: @[NimObjectPrefix, 255],
        piecesMetadata: Opt.some(@[byte 3]),
        pieces: Opt.some(@[byte 3]),
      ),
    )
  ).get()

  doAssert await disconnected.withTimeout(20.seconds),
    "Timed out waiting for Rust disconnect"

  echo "Nim reconciled complementary pieces with Rust; duplicate payload suppressed"
