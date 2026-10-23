# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

import std/strutils
import chronos
import ../../../../tests/libp2p/protocols/waggle_utils
import
  ../../../../libp2p/[
    crypto/crypto,
    multiaddress,
    multistream,
    muxers/muxer,
    muxers/yamux/yamux,
    protocols/secure/noise,
    protocols/secure/secure,
    transports/tcptransport,
    upgrademngrs/muxedupgrade,
  ]

const Topic = @[byte 0, 255, 1]

proc managedInterop*(address: string) {.async.} =
  let random = newRng()
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

  waggle = Waggle.new(rng = random, onEvent = onEvent)
  doAssert waggle.subscribe(Topic).get()
  let ms = MultistreamSelect.new()
  ms.addHandler(waggle)
  proc newMuxer(conn: Connection): Muxer =
    Yamux.new(conn)

  let
    parts = address.rsplit("/p2p/", maxsplit = 1)
    peer = PeerId.init(parts[1]).get()
    upgrade = MuxedUpgrade.new(
      @[MuxerProvider.new(newMuxer, YamuxCodec)],
      [Secure(Noise.new(random, PrivateKey.random(Ed25519, random).get()))],
      ms,
    )
    transport = TcpTransport.new(upgrade = upgrade)
    raw = await transport.dial(MultiAddress.init(parts[0]).get())
  defer:
    await raw.close()
  let mux = await upgrade.upgrade(raw, Opt.some(peer))
  defer:
    await waggle.stop()
    await mux.close()
    await mux.handler
  doAssert waggle.addConnection(mux).get()
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
  await mux.handler
  echo "Nim reconciled complementary pieces with Rust; duplicate payload suppressed"
