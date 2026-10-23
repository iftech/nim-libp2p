# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

import std/[os, strutils, sets]
import chronos
import
  ../../../../libp2p/[
    crypto/crypto,
    multiaddress,
    peerid,
    multistream,
    muxers/muxer,
    muxers/yamux/yamux,
    protocols/secure/noise,
    protocols/secure/secure,
    protocols/waggle,
    transports/tcptransport,
    upgrademngrs/muxedupgrade,
  ]

const
  Rust = byte 'R'
  Nim = byte 'N'

proc topic(index: byte): seq[byte] =
  @[byte 0, 255, index]

proc fixture(index, kind: byte, fromRust: bool): ObjectPieces =
  result.objectId = @[if fromRust: Rust else: Nim, index, kind]
  if kind != 1 or fromRust:
    result.piecesMetadata = Opt.some(
      if kind == 2:
        newSeq[byte]()
      else:
        @[byte 0, 255, 1]
    )
  if kind != 0:
    var payload: seq[byte]
    if kind == 1:
      for i in 0 .. 255:
        payload.add(byte i)
    result.pieces = Opt.some(payload)

proc run(address: string) {.async.} =
  let
    split = address.rsplit("/p2p/", maxsplit = 1)
    peer = PeerId.init(split[1]).get()
    remoteAddr = MultiAddress.init(split[0]).get()
    random = newRng()
    key = PrivateKey.random(Ed25519, random).get()
    waggle = Waggle.new()
    ms = MultistreamSelect.new()
  ms.addHandler(waggle)
  proc newMuxer(conn: Connection): Muxer =
    Yamux.new(conn)

  let
    upgrade = MuxedUpgrade.new(
      @[MuxerProvider.new(newMuxer, YamuxCodec)], [Secure(Noise.new(random, key))], ms
    )
    transport = TcpTransport.new(upgrade = upgrade)
    raw = await transport.dial(remoteAddr)
  defer:
    await raw.close()
  let mux = await upgrade.upgrade(raw, Opt.some(peer))
  var receiving: seq[Future[void]]
  defer:
    await waggle.stop()
    for task in receiving:
      await task.cancelAndWait()
    await mux.close()
    await mux.handler

  var received: HashSet[(byte, byte)]
  let confirmed = Future[void].Raising([CancelledError]).init()
  proc onPieces(
      source: PeerId, t: seq[byte], msg: ObjectPieces
  ) {.async: (raises: [CancelledError]).} =
    doAssert source == peer
    if msg.objectId == @[Rust, 255]:
      doAssert received.len == 6
      doAssert t == topic(0)
      doAssert msg.piecesMetadata == Opt.some(newSeq[byte]())
      doAssert msg.pieces == Opt.some(@[byte 1])
      doAssert not confirmed.finished
      confirmed.complete()
    else:
      doAssert msg.objectId.len == 3 and msg.objectId[0] == Rust
      let (index, kind) = (msg.objectId[1], msg.objectId[2])
      doAssert index < 2 and kind < 3 and t == topic(index)
      doAssert msg == fixture(index, kind, fromRust = true)
      doAssert (index, kind) notin received
      received.incl((index, kind))

  for index in 0.byte .. 1.byte:
    let stream = await mux.newStream()
    doAssert await ms.select(stream, WaggleCodec)
    receiving.add(waggle.subscribe(stream, topic(index), onPieces))
  while waggle.subscribers(topic(0)).len != 1 or waggle.subscribers(topic(1)).len != 1:
    await sleepAsync(10.milliseconds)
  for index in 0.byte .. 1.byte:
    for kind in 0.byte .. 2.byte:
      doAssert await waggle.send(
        peer, topic(index), fixture(index, kind, fromRust = false)
      )
  await confirmed
  doAssert await waggle.send(
    peer, topic(0), ObjectPieces(objectId: @[Nim, 255], pieces: Opt.some(@[byte 1]))
  )
  # The Rust peer exits only after validating our final acknowledgement.
  await mux.handler
  echo "Nim verified 6 Rust messages across 2 topics and Rust's acknowledgement"

when isMainModule:
  if paramCount() != 1 or "/p2p/" notin paramStr(1):
    quit("usage: peer <multiaddress/p2p/peer-id>", 1)
  waitFor run(paramStr(1)).wait(60.seconds)
