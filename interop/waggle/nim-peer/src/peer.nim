# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[os, strutils, sets]
import ./[constants, managed, network]
import chronos
import ../../../../libp2p/[builders, protocols/waggle]

proc topic(index: byte): seq[byte] =
  @[byte 0, 255, index]

proc fixture(index, kind: byte, fromRust: bool): ObjectPieces =
  var message = ObjectPieces(
    objectId: @[if fromRust: RustObjectPrefix else: NimObjectPrefix, index, kind]
  )
  if kind != PayloadKind or fromRust:
    message.piecesMetadata = Opt.some(
      if kind == EmptyFieldsKind:
        newSeq[byte]()
      else:
        @[byte 0, 255, 1]
    )
  if kind != MetadataOnlyKind:
    var payload: seq[byte]
    if kind == PayloadKind:
      for i in 0 .. 255:
        payload.add(byte i)
    message.pieces = Opt.some(payload)
  return message

proc run(address: string) {.async.} =
  let
    split = address.rsplit("/p2p/", maxsplit = 1)
    peer = PeerId.init(split[1]).get()
    remoteAddr = MultiAddress.init(split[0]).get()
    random = newRng()
    switch = SwitchBuilder
      .new()
      .withRng(random)
      .withAddress(MultiAddress.init("/ip4/127.0.0.1/tcp/0").get())
      .withTcpTransport()
      .withYamux()
      .withNoise()
      .build()
    waggle = Waggle.new(switch = switch, rng = random)
  switch.mount(waggle)
  var receiving: seq[Future[void]]
  defer:
    for task in receiving:
      await task.cancelAndWait()
    await switch.stop()

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
  await switch.connect(peer, @[remoteAddr])

  var received: HashSet[(byte, byte)]
  let confirmed = Future[void].Raising([CancelledError]).init()
  proc onPieces(
      source: PeerId, t: seq[byte], msg: ObjectPieces
  ) {.async: (raises: [CancelledError]).} =
    doAssert source == peer
    if msg.objectId == @[RustObjectPrefix, 255]:
      doAssert received.len == 6
      doAssert t == topic(0)
      doAssert msg.piecesMetadata == Opt.some(newSeq[byte]())
      doAssert msg.pieces == Opt.some(@[byte 1])
      doAssert not confirmed.finished
      confirmed.complete()
    else:
      doAssert msg.objectId.len == 3 and msg.objectId[0] == RustObjectPrefix
      let (index, kind) = (msg.objectId[1], msg.objectId[2])
      doAssert index < 2 and kind in FixtureKinds and t == topic(index)
      doAssert msg == fixture(index, kind, fromRust = true)
      doAssert (index, kind) notin received
      received.incl((index, kind))

  for index in 0.byte .. 1.byte:
    let stream = await switch.dial(peer, WaggleCodec)
    receiving.add(waggle.subscribe(stream, topic(index), onPieces))
  while waggle.subscribers(topic(0)).len != 1 or waggle.subscribers(topic(1)).len != 1:
    await sleepAsync(10.milliseconds)
  for index in 0.byte .. 1.byte:
    for kind in FixtureKinds:
      doAssert await waggle.send(
        peer, topic(index), fixture(index, kind, fromRust = false)
      )
  await confirmed
  doAssert await waggle.send(
    peer,
    topic(0),
    ObjectPieces(objectId: @[NimObjectPrefix, 255], pieces: Opt.some(@[byte 1])),
  )
  # The Rust peer exits only after validating our final acknowledgement.
  await disconnected
  echo "Nim verified 6 Rust messages across 2 topics and Rust's acknowledgement"

when isMainModule:
  if paramCount() notin [1, 2, 3] or "/p2p/" notin paramStr(1):
    quit(
      "usage: peer <multiaddress/p2p/peer-id> [reconcile|topology [1|4]|lifecycle|pressure]",
      1,
    )
  if paramCount() >= 2:
    if paramStr(2) == ReconcileScenario:
      waitFor managedInterop(paramStr(1)).wait(60.seconds)
    else:
      doAssert paramStr(2) in [TopologyScenario, LifecycleScenario, PressureScenario]
      let initial =
        if paramCount() == 3:
          byte(parseInt(paramStr(3)))
        else:
          1.byte
      doAssert initial in [1.byte, 4.byte]
      waitFor networkInterop(paramStr(1), paramStr(2), initial).wait(60.seconds)
  else:
    waitFor run(paramStr(1)).wait(60.seconds)
