# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[os, strutils, sets]
import ./constants
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

proc awaitStage(
    stage: Future[void], receiving: seq[Future[LPResult[void]]], description: string
) {.async.} =
  var pending = @[FutureBase(stage)]
  for task in receiving:
    pending.add(task)
  try:
    discard await race(pending).wait(20.seconds)
    for task in receiving:
      if task.finished:
        let outcome = task.read()
        if outcome.isErr:
          raise newException(
            IOError,
            "Subscription failed while waiting for " & description & ": " &
              $outcome.error,
          )
        raise
          newException(IOError, "Subscription closed while waiting for " & description)
    await stage
  except AsyncTimeoutError:
    raise newException(IOError, "Timed out waiting for " & description)

proc run(address: string) {.async.} =
  let subscribed = Future[void].Raising([CancelledError]).init()
  var remoteTopics: HashSet[TopicId]
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
    waggle = Waggle.new(
      switch = switch,
      rng = random,
      onEvent = proc(event: WaggleEvent) =
        if event.kind == WaggleEventKind.Subscribed and event.peerId == peer and
            event.topicId in [topic(0), topic(1)]:
          remoteTopics.incl(event.topicId)
          if remoteTopics.len == 2 and not subscribed.finished:
            subscribed.complete()
      ,
    )
  switch.mount(waggle)
  var receiving: seq[Future[LPResult[void]]]
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
  await awaitStage(subscribed, receiving, "Rust subscriptions to both topics")
  for index in 0.byte .. 1.byte:
    for kind in FixtureKinds:
      doAssert (
        await waggle.send(peer, topic(index), fixture(index, kind, fromRust = false))
      ).get()
  await awaitStage(confirmed, receiving, "Rust acknowledgement")
  doAssert (
    await waggle.send(
      peer,
      topic(0),
      ObjectPieces(objectId: @[NimObjectPrefix, 255], pieces: Opt.some(@[byte 1])),
    )
  ).get()
  # The Rust peer exits only after validating our final acknowledgement.
  await awaitStage(disconnected, @[], "Rust disconnect after the final acknowledgement")
  echo "Nim verified 6 Rust messages across 2 topics and Rust's acknowledgement"

when isMainModule:
  if paramCount() != 1 or "/p2p/" notin paramStr(1):
    quit("usage: peer <multiaddress/p2p/peer-id>", 1)
  waitFor run(paramStr(1)).wait(60.seconds)
