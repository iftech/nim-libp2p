# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    protocols/waggle,
    multistream,
    muxers/yamux/yamux,
    transports/transport,
    transports/tcptransport,
    upgrademngrs/upgrade,
  ]
import ../../tools/[unittest, crypto, multiaddress]

const topic = @[byte 0, 255, 1]

suite "Waggle wire messages":
  test "subscription uses field 1 with opaque bytes":
    let msg = TopicSubscription(topicId: topic)
    check msg.encode() == @[byte 0x0A, 3, 0, 255, 1]
    check TopicSubscription.decode(msg.encode()).get() == msg

  test "pieces use fields 2, 3 and 4":
    let msg = ObjectPieces(
      objectId: @[byte 1],
      piecesMetadata: Opt.some(@[byte 2]),
      pieces: Opt.some(@[byte 3]),
    )
    check msg.encode() == @[byte 0x12, 1, 1, 0x1A, 1, 2, 0x22, 1, 3]
    check msg.encodedSize() == msg.encode().len
    check ObjectPieces.decode(msg.encode()).get() == msg

  test "absent fields differ from present empty fields":
    let absent = ObjectPieces(objectId: @[])
    let present = ObjectPieces(
      objectId: @[],
      piecesMetadata: Opt.some(newSeq[byte]()),
      pieces: Opt.some(newSeq[byte]()),
    )
    check absent.encode() == @[byte 0x12, 0]
    check present.encode() == @[byte 0x12, 0, 0x1A, 0, 0x22, 0]
    check ObjectPieces.decode(absent.encode()).get() == absent
    check ObjectPieces.decode(present.encode()).get() == present

  test "missing required fields and truncated fields are rejected":
    check TopicSubscription.decode(@[]).isErr
    check TopicSubscription.decode(@[byte 0x0A, 2, 1]).isErr
    check ObjectPieces.decode(@[byte 0x1A, 0]).isErr
    check ObjectPieces.decode(@[byte 0x12, 1, 1, 0x22, 2, 1]).isErr

  test "unknown fields are ignored":
    let msg = ObjectPieces(objectId: @[byte 1])
    check ObjectPieces.decode(msg.encode() & @[byte 0x50, 1]).get() == msg

suite "Waggle topic streams":
  var
    listener, dialer: Transport
    listenerTask: Future[void]
    publisher, subscriber: Waggle
    streams: seq[Stream]
    tasks: seq[Future[void]]
    remotePeer, localPeer: PeerId

  proc openPair(): Future[(Stream, Stream)] {.async.} =
    let accepting = listener.accept()
    let outbound = await dialer.dial(listener.addrs[0])
    let inbound = await accepting
    inbound.peerId = remotePeer
    outbound.peerId = localPeer
    streams.add(inbound)
    streams.add(outbound)
    return (inbound, outbound)

  asyncSetup:
    listener = TcpTransport.new(upgrade = Upgrade())
    dialer = TcpTransport.new(upgrade = Upgrade())
    listenerTask = listener.start(@[TcpWildcardAddress])
    publisher = Waggle.new()
    subscriber = Waggle.new()
    streams = @[]
    tasks = @[]
    remotePeer = PeerId.random()
    localPeer = PeerId.random()

  asyncTeardown:
    await publisher.stop()
    await subscriber.stop()
    for stream in streams:
      await stream.reset()
    for task in tasks:
      await task.cancelAndWait()
    await listener.stop()
    await listenerTask
    await dialer.stop()
    checkTrackers()

  asyncTest "negotiates and delivers metadata and pieces on the subscriber stream":
    let (inbound, outbound) = await openPair()
    let ms = MultistreamSelect.new()
    ms.addHandler(publisher)
    tasks.add(ms.handle(inbound))
    let selector = MultistreamSelect.new()
    check await selector.select(outbound, WaggleCodec)
    var received: seq[ObjectPieces]
    proc onPieces(
        peer: PeerId, t: seq[byte], msg: ObjectPieces
    ) {.async: (raises: [CancelledError]).} =
      check peer == localPeer
      check t == topic
      received.add(msg)

    tasks.add(subscriber.subscribe(outbound, topic, onPieces).join())
    checkUntilTimeout:
      publisher.subscribers(topic) == @[remotePeer]
    let
      metadata = ObjectPieces(objectId: @[byte 42], piecesMetadata: Opt.some(@[byte 1]))
      piece = ObjectPieces(objectId: @[byte 42], pieces: Opt.some(newSeq[byte](256)))
    check (await publisher.send(remotePeer, topic, metadata)).get()
    check (await publisher.send(remotePeer, topic, piece)).get()
    checkUntilTimeout:
      received.len == 2
    check received == @[metadata, piece]
    await outbound.reset()
    checkUntilTimeout:
      publisher.subscribers(topic).len == 0

  asyncTest "half-closed subscribers receive pieces until disconnect":
    let (inbound, outbound) = await openPair()
    let publishing = Yamux.new(inbound)
    let receiving = Yamux.new(outbound)
    let ms = MultistreamSelect.new()
    ms.addHandler(publisher)
    var subscription: Stream
    proc handle(stream: Stream) {.async: (raises: []).} =
      subscription = stream
      try:
        await ms.handle(stream)
      except CancelledError:
        discard

    publishing.streamHandler = handle
    publishing.handler = publishing.handle()
    receiving.handler = receiving.handle()
    try:
      let stream = await receiving.newStream()
      check await MultistreamSelect.new().select(stream, WaggleCodec)
      await stream.writeLp(TopicSubscription(topicId: topic).encode())
      await stream.closeWrite()
      checkUntilTimeout:
        subscription != nil and subscription.isClosedRemotely and
          publisher.subscribers(topic) == @[remotePeer]
      check not subscription.closed
      let msg = ObjectPieces(objectId: @[byte 42], pieces: Opt.some(@[byte 1]))
      check (await publisher.send(remotePeer, topic, msg)).get()
      check ObjectPieces.decode(await stream.readLp(1024)).get() == msg
      await receiving.close()
      checkUntilTimeout:
        publisher.subscribers(topic).len == 0
    finally:
      await publishing.close()
      await receiving.close()
      await publishing.handler
      await receiving.handler

  asyncTest "topics are isolated and concurrent sends preserve frames":
    const messageCount = 20
    let received = newAsyncQueue[ObjectPieces]()
    proc onPieces(
        peer: PeerId, t: seq[byte], msg: ObjectPieces
    ) {.async: (raises: [CancelledError]).} =
      await received.addLast(msg)

    let (inbound, outbound) = await openPair()
    tasks.add(publisher.handler(inbound, WaggleCodec))
    tasks.add(subscriber.subscribe(outbound, topic, onPieces).join())
    checkUntilTimeout:
      publisher.subscribers(topic).len == 1
    check not (await publisher.send(remotePeer, @[byte 4], ObjectPieces())).get()
    check publisher.subscribers(@[byte 4]).len == 0
    var sends: seq[Future[LPResult[bool]]]
    for i in 0 ..< messageCount:
      sends.add(publisher.send(remotePeer, topic, ObjectPieces(objectId: @[byte i])))
    for sending in sends:
      check (await sending).get()
    for i in 0 ..< messageCount:
      check (await received.popFirst()).objectId == @[byte i]
