# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    protocols/waggle,
    multistream,
    stream/bufferstream,
    transports/transport,
    transports/tcptransport,
    upgrademngrs/upgrade,
  ]
import ../../tools/[unittest, crypto, multiaddress, bufferstream]

const topic = @[byte 0, 255, 1]

proc ignorePieces(
    peer: PeerId, topic: seq[byte], msg: ObjectPieces
) {.async: (raises: [CancelledError]).} =
  discard

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

    tasks.add(subscriber.subscribe(outbound, topic, onPieces))
    checkUntilTimeout:
      publisher.subscribers(topic) == @[remotePeer]
    let
      metadata = ObjectPieces(objectId: @[byte 42], piecesMetadata: Opt.some(@[byte 1]))
      piece = ObjectPieces(objectId: @[byte 42], pieces: Opt.some(newSeq[byte](256)))
    check await publisher.send(remotePeer, topic, metadata)
    check await publisher.send(remotePeer, topic, piece)
    checkUntilTimeout:
      received.len == 2
    check received == @[metadata, piece]
    await outbound.reset()
    checkUntilTimeout:
      publisher.subscribers(topic).len == 0

  asyncTest "topics are isolated and concurrent sends preserve frames":
    var received: seq[ObjectPieces]
    proc onPieces(
        peer: PeerId, t: seq[byte], msg: ObjectPieces
    ) {.async: (raises: [CancelledError]).} =
      received.add(msg)

    let (inbound, outbound) = await openPair()
    tasks.add(publisher.handler(inbound, WaggleCodec))
    tasks.add(subscriber.subscribe(outbound, topic, onPieces))
    checkUntilTimeout:
      publisher.subscribers(topic).len == 1
    check not (await publisher.send(remotePeer, @[byte 4], ObjectPieces()))
    check publisher.subscribers(@[byte 4]).len == 0
    var sends: seq[Future[bool]]
    for i in 0 ..< 20:
      sends.add(publisher.send(remotePeer, topic, ObjectPieces(objectId: @[byte i])))
    for sending in sends:
      check await sending
    checkUntilTimeout:
      received.len == 20
    for i in 0 ..< 20:
      check received[i].objectId == @[byte i]

  asyncTest "duplicate subscriptions are rejected without replacing the original":
    let (firstIn, firstOut) = await openPair()
    tasks.add(publisher.handler(firstIn, WaggleCodec))
    await firstOut.writeLp(TopicSubscription(topicId: topic).encode())
    checkUntilTimeout:
      publisher.subscribers(topic).len == 1
    let (secondIn, secondOut) = await openPair()
    let duplicate = publisher.handler(secondIn, WaggleCodec)
    tasks.add(duplicate)
    await secondOut.writeLp(TopicSubscription(topicId: topic).encode())
    await duplicate
    check secondIn.closed
    check publisher.subscribers(topic) == @[remotePeer]

  asyncTest "pending handshakes count against stream limits":
    publisher = Waggle.new(maxStreams = 1)
    let (firstIn, firstOut) = await openPair()
    tasks.add(publisher.handler(firstIn, WaggleCodec))
    let (secondIn, _) = await openPair()
    await publisher.handler(secondIn, WaggleCodec)
    check secondIn.closed
    await firstOut.writeLp(TopicSubscription(topicId: topic).encode())
    checkUntilTimeout:
      publisher.subscribers(topic).len == 1

  asyncTest "per-peer limits do not reject a different peer":
    publisher = Waggle.new(maxStreamsPerPeer = 1)
    let (firstIn, _) = await openPair()
    tasks.add(publisher.handler(firstIn, WaggleCodec))
    let (secondIn, _) = await openPair()
    await publisher.handler(secondIn, WaggleCodec)
    check secondIn.closed
    let (thirdIn, thirdOut) = await openPair()
    thirdIn.peerId = PeerId.random()
    tasks.add(publisher.handler(thirdIn, WaggleCodec))
    await thirdOut.writeLp(TopicSubscription(topicId: topic).encode())
    checkUntilTimeout:
      publisher.subscribers(topic) == @[thirdIn.peerId]

  asyncTest "malformed subscription and oversized frame are rejected":
    publisher = Waggle.new(maxMessageSize = 16)
    let (firstIn, firstOut) = await openPair()
    let malformed = publisher.handler(firstIn, WaggleCodec)
    tasks.add(malformed)
    await firstOut.writeLp(@[byte 0x0A, 2, 1])
    await malformed
    check firstIn.closed
    let (secondIn, secondOut) = await openPair()
    let oversized = publisher.handler(secondIn, WaggleCodec)
    tasks.add(oversized)
    # A length alone must be rejected before allocating or waiting for the body.
    await secondOut.write(@[byte 17])
    await oversized
    check secondIn.closed

  asyncTest "oversized topics are rejected in both directions":
    publisher = Waggle.new(maxTopicSize = 1)
    subscriber = Waggle.new(maxTopicSize = 1)
    let (firstIn, firstOut) = await openPair()
    let incoming = publisher.handler(firstIn, WaggleCodec)
    tasks.add(incoming)
    await firstOut.writeLp(TopicSubscription(topicId: topic).encode())
    await incoming
    check firstIn.closed
    let (_, secondOut) = await openPair()
    expect WaggleError:
      await subscriber.subscribe(secondOut, topic, ignorePieces)
    check secondOut.closed

  asyncTest "malformed pieces fail the subscription and release the stream":
    let (inbound, outbound) = await openPair()
    let receiving = subscriber.subscribe(outbound, topic, ignorePieces)
    discard await inbound.readLp(1024)
    await inbound.writeLp(@[byte 0x22, 1, 1])
    expect WaggleError:
      await receiving
    check outbound.closed
    subscriber = Waggle.new(maxMessageSize = 8)
    let (secondIn, secondOut) = await openPair()
    let oversized = subscriber.subscribe(secondOut, topic, ignorePieces)
    discard await secondIn.readLp(1024)
    await secondIn.write(@[byte 9])
    expect MaxSizeError:
      await oversized
    check secondOut.closed

  asyncTest "outbound size checks preserve a healthy subscription":
    publisher = Waggle.new(maxMessageSize = 16)
    let (inbound, outbound) = await openPair()
    tasks.add(publisher.handler(inbound, WaggleCodec))
    tasks.add(subscriber.subscribe(outbound, topic, ignorePieces))
    checkUntilTimeout:
      publisher.subscribers(topic).len == 1
    expect WaggleError:
      discard await publisher.send(
        remotePeer, topic, ObjectPieces(objectId: newSeq[byte](17))
      )
    check not inbound.closed
    check await publisher.send(
      remotePeer, topic, ObjectPieces(objectId: newSeq[byte](14))
    )
    check await publisher.send(remotePeer, topic, ObjectPieces(objectId: @[byte 1]))

  asyncTest "cancellation and stop close owned streams":
    let (inbound, outbound) = await openPair()
    tasks.add(publisher.handler(inbound, WaggleCodec))
    let receiving = subscriber.subscribe(outbound, topic, ignorePieces)
    tasks.add(receiving)
    checkUntilTimeout:
      publisher.subscribers(topic).len == 1
    await receiving.cancelAndWait()
    check outbound.closed
    checkUntilTimeout:
      publisher.subscribers(topic).len == 0
    let (secondIn, secondOut) = await openPair()
    tasks.add(publisher.handler(secondIn, WaggleCodec))
    await publisher.stop()
    check secondIn.closed
    expect WaggleError:
      await publisher.subscribe(secondOut, topic, ignorePieces)
    check secondOut.closed
    await publisher.start()
    let (thirdIn, thirdOut) = await openPair()
    tasks.add(publisher.handler(thirdIn, WaggleCodec))
    await thirdOut.writeLp(TopicSubscription(topicId: topic).encode())
    checkUntilTimeout:
      publisher.subscribers(topic) == @[remotePeer]

suite "Waggle write lifecycle":
  teardown:
    checkTrackers()

  asyncTest "cancelling a queued send preserves the active writer":
    let gate = Future[void].Raising([CancelledError]).init()
    var writes = 0
    proc write(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      inc writes
      await gate

    let stream = TestBufferStream.new(write)
    stream.peerId = PeerId.random()
    let p = Waggle.new()
    let incoming = p.handler(stream, WaggleCodec)
    await stream.pushData(@[byte 5] & TopicSubscription(topicId: topic).encode())
    checkUntilTimeout:
      p.subscribers(topic).len == 1
    let first = p.send(stream.peerId, topic, ObjectPieces(objectId: @[byte 1]))
    checkUntilTimeout:
      writes == 1
    let second = p.send(stream.peerId, topic, ObjectPieces(objectId: @[byte 2]))
    await second.cancelAndWait()
    check not stream.closed
    gate.complete()
    check await first
    check writes == 1
    await p.stop()
    await incoming

  asyncTest "cancelling an active write resets the subscription":
    let gate = Future[void].Raising([CancelledError]).init()
    var writing = false
    proc write(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      writing = true
      await gate

    let stream = TestBufferStream.new(write)
    stream.peerId = PeerId.random()
    let p = Waggle.new()
    let incoming = p.handler(stream, WaggleCodec)
    await stream.pushData(@[byte 5] & TopicSubscription(topicId: topic).encode())
    checkUntilTimeout:
      p.subscribers(topic).len == 1
    let sending = p.send(stream.peerId, topic, ObjectPieces(objectId: @[byte 1]))
    checkUntilTimeout:
      writing
    await sending.cancelAndWait()
    check stream.closed
    await incoming
    check p.subscribers(topic).len == 0
    await p.stop()

  asyncTest "failed writes reset the subscription and propagate the error":
    proc write(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "injected write failure")

    let stream = TestBufferStream.new(write)
    stream.peerId = PeerId.random()
    let p = Waggle.new()
    let incoming = p.handler(stream, WaggleCodec)
    await stream.pushData(@[byte 5] & TopicSubscription(topicId: topic).encode())
    checkUntilTimeout:
      p.subscribers(topic).len == 1
    expect LPStreamError:
      discard await p.send(stream.peerId, topic, ObjectPieces(objectId: @[byte 1]))
    check stream.closed
    await incoming
    await p.stop()
