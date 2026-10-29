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

suite "Waggle integration":
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
    let received = newAsyncQueue[ObjectPieces]()
    proc onPieces(
        peer: PeerId, t: seq[byte], msg: ObjectPieces
    ) {.async: (raises: [CancelledError]).} =
      check peer == localPeer
      check t == topic
      await received.addLast(msg)

    tasks.add(subscriber.subscribe(outbound, topic, onPieces).join())
    checkUntilTimeout:
      publisher.subscribers(topic) == @[remotePeer]
    let
      metadata = ObjectPieces(objectId: @[byte 42], piecesMetadata: Opt.some(@[byte 1]))
      piece = ObjectPieces(objectId: @[byte 42], pieces: Opt.some(newSeq[byte](256)))
    check (await publisher.send(remotePeer, topic, metadata)).get()
    check (await publisher.send(remotePeer, topic, piece)).get()
    check (await received.popFirst()) == metadata
    check (await received.popFirst()) == piece
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
