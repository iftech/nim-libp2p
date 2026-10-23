# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

{.used.}

import std/[sequtils, sets]
import chronos
import ./waggle_utils
import
  ../../../libp2p/[
    connmanager,
    stream/bufferstream,
    multistream,
    muxers/yamux/yamux,
    transports/transport,
    transports/tcptransport,
    upgrademngrs/upgrade,
  ]
import ../../tools/[unittest, crypto, multiaddress, bufferstream]

const topic = @[byte 0, 255, 1]

type Node = ref object
  peer: PeerId
  protocol: Waggle
  manager: ConnManager
  ms: MultistreamSelect
  events: seq[WaggleEvent]
  have: byte
  integrate: bool

type StalledMuxer = ref object of Muxer
  gate: AsyncEvent
  opened: int

method newStream(
    m: StalledMuxer, name: string = "", lazy: bool = false
): Future[Stream] {.async: (raises: [CancelledError, LPStreamError, MuxerError]).} =
  inc m.opened
  await m.gate.wait()
  return nil

suite "Waggle managed dissemination":
  var
    listener, dialer: Transport
    listening: Future[void]
    nodes: seq[Node]
    muxers: seq[Muxer]

  proc newNode(
      have: byte = 0, integrate = false, fanout = 50, maxQueued = 5000, managed = false
  ): Node =
    let node = Node(
      peer: PeerId.random(),
      have: have,
      integrate: integrate,
      ms: MultistreamSelect.new(),
    )
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      node.events.add(event)
      if node.integrate and event.kind == WaggleEventKind.Received and
          event.message.pieces.isSome:
        let pieces = event.message.pieces.get()
        doAssert pieces.len == 1 and pieces[0] <= 7
        let have = node.have or pieces[0]
        if have != node.have:
          node.have = have
          discard node.protocol.publish(
            event.topic, BitShard(id: event.message.objectId, have: have)
          )

    node.protocol = Waggle.new(
      onEvent = onEvent,
      rng = rng(),
      maxQueued = maxQueued,
      defaultTopicConfig = TopicConfig(publishFanout: fanout, gossipFanout: 50),
    )
    node.ms.addHandler(node.protocol)
    if managed:
      node.manager = ConnManager.new(maxConnsPerPeer = 4)
      node.protocol.attach(node.manager)
    nodes.add(node)
    node

  proc connect(a, b: Node): Future[(Muxer, Muxer)] {.async.} =
    let accepting = listener.accept()
    let outgoing = await dialer.dial(listener.addrs[0])
    let incoming = await accepting
    outgoing.peerId = b.peer
    incoming.peerId = a.peer
    let ready = newAsyncEvent()
    proc handleA(stream: Stream) {.async: (raises: []).} =
      try:
        await ready.wait()
        await a.ms.handle(stream)
      except CancelledError:
        discard
      finally:
        await stream.reset()

    proc handleB(stream: Stream) {.async: (raises: []).} =
      try:
        await ready.wait()
        await b.ms.handle(stream)
      except CancelledError:
        discard
      finally:
        await stream.reset()

    let am: Muxer = Yamux.new(outgoing)
    let bm: Muxer = Yamux.new(incoming)
    am.streamHandler = handleA
    bm.streamHandler = handleB
    am.handler = am.handle()
    bm.handler = bm.handle()
    muxers.add(am)
    muxers.add(bm)
    if a.manager != nil:
      doAssert (await a.manager.storeMuxer(am)).isOk
    else:
      doAssert a.protocol.addConnection(am).get()
    if b.manager != nil:
      doAssert (await b.manager.storeMuxer(bm)).isOk
    else:
      doAssert b.protocol.addConnection(bm).get()
    ready.fire()
    return (am, bm)

  asyncSetup:
    listener = TcpTransport.new(upgrade = Upgrade())
    dialer = TcpTransport.new(upgrade = Upgrade())
    listening = listener.start(@[TcpWildcardAddress])
    nodes = @[]
    muxers = @[]

  asyncTeardown:
    for node in nodes:
      await node.protocol.stop()
    for node in nodes:
      if node.manager != nil:
        await node.manager.stop()
    for muxer in muxers:
      await muxer.close()
      await muxer.handler
    await listener.stop()
    await listening
    await dialer.stop()
    checkTrackers()

  asyncTest "three peers reconcile complementary pieces along a chain":
    let a = newNode(1, integrate = true)
    let b = newNode(2, integrate = true)
    let c = newNode(4, integrate = true)
    for node in nodes:
      check node.protocol.subscribe(topic).get()
    discard await connect(a, b)
    discard await connect(b, c)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 2 and
        c.protocol.subscribers(topic).len == 1
    for node in nodes:
      check node.protocol.publish(topic, BitShard(id: @[byte 1], have: node.have)).isOk
    checkUntilTimeout:
      a.have == 7 and b.have == 7 and c.have == 7
    for node in nodes:
      check node.protocol.publish(topic, BitShard(id: @[byte 1], have: 7)).get() == 0
      check node.events.allIt(it.kind != WaggleEventKind.InvalidData)

  asyncTest "publish fanout limits initial recipients":
    let source = newNode(7, fanout = 1)
    let b = newNode()
    let c = newNode()
    for node in nodes:
      discard node.protocol.subscribe(topic).get()
    discard await connect(source, b)
    discard await connect(source, c)
    checkUntilTimeout:
      source.protocol.subscribers(topic).len == 2
    check source.protocol.publish(topic, BitShard(id: @[byte 1], have: 7)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) +
        c.events.countIt(it.kind == WaggleEventKind.Received) == 1

  asyncTest "queue saturation reports an event and unchanged snapshots can retry":
    let a = newNode(1, maxQueued = 1)
    let b = newNode()
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).isOk
    check a.protocol.publish(topic, BitShard(id: @[byte 2], have: 1)).isErr
    check a.events.anyIt(it.kind == WaggleEventKind.FullQueue)
    checkUntilTimeout:
      b.events.anyIt(it.kind == WaggleEventKind.Received)
    check a.protocol.publish(topic, BitShard(id: @[byte 2], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.anyIt(
        it.kind == WaggleEventKind.Received and it.message.objectId == @[byte 2]
      )

  asyncTest "subscriptions follow new connections and unsubscribe/resubscribe":
    let a = newNode(managed = true)
    let b = newNode(managed = true)
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 1
    check await b.protocol.unsubscribe(topic)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 0
    check a.events.anyIt(it.kind == WaggleEventKind.Unsubscribed)
    check b.protocol.subscribe(topic).get()
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 2
    let c = newNode(managed = true)
    discard c.protocol.subscribe(topic).get()
    discard await connect(a, c)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 2 and c.protocol.subscribers(topic).len == 1

  asyncTest "connection views are independent and reconnect clears old state":
    let a = newNode(1)
    let b = newNode()
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    let (first, _) = await connect(a, b)
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 2
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 2
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 2
    await first.close()
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 2
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 3

  asyncTest "invalid metadata is surfaced without disconnecting healthy peers":
    let a = newNode(1)
    let b = newNode(2)
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 1
    discard a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get()
    check await b.protocol.send(
      a.peer,
      topic,
      ObjectPieces(objectId: @[byte 1], piecesMetadata: Opt.some(@[byte 255])),
    )
    checkUntilTimeout:
      a.events.anyIt(it.kind == WaggleEventKind.InvalidData)
    check a.protocol.subscribers(topic).len == 1

  asyncTest "topic whitelist and configuration limits apply locally and remotely":
    let a = newNode()
    let b = newNode()
    await a.protocol.stop()
    a.protocol = Waggle.new(
      topicWhitelist = Opt.some([topic].toHashSet()),
      maxTopics = 1,
      onEvent = proc(event: WaggleEvent) {.gcsafe, raises: [].} =
        a.events.add(event),
    )
    a.ms = MultistreamSelect.new()
    a.ms.addHandler(a.protocol)
    check a.protocol.subscribe(@[byte 2]).isErr
    check a.protocol.subscribe(topic).get()
    check a.protocol.setTopicConfig(
      topic, TopicConfig(publishFanout: 0, gossipFanout: 1)
    ).isErr
    check a.protocol.setTopicConfig(
      topic, TopicConfig(publishFanout: 1, gossipFanout: 1)
    ).isOk
    check a.protocol.setTopicConfig(
      @[byte 2], TopicConfig(publishFanout: 1, gossipFanout: 1)
    ).isErr
    discard b.protocol.subscribe(@[byte 2]).get()
    discard await connect(a, b)
    checkUntilTimeout:
      b.protocol.subscribers(topic).len == 1
    check a.protocol.subscribers(@[byte 2]).len == 0

  asyncTest "stopping Waggle preserves the shared connection":
    let a = newNode(managed = true)
    let b = newNode(managed = true)
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    let (am, bm) = await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    await a.protocol.stop()
    check not am.connection.closed
    check not bm.connection.closed
    await a.protocol.start()
    # The remote explicitly renews the subscription closed by our stop.
    discard await b.protocol.unsubscribe(topic)
    discard b.protocol.subscribe(topic).get()
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 1

  asyncTest "pending outgoing opens obey stream budgets":
    proc write(
        data: sink seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      discard

    let stream = TestBufferStream.new(write)
    stream.peerId = PeerId.random()
    let alive = newAsyncEvent()
    proc keepAlive() {.async: (raises: []).} =
      await noCancel alive.wait()

    let mux =
      StalledMuxer(connection: stream, gate: newAsyncEvent(), handler: keepAlive())
    var rejected = 0
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.StreamFailed:
        inc rejected

    let p = Waggle.new(maxStreams = 2, maxStreamsPerPeer = 2, onEvent = onEvent)
    for index in 0.byte .. 9.byte:
      discard p.subscribe(@[index]).get()
    check p.addConnection(mux).get()
    checkUntilTimeout:
      mux.opened == 2
    check rejected == 8
    let incoming = TestBufferStream.new(write)
    incoming.peerId = stream.peerId
    await p.handler(incoming, WaggleCodec)
    check incoming.closed
    await p.stop()
    check not stream.closed
    alive.fire()
    await mux.handler
    await stream.close()

  asyncTest "closing a topic releases its queued connection budget":
    let a = newNode(1, maxQueued = 1)
    let b = newNode()
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    for index in 1.byte .. 3.byte:
      check a.protocol.publish(topic, BitShard(id: @[index], have: 1)).get() == 1
      discard await b.protocol.unsubscribe(topic)
      checkUntilTimeout:
        a.protocol.subscribers(topic).len == 0
      discard b.protocol.subscribe(topic).get()
      checkUntilTimeout:
        a.protocol.subscribers(topic).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 4], have: 1)).get() == 1
