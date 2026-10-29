# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, sets]
import chronos
import ./utils
import
  ../../../../libp2p/[
    switch,
    multistream,
    muxers/yamux/yamux,
    transports/transport,
    transports/tcptransport,
    upgrademngrs/upgrade,
  ]
import ../../../tools/[unittest, crypto, multiaddress]

const topic = @[byte 0, 255, 1]

type Node = ref object
  peer: PeerId
  protocol: Waggle
  manager: ConnManager
  ms: MultistreamSelect
  events: seq[WaggleEvent]
  onEvent: WaggleEventHandler
  have: byte
  integrate: bool

type CountingShard = ref object of BitShard
  preparations: int

method actionFromMetadata(
    s: CountingShard, peer: PeerId, connectionId: uint64, metadata: Opt[seq[byte]]
): Result[WaggleAction, string] =
  inc s.preparations
  procCall BitShard(s).actionFromMetadata(peer, connectionId, metadata)

suite "Waggle managed dissemination":
  var
    listener, dialer: Transport
    listening: Future[void]
    nodes: seq[Node]
    muxers: seq[Muxer]

  proc newNode(
      have: byte = 0,
      integrate = false,
      fanout = 50,
      maxQueued = 5000,
      maxQueuedBytes = 4 * 1024 * 1024,
      managed = false,
      forwardFanout = 50,
      gossipFanout = 50,
      start = true,
      maxStreamsPerPeer = 16,
  ): Future[Node] {.async.} =
    let node = Node(
      peer: PeerId.random(),
      have: have,
      integrate: integrate,
      ms: MultistreamSelect.new(),
    )
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      node.events.add(event)
      if node.onEvent != nil:
        node.onEvent(event)
      if node.integrate and event.kind == WaggleEventKind.Received and
          event.message.pieces.isSome:
        let pieces = event.message.pieces.get()
        doAssert pieces.len == 1 and pieces[0] <= 7
        let have = node.have or pieces[0]
        if have != node.have:
          node.have = have
          discard node.protocol.publish(
            event.topicId, BitShard(id: event.message.objectId, have: have)
          )

    if managed:
      node.manager = ConnManager.new(maxConnsPerPeer = 4)
    node.protocol = Waggle.new(
      switch = (if managed: Switch(connManager: node.manager) else: nil),
      onEvent = onEvent,
      maxStreamsPerPeer = maxStreamsPerPeer,
      rng = rng(),
      maxQueued = maxQueued,
      maxQueuedBytes = maxQueuedBytes,
      defaultTopicConfig = TopicConfig(
        publishFanout: fanout, forwardFanout: forwardFanout, gossipFanout: gossipFanout
      ),
    )
    node.ms.addHandler(node.protocol)
    nodes.add(node)
    if start:
      await node.protocol.start()
    return node

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
    let a = await newNode(1, integrate = true)
    let b = await newNode(2, integrate = true)
    let c = await newNode(4, integrate = true)
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
    let source = await newNode(7, fanout = 1)
    let b = await newNode()
    let c = await newNode()
    for node in nodes:
      discard node.protocol.subscribe(topic).get()
    discard await connect(source, b)
    discard await connect(source, c)
    checkUntilTimeout:
      source.protocol.subscribers(topic).len == 2
    let shard = CountingShard(id: @[byte 1], have: 7)
    check source.protocol.publish(topic, shard).get() == 1
    check shard.preparations == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) +
        c.events.countIt(it.kind == WaggleEventKind.Received) == 1

  asyncTest "queue saturation reports an event and unchanged snapshots can retry":
    let a = await newNode(1, maxQueued = 1)
    let b = await newNode()
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).isOk
    var failures = 0
    var retryFailed = false
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.FullQueue:
        inc failures
        if failures < 3:
          retryFailed =
            a.protocol.publish(topic, BitShard(id: @[byte 2], have: 1)).isErr

    a.onEvent = onEvent
    check a.protocol.publish(topic, BitShard(id: @[byte 2], have: 1)).isErr
    check failures == 1
    check retryFailed
    checkUntilTimeout:
      b.events.anyIt(it.kind == WaggleEventKind.Received)
    check a.protocol.publish(topic, BitShard(id: @[byte 2], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.anyIt(
        it.kind == WaggleEventKind.Received and it.message.objectId == @[byte 2] and
          it.message.pieces == Opt.some(@[byte 1]) and
          it.message.piecesMetadata == Opt.some(@[byte 1])
      )

  asyncTest "byte budget is shared across topics and released after writing":
    let a = await newNode(maxQueuedBytes = 9)
    let b = await newNode()
    let other = @[byte 2]
    discard b.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(other).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and a.protocol.subscribers(other).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 1
    check a.protocol.publish(other, BitShard(id: @[byte 2], have: 1)).isErr
    check a.events.countIt(it.kind == WaggleEventKind.FullQueue) == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 1
    check a.protocol.publish(other, BitShard(id: @[byte 2], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 2
    # A single message larger than the byte budget must also be rejected.
    check a.protocol.publish(topic, BitShard(id: @[byte 3, 4], have: 1)).isErr
    check a.events.countIt(it.kind == WaggleEventKind.FullQueue) == 2

  asyncTest "unsubscribing releases the topic configuration budget":
    let p = Waggle.new(maxTopics = 1, maxTopicSize = 3, rng = rng())
    let config = TopicConfig(publishFanout: 1, forwardFanout: 1, gossipFanout: 1)
    check p.setTopicConfig(@[byte 1, 2, 3, 4], config).error ==
      "Waggle topic exceeds maximum length"
    check p.subscribe(topic).get()
    check p.setTopicConfig(topic, config).isOk
    check p.setTopicConfig(@[byte 2], config).error ==
      "Waggle topic configuration limit reached"
    check await p.unsubscribe(topic)
    check p.subscribe(@[byte 2]).get()
    check p.setTopicConfig(@[byte 2], config).isOk
    await p.stop()

  asyncTest "start discovers existing switch connections":
    let a = await newNode(managed = true)
    let b = await newNode(managed = true)
    discard await connect(a, b)
    await a.protocol.stop()
    check a.ms.removeHandler(a.protocol)
    a.protocol = Waggle.new(switch = Switch(connManager: a.manager), rng = rng())
    a.ms.addHandler(a.protocol)
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    await a.protocol.start()
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 1

  asyncTest "subscriptions follow new connections and unsubscribe/resubscribe":
    let a = await newNode(managed = true)
    let b = await newNode(managed = true)
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
      a.protocol.subscribers(topic).len == 0 and
        a.events.anyIt(it.kind == WaggleEventKind.Unsubscribed)
    check b.protocol.subscribe(topic).get().added
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 2
    let c = await newNode(managed = true)
    discard c.protocol.subscribe(topic).get()
    discard await connect(a, c)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 2 and c.protocol.subscribers(topic).len == 1

  asyncTest "connection views are independent and reconnect clears old state":
    let a = await newNode(1)
    let b = await newNode()
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    let (first, _) = await connect(a, b)
    discard await connect(a, b)
    checkUntilTimeout:
      a.events.countIt(it.kind == WaggleEventKind.Subscribed) == 2
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 2
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 2
    await first.close()
    checkUntilTimeout:
      a.events.countIt(it.kind == WaggleEventKind.Unsubscribed) == 1
    discard await connect(a, b)
    checkUntilTimeout:
      a.events.countIt(it.kind == WaggleEventKind.Subscribed) == 3
    check a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get() == 1
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 3

  asyncTest "invalid metadata is surfaced without disconnecting healthy peers":
    let a = await newNode(1)
    let b = await newNode(2)
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 1
    discard a.protocol.publish(topic, BitShard(id: @[byte 1], have: 1)).get()
    check (
      await b.protocol.send(
        a.peer,
        topic,
        ObjectPieces(objectId: @[byte 1], piecesMetadata: Opt.some(@[byte 255])),
      )
    ).get()
    checkUntilTimeout:
      a.events.anyIt(it.kind == WaggleEventKind.InvalidData)
    check a.protocol.subscribers(topic).len == 1

  asyncTest "topic whitelist and configuration limits apply locally and remotely":
    let a = await newNode()
    let b = await newNode()
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
      topic, TopicConfig(publishFanout: 0, forwardFanout: 1, gossipFanout: 1)
    ).isErr
    check a.protocol.setTopicConfig(
      topic, TopicConfig(publishFanout: 1, forwardFanout: 1, gossipFanout: 1)
    ).isOk
    check a.protocol.setTopicConfig(
      @[byte 2], TopicConfig(publishFanout: 1, forwardFanout: 1, gossipFanout: 1)
    ).isErr
    discard b.protocol.subscribe(@[byte 2]).get()
    discard await connect(a, b)
    checkUntilTimeout:
      b.protocol.subscribers(topic).len == 1
    check a.protocol.subscribers(@[byte 2]).len == 0

  asyncTest "stopping Waggle preserves the shared connection":
    let a = await newNode(managed = true)
    let b = await newNode(managed = true)
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

  asyncTest "constructor waits for start before opening subscriptions":
    let a = await newNode(managed = true, start = false)
    let b = await newNode(managed = true)
    discard a.protocol.subscribe(topic).get()
    discard await connect(a, b)
    await sleepAsync(20.milliseconds)
    check b.events.len == 0
    await a.protocol.start()
    checkUntilTimeout:
      b.protocol.subscribers(topic).len == 1

  asyncTest "subscriber peers are unique across multiple connections":
    let a = await newNode(managed = true)
    let b = await newNode(managed = true)
    discard a.protocol.subscribe(topic).get()
    discard await connect(a, b)
    discard await connect(a, b)
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Subscribed) == 2
    check b.protocol.subscribers(topic) == @[a.peer]
    for peer in b.protocol.subscribers(topic):
      check (
        await b.protocol.send(
          peer, topic, ObjectPieces(objectId: @[byte 1], pieces: Opt.some(@[byte 1]))
        )
      ).get()
    checkUntilTimeout:
      a.events.countIt(it.kind == WaggleEventKind.Received) == 1

  asyncTest "explicit subscribe reopens a receiver after remote stop":
    let a = await newNode(managed = true)
    let b = await newNode(managed = true)
    discard a.protocol.subscribe(topic).get()
    let (am, bm) = await connect(a, b)
    checkUntilTimeout:
      b.protocol.subscribers(topic).len == 1
    await b.protocol.stop()
    checkUntilTimeout:
      a.events.anyIt(it.kind == WaggleEventKind.StreamFailed)
    await b.protocol.start()
    check not a.protocol.subscribe(topic).get().added
    checkUntilTimeout:
      b.protocol.subscribers(topic).len == 1
    check not am.connection.closed and not bm.connection.closed

  asyncTest "subscribe during unsubscribe waits for the old receivers":
    let a = await newNode(managed = true)
    let b = await newNode(managed = true)
    let c = await newNode(managed = true)
    discard a.protocol.subscribe(topic).get()
    discard await connect(a, b)
    discard await connect(a, c)
    checkUntilTimeout:
      b.protocol.subscribers(topic).len == 1 and c.protocol.subscribers(topic).len == 1
    let stopping = a.protocol.unsubscribe(topic)
    check a.protocol.subscribe(topic).get().added
    check await stopping
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Subscribed) == 2 and
        c.events.countIt(it.kind == WaggleEventKind.Subscribed) == 2
    check b.protocol.subscribers(topic) == @[a.peer]
    check c.protocol.subscribers(topic) == @[a.peer]
    check not a.events.anyIt(it.reason == "Duplicate Waggle topic stream")

  asyncTest "failure callbacks can change topics while connections are registered":
    let a = await newNode(managed = true, maxStreamsPerPeer = 1)
    let b = await newNode(managed = true)
    let c = await newNode(managed = true)
    discard await connect(a, b)
    discard await connect(a, c)
    discard a.protocol.subscribe(topic).get()
    checkUntilTimeout:
      b.protocol.subscribers(topic).len == 1 and c.protocol.subscribers(topic).len == 1
    var unsubscribing: Future[bool]
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.StreamFailed and unsubscribing == nil:
        unsubscribing = a.protocol.unsubscribe(@[byte 2])

    a.onEvent = onEvent
    check a.protocol.subscribe(@[byte 2]).get().blockedConnections.len == 2
    check unsubscribing == nil
    let d = await newNode(managed = true)
    discard await connect(a, d)
    check unsubscribing != nil
    check await unsubscribing
    check a.events.countIt(it.kind == WaggleEventKind.StreamFailed) == 1
    a.onEvent = nil
    # Adding a connection replays topics; its callback may mutate the topic set.
    let e = await newNode(managed = true)
    discard a.protocol.subscribe(@[byte 3]).get()
    var changed = false
    proc changeTopics(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.StreamFailed and not changed:
        changed = true
        discard a.protocol.subscribe(@[byte 4]).get()

    a.onEvent = changeTopics
    discard await connect(a, e)
    check changed

  asyncTest "failure callback can retry after negotiation failure":
    let a = await newNode(managed = true, maxStreamsPerPeer = 1)
    let b = await newNode(managed = true)
    check b.ms.removeHandler(b.protocol)
    discard await connect(a, b)
    var failures = 0
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.StreamFailed:
        inc failures
        if failures == 1:
          b.ms.addHandler(b.protocol)
          discard a.protocol.subscribe(topic).get()

    a.onEvent = onEvent
    check a.protocol.subscribe(topic).get().added
    checkUntilTimeout:
      b.protocol.subscribers(topic) == @[a.peer]
    check failures == 1

  asyncTest "failure callback can retry after invalid data":
    let a = await newNode(managed = true, maxStreamsPerPeer = 1)
    let b = await newNode(managed = true)
    let handle = b.protocol.handler
    var corrupted = false
    proc corruptOnce(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      if not corrupted:
        corrupted = true
        try:
          discard await stream.readLp(1024)
          await stream.writeLp(@[byte 0xff])
        except LPStreamError:
          discard
      else:
        await handle(stream, proto)

    b.protocol.handler = corruptOnce
    discard await connect(a, b)
    var failures = 0
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.InvalidData:
        inc failures
        if failures == 1:
          discard a.protocol.subscribe(topic).get()

    a.onEvent = onEvent
    check a.protocol.subscribe(topic).get().added
    checkUntilTimeout:
      b.protocol.subscribers(topic) == @[a.peer]
    check failures == 1

  asyncTest "background failure callbacks can inspect admission when retrying":
    let a = await newNode(managed = true, maxStreamsPerPeer = 1)
    let b = await newNode(managed = true)
    let other = @[byte 2]
    check a.protocol.subscribe(topic).get().added
    check a.protocol.subscribe(other).get().added
    var failures = 0
    var retryBlocked = false
    var blockedTopic: TopicId
    var blockedConnection: ConnectionId
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.StreamFailed:
        inc failures
        blockedTopic = event.topicId
        blockedConnection = event.connectionId
        if failures < 3:
          let retry = a.protocol.subscribe(event.topicId).get()
          retryBlocked =
            not retry.added and event.connectionId in retry.blockedConnections

    a.onEvent = onEvent
    discard await connect(a, b)
    checkUntilTimeout:
      failures == 1 and
        b.protocol.subscribers(topic).len + b.protocol.subscribers(other).len == 1
    check retryBlocked
    let retry = a.protocol.subscribe(blockedTopic).get()
    check not retry.added
    check retry.blockedConnections == @[blockedConnection]
    let drained = newAsyncEvent()
    callSoon proc(udata: pointer) {.gcsafe, raises: [].} =
      drained.fire()
    await drained.wait()
    check failures == 1
    let activeTopic = if blockedTopic == topic: other else: topic
    check await a.protocol.unsubscribe(activeTopic)
    let admitted = a.protocol.subscribe(blockedTopic).get()
    check not admitted.added
    check admitted.blockedConnections.len == 0
    checkUntilTimeout:
      b.protocol.subscribers(blockedTopic) == @[a.peer]

  asyncTest "admission reports preserve subscriptions and still attempt healthy connections":
    let a = await newNode(managed = true, maxStreamsPerPeer = 1)
    let b = await newNode(managed = true)
    let c = await newNode(managed = true)
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic) == @[b.peer]
    discard await connect(a, c)
    let other = @[byte 2]
    let blockedConnection =
      a.events.filterIt(it.kind == WaggleEventKind.Subscribed and it.peerId == b.peer)[
        0
      ].connectionId
    let attempt = a.protocol.subscribe(other).get()
    check attempt.added
    check attempt.blockedConnections == @[blockedConnection]
    checkUntilTimeout:
      c.protocol.subscribers(other) == @[a.peer]
    let retry = a.protocol.subscribe(other).get()
    check not retry.added
    check retry.blockedConnections == @[blockedConnection]
    check not a.events.anyIt(it.kind == WaggleEventKind.StreamFailed)
    check c.events.countIt(it.kind == WaggleEventKind.Subscribed) == 1
    let d = await newNode(managed = true)
    discard await connect(a, d)
    checkUntilTimeout:
      d.protocol.subscribers(other) == @[a.peer]
    check await b.protocol.unsubscribe(topic)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 0
    let admitted = a.protocol.subscribe(other).get()
    check not admitted.added
    check admitted.blockedConnections.len == 0
    checkUntilTimeout:
      b.protocol.subscribers(other) == @[a.peer]
    check c.events.countIt(it.kind == WaggleEventKind.Subscribed) == 1

  asyncTest "explicit admission reports do not cascade retry callbacks across peers":
    let a = await newNode(managed = true, maxStreamsPerPeer = 1)
    let b = await newNode(managed = true)
    let c = await newNode(managed = true)
    discard b.protocol.subscribe(topic).get()
    discard c.protocol.subscribe(topic).get()
    discard await connect(a, b)
    discard await connect(a, c)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 2
    var failures = 0
    let other = @[byte 2]
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      if event.kind == WaggleEventKind.StreamFailed:
        inc failures
        if failures < 10:
          discard a.protocol.subscribe(other).get()

    a.onEvent = onEvent
    let attempt = a.protocol.subscribe(other).get()
    check attempt.added
    check attempt.blockedConnections.len == 2
    check failures == 0
