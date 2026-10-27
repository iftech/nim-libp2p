# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import ./waggle_utils
import
  ../../../libp2p/[
    switch,
    multistream,
    muxers/yamux/yamux,
    transports/transport,
    transports/tcptransport,
    upgrademngrs/upgrade,
  ]
import ../../tools/[unittest, crypto, multiaddress]

const topic = @[byte 0, 255, 1]

type Node = ref object
  peer: PeerId
  protocol: Waggle
  manager: ConnManager
  ms: MultistreamSelect
  events: seq[WaggleEvent]

suite "Waggle managed dissemination":
  var
    listener, dialer: Transport
    listening: Future[void]
    nodes: seq[Node]
    muxers: seq[Muxer]

  proc newNode(managed = false): Node =
    let node = Node(peer: PeerId.random(), ms: MultistreamSelect.new())
    proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
      node.events.add(event)

    if managed:
      node.manager = ConnManager.new(maxConnsPerPeer = 4)
    node.protocol = Waggle.new(
      switch = (if managed: Switch(connManager: node.manager) else: nil),
      onEvent = onEvent,
    )
    node.ms.addHandler(node.protocol)
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

  asyncTest "constructor discovers existing switch connections":
    let a = newNode(managed = true)
    let b = newNode(managed = true)
    discard await connect(a, b)
    await a.protocol.stop()
    check a.ms.removeHandler(a.protocol)
    a.protocol = Waggle.new(switch = Switch(connManager: a.manager))
    a.ms.addHandler(a.protocol)
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 1
    check (
      await a.protocol.send(
        b.peer, topic, ObjectPieces(objectId: @[byte 1], pieces: Opt.some(@[byte 1]))
      )
    ).get()
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 1

  asyncTest "subscriptions follow new connections and unsubscribe/resubscribe":
    let a = newNode(managed = true)
    let b = newNode(managed = true)
    discard a.protocol.subscribe(topic).get()
    discard b.protocol.subscribe(topic).get()
    discard await connect(a, b)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1 and b.protocol.subscribers(topic).len == 1
    check (
      await a.protocol.send(
        b.peer, topic, ObjectPieces(objectId: @[byte 1], pieces: Opt.some(@[byte 1]))
      )
    ).get()
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 1
    check await b.protocol.unsubscribe(topic)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 0 and
        a.events.anyIt(it.kind == WaggleEventKind.Unsubscribed)
    check b.protocol.subscribe(topic).get()
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 1
    check (
      await a.protocol.send(
        b.peer, topic, ObjectPieces(objectId: @[byte 1], pieces: Opt.some(@[byte 1]))
      )
    ).get()
    checkUntilTimeout:
      b.events.countIt(it.kind == WaggleEventKind.Received) == 2
    let c = newNode(managed = true)
    discard c.protocol.subscribe(topic).get()
    discard await connect(a, c)
    checkUntilTimeout:
      a.protocol.subscribers(topic).len == 2 and c.protocol.subscribers(topic).len == 1

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
