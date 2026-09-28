# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, chronos, std/[sequtils, tables, strformat]
import
  ../../libp2p/[connmanager, stream/connection, crypto/crypto, muxers/muxer, peerinfo]
import ../tools/[unittest, compare, futures, crypto]

proc makeMuxer(peerId: PeerId, dir: Direction = Direction.In): Muxer =
  return Muxer(connection: Connection.new(peerId, dir))

type TestMuxer = ref object of Muxer
  peerId: PeerId

method newStream*(
    m: TestMuxer, name: string = "", lazy: bool = false
): Future[MuxedStream] {.async: (raises: [CancelledError, LPStreamError, MuxerError]).} =
  Connection.new(m.peerId, Direction.Out)

proc newMaxTotal(maxConnections = 10, maxConnsPerPeer = 1): ConnManager =
  return ConnManager.new(
    maxConnsPerPeer = maxConnsPerPeer,
    limits = Opt.some(ConnectionLimits.maxTotal(maxConnections)),
  )

proc newMaxInOut(maxIn: int, maxOut: int, maxConnsPerPeer = 1): ConnManager =
  return ConnManager.new(
    maxConnsPerPeer = maxConnsPerPeer,
    limits = Opt.some(ConnectionLimits.maxInOut(maxIn, maxOut)),
  )

proc newWatermark*(
    lowWater: int,
    highWater: int,
    gracePeriod: Duration = 0.seconds,
    silencePeriod: Duration = 0.seconds,
    outboundBonus: int = 0,
    decayResolution = 1.minutes,
): ConnManager =
  let wtCfg = WatermarkPolicy(
    lowWater: lowWater,
    highWater: highWater,
    gracePeriod: gracePeriod,
    silencePeriod: silencePeriod,
  )
  let scCfg =
    PeerScoring(outboundBonus: outboundBonus, decayResolution: decayResolution)
  return ConnManager.new(watermark = Opt.some(wtCfg), scoring = scCfg)

proc storeMuxers(connMngr: ConnManager, count: uint): Future[seq[PeerId]] {.async.} =
  let peers = PeerId.random(count, rng()).tryGet()
  for fut in peers.mapIt(connMngr.storeMuxer(makeMuxer(it))):
    check (await fut).isOk()
  return peers

suite "Connection Manager":
  teardown:
    checkTrackers()

  let peerId = PeerId.random(rng()).tryGet()

  asyncTest "add and retrieve a muxer":
    let connMngr = newMaxTotal()
    let mux = makeMuxer(peerId)

    check (await connMngr.storeMuxer(mux)).isOk()
    check mux in connMngr

    let peerMux = connMngr.selectMuxer(peerId)
    check peerMux == mux
    check peerMux.connection.dir == Direction.In

    await connMngr.stop()

  asyncTest "get all connections":
    let connMngr = newMaxTotal()

    let peers = PeerId.random(5, rng()).tryGet()
    let muxs = peers.mapIt(makeMuxer(it))
    for mux in muxs:
      check (await connMngr.storeMuxer(mux)).isOk()

    let connsMux = connMngr.getConnections().values.toSeq().mapIt(it[0])
    check unorderedCompare(connsMux, muxs)

    await connMngr.stop()

  asyncTest "shouldn't allow a closed connection":
    let connMngr = newMaxTotal()

    let mux = makeMuxer(peerId)
    await mux.connection.close()
    check (await connMngr.storeMuxer(mux)).isErr()

    await connMngr.stop()

  asyncTest "shouldn't allow an EOFed connection":
    let connMngr = newMaxTotal()

    let mux = makeMuxer(peerId)
    mux.connection.isEof = true
    check (await connMngr.storeMuxer(mux)).isErr()

    await mux.close()
    await connMngr.stop()

  asyncTest "shouldn't allow a muxer with no connection":
    let connMngr = newMaxTotal()

    let muxer = makeMuxer(peerId)
    let conn = muxer.connection
    muxer.connection = nil
    check (await connMngr.storeMuxer(muxer)).isErr()

    await conn.close()
    await muxer.close()
    await connMngr.stop()

  asyncTest "get conn with direction":
    let connMngr = newMaxTotal(maxConnsPerPeer = 2)

    let mux1 = makeMuxer(peerId, Direction.Out)
    let mux2 = makeMuxer(peerId)

    check (await connMngr.storeMuxer(mux1)).isOk()
    check (await connMngr.storeMuxer(mux2)).isOk()
    check mux1 in connMngr
    check mux2 in connMngr

    let outMux = connMngr.selectMuxer(peerId, Direction.Out)
    let inMux = connMngr.selectMuxer(peerId, Direction.In)

    check outMux != inMux
    check outMux == mux1
    check inMux == mux2
    check outMux.connection.dir == Direction.Out
    check inMux.connection.dir == Direction.In

    await connMngr.stop()

  asyncTest "get muxed stream for peer":
    let connMngr = newMaxTotal()

    let muxer = new TestMuxer
    let connection = Connection.new(peerId, Direction.In)
    muxer.peerId = peerId
    muxer.connection = connection

    check (await connMngr.storeMuxer(muxer)).isOk()
    check muxer in connMngr

    let stream = await connMngr.getStream(peerId)
    check not stream.isNil
    check stream.peerId == peerId

    await connMngr.stop()
    await connection.close()
    await stream.close()

  asyncTest "get stream from directed connection":
    let connMngr = newMaxTotal()

    let muxer = new TestMuxer
    let connection = Connection.new(peerId, Direction.In)
    muxer.peerId = peerId
    muxer.connection = connection

    check (await connMngr.storeMuxer(muxer)).isOk()
    check muxer in connMngr

    let stream1 = await connMngr.getStream(peerId, Direction.In)
    check not stream1.isNil
    let stream2 = await connMngr.getStream(peerId, Direction.Out)
    check stream2.isNil

    await connMngr.stop()
    await stream1.close()
    await connection.close()

  asyncTest "expect connection from peer":
    let connMngr = newMaxTotal(maxConnsPerPeer = 1)

    let muxs = @[makeMuxer(peerId), makeMuxer(peerId)]

    check (await connMngr.storeMuxer(muxs[0])).isOk()
    check (await connMngr.storeMuxer(muxs[1])).isErr()

    let waitedConn1 = connMngr.expectConnection(peerId, In)

    expect AlreadyExpectingConnectionError:
      discard await connMngr.expectConnection(peerId, In)

    await waitedConn1.cancelAndWait()
    let
      waitedConn2 = connMngr.expectConnection(peerId, In)
      waitedConn3 = connMngr.expectConnection(PeerId.random(rng()).tryGet(), In)
      conn = makeMuxer(peerId)
    check (await connMngr.storeMuxer(conn)).isOk()
    check (await waitedConn2) == conn

    check (await connMngr.storeMuxer(muxs[1])).isErr()

    await connMngr.stop()

    checkUntilTimeout:
      waitedConn3.cancelled()

    await allFuturesRaising(muxs.mapIt(it.close()))

  asyncTest "cleanup on connection close":
    let connMngr = newMaxTotal()
    let muxer = makeMuxer(peerId)

    check (await connMngr.storeMuxer(muxer)).isOk()
    check muxer in connMngr

    await muxer.close()
    checkUntilTimeout:
      muxer notin connMngr

    await connMngr.stop()

  asyncTest "waitForPeerReady unblocks when muxer is stored":
    let connMngr = newMaxTotal()

    let readyWaiter = connMngr.waitForPeerReady(peerId, 1.seconds)
    check (await connMngr.storeMuxer(makeMuxer(peerId))).isOk()

    check await readyWaiter
    await connMngr.stop()

  asyncTest "readiness waits work without start until stopped":
    let connMngr = ConnManager.new()
    check connMngr.isRunning()
    defer:
      await connMngr.stop()
    let readyWaiter = connMngr.waitForPeerReady(peerId, 1.seconds)
    check (await connMngr.storeMuxer(makeMuxer(peerId))).isOk()
    check await readyWaiter
    await connMngr.stop()
    check not connMngr.isRunning()
    check not (await connMngr.waitForPeerReady(peerId))

  asyncTest "new manager decays tags without explicit start":
    let connMngr = ConnManager.new(scoring = PeerScoring(decayResolution: 1.millis))
    defer:
      await connMngr.stop()
    connMngr.tagPeerDecaying(peerId, "initial", 1, 1.millis, decayFixed(1))
    checkUntilTimeoutCustom(1.seconds, 10.millis):
      connMngr.peerScore(peerId) == 0

  asyncTest "restart resumes readiness waits and retained tag decay":
    let connMngr = newWatermark(1, 2, decayResolution = 1.millis)
    connMngr.tagPeerDecaying(peerId, "retained", 1, 1.millis, decayFixed(1))
    await connMngr.stop()
    connMngr.start()
    check connMngr.isRunning()
    defer:
      await connMngr.stop()
    let readyWaiter = connMngr.waitForPeerReady(peerId, 1.seconds)
    check (await connMngr.storeMuxer(makeMuxer(peerId))).isOk()
    check await readyWaiter
    checkUntilTimeoutCustom(1.seconds, 10.millis):
      connMngr.peerScore(peerId) == 0

  asyncTest "tags configured while stopped decay only after start":
    let connMngr = newWatermark(1, 2, decayResolution = 10.millis)
    defer:
      connMngr.removeDecayingTag(peerId, "between-starts")
      await connMngr.stop()
    await connMngr.stop()
    connMngr.tagPeerDecaying(peerId, "between-starts", 100, 1.millis, decayFixed(1))
    await sleepAsync(50.millis)
    check connMngr.peerScore(peerId) == 100
    connMngr.start()
    connMngr.start()
    checkUntilTimeout:
      connMngr.peerScore(peerId) < 100
    await connMngr.stop()
    let scoreAtStop = connMngr.peerScore(peerId)
    await sleepAsync(50.millis)
    check connMngr.peerScore(peerId) == scoreAtStop

  asyncTest "waitForPeerReady timeout does not break concurrent waiters":
    let connMngr = newMaxTotal()

    let shortWaiter = connMngr.waitForPeerReady(peerId, 10.millis)
    let longWaiter = connMngr.waitForPeerReady(peerId, 1.seconds)

    check not (await shortWaiter)
    check (await connMngr.storeMuxer(makeMuxer(peerId))).isOk()
    check await longWaiter

    await connMngr.stop()

  asyncTest "waitForPeerReady cleanup after disconnect":
    let connMngr = newMaxTotal()
    let muxer = makeMuxer(peerId)

    check (await connMngr.storeMuxer(muxer)).isOk()
    await muxer.close()

    checkUntilTimeout:
      peerId notin connMngr

    check (await connMngr.waitForPeerReady(peerId, 10.millis)) == false
    await connMngr.stop()

  asyncTest "does not emit Joined when muxer is dropped before connected handlers finish":
    let connMngr = newMaxTotal()
    defer:
      await connMngr.stop()

    let
      muxer = makeMuxer(peerId)
      unblockConnected = newAsyncEvent()
    var
      connectedStarted = false
      events: seq[string]

    proc connectedHandler(
        handlerPeerId: PeerId, event: ConnEvent
    ) {.async: (raises: [CancelledError]).} =
      if handlerPeerId == peerId:
        events.add("Connected")
        connectedStarted = true
        await unblockConnected.wait()

    proc disconnectedHandler(
        handlerPeerId: PeerId, event: ConnEvent
    ) {.async: (raises: [CancelledError]).} =
      if handlerPeerId == peerId:
        events.add("Disconnected")

    proc peerHandler(kind: string): PeerEventHandler =
      return proc(
          handlerPeerId: PeerId, event: PeerEvent
      ) {.async: (raises: [CancelledError]).} =
        if handlerPeerId == peerId:
          events.add(kind)

    connMngr.addConnEventHandler(connectedHandler, ConnEventKind.Connected)
    connMngr.addConnEventHandler(disconnectedHandler, ConnEventKind.Disconnected)
    connMngr.addPeerEventHandler(peerHandler("Joined"), PeerEventKind.Joined)
    connMngr.addPeerEventHandler(peerHandler("Left"), PeerEventKind.Left)

    let storeFut = connMngr.storeMuxer(muxer)

    checkUntilTimeout:
      connectedStarted

    check muxer in connMngr

    await connMngr.dropPeer(peerId)
    check peerId notin connMngr

    unblockConnected.fire()
    check (await storeFut).isOk()

    checkUntilTimeout:
      events == @["Connected", "Left", "Disconnected"]

  asyncTest "drop connections for peer":
    let connMngr = newMaxTotal(maxConnsPerPeer = 2)

    for i in 0 ..< 2:
      let dir = if i mod 2 == 0: Direction.In else: Direction.Out

      let muxer = makeMuxer(peerId, dir)
      check (await connMngr.storeMuxer(muxer)).isOk()
      check muxer in connMngr
      check not connMngr.selectMuxer(peerId, dir).isNil

    check peerId in connMngr
    await connMngr.dropPeer(peerId)

    checkUntilTimeout:
      peerId notin connMngr
    check connMngr.selectMuxer(peerId, Direction.In).isNil
    check connMngr.selectMuxer(peerId, Direction.Out).isNil

    await connMngr.stop()

  asyncTest "track total incoming connection limits":
    let connMngr = newMaxTotal(3)

    for i in 0 ..< 3:
      check await connMngr.getIncomingSlot().withTimeout(10.millis)

    # should timeout adding a connection over the limit
    check not (await connMngr.getIncomingSlot().withTimeout(10.millis))

    await connMngr.stop()

  asyncTest "try incoming connection slot":
    let connMngr = newMaxTotal(1)

    let slot = connMngr.tryGetIncomingSlot()
    check slot.isSome
    check connMngr.tryGetIncomingSlot().isNone

    slot.get().release()
    let reacquired = connMngr.tryGetIncomingSlot()
    check reacquired.isSome
    reacquired.get().release()

    await connMngr.stop()

  asyncTest "track total outgoing connection limits":
    let connMngr = newMaxTotal(3)

    for i in 0 ..< 3:
      check connMngr.getOutgoingSlot().isOk()

    check connMngr.getOutgoingSlot().isErr()

    await connMngr.stop()

  asyncTest "track both incoming and outgoing total connections limits - fail on incoming":
    let connMngr = newMaxTotal(3)

    for i in 0 ..< 3:
      check connMngr.getOutgoingSlot().isOk()

    # should timeout adding a connection over the limit
    check not (await connMngr.getIncomingSlot().withTimeout(10.millis))

    await connMngr.stop()

  asyncTest "track both incoming and outgoing total connections limits - fail on outgoing":
    let connMngr = newMaxTotal(3)

    for i in 0 ..< 3:
      check await connMngr.getIncomingSlot().withTimeout(10.millis)

    check connMngr.getOutgoingSlot().isErr()

    await connMngr.stop()

  asyncTest "track max incoming connection limits":
    let connMngr = newMaxInOut(3, 1)

    for i in 0 ..< 3:
      check await connMngr.getIncomingSlot().withTimeout(10.millis)

    check not (await connMngr.getIncomingSlot().withTimeout(10.millis))

    await connMngr.stop()

  asyncTest "track max outgoing connection limits":
    let connMngr = newMaxInOut(1, 3)

    for i in 0 ..< 3:
      check connMngr.getOutgoingSlot().isOk()

    check connMngr.getOutgoingSlot().isErr()

    await connMngr.stop()

  asyncTest "track incoming max connections limits - fail on incoming":
    let connMngr = newMaxInOut(1, 3)

    for i in 0 ..< 3:
      check connMngr.getOutgoingSlot().isOk()

    check await connMngr.getIncomingSlot().withTimeout(10.millis)

    # should timeout adding a connection over the limit
    check not (await connMngr.getIncomingSlot().withTimeout(10.millis))

    await connMngr.stop()

  asyncTest "track incoming max connections limits - fail on outgoing":
    let connMngr = newMaxInOut(3, 1)

    for i in 0 ..< 3:
      check await connMngr.getIncomingSlot().withTimeout(10.millis)

    check connMngr.getOutgoingSlot().isOk()

    check connMngr.getOutgoingSlot().isErr()

    await connMngr.stop()

  asyncTest "allow force dial":
    let connMngr = newMaxTotal(2)

    for i in 0 ..< 3:
      check connMngr.getOutgoingSlot(true).isOk()

    check connMngr.getOutgoingSlot(false).isErr()

    await connMngr.stop()

  asyncTest "release slot on connection end":
    let connMngr = newMaxTotal(3)

    var muxs: seq[Muxer]
    for i in 0 ..< 3:
      let slot = connMngr.getOutgoingSlot().tryGet()
      let muxer = makeMuxer(PeerId.random(rng()).tryGet(), Direction.In)

      slot.trackMuxer(muxer)
      muxs.add(muxer)

    let incomingSlot = connMngr.getIncomingSlot()

    # should be full now
    check not (await incomingSlot.withTimeout(10.millis))

    # should have slots after closing muxers
    await allFuturesRaising(muxs.mapIt(it.close()))
    check await incomingSlot.withTimeout(10.millis)

    await connMngr.stop()

suite "Connection Manager maxConnsPerPeer":
  teardown:
    checkTrackers()

  let peerId = PeerId.random(rng()).tryGet()
  const defaultMaxConnsPerPeer = 2

  proc runTest(maxConnsPerPeer: int, numberOfMuxersToConnect: int) {.async.} =
    let connMngr = newMaxTotal(maxConnsPerPeer = maxConnsPerPeer)

    # store up to limit
    for _ in 0 ..< numberOfMuxersToConnect:
      check (await connMngr.storeMuxer(makeMuxer(peerId))).isOk()

    check connMngr.connCount(peerId) == numberOfMuxersToConnect

    # add one more to exceed limit
    let extraMuxer = makeMuxer(peerId)
    check (await connMngr.storeMuxer(extraMuxer)).isErr()
    await extraMuxer.close()

    check connMngr.connCount(peerId) == numberOfMuxersToConnect

    await connMngr.stop()

  asyncTest "maxConnsPerPeer = -1 uses default":
    await runTest(-1, defaultMaxConnsPerPeer)

  asyncTest "maxConnsPerPeer = 0 uses default":
    await runTest(0, defaultMaxConnsPerPeer)

  for i in 1 ..< 10:
    let limit = i
    asyncTest fmt"peer limit is reached with {limit} muxers":
      await runTest(limit, limit)

suite "Connection Manager Watermark":
  teardown:
    checkTrackers()

  let peerId = PeerId.random(rng()).tryGet()

  asyncTest "trim fires when peer count exceeds highWater":
    const peersToConnect = 5
    const lowWater = 2
    const highWater = peersToConnect - 1 # connect 1 peer above high water
    let connMngr = newWatermark(lowWater, highWater)

    # connect peers - one over the highWater
    discard await storeMuxers(connMngr, peersToConnect)

    check connMngr.getConnections().len == lowWater

    await connMngr.stop()

  asyncTest "grace period protects newly connected peers":
    # long grace period - newly connected peers must not be pruned
    const peersToConnect = 5
    const lowWater = 1
    const highWater = peersToConnect - 3
    let connMngr = newWatermark(lowWater, highWater, gracePeriod = 1.hours)

    discard await storeMuxers(connMngr, peersToConnect)

    # all peers are within grace period - none should be pruned
    check connMngr.getConnections().len == peersToConnect

    await connMngr.stop()

  asyncTest "protected peers survive trim":
    const peersToConnect = 3
    const lowWater = 1
    const highWater = peersToConnect
    let connMngr = newWatermark(lowWater, highWater)

    let peers = await storeMuxers(connMngr, peersToConnect)

    # protect the first two peers before the trim-triggering store
    connMngr.protect(peers[0], "important")
    connMngr.protect(peers[1], "important")

    # adding extra peer, triggering trim
    check (await connMngr.storeMuxer(makeMuxer(peerId))).isOk()

    # protected peers must still be connected
    check connMngr.contains(peers[0])
    check connMngr.contains(peers[1])

    await connMngr.stop()

  asyncTest "unprotect removes tag and allows trimming":
    let connMngr = newWatermark(1, 3)

    check (await connMngr.storeMuxer(makeMuxer(peerId))).isOk()

    connMngr.protect(peerId, "tag-a")
    connMngr.protect(peerId, "tag-b")

    check connMngr.isProtected(peerId)
    check connMngr.unprotect(peerId, "tag-a") == true # still protected via tag-b
    check connMngr.unprotect(peerId, "tag-b") == false # no longer protected
    check not connMngr.isProtected(peerId)

    await connMngr.stop()

  asyncTest "silence period throttles back-to-back trims":
    const peersToConnect = 3
    const highWater = peersToConnect - 1
    let connMngr = newWatermark(1, highWater, silencePeriod = 1.hours)

    # connect first batch of peers - should cause trim after last peer
    discard await storeMuxers(connMngr, peersToConnect)

    let connectedPeers = connMngr.getConnections().len

    # connect second batch of peers.
    # silence period prevents a second trim,
    # adding more peers should not immediately trigger another trim
    discard await storeMuxers(connMngr, peersToConnect)

    # silence period still active - count should be >= before
    check connMngr.getConnections().len == connectedPeers + peersToConnect

    await connMngr.stop()

  asyncTest "getIncomingSlot does not block in watermark mode":
    let connMngr = newWatermark(1, 5)

    # should return immediately without semaphore blocking
    check await connMngr.getIncomingSlot().withTimeout(10.millis)

    await connMngr.stop()

  asyncTest "getOutgoingSlot does not fail in watermark mode":
    let connMngr = newWatermark(1, 5)

    for i in 0 ..< 10:
      check connMngr.getOutgoingSlot().isOk()

    await connMngr.stop()

  asyncTest "lifecycle events stay ordered when trim prunes the new connection":
    # The trim may prune the just-stored connection, but consumers such as
    # pubsub rely on Joined being observed before Left for the same peer.
    let connMngr = newWatermark(1, 2)
    defer:
      await connMngr.stop()

    let peers = PeerId.random(3, rng()).tryGet()
    let prunedPeer = peers[2]

    var
      events: seq[string]
      peerTracked = false
    proc connHandler(kind: string): ConnEventHandler =
      return proc(
          peerId: PeerId, event: ConnEvent
      ) {.async: (raises: [CancelledError]).} =
        if peerId == prunedPeer:
          events.add(kind)

    proc peerHandler(kind: string): PeerEventHandler =
      return proc(
          peerId: PeerId, event: PeerEvent
      ) {.async: (raises: [CancelledError]).} =
        if peerId == prunedPeer:
          events.add(kind)
          case event.kind
          of PeerEventKind.Joined:
            peerTracked = true
          of PeerEventKind.Left:
            peerTracked = false
          of PeerEventKind.Identified:
            discard

    connMngr.addConnEventHandler(connHandler("Connected"), ConnEventKind.Connected)
    connMngr.addConnEventHandler(
      connHandler("Disconnected"), ConnEventKind.Disconnected
    )
    connMngr.addPeerEventHandler(peerHandler("Joined"), PeerEventKind.Joined)
    connMngr.addPeerEventHandler(peerHandler("Left"), PeerEventKind.Left)

    check (await connMngr.storeMuxer(makeMuxer(peers[0]))).isOk()
    check (await connMngr.storeMuxer(makeMuxer(peers[1]))).isOk()
    # protecting peers[0] leaves peers[1] and prunedPeer as the only trim candidates.
    # reaching lowWater then forces the trim to prune prunedPeer's just-stored connection.
    connMngr.protect(peers[0], "keep")
    check (await connMngr.storeMuxer(makeMuxer(prunedPeer))).isOk()

    checkUntilTimeout:
      events.len == 4
    check events == @["Connected", "Joined", "Left", "Disconnected"]
    check not peerTracked

  asyncTest "ready state is cleared when trim prunes the new connection":
    # A pruned peer must not remain ready after trim removes its only muxer.
    let connMngr = newWatermark(1, 2)
    defer:
      await connMngr.stop()

    let peers = PeerId.random(3, rng()).tryGet()
    let prunedPeer = peers[2]

    check (await connMngr.storeMuxer(makeMuxer(peers[0]))).isOk()
    check (await connMngr.storeMuxer(makeMuxer(peers[1]))).isOk()
    # protecting peers[0] forces the trim to prune prunedPeer's just-stored connection
    connMngr.protect(peers[0], "keep")
    check (await connMngr.storeMuxer(makeMuxer(prunedPeer))).isOk()

    checkUntilTimeout:
      prunedPeer notin connMngr

    let readyState = await connMngr.waitForPeerReady(prunedPeer, 50.millis)
    check not readyState

suite "Connection Manager Scoring":
  teardown:
    checkTrackers()

  const tag = "λ"
  let peerId = PeerId.random(rng()).tryGet()

  asyncTest "peerScore returns 0 for unknown peer":
    let cm = newWatermark(1, 2)
    check cm.peerScore(peerId) == 0
    await cm.stop()

  asyncTest "static tag contributes to peer score":
    let cm = newWatermark(1, 2)
    check (await cm.storeMuxer(makeMuxer(peerId))).isOk()
    cm.tagPeer(peerId, "🌞", 50)
    check cm.peerScore(peerId) == 50
    cm.tagPeer(peerId, "🕶️", 30)
    check cm.peerScore(peerId) == 80
    await cm.stop()

  asyncTest "untagPeer removes score contribution":
    let cm = newWatermark(1, 2)
    check (await cm.storeMuxer(makeMuxer(peerId))).isOk()
    cm.tagPeer(peerId, tag, 50)
    cm.untagPeer(peerId, tag)
    check cm.peerScore(peerId) == 0
    await cm.stop()

  asyncTest "outbound connection gets outboundBonus":
    const outboundBonus = 2345432
    let cm = newWatermark(1, 2, outboundBonus = outboundBonus)
    check (await cm.storeMuxer(makeMuxer(peerId, Direction.Out))).isOk()
    check cm.peerScore(peerId) == outboundBonus
    await cm.stop()

  asyncTest "inbound connection gets no outboundBonus":
    let cm = newWatermark(1, 2)
    check (await cm.storeMuxer(makeMuxer(peerId, Direction.In))).isOk()
    check cm.peerScore(peerId) == 0
    await cm.stop()

  asyncTest "decaying tag contributes initial value to score":
    let cm = newWatermark(1, 2)
    check (await cm.storeMuxer(makeMuxer(peerId))).isOk()
    cm.tagPeerDecaying(peerId, tag, 100, 1.hours, decayLinear(0.5))
    check cm.peerScore(peerId) == 100
    await cm.stop()

  asyncTest "decaying tag value decreases over interval":
    let cm = newWatermark(1, 2, decayResolution = 20.millis)
    check (await cm.storeMuxer(makeMuxer(peerId))).isOk()
    cm.tagPeerDecaying(peerId, tag, 100, 20.millis, decayFixed(30))
    checkUntilTimeout:
      cm.peerScore(peerId) < 100
    await cm.stop()

  asyncTest "decaying tag auto-removed when value hits zero":
    let cm = newWatermark(1, 2, decayResolution = 20.millis)
    check (await cm.storeMuxer(makeMuxer(peerId))).isOk()
    cm.tagPeerDecaying(peerId, tag, 10, 20.millis, decayFixed(15))
    checkUntilTimeout:
      cm.peerScore(peerId) == 0
    await cm.stop()

  asyncTest "bumpDecayingTag increases tag value":
    let cm = newWatermark(1, 2)
    check (await cm.storeMuxer(makeMuxer(peerId))).isOk()
    cm.tagPeerDecaying(peerId, tag, 50, 1.hours, decayNone())
    cm.bumpDecayingTag(peerId, tag, 25)
    check cm.peerScore(peerId) == 75
    await cm.stop()

  asyncTest "removeDecayingTag removes tag immediately":
    let cm = newWatermark(1, 2)
    check (await cm.storeMuxer(makeMuxer(peerId))).isOk()
    cm.tagPeerDecaying(peerId, tag, 50, 1.hours, decayNone())
    cm.removeDecayingTag(peerId, tag)
    check cm.peerScore(peerId) == 0
    await cm.stop()

  asyncTest "watermark trim prunes lowest-score peer first":
    let cm = newWatermark(1, 2)
    let highScorePeer = PeerId.random(rng()).tryGet()
    let lowScorePeer1 = PeerId.random(rng()).tryGet()
    check (await cm.storeMuxer(makeMuxer(highScorePeer))).isOk()
    cm.tagPeer(highScorePeer, "destacado", 500)
    check (await cm.storeMuxer(makeMuxer(lowScorePeer1))).isOk()
    # store a third peer to trigger trim (count=3 > highWater=2)
    check (await cm.storeMuxer(makeMuxer(PeerId.random(rng()).tryGet()))).isOk()
    check cm.contains(highScorePeer)
    check cm.getConnections().len == 1
    await cm.stop()

  asyncTest "outbound peer survives watermark trim over inbound peers":
    let cm = newWatermark(1, 2, outboundBonus = 500)
    let outboundPeer = PeerId.random(rng()).tryGet()
    check (await cm.storeMuxer(makeMuxer(outboundPeer, Direction.Out))).isOk()
    check (await cm.storeMuxer(makeMuxer(PeerId.random(rng()).tryGet(), Direction.In))).isOk()
    # add one more over the high water to trigger the trim
    check (await cm.storeMuxer(makeMuxer(PeerId.random(rng()).tryGet(), Direction.In))).isOk()
    check cm.contains(outboundPeer)
    check cm.getConnections().len == 1
    await cm.stop()

suite "Connection Manager: watermark with connection limiting":
  teardown:
    checkTrackers()

  asyncTest "protected peers fill semaphore cap blocking new connections":
    # both connection limiting (maxConnections=3) and watermark trimming (highWater=2)
    # are active simultaneously. protected peers survive every trim cycle, so the
    # semaphore stays exhausted and all further connection attempts are rejected.
    const maxConns = 3
    let connMngr = ConnManager.new(
      limits = Opt.some(ConnectionLimits.maxTotal(maxConns)),
      watermark = Opt.some(
        WatermarkPolicy(
          lowWater: 1, highWater: 2, gracePeriod: 0.seconds, silencePeriod: 0.seconds
        )
      ),
    )

    # acquire a semaphore slot for each peer, protect it, then register it.
    # protecting before storeMuxer ensures the peer is already shielded when
    # trim fires on the 3rd store (peer count 3 > highWater 2).
    for _ in 0 ..< maxConns:
      let peerId = PeerId.random(rng()).tryGet()
      let slot = await connMngr.getIncomingSlot()
      let muxer = makeMuxer(peerId)
      connMngr.protect(peerId, "keep-forever")
      slot.trackMuxer(muxer)
      check (await connMngr.storeMuxer(muxer)).isOk()

    # trim fired but found no unprotected candidates, all 3 peers still connected
    check connMngr.getConnections().len == maxConns

    # all connection slots should be used, getting incoming slot must block
    check not (await connMngr.getIncomingSlot().withTimeout(50.millis))

    check connMngr.getOutgoingSlot().isErr()

    await connMngr.stop()
