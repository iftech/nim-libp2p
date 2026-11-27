# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, importutils, tables]
import chronos
import
  ../../libp2p/[
    builders, switch, dial, multiaddress, wire, transports/transport, stream/connection
  ]
import ../../libp2p/protocols/protocol
import ../../libp2p/transports/tcptransport
import ../../libp2p/transports/memorytransport except MemoryAutoAddress
import ../stubs/transportstub
import ../tools/[unittest, crypto, lifecycle, multiaddress, switch_builder]

privateAccess(Switch)
privateAccess(TcpTransport)

proc newStubAcceptSwitch(
    behavior: StubAcceptBehavior, withTcp = false, maxIn = 0, acceptLimit = 0
): (Switch, MemoryTransportStub) =
  var addrs = @[MemoryAutoAddress()]
  if withTcp:
    addrs.add(TcpAutoAddress)

  var b = SwitchBuilder
    .new()
    .withRng(rng())
    .withNoise()
    .withMplex()
    .withAddresses(addrs)
    .withTransport(
      proc(config: TransportConfig): Transport =
        MemoryTransportStub.new(config.upgr, rng(), behavior, acceptLimit = acceptLimit)
    )
  if withTcp:
    b = b.withTcpTransport()
  if maxIn > 0:
    b = b.withMaxInOut(maxIn, 8)

  let switch = b.build()
  (switch, MemoryTransportStub(switch.transports[0]))

type SourceAddressTransport = ref object of MemoryTransport
  sourceAddresses: seq[MultiAddress]
  accepted: int

method accept(
    self: SourceAddressTransport
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  let conn = await procCall MemoryTransport(self).accept()
  conn.observedAddr = Opt.some(self.sourceAddresses[self.accepted])
  self.accepted.inc()
  return conn

type SlowStopProtocol = ref object of LPProtocol
  stopping, release: AsyncEvent

method stop(p: SlowStopProtocol) {.async: (raises: []).} =
  p.stopping.fire()
  await noCancel p.release.wait()
  p.started = false

proc newSlowStopProtocol(): SlowStopProtocol =
  result = SlowStopProtocol(stopping: newAsyncEvent(), release: newAsyncEvent())
  result.codec = ProtoCodec("/test/slow-stop/1.0.0")
  result.handler = proc(
      stream: Stream, proto: ProtoCodec
  ) {.async: (raises: [CancelledError]).} =
    await stream.close()

suite "Switch accept-loop failure handling":
  teardown:
    checkTrackers()

  asyncTest "accept raising exits the loop while the transport still looks reachable":
    # A failed accept must not consume inbound capacity.
    let (server, transport) = newStubAcceptSwitch(RaiseAlways, maxIn = 1)
    startAndDeferStop(@[server])

    # the loop calls accept, it raises, and the loop returns and is not respawned
    checkUntilTimeout:
      server.acceptFuts[0].finished
    check transport.acceptCalls == 1

    # yet the transport still reports running and its address stays advertised,
    # so the switch keeps looking reachable while nothing is accepting
    check transport.running
    check transport.addrs[0] in server.peerInfo.listenAddrs

    check server.connManager.availableSlots(Direction.In) == 1

  asyncTest "inbound connections are dropped after a transport's accept loop dies":
    let (server, transport) = newStubAcceptSwitch(RaiseAlways)
    let client = makeStandardSwitch(MemoryAutoAddress())
    startAndDeferStop(@[server, client])

    # wait until the server's accept loop has given up
    checkUntilTimeout:
      server.acceptFuts[0].finished

    # the server still advertises its address
    check transport.addrs[0] in server.peerInfo.listenAddrs
    # but nothing is accepting, so an inbound dial fails
    expect DialFailedError:
      await client.connect(server)

  asyncTest "TCP retries do not consume a slot and a one-slot switch recovers":
    let server = makeStandardSwitchBuilder(TcpAutoAddress).withMaxInOut(1, 8).build()
    let client = makeStandardSwitch(TcpAutoAddress)
    let transport = TcpTransport(server.transports[0])
    let pending = typeof(transport.acceptFuts[0]).init("test failed accept")
    pending.fail(newException(TransportTooManyError, "descriptor limit"))
    transport.acceptFuts = @[pending]
    startAndDeferStop(@[server, client])

    check transport.acceptFuts[0] != pending
    check not server.acceptFuts[0].finished
    check server.connManager.availableSlots(Direction.In) == 1
    await client.connect(server)
    check client.isConnected(server)
    check server.connManager.availableSlots(Direction.In) == 0

  asyncTest "rejecting a connection does not wait for its close":
    let (server, transport) =
      newStubAcceptSwitch(BlockingClose, maxIn = 1, acceptLimit = 2)
    let slot = await server.connManager.getIncomingSlot()
    defer:
      slot.release()
    startAndDeferStop(@[server])
    defer:
      transport.closeGate.fire()

    checkUntilTimeout:
      transport.closeCalls > 0
      transport.acceptCalls > 1

  asyncTest "pending rejected connection closes are bounded":
    let (server, transport) = newStubAcceptSwitch(
      BlockingClose, maxIn = 1, acceptLimit = ConcurrentUpgrades + 1
    )
    let slot = await server.connManager.getIncomingSlot()
    defer:
      slot.release()
    startAndDeferStop(@[server])
    defer:
      transport.closeGate.fire()

    checkUntilTimeout:
      transport.closeCalls == ConcurrentUpgrades
    await sleepAsync(100.millis)
    check transport.acceptCalls == ConcurrentUpgrades

  asyncTest "one transport's accept failure does not stop other transports from accepting":
    let (server, _) = newStubAcceptSwitch(RaiseAlways, withTcp = true)
    let client = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[server, client])

    # the memory transport's accept loop has died
    checkUntilTimeout:
      server.acceptFuts[0].finished

    # but the TCP transport still accepts connections
    let tcpAddrs = server.peerInfo.addrs.filterIt(TCP.match(it))
    await client.connect(server.peerInfo.peerId, tcpAddrs)
    check client.isConnected(server)

  asyncTest "accepts and registered upgrades drain before slow protocol teardown":
    let
      server = makeStandardSwitch(MemoryAutoAddress())
      client = makeStandardSwitch(MemoryAutoAddress())
      protocol = newSlowStopProtocol()
      registered = newAsyncEvent()
      releaseUpgrade = newAsyncEvent()

    proc onConnected(
        peerId: PeerId, event: ConnEvent
    ) {.async: (raises: [CancelledError]).} =
      registered.fire()
      await releaseUpgrade.wait()

    server.addConnEventHandler(onConnected, ConnEventKind.Connected)
    server.mount(protocol)
    startAndDeferStop(@[server, client])
    defer:
      releaseUpgrade.fire()
      protocol.release.fire()

    let connecting = client.connect(server)
    await registered.wait()
    check:
      server.pendingUpgrades == 1
      server.pendingUpgradesBySource.len == 0
    await connecting
    let conn = server.connManager.selectMuxer(client.peerInfo.peerId).connection
    check not conn.closed

    let stopped = server.stop()
    await protocol.stopping.wait()
    check:
      server.acceptFuts.allIt(it.finished)
      server.pendingUpgrades == 0
      server.pendingUpgradesBySource.len == 0
      conn.closed
      server.connManager.isRunning()
      not stopped.finished
    releaseUpgrade.fire()
    protocol.release.fire()
    await stopped
    check server.isStopping
    await server.start()
    check not server.isStopping

suite "Pending inbound upgrades":
  teardown:
    checkTrackers()

  asyncTest "one IP cannot fill inbound capacity or block outbound repair":
    let server = makeStandardSwitch(TcpAutoAddress)
    let peer = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[server, peer])
    var sockets: seq[StreamTransport]
    defer:
      for socket in sockets:
        await socket.closeWait()
    for _ in 0 ..< MaxPendingUpgradesPerSource + 4:
      sockets.add(await wire.connect(server.peerInfo.addrs[0]))
    check (await sockets[^1].read().wait(1.seconds)).len == 0
    checkUntilTimeout:
      server.pendingUpgrades == MaxPendingUpgradesPerSource
      server.upgradeFuts.len == MaxPendingUpgradesPerSource
      server.rejectedConnCloseFuts.allIt(it.finished)
    check server.connManager.availableSlots(Direction.In) ==
      server.connManager.maxConnections(Direction.In) - MaxPendingUpgradesPerSource
    await server.connect(peer)
    check:
      server.isConnected(peer)
      server.connManager.availableSlots(Direction.Out) ==
        server.connManager.maxConnections(Direction.Out) - MaxPendingUpgradesPerSource -
        1
    for socket in sockets:
      await socket.closeWait()
    checkUntilTimeout:
      server.pendingUpgrades == 0
      server.pendingUpgradesBySource.len == 0
    await peer.connect(server, reuseConnection = false)
    checkUntilTimeout:
      server.pendingUpgrades == 0
      server.connManager.availableSlots(Direction.In) ==
        server.connManager.maxConnections(Direction.In) - 2

  asyncTest "IPv6 address rotation within a /56 shares one pending budget":
    var sources: seq[MultiAddress]
    for i in 1 .. MaxPendingUpgradesPerSource:
      sources.add(ma("/ip6/2001:db8:1234:5600::" & $i & "/tcp/1"))
    sources.add(ma("/ip6/2001:db8:1234:56ff::1/tcp/2"))
    sources.add(ma("/ip6/2001:db8:1234:5700::1/tcp/1"))
    let server = SwitchBuilder
      .new()
      .withRng(rng())
      .withNoise()
      .withMplex()
      .withAddresses(@[MemoryAutoAddress()])
      .withTransport(
        proc(config: TransportConfig): Transport =
          let transport = SourceAddressTransport(
            upgrader: config.upgr, rng: rng(), sourceAddresses: sources
          )
          transport.initialize()
          transport
      )
      .build()
    let peer = makeStandardSwitch(MemoryAutoAddress())
    startAndDeferStop(@[server, peer])
    var connections: seq[RawConn]
    defer:
      for conn in connections:
        await conn.close()
    for _ in sources:
      connections.add(await peer.transports[0].dial("", server.peerInfo.addrs[0]))
      checkUntilTimeout:
        SourceAddressTransport(server.transports[0]).accepted == connections.len
    checkUntilTimeout:
      server.pendingUpgrades == MaxPendingUpgradesPerSource + 1
      server.pendingUpgradesBySource.len == 2
    check server.connManager.availableSlots(Direction.In) ==
      server.connManager.maxConnections(Direction.In) - MaxPendingUpgradesPerSource - 1
    for conn in connections:
      await conn.close()
    checkUntilTimeout:
      server.pendingUpgrades == 0
      server.pendingUpgradesBySource.len == 0

  asyncTest "connections without an IP use only the global pending budget":
    let server =
      makeStandardSwitchBuilder(MemoryAutoAddress()).withMaxInOut(20, 2).build()
    let peer = makeStandardSwitch(MemoryAutoAddress())
    startAndDeferStop(@[server, peer])
    var connections: seq[RawConn]
    defer:
      for conn in connections:
        await conn.close()
    for _ in 0 ..< 10:
      connections.add(await peer.transports[0].dial("", server.peerInfo.addrs[0]))
      await idleAsync()
    checkUntilTimeout:
      server.pendingUpgrades == 10
    check server.pendingUpgradesBySource.len == 0
    let rejected = await peer.transports[0].dial("", server.peerInfo.addrs[0])
    connections.add(rejected)
    var buffer: byte
    check (await rejected.readOnce(addr buffer, 1).wait(1.seconds)) == 0
    check server.pendingUpgrades == 10
    for conn in connections:
      await conn.close()
    checkUntilTimeout:
      server.pendingUpgrades == 0
      server.pendingUpgradesBySource.len == 0

  asyncTest "pending budget is shared across transports and leaves inbound capacity":
    let server = makeStandardSwitchBuilder(@[MemoryAutoAddress(), TcpAutoAddress])
      .withMaxInOut(2, 2)
      .build()
    let peer = makeStandardSwitch(MemoryAutoAddress())
    startAndDeferStop(@[server, peer])
    let memoryAddr = server.peerInfo.addrs.filterIt(Memory.match(it))[0]
    let tcpAddr = server.peerInfo.addrs.filterIt(TCP.match(it))[0]
    let first = await peer.transports[0].dial("", memoryAddr)
    defer:
      await first.close()
    checkUntilTimeout:
      server.pendingUpgrades == 1
    let second = await wire.connect(tcpAddr)
    defer:
      await second.closeWait()
    check (await second.read().wait(1.seconds)).len == 0
    check:
      server.pendingUpgrades == 1
      server.connManager.availableSlots(Direction.In) == 1

  asyncTest "idle upgrades expire before the full upgrade deadline":
    let server = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[server])
    let socket = await wire.connect(server.peerInfo.addrs[0])
    defer:
      await socket.closeWait()
    checkUntilTimeout:
      server.pendingUpgrades == 1
    checkUntilTimeoutCustom(IncomingUpgradeTimeout + 2.seconds, 50.milliseconds):
      server.pendingUpgrades == 0
      server.pendingUpgradesBySource.len == 0
      server.connManager.availableSlots(Direction.In) ==
        server.connManager.maxConnections(Direction.In)

  asyncTest "stop cancels pending upgrades and restart restores their budget":
    let server = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[server])
    let socket = await wire.connect(server.peerInfo.addrs[0])
    defer:
      await socket.closeWait()
    checkUntilTimeout:
      server.pendingUpgrades == 1
    await server.stop()
    check:
      server.pendingUpgrades == 0
      server.pendingUpgradesBySource.len == 0
      server.connManager.availableSlots(Direction.In) ==
        server.connManager.maxConnections(Direction.In)
    await server.start()
    let peer = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[peer])
    await peer.connect(server)
    check peer.isConnected(server)
