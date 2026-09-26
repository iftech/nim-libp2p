# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[net, sequtils]
import chronos, results
import ../../../libp2p/[builders, switch, multiaddress, multicodec, peerinfo, wire]
import ../../../libp2p/services/natservice
import ../../../libp2p/services/nat/portmapper
import ../../../libp2p/protocols/connectivity/dcutr/core
import ../../tools/[unittest, multiaddress, switch_builder]

type
  MockCallKind = enum
    mckMap
    mckUnmap
    mckClose

  MockCall = object
    kind: MockCallKind
    internalPort: Port
    externalPort: Port
    proto: MapProto

  MockPortMapper = ref object of PortMapper
    extIp: IpAddress
    extPortQueue: seq[Port] ## ports handed out in order; once empty, echo request
    extPortIdx: int
    mapErr: Opt[string]
    calls: seq[MockCall]

proc newMock(
    extIp = parseIpAddress("203.0.113.7"),
    extPorts: seq[Port] = @[],
    mapErr = Opt.none(string),
): MockPortMapper =
  MockPortMapper(extIp: extIp, mapErr: mapErr, extPortQueue: extPorts)

proc mapperFactory(m: MockPortMapper): PortMapperFactory =
  proc(mode: PortMappingMode): Opt[PortMapper] {.gcsafe, raises: [].} =
    Opt.some(PortMapper(m))

method map*(
    self: MockPortMapper, internalPort: Port, externalPort: Port, proto: MapProto
): Future[LPResult[MappedPort]] {.async: (raises: [CancelledError]), gcsafe.} =
  let assigned =
    if self.extPortIdx < self.extPortQueue.len:
      let p = self.extPortQueue[self.extPortIdx]
      self.extPortIdx.inc
      p
    else:
      externalPort
  self.calls.add(
    MockCall(
      kind: mckMap, internalPort: internalPort, externalPort: assigned, proto: proto
    )
  )
  if self.mapErr.isSome:
    return err(self.mapErr.get())
  ok(MappedPort(externalIp: self.extIp, externalPort: assigned))

method unmap*(
    self: MockPortMapper, externalPort: Port, proto: MapProto
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  self.calls.add(MockCall(kind: mckUnmap, externalPort: externalPort, proto: proto))
  ok()

method close*(self: MockPortMapper) {.async: (raises: []), gcsafe.} =
  self.calls.add(MockCall(kind: mckClose))

proc callsOfKind(m: MockPortMapper, kind: MockCallKind): seq[MockCall] =
  m.calls.filterIt(it.kind == kind)

proc countCalls(m: MockPortMapper, kind: MockCallKind): int =
  m.callsOfKind(kind).len

proc mapCalls(m: MockPortMapper): seq[MockCall] =
  m.callsOfKind(mckMap)

proc unmapCalls(m: MockPortMapper): seq[MockCall] =
  m.callsOfKind(mckUnmap)

proc unmappedPorts(m: MockPortMapper): seq[Port] =
  m.unmapCalls.mapIt(it.externalPort)

proc closed(m: MockPortMapper): bool =
  m.countCalls(mckClose) > 0

proc standardBuilder(listenAddrs: seq[MultiAddress]): SwitchBuilder =
  makeStandardSwitchBuilder(listenAddrs).withWildcardResolver(false)

proc makeSwitch(
    config: NATConfig,
    listenAddrs: seq[MultiAddress],
    portMapperFactory: PortMapperFactory = nil,
): Switch {.raises: [LPError].} =
  standardBuilder(listenAddrs).withNAT(config, portMapperFactory).build()

proc findNatService(switch: Switch): NATService =
  switch.natService().valueOr:
    raiseAssert "NATService not found in switch.services"

proc noopReachabilityHandler(
    reachability: NetworkReachability,
    confidence: Opt[float],
    dialBackAddr: Opt[MultiAddress],
) {.async: (raises: [CancelledError]).} =
  discard

suite "NATService":
  teardown:
    checkTrackers()

  test "explicitIpMapped preserves port and suffix; drops mismatching family":
    let
      ip4 = parseIpAddress("203.0.113.7")
      ip6 = parseIpAddress("2001:db8::1")
      mixed = @[
        ma("/ip4/127.0.0.1/tcp/1234"),
        ma("/ip4/127.0.0.1/tcp/80/ws"),
        ma("/ip4/127.0.0.1/tcp/80/tls/ws"),
        ma("/ip4/127.0.0.1/udp/9000/quic-v1"),
        ma("/ip6/::1/tcp/1234"),
        ma("/unix/tmp/sock"),
      ]
    check:
      explicitIpMapped(mixed, ip4) ==
        @[
          ma("/ip4/203.0.113.7/tcp/1234"),
          ma("/ip4/203.0.113.7/tcp/80/ws"),
          ma("/ip4/203.0.113.7/tcp/80/tls/ws"),
          ma("/ip4/203.0.113.7/udp/9000/quic-v1"),
        ]
      explicitIpMapped(mixed, ip6) == @[ma("/ip6/2001:db8::1/tcp/1234")]
      explicitIpMapped(@[ma("/unix/tmp/sock")], ip4).len == 0

  test "explicitIpMapped dedupes addresses sharing port across interfaces":
    let
      ip4 = parseIpAddress("203.0.113.7")
      resolved = @[ma("/ip4/192.168.1.10/tcp/50000"), ma("/ip4/10.0.0.5/tcp/50000")]
    check explicitIpMapped(resolved, ip4) == @[ma("/ip4/203.0.113.7/tcp/50000")]

  asyncTest "ExplicitIp announces the explicit IP with bound ports":
    let
      explicitIp = parseIpAddress("203.0.113.7")
      cfg = explicitIpConfig(explicitIp)
      switch = makeSwitch(cfg, @[TcpAutoAddress])

    await switch.start()
    defer:
      await switch.stop()

    check switch.peerInfo.listenAddrs.len == 1
    let boundPort = switch.peerInfo.listenAddrs[0][multiCodec("tcp")].get
    let expected = ma("/ip4/" & $explicitIp & $boundPort)

    check switch.peerInfo.addrs == @[expected]

  asyncTest "empty NATConfig is a no-op on announced addresses":
    let
      cfg = NATConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress])

    await switch.start()
    defer:
      await switch.stop()

    check switch.peerInfo.announcedAddrs.len == 0
    # addrs falls back to mapper-chain output (which here is just listenAddrs).
    check switch.peerInfo.addrs == switch.peerInfo.listenAddrs
    # No reachability config, so there is nothing to subscribe to.
    let nat = findNatService(switch)
    check:
      not nat.addReachabilityHandler(noopReachabilityHandler)
      nat.networkReachability == NetworkReachability.Unknown

  asyncTest "Upnp maps private listen addrs to extIp/extPort":
    let mock = newMock()
    let factory = mapperFactory(mock)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    # Start ran addressMapper against loopback listenAddrs which findMappable
    # filters out, so no map yet.
    check mock.calls.len == 0
    check switch.peerInfo.addressMappers.len == 1

    let announced =
      await switch.peerInfo.addressMappers[0](@[ma("/ip4/192.168.1.10/tcp/4242")])
    check announced == @[ma("/ip4/203.0.113.7/tcp/4242")]
    check mock.countCalls(mckMap) == 1

  asyncTest "Upnp preserves already-public listenAddrs alongside mapped ones":
    let mock = newMock(extPorts = @[Port(9000)])
    let factory = mapperFactory(mock)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    let
      pub = ma("/ip4/198.51.100.5/tcp/4001")
      priv = ma("/ip4/192.168.1.10/tcp/4242")
      announced = await switch.peerInfo.addressMappers[0](@[pub, priv])
    check:
      pub in announced
      ma("/ip4/203.0.113.7/tcp/9000") in announced

  asyncTest "Upnp unmaps stale extPort when IGD reassigns on refresh":
    let mock = newMock(extPorts = @[Port(9000), Port(9001)])
    let factory = mapperFactory(mock)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    let priv = @[ma("/ip4/192.168.1.10/tcp/4242")]
    let first = await switch.peerInfo.addressMappers[0](priv)
    let second = await switch.peerInfo.addressMappers[0](priv)

    check first == @[ma("/ip4/203.0.113.7/tcp/9000")]
    check second == @[ma("/ip4/203.0.113.7/tcp/9001")]
    # extPort changed between refreshes — old mapping (9000) must be unmapped.
    check Port(9000) in mock.unmappedPorts()
    check Port(9001) notin mock.unmappedPorts()

  asyncTest "Upnp unmaps everything when private listenAddrs disappear":
    let mock = newMock(extPorts = @[Port(7000)])
    let factory = mapperFactory(mock)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    discard await switch.peerInfo.addressMappers[0](@[ma("/ip4/192.168.1.10/tcp/4242")])
    discard await switch.peerInfo.addressMappers[0](@[])

    check Port(7000) in mock.unmappedPorts()

  asyncTest "Upnp inactive when factory returns none":
    let factory: PortMapperFactory = proc(
        mode: PortMappingMode
    ): Opt[PortMapper] {.gcsafe, raises: [].} =
      Opt.none(PortMapper)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    # No addressMapper installed; peerInfo.addrs falls back to listenAddrs.
    check switch.addressManager.mapperSources().len == 0
    check switch.peerInfo.addrs == switch.peerInfo.listenAddrs

  asyncTest "stop unmaps active mappings and closes the mapper":
    let mock = newMock(extPorts = @[Port(5555)])
    let factory = mapperFactory(mock)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    discard await switch.peerInfo.addressMappers[0](@[ma("/ip4/192.168.1.10/tcp/4242")])
    await switch.stop()

    check Port(5555) in mock.unmappedPorts()
    check mock.countCalls(mckClose) == 1

  asyncTest "setup raises when config has zero discoveryTimeout":
    let cfg = natPmpConfig(discoveryTimeout = 0.seconds)
    expect ServiceSetupError:
      discard makeSwitch(cfg, @[TcpAutoAddress])

  asyncTest "setup raises when config has zero mappingTimeout":
    let cfg = upnpConfig(mappingTimeout = 0.seconds)
    expect ServiceSetupError:
      discard makeSwitch(cfg, @[TcpAutoAddress])

  asyncTest "factory receives the configured mode":
    var seenMode = Upnp
    let mock = newMock()
    let factory: PortMapperFactory = proc(
        mode: PortMappingMode
    ): Opt[PortMapper] {.gcsafe, raises: [].} =
      seenMode = mode
      Opt.some(PortMapper(mock))

    let switch = makeSwitch(natPmpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    check seenMode == NatPmp

  asyncTest "map failure leaves no stale entry; announced falls through":
    let mock = newMock(extPorts = @[Port(8000)], mapErr = Opt.some("mapping refused"))
    let factory = mapperFactory(mock)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    let priv = @[ma("/ip4/192.168.1.10/tcp/4242")]
    let res = await switch.peerInfo.addressMappers[0](priv)
    # No successful mapping → addressMapper falls back to listenAddrs unchanged.
    check res == priv
    check mock.countCalls(mckMap) == 1
    check mock.unmappedPorts().len == 0

  asyncTest "non-IPv4 private addrs are skipped":
    # libplum maps IPv4 only, so any IPv6 listenAddr must be filtered before map().
    let mock = newMock()
    let factory = mapperFactory(mock)

    let switch = makeSwitch(upnpConfig(), @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    let res = await switch.peerInfo.addressMappers[0](@[ma("/ip6/fc00::1/tcp/4242")])
    check res == @[ma("/ip6/fc00::1/tcp/4242")] # fall-through, no map()
    check mock.countCalls(mckMap) == 0

  proc dcutrMounted(switch: Switch): bool =
    switch.ms.handlers.anyIt(DcutrCodec in it.protos)

  asyncTest "autonat v1 spins up the AutonatService":
    let switch = makeSwitch(autonatConfig(AutonatV1), @[TcpAutoAddress])
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.addReachabilityHandler(noopReachabilityHandler)
      nat.autonatV2Service.isNone()
      not dcutrMounted(switch)
      # AutonatService registers exactly one reachability addressMapper.
      switch.peerInfo.addressMappers.len == 1
      nat.networkReachability == NetworkReachability.Unknown

  asyncTest "autonat v2 spins up the AutonatV2 service":
    let switch = makeSwitch(autonatConfig(AutonatV2), @[TcpAutoAddress])
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.addReachabilityHandler(noopReachabilityHandler)
      nat.autonatV2Service.isSome()
      not dcutrMounted(switch)
      nat.networkReachability == NetworkReachability.Unknown

  asyncTest "holePunchingConfig composes the full HP stack":
    let switch = makeSwitch(holePunchingConfig(maxNumRelays = 2), @[TcpAutoAddress])
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.addReachabilityHandler(noopReachabilityHandler)
      # HPService mounts DCUtR and drives AutoNAT v1, not v2.
      dcutrMounted(switch)
      nat.autonatV2Service.isNone()
      nat.networkReachability == NetworkReachability.Unknown

  test "hole-punching paired with AutonatV2 reachability is rejected at setup":
    # The realistic path: two withNAT calls for the conflicting concerns.
    expect ServiceSetupError:
      discard standardBuilder(@[TcpAutoAddress])
        .withNAT(holePunchingConfig())
        .withNAT(autonatConfig(AutonatV2))
        .build()

  asyncTest "Upnp combined with autonat v1 wires both subsystems":
    # NATConfig keeps mode (port-mapping) and autonat orthogonal: enabling
    # both must spin up the UPnP addressMapper *and* the AutonatService.
    let mock = newMock()
    let factory = mapperFactory(mock)

    var cfg = upnpConfig()
    cfg.reachability = autonatConfig(AutonatV1).reachability

    let switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.autonatV2Service.isNone()
      # UPnP addressMapper from NATService + AutoNAT v1 mapper both registered.
      switch.addressManager.mapperSources() == @[AddrSource.Upnp, AddrSource.Autonat]

  asyncTest "autonat v1 survives stop/start cycle":
    let switch = makeSwitch(autonatConfig(AutonatV1), @[TcpAutoAddress])
    await switch.start()
    await switch.stop()
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.autonatV2Service.isNone()
      switch.peerInfo.addressMappers.len == 1

  asyncTest "autonat v2 survives stop/start cycle":
    let switch = makeSwitch(autonatConfig(AutonatV2), @[TcpAutoAddress])
    await switch.start()
    await switch.stop()
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.autonatV2Service.isSome()

  asyncTest "deprecated withAutonatV2 still wires the v2 service":
    {.push warning[Deprecated]: off.}
    let switch = standardBuilder(@[TcpAutoAddress]).withAutonatV2().build()
    {.pop.}
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.autonatV2Service.isSome()
      not dcutrMounted(switch)

  asyncTest "deprecated withHolePunching still composes the HP stack":
    {.push warning[Deprecated]: off.}
    let switch = standardBuilder(@[TcpAutoAddress]).withHolePunching(2, nil).build()
    {.pop.}
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      dcutrMounted(switch)
      nat.autonatV2Service.isNone()

  asyncTest "withNAT can be called once per distinct concern":
    let mock = newMock()
    let factory = mapperFactory(mock)

    let switch = standardBuilder(@[TcpAutoAddress])
      .withNAT(upnpConfig(), factory)
      .withNAT(autonatConfig(AutonatV1))
      .build()
    await switch.start()
    defer:
      await switch.stop()

    let nat = findNatService(switch)
    check:
      nat.autonatV2Service.isNone()
      # UPnP addressMapper + AutoNAT v1 mapper both registered.
      switch.addressManager.mapperSources() == @[AddrSource.Upnp, AddrSource.Autonat]

  test "withNAT configuring the same concern twice is a programmer error":
    expect AssertionDefect:
      discard standardBuilder(@[TcpAutoAddress])
        .withNAT(autonatConfig(AutonatV1))
        .withNAT(autonatConfig(AutonatV2))

proc privateAddr(port: int = 9000): MultiAddress =
  ma("/ip4/192.168.1.5/tcp/" & $port)

suite "NATService (setupMappings)":
  teardown:
    checkTrackers()

  asyncTest "NatPmp announces external IP after successful mapping":
    let
      externalIp = parseIpAddress("203.0.113.99")
      mapper = newMock(extIp = externalIp)
      factory = mapperFactory(mapper)
      cfg = natPmpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
      svc = findNatService(switch)

    await switch.start()
    defer:
      await switch.stop()

    let announced = await svc.setupMappings(@[privateAddr(9000)])
    check announced.len == 1
    check svc.externalIp.isSome
    check svc.externalIp.get() == externalIp

  asyncTest "an external IPv6 from the IGD maps the port but announces nothing":
    # the port mapping still succeeds, but a v6 external IP has no announced form
    # on a v4 listen address, so the mapping produces no announced address
    let
      externalIp = parseIpAddress("2001:db8::1")
      mapper = newMock(extIp = externalIp)
      factory = mapperFactory(mapper)
      cfg = upnpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
      svc = findNatService(switch)

    await switch.start()
    defer:
      await switch.stop()

    let announced = await svc.setupMappings(@[privateAddr(9000)])
    check announced.len == 0
    check mapper.mapCalls.len == 1

  asyncTest "non-private listen addresses are skipped":
    let
      externalIp = parseIpAddress("203.0.113.1")
      mapper = newMock(extIp = externalIp)
      factory = mapperFactory(mapper)
      cfg = upnpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
      svc = findNatService(switch)

    await switch.start()
    defer:
      await switch.stop()

    # Public + loopback addresses only → no mappable ports, no mappings made.
    let announced = await svc.setupMappings(
      @[ma("/ip4/8.8.8.8/tcp/9000"), ma("/ip4/127.0.0.1/tcp/9001")]
    )

    check mapper.mapCalls.len == 0
    check announced.len == 0

  asyncTest "user-set announcedAddrs are not overwritten":
    let
      externalIp = parseIpAddress("203.0.113.111")
      userAddr = ma("/ip4/198.51.100.7/tcp/4242")
      mapper = newMock(extIp = externalIp)
      factory = mapperFactory(mapper)
      cfg = upnpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)

    switch.peerInfo.announcedAddrs = @[userAddr]

    await switch.start()
    defer:
      await switch.stop()

    check switch.peerInfo.announcedAddrs == @[userAddr]
    # expandAddrs uses announcedAddrs directly when set, bypassing the
    # addressMapper chain — so the mapper should never have been consulted.
    check mapper.mapCalls.len == 0

  asyncTest "multiple private listen addresses are each mapped once":
    let
      externalIp = parseIpAddress("203.0.113.10")
      mapper = newMock(extIp = externalIp)
      factory = mapperFactory(mapper)
      cfg = upnpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
      svc = findNatService(switch)

    await switch.start()
    defer:
      await switch.stop()

    let
      tcpAddr = privateAddr(9000)
      udpAddr = ma("/ip4/192.168.1.5/udp/9000")
      otherTcp = privateAddr(9001)
      announced = await svc.setupMappings(@[tcpAddr, udpAddr, otherTcp])

    # One map call per listen address.
    check mapper.mapCalls.len == 3
    check announced.len == 3
    # TCP+UDP on the same port are two distinct (port, proto) mappings.
    let protos = mapper.mapCalls.mapIt(it.proto)
    check mpTcp in protos
    check mpUdp in protos

  asyncTest "setupMappings unmaps stale ports when a listen addr is removed":
    let
      externalIp = parseIpAddress("203.0.113.20")
      mapper = newMock(extIp = externalIp)
      factory = mapperFactory(mapper)
      cfg = upnpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
      svc = findNatService(switch)

    await switch.start()
    defer:
      await switch.stop()

    # First cycle: two private addresses mapped.
    discard await svc.setupMappings(@[privateAddr(9000), privateAddr(9001)])
    check mapper.mapCalls.len == 2
    check mapper.unmapCalls.len == 0

    # Second cycle: one of them is gone. unmapStale must clean it up.
    discard await svc.setupMappings(@[privateAddr(9000)])
    check mapper.unmapCalls.len == 1
    check mapper.unmapCalls[^1].externalPort == Port(9001)
    check mapper.unmapCalls[^1].proto == mpTcp

  asyncTest "IGD returning a different external port surfaces in announced":
    let
      externalIp = parseIpAddress("203.0.113.30")
      # queued external port simulates the IGD remapping to a different port.
      mapper = newMock(extIp = externalIp, extPorts = @[Port(54321)])
      factory = mapperFactory(mapper)
      cfg = upnpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
      svc = findNatService(switch)

    await switch.start()
    defer:
      await switch.stop()

    let announced = await svc.setupMappings(@[privateAddr(9000)])
    check announced.len == 1
    let annTa = initTAddress(announced[0]).tryGet()
    check annTa.address_v4 == externalIp.address_v4
    check annTa.port == Port(54321)

  asyncTest "NatPmp mapping failure leaves announced empty":
    let
      cfg = natPmpConfig()
      mapper = newMock(mapErr = Opt.some("mock no IGD"))
      switch = makeSwitch(cfg, @[TcpAutoAddress], mapperFactory(mapper))
      svc = findNatService(switch)

    await switch.start()
    defer:
      await switch.stop()

    let announced = await svc.setupMappings(@[privateAddr(9000)])
    check announced.len == 0
    check svc.externalIp.isNone

  asyncTest "NatPmp stop unmaps all created mappings":
    let
      externalIp = parseIpAddress("203.0.113.40")
      mapper = newMock(extIp = externalIp)
      factory = mapperFactory(mapper)
      cfg = natPmpConfig()
      switch = makeSwitch(cfg, @[TcpAutoAddress], factory)
      svc = findNatService(switch)

    await switch.start()

    discard await svc.setupMappings(@[privateAddr(9000)])
    let mapsBefore = mapper.mapCalls.len

    await switch.stop()

    check mapsBefore >= 1
    check mapper.unmapCalls.len == mapsBefore
    check mapper.closed
