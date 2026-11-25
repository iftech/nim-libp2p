# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils, tables]
import chronos
import chronos/transports/osnet
import ../../../libp2p/[switch, peerinfo, peerstore, utils/future]
import ../../../libp2p/services/mdns
import ../../../libp2p/services/mdns/ratelimit
import ../../../libp2p/peeraddrpolicy
import ../../../libp2p/services/mdns/network
import ../../../libp2p/nameresolving/dnsmessage
import ../../tools/[unittest, crypto, mdns_sender, multiaddress, switch_builder]

when defined(macosx):
  from std/posix import nil

const
  FixturePort = 12345
  FixtureAddress = "/ip4/192.168.1.2/tcp/" & $FixturePort
  FixtureInstance = "test-peer"
  PeerInstance = "peer"
  DnsAddressPrefix = "dnsaddr="
  PeerIdSuffix = "/p2p/"
  PrivateAddress = "/ip4/192.168.1.2/tcp/4001"
  AlternatePrivateAddress = "/ip4/10.0.0.1/tcp/4001"
  PrivateIpv6Address = "/ip6/fd00::1/tcp/4001"
  WildcardAddress = "/ip4/0.0.0.0/tcp/4001"
  EphemeralWildcardAddress = "/ip4/0.0.0.0/tcp/0"
  InterfaceIp = "10.20.30.40"
  ServiceLabels = ["_p2p", "_udp", "local"]
  FixturePeerId = "12D3KooWSCxTfVvMBJbpF75PQmnFdxdBfC1ZxAGYbFc3U9MjALXz"
  # Independently assembled DNS-SD response using compressed names, go-libp2p's
  # dnsaddr TXT convention and its fixed SRV port 4001. This is not a capture.
  # https://github.com/libp2p/go-libp2p/blob/v0.47.0/p2p/discovery/mdns/mdns.go
  SyntheticResponseHex =
    "000084000000000100000003045f703270045f756470056c6f63616c00000c000100000078" &
    "000c09746573742d70656572c00c09746573742d70656572056c6f63616c0000018001" &
    "000000780004c0a80102c02700218001000000780017000000000fa109746573742d" &
    "70656572056c6f63616c00c0270010800100000078005c5b646e73616464723d2f697034" &
    "2f3139322e3136382e312e322f7463702f31323334352f7032702f313244334b6f6f5753" &
    "4378546656764d424a627046373550516d6e46647864426643315a784147596246633355" &
    "394d6a414c587a"
  # Expected uncompressed DNS-SD announcement for the same fixed peer/address.
  AnnouncementHex =
    "000084000000000100000003045f703270045f756470056c6f63616c00000c000100000078" &
    "001b09746573742d70656572045f703270045f756470056c6f63616c0009746573742d" &
    "70656572056c6f63616c0000018001000000780004c0a8010209746573742d70656572" &
    "045f703270045f756470056c6f63616c0000218001000000780017000000003039097465" &
    "73742d70656572056c6f63616c0009746573742d70656572045f703270045f75647005" &
    "6c6f63616c000010800100000078005c5b646e73616464723d2f6970342f3139322e31" &
    "36382e312e322f7463702f31323334352f7032702f313244334b6f6f57534378546656" &
    "764d424a627046373550516d6e46647864426643315a784147596246633355394d6a414c587a"

proc packet(hex: string): seq[byte] =
  hex.parseHexStr().mapIt(byte(it))

const MdnsMulticastAddress = "224.0.0.251"

proc sendMulticast(sender: DatagramTransport, payload: seq[byte]) {.async.} =
  await sender.sendTo(initTAddress(MdnsMulticastAddress, Port(MdnsPort)), payload)

proc sendMulticast(sender: DatagramTransport, message: DnsMessage) {.async.} =
  await sender.sendMulticast(encodeMessage(message))

proc sendSyntheticResponse(sender: DatagramTransport) {.async.} =
  await sender.sendMulticast(packet(SyntheticResponseHex))

proc ignoreDatagram(
    t: DatagramTransport, remote: TransportAddress
) {.async: (raises: []).} =
  discard

template newMulticastSender(
    callback: DatagramCallback = ignoreDatagram
): DatagramTransport =
  newMdnsTestSender(callback)

template requireStarted(service, node: untyped) =
  block:
    let started = await service.tryStart(node)
    if started.isErr:
      checkpoint "mDNS startup failed: " & $started.error
    require started.isOk

suite "mDNS discovery":
  teardown:
    checkTrackers()

  test "multicast response limits are independent for IPv4 and IPv6":
    var limits: MulticastLimits
    let now = Moment.now()
    check limits.acquire(false, now)
    check not limits.acquire(false, now)
    check limits.acquire(true, now)
    check not limits.acquire(true, now)
    limits.finish(false, true, now, MdnsResponseInterval)
    limits.finish(true, false, now, MdnsResponseInterval)
    check not limits.acquire(false, now)
    check limits.acquire(true, now)
    limits.finish(true, true, now, MdnsResponseInterval)
    check not limits.acquire(true, now)
    check limits.acquire(false, now + MdnsResponseInterval)
    check limits.acquire(true, now + MdnsResponseInterval)

  test "multicast response limits are independent per interface":
    var limits: Table[uint32, MulticastLimits]
    let now = Moment.now()
    check limits.mgetOrPut(1, default(MulticastLimits)).acquire(false, now)
    check not limits.mgetOrPut(1, default(MulticastLimits)).acquire(false, now)
    check limits.mgetOrPut(2, default(MulticastLimits)).acquire(false, now)
    limits[1].finish(false, true, now, MdnsResponseInterval)
    limits[2].finish(false, true, now, MdnsResponseInterval)
    check not limits[1].acquire(false, now)
    check not limits[2].acquire(false, now)
    check limits[1].acquire(false, now + MdnsResponseInterval)
    check limits[2].acquire(false, now + MdnsResponseInterval)

  test "removed interface limits are discarded even with a pending reply":
    let
      limits = newInterfaceLimits()
      now = Moment.now()
      old = limits.get(1)
      retained = limits.get(2)
    check old[].acquire(false, now)
    check retained[].acquire(false, now)
    limits.prune([2'u32])
    let replacement = limits.get(1)
    check replacement[].acquire(false, now)
    old[].finish(false, true, now, MdnsResponseInterval)
    replacement[].finish(false, false, now, MdnsResponseInterval)
    check replacement[].acquire(false, now)
    check not limits.get(2)[].acquire(false, now)

  test "DNS-SD records round trip and group peer addresses":
    let
      service = MdnsService.new()
      id = PeerId.random()
      local = PeerId.random()
      addresses = @[ma(FixtureAddress), ma("/ip6/fd00::1/udp/4001/quic-v1")]
      peer = PeerInfo(peerId: id, listenAddrs: addresses)
      message = parseMessage(encodeMessage(service.announcement(peer, FixtureInstance)))
      found = service.peers(message, local)
    check:
      message.response
      message.answers.mapIt(it.kind) == @[PTR]
      message.answers.mapIt(it.name) == @[@ServiceLabels]
      message.additionals.anyIt(it.kind == SRV and it.port == FixturePort)
      message.additionals.anyIt(it.kind == A)
      message.additionals.anyIt(it.kind == AAAA)
      found == @[MdnsPeer(peerId: id, addrs: addresses)]
      service.peers(message, id).len == 0

  test "decode compressed DNS-SD response with go-libp2p TXT layout":
    let
      service = MdnsService.new()
      id = PeerId.init(FixturePeerId).get()
      message = parseMessage(packet(SyntheticResponseHex))
    check service.peers(message, PeerId.random()) ==
      @[MdnsPeer(peerId: id, addrs: @[ma(FixtureAddress)])]

  test "announcement matches fixed DNS-SD wire bytes":
    let
      peer = PeerInfo(
        peerId: PeerId.init(FixturePeerId).get(), listenAddrs: @[ma(FixtureAddress)]
      )
      announcement = MdnsService.new().announcement(peer, FixtureInstance)
    check encodeMessage(announcement) == packet(AnnouncementHex)

  test "ignore unrelated services, queries, expired and invalid TXT entries":
    let
      service = MdnsService.new()
      id = PeerId.random()
      local = PeerId.random()
      text = DnsAddressPrefix & PrivateAddress & PeerIdSuffix & $id
    var message = DnsMessage(
      response: true,
      additionals: @[
        DnsRecord(
          name: @[PeerInstance] & @ServiceLabels,
          kind: TXT,
          ttl: 120,
          strings: @[
            "other=value",
            "dnsaddr=invalid",
            text,
            text,
            DnsAddressPrefix & PrivateAddress,
            text & "/tcp/4002",
            text & PeerIdSuffix & $id,
          ],
        )
      ],
    )
    check service.peers(message, local) ==
      @[MdnsPeer(peerId: id, addrs: @[ma(PrivateAddress)])]
    message.response = false
    check service.peers(message, local).len == 0
    message.response = true
    message.additionals[0].ttl = 0
    check service.peers(message, local).len == 0
    message.additionals[0].ttl = 120
    message.additionals[0].name = @[PeerInstance, "_other", "_udp", "local"]
    check service.peers(message, local).len == 0

  test "accept usable IP transport addresses regardless of IP range":
    let
      service = MdnsService.new()
      id = PeerId.random()
      local = PeerId.random()
      accepted = @[
        AlternatePrivateAddress, "/ip4/169.254.1.2/tcp/4001", PrivateIpv6Address,
        "/ip6/fe80::1/tcp/4001", "/ip4/8.8.8.8/tcp/4001",
        "/ip6/2606:4700::1111/tcp/4001",
      ]
      rejected = @[
        "/ip4/127.0.0.1/tcp/4001", "/ip6/::1/tcp/4001",
        "/ip6/::ffff:127.0.0.1/tcp/4001", WildcardAddress, "/ip4/224.0.0.1/tcp/4001",
        "/dns4/example.com/tcp/4001", "/ip4/10.0.0.1/tcp/0",
      ]
    var strings: seq[string]
    for address in accepted & rejected:
      strings.add(DnsAddressPrefix & address & PeerIdSuffix & $id)
    let message = DnsMessage(
      response: true,
      additionals: @[
        DnsRecord(
          name: @[PeerInstance] & @ServiceLabels, kind: TXT, ttl: 120, strings: strings
        )
      ],
    )
    check service.peers(message, local) ==
      @[MdnsPeer(peerId: id, addrs: accepted.mapIt(ma(it)))]

    # Wildcard binds expand to host interfaces before filtering.
    let concrete = rejected.filterIt(it != WildcardAddress) & accepted
    let peer = PeerInfo(peerId: id, listenAddrs: concrete.mapIt(ma(it)))
    let announcement = service.announcement(peer, PeerInstance)
    let txt = announcement.additionals.filterIt(it.kind == TXT)
    check:
      txt.mapIt(it.strings) ==
        @[accepted.mapIt(DnsAddressPrefix & it & PeerIdSuffix & $id)]
      service.peers(announcement, local) ==
        @[MdnsPeer(peerId: id, addrs: accepted.mapIt(ma(it)))]
      announcement.additionals.filterIt(it.kind == A or it.kind == AAAA).len ==
        accepted.len

    peer.listenAddrs = @[ma(WildcardAddress), ma("/ip6/::/tcp/4001")]
    let wildcard = service.announcement(peer, PeerInstance)
    for record in wildcard.additionals:
      check record.address notin ["127.0.0.1", "::1"]
      for text in record.strings:
        check "/ip4/127." notin text and "/ip6/::1/" notin text

  test "announcements expand wildcard addresses using the configured interfaces":
    const Address = initTAddress(InterfaceIp & ":0")
    proc interfaces(
        family: AddressFamily
    ): seq[InterfaceAddress] {.gcsafe, raises: [].} =
      if family == AddressFamily.IPv4:
        @[InterfaceAddress.init(Address, 24)]
      else:
        @[]

    let
      service = MdnsService.new(networkInterfaceProvider = interfaces)
      peer = PeerInfo(peerId: PeerId.random(), listenAddrs: @[ma(WildcardAddress)])
      message = service.announcement(peer, PeerInstance)
    check service.peers(message, PeerId.random()) ==
      @[
        MdnsPeer(peerId: peer.peerId, addrs: @[ma("/ip4/" & InterfaceIp & "/tcp/4001")])
      ]

  test "custom service names and case insensitive DNS names":
    let
      service = MdnsService.new(serviceName = "_example._udp")
      peer = PeerInfo(peerId: PeerId.random(), listenAddrs: @[ma(PrivateAddress)])
    var message = service.announcement(peer, PeerInstance)
    message.additionals[^1].name = @[PeerInstance, "_EXAMPLE", "_UDP", "LOCAL"]
    check service.peers(message, PeerId.random()) ==
      @[MdnsPeer(peerId: peer.peerId, addrs: peer.listenAddrs)]
    check MdnsService.new().peers(message, PeerId.random()).len == 0

  test "filter browser transports and relay addresses":
    let
      service = MdnsService.new()
      peer = PeerInfo(
        peerId: PeerId.random(),
        listenAddrs: @[
          ma("/ip4/192.168.1.2/tcp/4001/ws"),
          ma("/ip4/192.168.1.2/tcp/4001/p2p-circuit"),
        ],
      )
    check service.announcement(peer, PeerInstance).answers.len == 0

  test "omit unbound addresses from announcements":
    const BoundPort = 51234
    let
      service = MdnsService.new()
      bound = ma("/ip4/192.168.1.2/tcp/" & $BoundPort)
      peer = PeerInfo(
        peerId: PeerId.random(),
        listenAddrs: @[
          ma(EphemeralWildcardAddress),
          ma("/ip4/192.168.1.2/tcp/0"),
          ma("/ip6/2001:db8::1/udp/0/quic-v1"),
        ],
      )
    check service.announcement(peer, PeerInstance).answers.len == 0
    peer.listenAddrs.add(bound)
    let message = service.announcement(peer, PeerInstance)
    let found = service.peers(message, PeerId.random())
    check:
      message.additionals.anyIt(it.kind == SRV and it.port == BoundPort)
      found == @[MdnsPeer(peerId: peer.peerId, addrs: @[bound])]

  test "reject invalid configuration":
    check:
      not MdnsService.new(nil).isNil
      not MdnsService.new().isNil
    expect AssertionDefect:
      discard MdnsService.new(serviceName = "bad..name")
    expect AssertionDefect:
      discard MdnsService.new(queryInterval = 0.seconds)
    expect AssertionDefect:
      discard MdnsService.new(queryInterval = -1.seconds)
    expect AssertionDefect:
      discard MdnsService.new(queryInterval = MdnsMinQueryInterval - 1.milliseconds)
    expect AssertionDefect:
      discard MdnsService.new(queryInterval = MdnsMaxQueryInterval + 1.milliseconds)

  test "record TTL covers two query intervals":
    let peer = PeerInfo(peerId: PeerId.random(), listenAddrs: @[ma(PrivateAddress)])
    for (interval, ttl) in [
      (MdnsDefaultQueryInterval, 120'u32),
      (5.minutes, 600'u32),
      (5.minutes + 1.milliseconds, 602'u32),
      (MdnsMaxQueryInterval, high(uint32) - 1),
    ]:
      let message =
        MdnsService.new(queryInterval = interval).announcement(peer, PeerInstance)
      check message.answers.allIt(it.ttl == ttl)
      check message.additionals.allIt(it.ttl == ttl)
    let goodbye = MdnsService.new().announcement(peer, PeerInstance, 0)
    check goodbye.answers.allIt(it.ttl == 0)
    check goodbye.additionals.allIt(it.ttl == 0)

  asyncTest "legacy query responses are cached and not rate limited":
    let
      address = ma(PrivateAddress)
      local = Switch(
        peerInfo: PeerInfo(peerId: PeerId.random(), listenAddrs: @[address]),
        peerStore: PeerStore.new(nil),
        rng: rng(),
      )
      service = MdnsService.new()
      query =
        DnsMessage(id: 42, questions: @[DnsQuestion(name: @ServiceLabels, kind: PTR)])
    var responses: seq[DnsMessage]
    proc received(
        t: DatagramTransport, remote: TransportAddress
    ) {.async: (raises: []).} =
      try:
        responses.add(parseMessage(t.getMessage()))
      except ValueError, TransportError:
        raiseAssert "Unexpected error: " & getCurrentExceptionMsg()

    # Bind explicitly so Chronos receives the unicast replies on this socket.
    let sender = newMulticastSender(received)
    defer:
      await service.stop(local)
      await sender.closeWait()

    requireStarted(service, local)
    local.peerInfo.listenAddrs = @[ma(AlternatePrivateAddress)]
    const sendCount = 5
    for i in 0 ..< sendCount:
      await sender.sendMulticast(query)
    checkUntilTimeout:
      responses.len >= sendCount
    check:
      responses[0].id == query.id
      responses[0].questions == query.questions
      responses[0].answers.allIt(not it.cacheFlush)
      responses[0].additionals.allIt(not it.cacheFlush)
      service.peers(responses[0], PeerId.random()) ==
        @[MdnsPeer(peerId: local.peerInfo.peerId, addrs: @[address])]

  asyncTest "multicast query responses are rate limited independently per interface":
    when not defined(linux):
      # Exact per-interface counts require Linux's ingress socket binding.
      skip()
    else:
      let
        local = Switch(
          peerInfo:
            PeerInfo(peerId: PeerId.random(), listenAddrs: @[ma(PrivateAddress)]),
          peerStore: PeerStore.new(nil),
          rng: rng(),
        )
        service = MdnsService.new()
        listener = MdnsNetwork.new()
        query = DnsMessage(questions: @[DnsQuestion(name: @ServiceLabels, kind: PTR)])
      var responses: Table[uint32, int]

      var unicastResponses = 0
      proc received(
          packet: seq[byte], context: MdnsReplyContext
      ) {.async: (raises: []).} =
        try:
          let message = parseMessage(packet)
          if not context.isIpv6 and message.response and
              service.peers(message, PeerId.random()).anyIt(
                it.peerId == local.peerInfo.peerId
              ):
            responses.mgetOrPut(context.interfaceIndex, 0).inc
        except ValueError:
          raiseAssert "Unexpected error: " & getCurrentExceptionMsg()

      proc receivedUnicast(
          transport: DatagramTransport, remote: TransportAddress
      ) {.async: (raises: []).} =
        try:
          discard transport.getMessage()
          inc unicastResponses
        except TransportError:
          raiseAssert "Unexpected error: " & getCurrentExceptionMsg()

      # Bind explicitly so Chronos receives the unicast replies on this socket.
      let sender = newMulticastSender(receivedUnicast)
      defer:
        await sender.closeWait()
        await listener.close()
        await service.stop(local)
      requireStarted(service, local)
      let opened = await listener.open(received)
      require opened.isOk
      # Let the initial announcement finish before counting query responses.
      await sleepAsync(200.milliseconds)
      let configured = listener.ipv4InterfaceIndices()
      responses.clear()
      for i in 0 ..< 5:
        check await listener.multicast(encodeMessage(query))
      checkUntilTimeout:
        responses.len > 0
      for i in 0 ..< 2:
        await sender.sendMulticast(query)
      checkUntilTimeout:
        unicastResponses >= 2
      # A response sent on another interface on the same LAN can also arrive
      # here, so each ingress may see one copy per sending interface.
      await sleepAsync(MdnsResponseInterval)
      for count in responses.values:
        check count <= configured.len
      var previous: Table[uint32, int]
      for index, count in responses:
        previous[index] = count
      check await listener.multicast(encodeMessage(query))
      checkUntilTimeout:
        responses.pairs.toSeq.anyIt(it[1] > previous.getOrDefault(it[0]))

  asyncTest "advertise after ephemeral transport addresses are bound":
    requireMdnsMulticastRoute(ignoreDatagram)
    const Address = initTAddress(InterfaceIp & ":0")
    proc interfaces(
        family: AddressFamily
    ): seq[InterfaceAddress] {.gcsafe, raises: [].} =
      if family == AddressFamily.IPv4:
        @[InterfaceAddress.init(Address, 24)]
      else:
        @[]

    let
      node = makeStandardSwitch(ma(EphemeralWildcardAddress))
      service = MdnsService.new(networkInterfaceProvider = interfaces)
      listener = MdnsNetwork.new()
      found = newFuture[MdnsPeer]()
      other = PeerId.random()
    defer:
      await node.stop()
      await listener.close()

    proc received(
        packet: seq[byte], context: MdnsReplyContext
    ) {.async: (raises: []).} =
      try:
        for peer in service.peers(parseMessage(packet), other):
          if peer.peerId == node.peerInfo.peerId:
            found.completeOnce(peer)
      except ValueError:
        raiseAssert "Unexpected error: " & getCurrentExceptionMsg()

    node.services.add(service)
    let opened = await listener.open(received)
    require opened.isOk
    await node.start()
    let peer = await found
    check peer.addrs.len > 0
    check peer.addrs[0] != ma("/ip4/" & InterfaceIp & "/tcp/0")

  asyncTest "start, receive a DNS-SD TXT response, stop and restart":
    let
      local = Switch(
        peerInfo: PeerInfo(peerId: PeerId.random()),
        peerStore: PeerStore.new(nil),
        rng: rng(),
      )
      remoteId = PeerId.init(FixturePeerId).get()
      found = newFuture[MdnsPeer]()
      service = MdnsService.new(
        proc(switch: Switch, peer: MdnsPeer) {.async: (raises: [CancelledError]).} =
          check peer.addrs[0] in local.peerStore[AddressBook][peer.peerId]
          found.completeOnce(peer)
      )
    let previous = ma("/ip4/192.168.1.3/tcp/4001")
    local.peerStore[AddressBook].extend(remoteId, @[previous], AddressConfidence.High)
    let sender = newMulticastSender()
    defer:
      await service.stop(local)
      await sender.closeWait()

    requireStarted(service, local)
    requireStarted(service, local)
    let remoteAddress = ma(FixtureAddress)
    await sender.sendSyntheticResponse()
    checkpoint "No IPv4 mDNS multicast response received"
    check (await found) == MdnsPeer(peerId: remoteId, addrs: @[remoteAddress])
    let entries = local.peerStore[AddressBook].entries(remoteId)
    check entries.len == 2
    check entries.anyIt(
      it.address == previous and it.confidence == AddressConfidence.High
    )
    check entries.anyIt(
      it.address == remoteAddress and it.confidence == AddressConfidence.Low
    )
    await service.stop(local)
    await service.stop(local)
    requireStarted(service, local)

  asyncTest "store discoveries without a callback":
    let
      local = Switch(
        peerInfo: PeerInfo(peerId: PeerId.random()),
        peerStore: PeerStore.new(nil),
        rng: rng(),
      )
      remoteId = PeerId.init(FixturePeerId).get()
      service = MdnsService.new()
      sender = newMulticastSender()
    defer:
      await service.stop(local)
      await sender.closeWait()
    requireStarted(service, local)
    await sender.sendSyntheticResponse()
    checkUntilTimeout:
      local.peerStore[AddressBook][remoteId] == @[ma(FixtureAddress)]

  asyncTest "apply address policy and merge repeated discoveries":
    let
      local = Switch(
        peerInfo: PeerInfo(peerId: PeerId.random()),
        peerStore: PeerStore.new(nil),
        rng: rng(),
      )
      remoteId = PeerId.init(FixturePeerId).get()
      sender = newMulticastSender()
      found = newAsyncEvent()
    var calls = 0
    var expectedAddress: MultiAddress
    var processed = Future[void].Raising([CancelledError]).init("test_mdns.processed")
    let service = MdnsService.new(
      proc(switch: Switch, peer: MdnsPeer) {.async: (raises: [CancelledError]).} =
        if peer.peerId == remoteId and expectedAddress in peer.addrs:
          processed.completeOnce()
    )
    # The callback still receives the discovery when policy rejects its address.
    let observing = MdnsService.new(
      proc(switch: Switch, peer: MdnsPeer) {.async: (raises: [CancelledError]).} =
        inc calls
        found.fire()
    )
    defer:
      await observing.stop(local)
      await service.stop(local)
      await sender.closeWait()
    local.peerStore.addressPolicy = noPrivateAddressPolicy
    requireStarted(observing, local)
    await sender.sendSyntheticResponse()
    await found.wait()
    check calls == 1
    check local.peerStore[AddressBook][remoteId].len == 0
    await observing.stop(local)

    local.peerStore.addressPolicy = defaultAddressPolicy
    requireStarted(service, local)
    const discoveryCount = 8
    let book = local.peerStore[AddressBook]
    var known: seq[MultiAddress]
    for port in 1 ..< discoveryCount:
      known.add(ma("/ip4/192.168.1.2/tcp/" & $port))
    book.extend(remoteId, known, AddressConfidence.High)
    expectedAddress = ma("/ip4/192.168.1.2/tcp/" & $discoveryCount)
    let mixed = PeerInfo(peerId: remoteId, listenAddrs: @[known[0], expectedAddress])
    await sender.sendMulticast(service.announcement(mixed, FixtureInstance))
    await processed
    check book.entries(remoteId).len == discoveryCount
    check expectedAddress in book[remoteId]
    check book.entries(remoteId).anyIt(
      it.address == known[0] and it.confidence == AddressConfidence.High
    )
    book.set(remoteId, @[])
    for port in 1 .. discoveryCount + 2:
      expectedAddress = ma("/ip4/192.168.1.2/tcp/" & $port)
      processed = Future[void].Raising([CancelledError]).init("test_mdns.processed")
      let peer = PeerInfo(peerId: remoteId, listenAddrs: @[expectedAddress])
      await sender.sendMulticast(service.announcement(peer, FixtureInstance))
      await processed
    check local.peerStore[AddressBook].entries(remoteId).len == discoveryCount + 2

  asyncTest "bound pending discovery callbacks":
    const maxPendingCallbacks = 5
    let
      sender = newMulticastSender()
      release = newAsyncEvent()
      overflowId = PeerId.random()
      overflowAddress = ma("/ip4/192.168.1.2/tcp/12345")
    var started = 0
    var completed = 0
    proc onPeerFound(
        switch: Switch, peer: MdnsPeer
    ) {.async: (raises: [CancelledError]).} =
      inc started
      await release.wait()
      inc completed

    let
      service = MdnsService.new()
      local = makeStandardSwitchBuilder(ma(EphemeralWildcardAddress))
        .withMdns(onPeerFound = onPeerFound, maxPendingCallbacks = maxPendingCallbacks)
        .build()
    defer:
      await local.stop()
      await sender.closeWait()
    await local.start()
    for i in 1 .. maxPendingCallbacks:
      await sender.sendSyntheticResponse()
      checkUntilTimeout:
        started == i

    let overflowPeer = PeerInfo(peerId: overflowId, listenAddrs: @[overflowAddress])
    let overflowPacket =
      encodeMessage(service.announcement(overflowPeer, FixtureInstance))
    await sender.sendMulticast(overflowPacket)
    checkUntilTimeout:
      local.peerStore[AddressBook][overflowId] == @[overflowAddress]
    check started == maxPendingCallbacks

    release.fire()
    checkUntilTimeout:
      completed == maxPendingCallbacks
    await sender.sendSyntheticResponse()
    checkUntilTimeout:
      started == maxPendingCallbacks + 1

  asyncTest "switch shutdown cancels async discovery callbacks":
    let
      started = Future[void].Raising([CancelledError]).init("test_mdns.started")
      cancelled = Future[void].Raising([CancelledError]).init("test_mdns.cancelled")
    let node = makeStandardSwitchBuilder(ma(EphemeralWildcardAddress))
      .withMdns(
        onPeerFound = proc(
            switch: Switch, peer: MdnsPeer
        ) {.async: (raises: [CancelledError]).} =
          started.completeOnce()
          try:
            await newAsyncEvent().wait()
          finally:
            cancelled.completeOnce()
      )
      .build()
    let sender = newMulticastSender()
    await node.start()
    defer:
      await node.stop()
      await sender.closeWait()

    await sender.sendSyntheticResponse()
    await started
    await node.stop()
    check cancelled.finished()

  asyncTest "receive an IPv6 multicast datagram":
    var interfaceIndex = 0'u32
    for iface in getInterfaces():
      when defined(macosx):
        # An active interface can have an IPv6 address without supporting
        # multicast. Only consider interfaces that advertise IFF_MULTICAST.
        if (iface.flags and uint64(MacosMulticastFlag)) == 0:
          continue
      if iface.ifType != IfSoftwareLoopback and iface.state == StatusUp:
        for address in iface.addresses:
          if address.host.family == AddressFamily.IPv6:
            interfaceIndex = uint32(iface.ifIndex)
            break
        if interfaceIndex != 0:
          break
    if interfaceIndex == 0:
      # No active non-loopback interface has an IPv6 address.
      skip()
      return

    var foundCount = 0
    let
      local = Switch(
        peerInfo: PeerInfo(peerId: PeerId.random()),
        peerStore: PeerStore.new(nil),
        rng: rng(),
      )
      remote = PeerInfo(peerId: PeerId.random(), listenAddrs: @[ma(PrivateIpv6Address)])
      found = newFuture[MdnsPeer]()
      service = MdnsService.new(
        proc(switch: Switch, peer: MdnsPeer) {.async: (raises: [CancelledError]).} =
          inc foundCount
          found.completeOnce(peer)
      )
    let sender = newDatagramTransport6(ignoreDatagram)
    defer:
      await service.stop(local)
      await sender.closeWait()

    require sender.selectMulticastInterface6(interfaceIndex)
    requireStarted(service, local)
    try:
      await sender.sendTo(
        initTAddress("[ff02::fb]:5353"),
        encodeMessage(service.announcement(remote, "ipv6-peer")),
      )
    except TransportOsError as e:
      when defined(macosx):
        if e.code.int in
            [posix.EHOSTUNREACH.int, posix.ENETUNREACH.int, posix.EADDRNOTAVAIL.int]:
          checkpoint "The runner has no IPv6 multicast route on the selected interface"
          skip()
          return
      raise e
    check (await found) == MdnsPeer(peerId: remote.peerId, addrs: remote.listenAddrs)
    # No condition to wait for: verify the peer is not reported a second time.
    await sleepAsync(MdnsResponseInterval)
    check foundCount == 1

  asyncTest "two services discover each other over multicast":
    requireMdnsMulticastRoute(ignoreDatagram)
    let
      address = ma(PrivateAddress)
      first = Switch(
        peerInfo: PeerInfo(peerId: PeerId.random(), listenAddrs: @[address]),
        peerStore: PeerStore.new(nil),
        rng: rng(),
      )
      second = Switch(
        peerInfo: PeerInfo(peerId: PeerId.random(), listenAddrs: @[address]),
        peerStore: PeerStore.new(nil),
        rng: rng(),
      )
      firstFound = newFuture[void]()
      secondFound = newFuture[void]()
      firstService = MdnsService.new(
        proc(switch: Switch, peer: MdnsPeer) {.async: (raises: [CancelledError]).} =
          if peer.peerId == second.peerInfo.peerId:
            firstFound.completeOnce()
      )
      secondService = MdnsService.new(
        proc(switch: Switch, peer: MdnsPeer) {.async: (raises: [CancelledError]).} =
          if peer.peerId == first.peerInfo.peerId:
            secondFound.completeOnce()
      )
    defer:
      await firstService.stop(first)
      await secondService.stop(second)

    requireStarted(firstService, first)
    requireStarted(secondService, second)
    await firstFound
    await secondFound
