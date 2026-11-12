# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils]
import chronos
import chronos/transports/osnet
import ../../../libp2p/[switch, peerinfo, utils/future]
import ../../../libp2p/services/mdns
when not defined(macosx):
  import ../../../libp2p/services/mdns/network
import ../../../libp2p/nameresolving/dnsmessage
import ../../tools/[unittest, crypto, multiaddress]

const
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

template requireStarted(service, node: untyped) =
  block:
    let started = await service.tryStart(node)
    if started.isErr:
      checkpoint "mDNS startup failed: " & $started.error
    require started.isOk

suite "mDNS discovery":
  teardown:
    checkTrackers()

  test "DNS-SD records round trip and group peer addresses":
    let
      service = MdnsService.new()
      id = PeerId.random()
      local = PeerId.random()
      addresses =
        @[ma("/ip4/192.168.1.2/tcp/12345"), ma("/ip6/fd00::1/udp/4001/quic-v1")]
      peer = PeerInfo(peerId: id, listenAddrs: addresses)
      message = parseMessage(encodeMessage(service.announcement(peer, "test-peer")))
      found = service.peers(message, local)
    check:
      message.response
      message.answers.mapIt(it.kind) == @[PTR]
      message.answers.mapIt(it.name) == @[@["_p2p", "_udp", "local"]]
      message.additionals.anyIt(it.kind == SRV and it.port == 12345)
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
      @[MdnsPeer(peerId: id, addrs: @[ma("/ip4/192.168.1.2/tcp/12345")])]

  test "announcement matches fixed DNS-SD wire bytes":
    let
      peer = PeerInfo(
        peerId: PeerId.init(FixturePeerId).get(),
        listenAddrs: @[ma("/ip4/192.168.1.2/tcp/12345")],
      )
      announcement = MdnsService.new().announcement(peer, "test-peer")
    check encodeMessage(announcement) == packet(AnnouncementHex)

  test "ignore unrelated services, queries, expired and invalid TXT entries":
    let
      service = MdnsService.new()
      id = PeerId.random()
      local = PeerId.random()
      text = "dnsaddr=/ip4/192.168.1.2/tcp/4001/p2p/" & $id
    var message = DnsMessage(
      response: true,
      additionals: @[
        DnsRecord(
          name: @["peer", "_p2p", "_udp", "local"],
          kind: TXT,
          ttl: 120,
          strings: @["other=value", "dnsaddr=invalid", text, text],
        )
      ],
    )
    check service.peers(message, local) ==
      @[MdnsPeer(peerId: id, addrs: @[ma("/ip4/192.168.1.2/tcp/4001")])]
    message.response = false
    check service.peers(message, local).len == 0
    message.response = true
    message.additionals[0].ttl = 0
    check service.peers(message, local).len == 0
    message.additionals[0].ttl = 120
    message.additionals[0].name = @["peer", "_other", "_udp", "local"]
    check service.peers(message, local).len == 0

  test "accept only private and link-local IP transport addresses":
    let
      service = MdnsService.new()
      id = PeerId.random()
      local = PeerId.random()
      accepted = @[
        "/ip4/10.0.0.1/tcp/4001", "/ip4/169.254.1.2/tcp/4001", "/ip6/fd00::1/tcp/4001",
        "/ip6/fe80::1/tcp/4001",
      ]
      rejected = @[
        "/ip4/8.8.8.8/tcp/4001", "/ip6/2606:4700::1111/tcp/4001",
        "/ip4/127.0.0.1/tcp/4001", "/ip6/::1/tcp/4001",
        "/ip6/::ffff:127.0.0.1/tcp/4001", "/ip4/0.0.0.0/tcp/4001",
        "/ip4/224.0.0.1/tcp/4001", "/dns4/example.com/tcp/4001", "/ip4/10.0.0.1/tcp/0",
      ]
    var strings: seq[string]
    for address in accepted & rejected:
      strings.add("dnsaddr=" & address & "/p2p/" & $id)
    let message = DnsMessage(
      response: true,
      additionals: @[
        DnsRecord(
          name: @["peer", "_p2p", "_udp", "local"],
          kind: TXT,
          ttl: 120,
          strings: strings,
        )
      ],
    )
    check service.peers(message, local) ==
      @[MdnsPeer(peerId: id, addrs: accepted.mapIt(ma(it)))]

    # Wildcard binds expand to host interfaces before filtering.
    let concrete = rejected.filterIt(it != "/ip4/0.0.0.0/tcp/4001") & accepted
    let peer = PeerInfo(peerId: id, listenAddrs: concrete.mapIt(ma(it)))
    let announcement = service.announcement(peer, "peer")
    let txt = announcement.additionals.filterIt(it.kind == TXT)
    check:
      txt.mapIt(it.strings) == @[accepted.mapIt("dnsaddr=" & it & "/p2p/" & $id)]
      service.peers(announcement, local) ==
        @[MdnsPeer(peerId: id, addrs: accepted.mapIt(ma(it)))]
      announcement.additionals.filterIt(it.kind == A or it.kind == AAAA).len ==
        accepted.len

    peer.listenAddrs = @[ma("/ip4/0.0.0.0/tcp/4001"), ma("/ip6/::/tcp/4001")]
    let wildcard = service.announcement(peer, "peer")
    for record in wildcard.additionals:
      check record.address notin ["127.0.0.1", "::1"]
      for text in record.strings:
        check "/ip4/127." notin text and "/ip6/::1/" notin text

  test "announcements expand wildcard addresses using the configured interfaces":
    const Address = initTAddress("10.20.30.40:0")
    proc interfaces(
        family: AddressFamily
    ): seq[InterfaceAddress] {.gcsafe, raises: [].} =
      if family == AddressFamily.IPv4:
        @[InterfaceAddress.init(Address, 24)]
      else:
        @[]

    let
      service = MdnsService.new(networkInterfaceProvider = interfaces)
      peer =
        PeerInfo(peerId: PeerId.random(), listenAddrs: @[ma("/ip4/0.0.0.0/tcp/4001")])
      message = service.announcement(peer, "peer")
    check service.peers(message, PeerId.random()) ==
      @[MdnsPeer(peerId: peer.peerId, addrs: @[ma("/ip4/10.20.30.40/tcp/4001")])]

  test "custom service names and case insensitive DNS names":
    let
      service = MdnsService.new(serviceName = "_example._udp")
      peer = PeerInfo(
        peerId: PeerId.random(), listenAddrs: @[ma("/ip4/192.168.1.2/tcp/4001")]
      )
    var message = service.announcement(peer, "peer")
    message.additionals[^1].name = @["peer", "_EXAMPLE", "_UDP", "LOCAL"]
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
    check service.announcement(peer, "peer").answers.len == 0

  test "omit unbound addresses from announcements":
    let
      service = MdnsService.new()
      bound = ma("/ip4/192.168.1.2/tcp/51234")
      peer = PeerInfo(
        peerId: PeerId.random(),
        listenAddrs: @[
          ma("/ip4/0.0.0.0/tcp/0"),
          ma("/ip4/192.168.1.2/tcp/0"),
          ma("/ip6/2001:db8::1/udp/0/quic-v1"),
        ],
      )
    check service.announcement(peer, "peer").answers.len == 0
    peer.listenAddrs.add(bound)
    let message = service.announcement(peer, "peer")
    let found = service.peers(message, PeerId.random())
    check:
      message.additionals.anyIt(it.kind == SRV and it.port == 51234)
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
    let peer =
      PeerInfo(peerId: PeerId.random(), listenAddrs: @[ma("/ip4/192.168.1.2/tcp/4001")])
    for (interval, ttl) in [
      (MdnsDefaultQueryInterval, 120'u32),
      (5.minutes, 600'u32),
      (5.minutes + 1.milliseconds, 602'u32),
      (MdnsMaxQueryInterval, high(uint32) - 1),
    ]:
      let message = MdnsService.new(queryInterval = interval).announcement(peer, "peer")
      check message.answers.allIt(it.ttl == ttl)
      check message.additionals.allIt(it.ttl == ttl)
    let goodbye = MdnsService.new().announcement(peer, "peer", 0)
    check goodbye.answers.allIt(it.ttl == 0)
    check goodbye.additionals.allIt(it.ttl == 0)

  asyncTest "query responses are cached and rate limited":
    when defined(macosx):
      skip()
    else:
      let
        address = ma("/ip4/192.168.1.2/tcp/4001")
        local = Switch(
          peerInfo: PeerInfo(peerId: PeerId.random(), listenAddrs: @[address]),
          rng: rng(),
        )
        service = MdnsService.new()
        query = DnsMessage(
          id: 42, questions: @[DnsQuestion(name: @["_p2p", "_udp", "local"], kind: PTR)]
        )
      var responses: seq[DnsMessage]
      proc received(
          t: DatagramTransport, remote: TransportAddress
      ) {.async: (raises: []).} =
        try:
          responses.add(parseMessage(t.getMessage()))
        except ValueError, TransportError:
          raiseAssert "Unexpected error: " & getCurrentExceptionMsg()

      let sender = newDatagramTransport(received)
      # Multicast is delivered to all group members even when another local
      # mDNS responder shares port 5353.
      let destination = initTAddress("224.0.0.251", Port(MdnsPort))
      try:
        requireStarted(service, local)
        local.peerInfo.listenAddrs = @[ma("/ip4/10.0.0.1/tcp/4001")]
        for i in 0 ..< 5:
          await sender.sendTo(destination, encodeMessage(query))
        checkUntilTimeout:
          responses.len > 0
        check:
          responses[0].id == query.id
          responses[0].questions == query.questions
          responses[0].answers.allIt(not it.cacheFlush)
          responses[0].additionals.allIt(not it.cacheFlush)
          service.peers(responses[0], PeerId.random()) ==
            @[MdnsPeer(peerId: local.peerInfo.peerId, addrs: @[address])]
        await sleepAsync(MdnsResponseInterval)
        await sender.sendTo(destination, encodeMessage(query))
        checkUntilTimeout:
          responses.len >= 2
      finally:
        await service.stop(local)
        await sender.closeWait()

  asyncTest "start, receive a DNS-SD TXT response, stop and restart":
    let
      local = Switch(peerInfo: PeerInfo(peerId: PeerId.random()), rng: rng())
      remoteId = PeerId.init(FixturePeerId).get()
      found = newFuture[MdnsPeer]()
      service = MdnsService.new(
        proc(peer: MdnsPeer) {.gcsafe, raises: [].} =
          found.completeOnce(peer)
      )
    proc received(
        t: DatagramTransport, remote: TransportAddress
    ) {.async: (raises: []).} =
      discard

    let sender = newDatagramTransport(received)
    try:
      requireStarted(service, local)
      requireStarted(service, local)
      when defined(macosx):
        # Hosted macOS runners may not have a usable multicast route.
        await service.stop(local)
        await service.stop(local)
        requireStarted(service, local)
        skip()
      else:
        await sender.sendTo(
          initTAddress("224.0.0.251", Port(MdnsPort)), packet(SyntheticResponseHex)
        )
        checkpoint "No IPv4 mDNS multicast response received"
        check (await found) ==
          MdnsPeer(peerId: remoteId, addrs: @[ma("/ip4/192.168.1.2/tcp/12345")])
        await service.stop(local)
        await service.stop(local)
        requireStarted(service, local)
    finally:
      await service.stop(local)
      await sender.closeWait()

  asyncTest "receive an IPv6 multicast datagram":
    when defined(macosx):
      # Hosted macOS runners do not necessarily have an IPv6 multicast route.
      skip()
    else:
      var interfaceIndex = 0'u32
      for iface in getInterfaces():
        if iface.ifType != IfSoftwareLoopback and iface.state == StatusUp:
          for address in iface.addresses:
            if address.host.family == AddressFamily.IPv6:
              interfaceIndex = uint32(iface.ifIndex)
              break
          if interfaceIndex != 0:
            break
      if interfaceIndex != 0:
        var foundCount = 0
        let
          local = Switch(peerInfo: PeerInfo(peerId: PeerId.random()), rng: rng())
          remote = PeerInfo(
            peerId: PeerId.random(), listenAddrs: @[ma("/ip6/fd00::1/tcp/4001")]
          )
          found = newFuture[MdnsPeer]()
          service = MdnsService.new(
            proc(peer: MdnsPeer) {.gcsafe, raises: [].} =
              inc foundCount
              found.completeOnce(peer)
          )
        proc received(
            t: DatagramTransport, remote: TransportAddress
        ) {.async: (raises: []).} =
          discard

        let sender = newDatagramTransport6(received)
        try:
          require sender.selectMulticastInterface6(interfaceIndex)
          requireStarted(service, local)
          await sender.sendTo(
            initTAddress("[ff02::fb]:5353"),
            encodeMessage(service.announcement(remote, "ipv6-peer")),
          )
          check (await found) ==
            MdnsPeer(peerId: remote.peerId, addrs: remote.listenAddrs)
          await sleepAsync(MdnsResponseInterval)
          check foundCount == 1
        finally:
          await service.stop(local)
          await sender.closeWait()
      else:
        # No active non-loopback interface has an IPv6 address.
        skip()

  asyncTest "two services discover each other over multicast":
    when defined(macosx):
      # Multicast delivery on hosted macOS runners depends on their network setup.
      skip()
    else:
      let
        address = ma("/ip4/192.168.1.2/tcp/4001")
        first = Switch(
          peerInfo: PeerInfo(peerId: PeerId.random(), listenAddrs: @[address]),
          rng: rng(),
        )
        second = Switch(
          peerInfo: PeerInfo(peerId: PeerId.random(), listenAddrs: @[address]),
          rng: rng(),
        )
        firstFound = newFuture[void]()
        secondFound = newFuture[void]()
        firstService = MdnsService.new(
          proc(peer: MdnsPeer) {.gcsafe, raises: [].} =
            if peer.peerId == second.peerInfo.peerId:
              firstFound.completeOnce()
        )
        secondService = MdnsService.new(
          proc(peer: MdnsPeer) {.gcsafe, raises: [].} =
            if peer.peerId == first.peerInfo.peerId:
              secondFound.completeOnce()
        )
      try:
        requireStarted(firstService, first)
        requireStarted(secondService, second)
        checkpoint "mDNS multicast discovery failed; check UDP port 5353 and multicast connectivity"
        await firstFound
        await secondFound
      finally:
        await firstService.stop(first)
        await secondService.stop(second)
