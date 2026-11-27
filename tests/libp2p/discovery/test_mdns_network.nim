# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import chronos/transports/osnet
import ../../../libp2p/[multiaddress, results]
import ../../../libp2p/utils/future
import std/sequtils
import ../../../libp2p/services/mdns/network
import ../../tools/[unittest, mdns_sender, multiaddress]
import ./mdns_fixtures

proc ignorePacket(
    packet: seq[byte], context: MdnsReplyContext
) {.async: (raises: []).} =
  discard

proc ignoreDatagram(
    transport: DatagramTransport, remote: TransportAddress
) {.async: (raises: []).} =
  discard

template requireOpened(network, callback: untyped) =
  block:
    let opened = await network.open(callback)
    if opened.isErr:
      checkpoint "mDNS network startup failed: " & $opened.error
    require opened.isOk

type TestInterfaceProvider = object
  current: seq[NetworkInterface]
  queries: int

proc setInterfaces(
    provider: ref TestInterfaceProvider, interfaces: seq[NetworkInterface]
) =
  provider.current = interfaces

proc interfaces(
    provider: ref TestInterfaceProvider
): proc(): seq[NetworkInterface] {.gcsafe, raises: [].} =
  proc queryInterfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
    inc provider.queries
    provider.current

  queryInterfaces

proc ipv4Interfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
  var interfaces: seq[NetworkInterface]
  for iface in getInterfaces():
    if iface.ifIndex <= 0 or
        (iface.state != StatusUp and iface.ifType != IfSoftwareLoopback):
      continue
    var ipv4 = iface
    ipv4.addresses = @[]
    for address in iface.addresses:
      if address.host.family == AddressFamily.IPv4:
        ipv4.addresses.add(address)
    if ipv4.addresses.len > 0:
      interfaces.add(ipv4)
  interfaces

suite "mDNS network":
  teardown:
    checkTrackers()

  test "sender must belong to an active interface subnet":
    proc interfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
      @[
        NetworkInterface(
          ifIndex: 1,
          state: StatusUp,
          addresses: @[
            InterfaceAddress.init(LocalSubnet4, 24),
            InterfaceAddress.init(LocalSubnet6, 64),
          ],
        ),
        NetworkInterface(
          ifIndex: 2,
          state: StatusDown,
          addresses: @[InterfaceAddress.init(DownInterface4, 16)],
        ),
      ]

    let network = MdnsNetwork.new(interfaceProvider = interfaces)
    network.refreshInterfaces()
    check:
      network.isLocalAddress(SubnetPeer4)
      network.isLocalAddress(SubnetPeer6)
      not network.isLocalAddress(AdjacentSubnetPeer4)
      not network.isLocalAddress(DownSubnetPeer4)
      not network.isLocalAddress(AdjacentSubnetPeer6)
      not network.isLocalAddress(WildcardMdns4)
      not network.isLocalAddress(MulticastMdns4)

  test "source subnets are cached until interface refresh":
    let provider = new TestInterfaceProvider
    provider.setInterfaces(
      @[
        NetworkInterface(
          ifIndex: 1,
          state: StatusUp,
          addresses: @[InterfaceAddress.init(LocalSubnet4, 24)],
        )
      ]
    )
    let network = MdnsNetwork.new(interfaceProvider = provider.interfaces)
    network.refreshInterfaces()
    provider.setInterfaces(@[])
    let remote = SubnetPeer4
    check:
      network.isLocalAddress(remote)
      network.isLocalAddress(remote)
      network.sourceInterfaceIndex(remote) == 1
      network.sourceInterfaceIndex(remote) == 1
      provider.queries == 1
    network.refreshInterfaces()
    check:
      not network.isLocalAddress(remote)
      network.sourceInterfaceIndex(remote) == 0
      provider.queries == 2

  test "invalid sources do not match even broad interface subnets":
    const
      broad4Low = initTAddress("1.0.0.1:0")
      broad4High = initTAddress("224.0.0.1:0")
      broad6Low = initTAddress("[::1]:0")
      broad6High = initTAddress("[ff00::1]:0")
    proc interfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
      @[
        NetworkInterface(
          ifIndex: 1,
          state: StatusUp,
          addresses: @[
            InterfaceAddress.init(broad4Low, 1),
            InterfaceAddress.init(broad4High, 1),
            InterfaceAddress.init(broad6Low, 1),
            InterfaceAddress.init(broad6High, 1),
          ],
        )
      ]

    let network = MdnsNetwork.new(interfaceProvider = interfaces)
    network.refreshInterfaces()
    for remote in [
      WildcardMdns4,
      MulticastMdns4,
      initTAddress("[::]:5353"),
      initTAddress("[ff02::fb]:5353"),
      default(TransportAddress),
    ]:
      check:
        not network.isLocalAddress(remote)
        network.sourceInterfaceIndex(remote) == 0

  test "cached ingress matching rejects overlapping interfaces":
    proc interfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
      @[
        NetworkInterface(
          ifIndex: 1,
          state: StatusUp,
          addresses: @[
            InterfaceAddress.init(LocalSubnet4, 24),
            InterfaceAddress.init(LocalSubnet4, 16),
            InterfaceAddress.init(LocalSubnet6, 64),
            InterfaceAddress.init(LocalSubnet4, 0),
          ],
        ),
        NetworkInterface(
          ifIndex: 2,
          state: StatusUp,
          addresses: @[InterfaceAddress.init(OverlappingSubnet4, 24)],
        ),
      ]

    let network = MdnsNetwork.new(interfaceProvider = interfaces)
    network.refreshInterfaces()
    check:
      network.sourceInterfaceIndex(SubnetPeer4) == 0
      network.sourceInterfaceIndex(AdjacentSubnetPeer4) == 1
      network.sourceInterfaceIndex(SubnetPeer6) == 1
      network.sourceInterfaceIndex(UnmatchedSubnetPeer4) == 0

  test "wildcard expansion uses the supplied interface provider":
    proc interfaces(
        family: AddressFamily
    ): seq[InterfaceAddress] {.gcsafe, raises: [].} =
      case family
      of AddressFamily.IPv4:
        @[InterfaceAddress.init(ExpansionInterface4, 24)]
      of AddressFamily.IPv6:
        @[InterfaceAddress.init(ExpansionInterface6, 64)]
      else:
        @[]

    let network = MdnsNetwork.new(interfaces)
    check:
      network.expandAddresses(@[ma(WildcardAddress)]) == @[ma(AlternatePrivateAddress)]
      network.expandAddresses(@[ma(WildcardQuic6Address)]) ==
        @[ma(PrivateQuic6Address), ma(PrivateQuic4Address)]
      network.expandAddresses(@[ma(AlternatePortAddress)]) == @[
        ma(AlternatePortAddress)
      ]

  test "wildcard expansion omits families with no interface addresses":
    proc interfaces(
        family: AddressFamily
    ): seq[InterfaceAddress] {.gcsafe, raises: [].} =
      @[]

    let network = MdnsNetwork.new(interfaces)
    check network.expandAddresses(@[ma(WildcardAddress), ma(Wildcard6Address)]).len == 0

  asyncTest "closed networks reject sends and can be closed repeatedly":
    let network = MdnsNetwork.new()
    check:
      not network.isOpen
      not (await network.multicast(@[1'u8]))
      not (await network.reply(@[1'u8], default(MdnsReplyContext), unicast = true))
    await network.close()
    await network.close()
    check not network.isOpen

  asyncTest "startup fails when all interface sockets fail and can be retried":
    var expose = true
    proc interfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
      if expose:
        return @[
          NetworkInterface(
            ifIndex: high(int32),
            state: StatusUp,
            addresses: @[InterfaceAddress.init(MissingInterface4, 24)],
          )
        ]
      else:
        return @[]

    let network = MdnsNetwork.new(interfaceProvider = interfaces)
    defer:
      await network.close()
    let opened = await network.open(ignorePacket)
    check:
      opened.isErr
      not network.isOpen
      network.ipv4InterfaceIndices().len == 0
      not (await network.multicast(@[1'u8]))
    expose = false
    requireOpened(network, ignorePacket)
    check network.isOpen

  when defined(linux) or defined(android):
    # This test relies on Linux UDP bind semantics: a socket without reuse flags
    # prevents other sockets from sharing its port. Other platforms need their
    # own setup to reserve the port exclusively.
    asyncTest "startup reports an occupied port when interfaces exist":
      requireMdnsMulticastRoute()
      require ipv4Interfaces().len > 0
      var blocker: DatagramTransport
      try:
        blocker =
          newDatagramTransport(ignoreDatagram, local = WildcardMdns4, flags = {})
      except TransportError:
        checkpoint "Cannot exclusively reserve mDNS port for startup test"
        skip()
      if not blocker.isNil:
        defer:
          await blocker.closeWait()
        let network = MdnsNetwork.new(interfaceProvider = ipv4Interfaces)
        defer:
          await network.close()
        let opened = await network.open(ignorePacket)
        check:
          opened.isErr
          not network.isOpen
          network.ipv4InterfaceIndices().len == 0
          not (await network.multicast(@[1'u8]))
        # No-interface startup must still succeed while the port is occupied.
        let emptyProvider = new TestInterfaceProvider
        let empty = MdnsNetwork.new(interfaceProvider = emptyProvider.interfaces)
        defer:
          await empty.close()
        requireOpened(empty, ignorePacket)
        await empty.close()
        await blocker.closeWait()
        requireOpened(network, ignorePacket)
        check network.ipv4InterfaceIndices().len > 0

    asyncTest "refresh retries sockets after the port becomes available":
      requireMdnsMulticastRoute()
      require ipv4Interfaces().len > 0
      var blocker: DatagramTransport
      try:
        blocker =
          newDatagramTransport(ignoreDatagram, local = WildcardMdns4, flags = {})
      except TransportError:
        checkpoint "Cannot exclusively reserve mDNS port for refresh test"
        skip()
      if not blocker.isNil:
        defer:
          await blocker.closeWait()
        let provider = new TestInterfaceProvider
        let network = MdnsNetwork.new(interfaceProvider = provider.interfaces)
        defer:
          await network.close()
        requireOpened(network, ignorePacket)
        provider.setInterfaces(getInterfaces())
        network.refreshInterfaces()
        check network.ipv4InterfaceIndices().len == 0
        await blocker.closeWait()
        network.refreshInterfaces()
        check network.ipv4InterfaceIndices().len > 0

  asyncTest "refresh joins and leaves interfaces after startup":
    requireMdnsMulticastRoute()
    var refreshed: seq[uint32]
    proc changed(indices: seq[uint32]) {.gcsafe, raises: [].} =
      refreshed = indices

    let provider = new TestInterfaceProvider
    let network = MdnsNetwork.new(
      interfaceProvider = provider.interfaces, onInterfacesChanged = changed
    )
    requireOpened(network, ignorePacket)
    defer:
      await network.close()
    check not (await network.multicast(@[1'u8]))
    provider.setInterfaces(getInterfaces())
    network.refreshInterfaces()
    check (await network.multicast(@[1'u8]))
    check refreshed.len > 0
    network.refreshInterfaces() # Repeated refreshes retain existing memberships.
    check (await network.multicast(@[1'u8]))
    provider.setInterfaces(@[])
    network.refreshInterfaces()
    check not (await network.multicast(@[1'u8]))
    check refreshed.len == 0
    provider.setInterfaces(getInterfaces())
    network.refreshInterfaces()
    check (await network.multicast(@[1'u8]))

  asyncTest "interfaces are refreshed periodically":
    let provider = new TestInterfaceProvider
    let network = MdnsNetwork.new(
      interfaceProvider = provider.interfaces, refreshInterval = 10.milliseconds
    )
    requireOpened(network, ignorePacket)
    defer:
      await network.close()
    check provider.queries == 1 # Opening performs the initial refresh.
    checkUntilTimeout:
      provider.queries >= 2

  asyncTest "receive arbitrary bytes and reply to the original sender":
    let
      network = MdnsNetwork.new()
      packet = @[0'u8, 255, 42]
      response = @[4'u8, 0, 5]
      receivedReply = newFuture[seq[byte]]()
    var contexts: seq[MdnsReplyContext]
    proc received(data: seq[byte], context: MdnsReplyContext) {.async: (raises: []).} =
      if data == packet:
        contexts.add(context)
        check await noCancel network.reply(response, context, unicast = true)

    proc senderReceived(
        transport: DatagramTransport, remote: TransportAddress
    ) {.async: (raises: []).} =
      try:
        receivedReply.completeOnce(transport.getMessage())
      except TransportError as e:
        raiseAssert "Unexpected error: " & e.msg

    let sender = newMdnsTestSender(senderReceived)
    defer:
      await sender.closeWait()
    requireOpened(network, received)
    defer:
      await network.close()

    # A repeated open must not replace the active callback.
    requireOpened(network, ignorePacket)
    # Unicast to a shared mDNS port can be delivered to another local
    # responder, particularly on Windows. Multicast reaches group members.
    await sender.sendTo(MulticastMdns4, packet)
    check (await receivedReply) == response
    # Observe a bounded window for duplicate deliveries from wildcard sockets;
    # an event-loop step alone cannot establish that no datagram will arrive.
    await sleepAsync(100.milliseconds)
    require contexts.len == 1
    check contexts[0].isLegacyQuery
    let other = MdnsNetwork.new()
    requireOpened(other, ignorePacket)
    defer:
      await other.close()
    check not (await other.reply(response, contexts[0], unicast = true))
    await network.close()
    check not (await network.reply(response, contexts[0], unicast = true))
    requireOpened(network, ignorePacket)
    check:
      network.isOpen
      not (await network.reply(response, contexts[0], unicast = true))
      not (await network.reply(response, default(MdnsReplyContext), unicast = true))

  asyncTest "close drains handlers and packets remain stable across receives":
    let provider = new TestInterfaceProvider
    provider.setInterfaces(getInterfaces())

    let
      network = MdnsNetwork.new(interfaceProvider = provider.interfaces)
      firstEntered = newAsyncEvent()
      secondEntered = newAsyncEvent()
      release = newAsyncEvent()
      first = @[1'u8, 2, 3]
      second = @[4'u8, 5, 6]
    var
      firstAfterYield: seq[byte]
      completed = false
    proc received(
        packet: seq[byte], context: MdnsReplyContext
    ) {.async: (raises: []).} =
      if packet == first:
        firstEntered.fire()
        await noCancel release.wait()
        firstAfterYield = packet
        completed = true
      elif packet == second:
        secondEntered.fire()

    let sender = newMdnsTestSender(ignoreDatagram)
    defer:
      await sender.closeWait()
    requireOpened(network, received)
    defer:
      release.fire()
      await network.close()

    let destination = MulticastMdns4
    await sender.sendTo(destination, first)
    await firstEntered.wait()
    await sender.sendTo(destination, second)
    await secondEntered.wait()
    let closing = network.close()
    check:
      not network.isOpen
      not closing.finished
      cast[pointer](network.close()) == cast[pointer](closing)
      not completed
      (await network.open(ignorePacket)).isErr
      not (await network.multicast(second))
    let countBeforeRefresh = provider.queries
    network.refreshInterfaces()
    network.refreshInterfaces()
    check provider.queries == countBeforeRefresh
    release.fire()
    await closing
    check:
      completed
      firstAfterYield == first
      not network.isOpen
    requireOpened(network, ignorePacket)
    check network.isOpen

  asyncTest "close waits for queued multicast sends":
    requireMdnsMulticastRoute()
    let network = MdnsNetwork.new()
    requireOpened(network, ignorePacket)
    defer:
      await network.close()
    let
      sending = network.multicast(@[7'u8, 8, 9])
      closing = network.close()
    await closing
    check:
      sending.finished
      (await sending)
      not network.isOpen

  asyncTest "refreshing interfaces while a multicast send is queued":
    requireMdnsMulticastRoute()
    let provider = new TestInterfaceProvider
    provider.setInterfaces(getInterfaces())
    let network = MdnsNetwork.new(interfaceProvider = provider.interfaces)
    requireOpened(network, ignorePacket)
    defer:
      await network.close()
    let sending = network.multicast(@[7'u8, 8, 9])
    provider.setInterfaces(@[])
    network.refreshInterfaces()
    check await sending
    check not (await network.multicast(@[7'u8, 8, 9]))

  asyncTest "cancelling a queued multicast send keeps its packet alive":
    requireMdnsMulticastRoute()
    let network = MdnsNetwork.new()
    requireOpened(network, ignorePacket)
    defer:
      await network.close()
    let sending = network.multicast(@[7'u8, 8, 9])
    check not sending.finished
    await sending.cancelAndWait()
    # The shielded write may finish before cancellation reaches the caller.
    check sending.cancelled or (sending.completed and sending.read())
    await network.close()
    check not network.isOpen

  asyncTest "multicast replies return on their sending interface":
    requireMdnsMulticastRoute()
    var interfaces = ipv4Interfaces()
    block:
      proc provider(): seq[NetworkInterface] {.gcsafe, raises: [].} =
        interfaces

      let
        network = MdnsNetwork.new(interfaceProvider = provider)
        query = @[31'u8, 41, 59]
      var responses: seq[tuple[origin, receivedOn: uint32]]
      var contexts: seq[MdnsReplyContext]
      var accepting = true
      var pending = 0
      proc received(
          data: seq[byte], context: MdnsReplyContext
      ) {.async: (raises: []).} =
        if data == query and accepting:
          inc pending
          contexts.add(context)
          let index = context.interfaceIndex
          let response = @[
            26'u8,
            byte(index and 255),
            byte((index shr 8) and 255),
            byte((index shr 16) and 255),
            byte(index shr 24),
          ]
          check await noCancel network.reply(response, context, unicast = false)
          dec pending
        elif data.len == 5 and data[0] == 26:
          let origin =
            uint32(data[1]) or (uint32(data[2]) shl 8) or (uint32(data[3]) shl 16) or
            (uint32(data[4]) shl 24)
          responses.add((origin, context.interfaceIndex))

      requireOpened(network, received)
      defer:
        await network.close()

      let configured = network.ipv4InterfaceIndices()
      if configured.len == 0 or not network.ipv4IngressPinned():
        checkpoint "No IPv4 multicast interface is configured or ingress cannot be pinned"
        skip()
        return

      check await network.multicast(query)
      checkUntilTimeout:
        configured.allIt((it, it) in responses)
      accepting = false
      checkUntilTimeout:
        pending == 0
      # Removing and re-adding an interface must not revive old reply contexts.
      interfaces = @[]
      network.refreshInterfaces()
      for context in contexts:
        check not (await network.reply(query, context, unicast = false))
      interfaces = getInterfaces()
      network.refreshInterfaces()
      for context in contexts:
        check not (await network.reply(query, context, unicast = false))

  asyncTest "multicast sends bytes and replies through a multicast context":
    requireMdnsMulticastRoute()
    let
      network = MdnsNetwork.new()
      packet = @[9'u8, 8, 7]
      response = @[6'u8, 5, 4]
      receivedResponse = newFuture[void]()
    var legacy = true
    proc received(data: seq[byte], context: MdnsReplyContext) {.async: (raises: []).} =
      if data == packet:
        legacy = context.isLegacyQuery
        check await noCancel network.reply(response, context, unicast = false)
      elif data == response:
        receivedResponse.completeOnce()

    requireOpened(network, received)
    defer:
      await network.close()
    check (await network.multicast(packet))
    await receivedResponse
    check not legacy
