# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import chronos/transports/osnet
import ../../../libp2p/[multiaddress, results]
when not defined(macosx):
  import ../../../libp2p/utils/future
import ../../../libp2p/services/mdns/network
import ../../tools/[unittest, multiaddress]

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

var exposeInterfaces = false
var interfaceQueries = 0

proc changingInterfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
  if exposeInterfaces:
    getInterfaces()
  else:
    @[]

proc countingInterfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
  inc interfaceQueries
  @[]

proc cachedInterfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
  const local = initTAddress("192.168.10.1:0")
  inc interfaceQueries
  if exposeInterfaces:
    @[
      NetworkInterface(
        ifIndex: 1, state: StatusUp, addresses: @[InterfaceAddress.init(local, 24)]
      )
    ]
  else:
    @[]

suite "mDNS network":
  teardown:
    checkTrackers()

  test "sender must belong to an active interface subnet":
    const
      Local4 = initTAddress("192.168.10.1:0")
      Local6 = initTAddress("[fd12:3456::1]:0")
      Down4 = initTAddress("10.2.0.1:0")
    proc interfaces(): seq[NetworkInterface] {.gcsafe, raises: [].} =
      @[
        NetworkInterface(
          ifIndex: 1,
          state: StatusUp,
          addresses:
            @[InterfaceAddress.init(Local4, 24), InterfaceAddress.init(Local6, 64)],
        ),
        NetworkInterface(
          ifIndex: 2, state: StatusDown, addresses: @[InterfaceAddress.init(Down4, 16)]
        ),
      ]

    let network = MdnsNetwork.new(interfaceProvider = interfaces)
    network.refreshInterfaces()
    check:
      network.isLocalAddress(initTAddress("192.168.10.42:5353"))
      network.isLocalAddress(initTAddress("[fd12:3456::42]:5353"))
      not network.isLocalAddress(initTAddress("192.168.11.42:5353"))
      not network.isLocalAddress(initTAddress("10.2.0.42:5353"))
      not network.isLocalAddress(initTAddress("[fd12:3457::42]:5353"))
      not network.isLocalAddress(initTAddress("0.0.0.0:5353"))
      not network.isLocalAddress(initTAddress("224.0.0.251:5353"))

  test "source subnets are cached until interface refresh":
    interfaceQueries = 0
    exposeInterfaces = true
    let network = MdnsNetwork.new(interfaceProvider = cachedInterfaces)
    network.refreshInterfaces()
    exposeInterfaces = false
    let remote = initTAddress("192.168.10.42:5353")
    check:
      network.isLocalAddress(remote)
      network.isLocalAddress(remote)
      interfaceQueries == 1
    network.refreshInterfaces()
    check:
      not network.isLocalAddress(remote)
      interfaceQueries == 2

  test "wildcard expansion uses the supplied interface provider":
    const
      Address4 = initTAddress("10.0.0.1:0")
      Address6 = initTAddress("[fd00::1]:0")
    proc interfaces(
        family: AddressFamily
    ): seq[InterfaceAddress] {.gcsafe, raises: [].} =
      case family
      of AddressFamily.IPv4:
        @[InterfaceAddress.init(Address4, 24)]
      of AddressFamily.IPv6:
        @[InterfaceAddress.init(Address6, 64)]
      else:
        @[]

    let network = MdnsNetwork.new(interfaces)
    check:
      network.expandAddresses(@[ma("/ip4/0.0.0.0/tcp/4001")]) ==
        @[ma("/ip4/10.0.0.1/tcp/4001")]
      network.expandAddresses(@[ma("/ip6/::/udp/4001/quic-v1")]) ==
        @[ma("/ip6/fd00::1/udp/4001/quic-v1"), ma("/ip4/10.0.0.1/udp/4001/quic-v1")]
      network.expandAddresses(@[ma("/ip4/192.168.1.2/tcp/5000")]) ==
        @[ma("/ip4/192.168.1.2/tcp/5000")]

  test "wildcard expansion omits families with no interface addresses":
    proc interfaces(
        family: AddressFamily
    ): seq[InterfaceAddress] {.gcsafe, raises: [].} =
      @[]

    let network = MdnsNetwork.new(interfaces)
    check network.expandAddresses(
      @[ma("/ip4/0.0.0.0/tcp/4001"), ma("/ip6/::/tcp/4001")]
    ).len == 0

  asyncTest "closed networks reject sends and can be closed repeatedly":
    let network = MdnsNetwork.new()
    check:
      not network.isOpen
      not (await network.multicast(@[1'u8]))
      not (await network.reply(@[1'u8], default(MdnsReplyContext), unicast = true))
    await network.close()
    await network.close()
    check not network.isOpen

  asyncTest "refresh joins and leaves interfaces after startup":
    when defined(macosx):
      skip()
    else:
      let network = MdnsNetwork.new(interfaceProvider = changingInterfaces)
      exposeInterfaces = false
      requireOpened(network, ignorePacket)
      defer:
        exposeInterfaces = false
        await network.close()
      check not (await network.multicast(@[1'u8]))
      exposeInterfaces = true
      network.refreshInterfaces()
      check (await network.multicast(@[1'u8]))
      network.refreshInterfaces() # Repeated refreshes retain existing memberships.
      check (await network.multicast(@[1'u8]))
      exposeInterfaces = false
      network.refreshInterfaces()
      check not (await network.multicast(@[1'u8]))
      exposeInterfaces = true
      network.refreshInterfaces()
      check (await network.multicast(@[1'u8]))

  asyncTest "interfaces are refreshed periodically":
    interfaceQueries = 0
    let network = MdnsNetwork.new(
      interfaceProvider = countingInterfaces, refreshInterval = 10.milliseconds
    )
    requireOpened(network, ignorePacket)
    defer:
      await network.close()
    check interfaceQueries == 1 # Opening performs the initial refresh.
    checkUntilTimeout:
      interfaceQueries >= 2

  asyncTest "receive arbitrary bytes and reply to the original sender":
    when defined(macosx):
      skip()
    else:
      let
        network = MdnsNetwork.new()
        packet = @[0'u8, 255, 42]
        response = @[4'u8, 0, 5]
        receivedReply = newFuture[seq[byte]]()
      var contexts: seq[MdnsReplyContext]
      proc received(
          data: seq[byte], context: MdnsReplyContext
      ) {.async: (raises: []).} =
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

      let sender =
        newDatagramTransport(senderReceived, local = initTAddress("127.0.0.1:0"))
      defer:
        await sender.closeWait()
      requireOpened(network, received)
      defer:
        await network.close()

      # A repeated open must not replace the active callback.
      requireOpened(network, ignorePacket)
      # Unicast to a shared mDNS port can be delivered to another local
      # responder, particularly on Windows. Multicast reaches group members.
      await sender.sendTo(initTAddress("224.0.0.251", Port(MdnsPort)), packet)
      check (await receivedReply) == response
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
    when defined(macosx):
      skip()
    else:
      let
        network = MdnsNetwork.new()
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

      let sender =
        newDatagramTransport(ignoreDatagram, local = initTAddress("127.0.0.1:0"))
      defer:
        await sender.closeWait()
      requireOpened(network, received)
      defer:
        release.fire()
        await network.close()

      let destination = initTAddress("224.0.0.251", Port(MdnsPort))
      await sender.sendTo(destination, first)
      await firstEntered.wait()
      await sender.sendTo(destination, second)
      await secondEntered.wait()
      let closing = network.close()
      check:
        not network.isOpen
        not closing.finished
        network.close() == closing
        not completed
        (await network.open(ignorePacket)).isErr
        not (await network.multicast(second))
      release.fire()
      await closing
      check:
        completed
        firstAfterYield == first
        not network.isOpen
      requireOpened(network, ignorePacket)
      check network.isOpen

  asyncTest "close waits for queued multicast sends":
    when defined(macosx):
      skip()
    else:
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
    let network = MdnsNetwork.new(interfaceProvider = changingInterfaces)
    exposeInterfaces = true
    requireOpened(network, ignorePacket)
    defer:
      exposeInterfaces = false
      await network.close()
    let sending = network.multicast(@[7'u8, 8, 9])
    exposeInterfaces = false
    network.refreshInterfaces()
    check await sending
    check not (await network.multicast(@[7'u8, 8, 9]))

  asyncTest "cancelling a queued multicast send keeps its packet alive":
    when defined(macosx):
      skip()
    else:
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

  asyncTest "multicast sends bytes and replies through a multicast context":
    when defined(macosx):
      skip()
    else:
      let
        network = MdnsNetwork.new()
        packet = @[9'u8, 8, 7]
        response = @[6'u8, 5, 4]
        receivedResponse = newFuture[void]()
      var legacy = true
      proc received(
          data: seq[byte], context: MdnsReplyContext
      ) {.async: (raises: []).} =
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
