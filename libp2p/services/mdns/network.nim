# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## UDP multicast transport for mDNS. DNS records and discovery policy belong to
## the service; this module only receives, routes and sends packets.

{.push raises: [].}

import std/os
import chronos, chronicles
import chronos/transports/osnet
import ../../[address_manager, multiaddress, results]
import ../../utils/lock

when defined(windows):
  import std/winlean
else:
  import std/posix
  when declared(posix.IP_ADD_MEMBERSHIP) and declared(posix.IP_MULTICAST_TTL):
    const
      membershipOption = posix.IP_ADD_MEMBERSHIP
      ttlOption = posix.IP_MULTICAST_TTL
  elif defined(linux) or defined(android):
    const
      membershipOption = cint(35)
      ttlOption = cint(33)
  elif defined(macosx) or defined(ios) or defined(freebsd) or defined(openbsd) or
      defined(netbsd) or defined(dragonfly):
    const
      membershipOption = cint(12)
      ttlOption = cint(10)
  else:
    {.error: "mDNS IPv4 multicast socket options are unavailable on this platform".}

const
  MdnsPort* = 5353
  MdnsDestination = initTAddress("224.0.0.251:5353")
  MdnsBindAddress = initTAddress("0.0.0.0:5353")
  MdnsDestination6 = initTAddress("[ff02::fb]:5353")
  MdnsBindAddress6 = initTAddress("[::]:5353")

type
  MdnsReplyContext* = object
    ## Identifies the receiving socket and sender. Valid only while that socket
    ## remains open; a context from an earlier open cannot be reused.
    transport: DatagramTransport
    remote: TransportAddress

  MdnsPacketReceived* = proc(
    packet: seq[byte], context: MdnsReplyContext
  ): Future[void].Raising([]) {.gcsafe, raises: [].}

  MdnsNetwork* = ref object
    transport: DatagramTransport
    transport6: DatagramTransport
    interfaces6: seq[uint32]
    multicastLock6: AsyncLock
    networkInterfaceProvider: NetworkInterfaceProvider
    onPacket: MdnsPacketReceived
    activeOperations: int
    idle: AsyncEvent
    closing: bool
    closeFut: Future[void].Raising([])

logScope:
  topics = "libp2p mdns network"

proc new*(
    T: typedesc[MdnsNetwork],
    networkInterfaceProvider: NetworkInterfaceProvider = getAddresses,
): T =
  T(
    multicastLock6: newAsyncLock(),
    networkInterfaceProvider: networkInterfaceProvider,
    idle: newAsyncEvent(),
  )

func isOpen*(network: MdnsNetwork): bool =
  not network.closing and (not network.transport.isNil or not network.transport6.isNil)

func isLegacyQuery*(context: MdnsReplyContext): bool =
  context.remote.port != Port(MdnsPort)

proc expandAddresses*(
    network: MdnsNetwork, addresses: seq[MultiAddress]
): seq[MultiAddress] =
  ## Expand wildcard listen addresses using the configured interface provider.
  expandWildcardAddresses(network.networkInterfaceProvider, addresses)

template checkSocketOption(status: cint, option: string) =
  if status != 0:
    let code =
      when defined(windows):
        OSErrorCode(winlean.wsaGetLastError())
      else:
        osLastError()
    return err(option & " failed (OS error " & $code.int & "): " & osErrorMsg(code))

proc configureMulticast(transport: DatagramTransport): LPResult[void] =
  # ip_mreq is two network-order IPv4 addresses on both Winsock and POSIX.
  var membership: array[2, uint32]
  cast[ptr array[8, uint8]](addr membership)[] = [224'u8, 0, 0, 251, 0, 0, 0, 0]
  var ttl = 255.cint
  when defined(windows):
    let status = winlean.setsockopt(
      winlean.SocketHandle(transport.fd),
      0,
      12,
      addr membership[0],
      winlean.SockLen(sizeof(membership)),
    )
    checkSocketOption(status, "IP_ADD_MEMBERSHIP")
    let ttlStatus = winlean.setsockopt(
      winlean.SocketHandle(transport.fd), 0, 10, addr ttl, winlean.SockLen(sizeof(ttl))
    )
    checkSocketOption(ttlStatus, "IP_MULTICAST_TTL")
  else:
    let status = posix.setsockopt(
      posix.SocketHandle(transport.fd),
      posix.IPPROTO_IP,
      membershipOption,
      addr membership[0],
      posix.SockLen(sizeof(membership)),
    )
    checkSocketOption(status, "IP_ADD_MEMBERSHIP")
    let ttlStatus = posix.setsockopt(
      posix.SocketHandle(transport.fd),
      posix.IPPROTO_IP,
      ttlOption,
      addr ttl,
      posix.SockLen(sizeof(ttl)),
    )
    checkSocketOption(ttlStatus, "IP_MULTICAST_TTL")
  ok()

proc configureMulticast6(transport: DatagramTransport, index: uint32): LPResult[void] =
  # ipv6_mreq contains the 16-byte group followed by the native interface index.
  type Ipv6Membership = object
    group: array[16, uint8]
    interfaceIndex: uint32

  var membership: Ipv6Membership
  membership.group = [0xff'u8, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb]
  membership.interfaceIndex = index
  var hops = 255.cint
  when defined(windows):
    let socket = winlean.SocketHandle(transport.fd)
    let joined = winlean.setsockopt(
      socket, 41, 12, addr membership, winlean.SockLen(sizeof(membership))
    )
    checkSocketOption(joined, "IPV6_JOIN_GROUP")
    let hopStatus =
      winlean.setsockopt(socket, 41, 10, addr hops, winlean.SockLen(sizeof(hops)))
    checkSocketOption(hopStatus, "IPV6_MULTICAST_HOPS")
  else:
    let socket = posix.SocketHandle(transport.fd)
    let joined = posix.setsockopt(
      socket,
      posix.IPPROTO_IPV6,
      posix.IPV6_JOIN_GROUP,
      addr membership,
      posix.SockLen(sizeof(membership)),
    )
    checkSocketOption(joined, "IPV6_JOIN_GROUP")
    let hopStatus = posix.setsockopt(
      socket,
      posix.IPPROTO_IPV6,
      posix.IPV6_MULTICAST_HOPS,
      addr hops,
      posix.SockLen(sizeof(hops)),
    )
    checkSocketOption(hopStatus, "IPV6_MULTICAST_HOPS")
  ok()

proc selectMulticastInterface6*(transport: DatagramTransport, index: uint32): bool =
  ## Select the outgoing interface for IPv6 multicast on this transport.
  var interfaceIndex = index
  when defined(windows):
    winlean.setsockopt(
      winlean.SocketHandle(transport.fd),
      41,
      9,
      addr interfaceIndex,
      winlean.SockLen(sizeof(interfaceIndex)),
    ) == 0
  else:
    posix.setsockopt(
      posix.SocketHandle(transport.fd),
      posix.IPPROTO_IPV6,
      posix.IPV6_MULTICAST_IF,
      addr interfaceIndex,
      posix.SockLen(sizeof(interfaceIndex)),
    ) == 0

proc sendPacket(
    transport: DatagramTransport, packet: seq[byte], destination: TransportAddress
): Future[bool] {.async: (raises: [CancelledError]).} =
  try:
    if not transport.isNil:
      # Chronos keeps a pointer to the packet in its send queue. Cancelling
      # sendTo releases its buffer before the queued write is processed.
      await noCancel transport.sendTo(destination, packet)
      return true
  except TransportError:
    debug "mDNS send failed", err = getCurrentExceptionMsg()
  return false

proc multicast6(
    network: MdnsNetwork, packet: seq[byte]
): Future[bool] {.async: (raises: [CancelledError]).} =
  if network.transport6.isNil:
    return false
  # The interface is a socket-wide option; keep it stable until the queued send finishes.
  withLock network.multicastLock6:
    for index in network.interfaces6:
      if selectMulticastInterface6(network.transport6, index):
        if await network.transport6.sendPacket(packet, MdnsDestination6):
          result = true
      else:
        debug "IPv6 mDNS multicast interface selection failed", interfaceIndex = index

template trackOperation(network: MdnsNetwork, body: untyped) =
  inc network.activeOperations
  network.idle.clear()
  try:
    body
  finally:
    dec network.activeOperations
    if network.activeOperations == 0:
      network.idle.fire()

proc multicast*(
    network: MdnsNetwork, packet: seq[byte]
): Future[bool] {.async: (raises: [CancelledError]).} =
  if not network.isOpen:
    return false
  trackOperation network:
    let sent4 = await network.transport.sendPacket(packet, MdnsDestination)
    let sent6 = await network.multicast6(packet)
    return sent4 or sent6

proc reply*(
    network: MdnsNetwork, packet: seq[byte], context: MdnsReplyContext, unicast: bool
): Future[bool] {.async: (raises: [CancelledError]).} =
  if not network.isOpen or context.transport.isNil or (
    context.transport != network.transport and context.transport != network.transport6
  ):
    return false
  trackOperation network:
    if not unicast and context.remote.family == AddressFamily.IPv6:
      return await network.multicast6(packet)
    return await context.transport.sendPacket(
      packet, if unicast: context.remote else: MdnsDestination
    )

proc closeImpl(network: MdnsNetwork) {.async: (raises: []).} =
  network.closing = true
  # Ignore new datagrams, but let queued sends and handlers finish before
  # closing their sockets. Chronos does not drain queued sends on close.
  if network.activeOperations > 0:
    await noCancel network.idle.wait()
  if not network.transport.isNil:
    await network.transport.closeWait()
  if not network.transport6.isNil:
    await network.transport6.closeWait()
  network.transport = nil
  network.transport6 = nil
  network.interfaces6.setLen(0)
  network.onPacket = nil
  network.closing = false

proc close*(network: MdnsNetwork): Future[void].Raising([]) =
  ## Ignore new datagrams and wait for active sends and packet handlers. A
  ## handler must not await close itself. Concurrent closes share cleanup.
  if network.closeFut.isNil:
    network.closeFut = network.closeImpl()
  network.closeFut

proc open*(
    network: MdnsNetwork, onPacket: MdnsPacketReceived
): Future[LPResult[void]] {.async: (raises: []).} =
  ## Open either or both IP families. Repeated opens retain the first callback.
  if network.closing:
    return err("mDNS network is closing")
  if network.isOpen:
    return ok()
  doAssert not onPacket.isNil, "mDNS packet callback must not be nil"
  network.closeFut = nil
  network.onPacket = onPacket
  proc received(
      transport: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    if network.closing or
        (transport != network.transport and transport != network.transport6):
      return
    try:
      # Copy the datagram before the callback can yield and Chronos reuses it.
      let packet = transport.getMessage()
      trackOperation network:
        await network.onPacket(
          packet, MdnsReplyContext(transport: transport, remote: remote)
        )
    except TransportError:
      debug "mDNS datagram ignored", err = getCurrentExceptionMsg()

  try:
    network.transport = newDatagramTransport(
      received, local = MdnsBindAddress, flags = {ReuseAddr, ReusePort}, bufSize = 9000
    )
    let configured = configureMulticast(network.transport)
    if configured.isErr:
      debug "IPv4 mDNS multicast configuration failed", err = configured.error
      await network.transport.closeWait()
      network.transport = nil
  except TransportError as exc:
    debug "IPv4 mDNS unavailable", err = exc.msg

  for iface in getInterfaces():
    if iface.ifIndex <= 0 or
        (iface.state != StatusUp and iface.ifType != IfSoftwareLoopback):
      continue
    var hasIPv6 = false
    for address in iface.addresses:
      if address.host.family == AddressFamily.IPv6:
        hasIPv6 = true
        break
    if not hasIPv6:
      continue
    if network.transport6.isNil:
      try:
        network.transport6 = newDatagramTransport6(
          received,
          local = MdnsBindAddress6,
          flags = {ReuseAddr, ReusePort},
          bufSize = 9000,
          dualstack = DualStackType.Disabled,
        )
      except TransportError as exc:
        debug "IPv6 mDNS unavailable", interfaceName = iface.name, err = exc.msg
        break
    let configured = configureMulticast6(network.transport6, uint32(iface.ifIndex))
    if configured.isOk:
      network.interfaces6.add(uint32(iface.ifIndex))
    else:
      debug "IPv6 mDNS multicast configuration failed",
        interfaceName = iface.name, err = configured.error

  if not network.transport6.isNil and network.interfaces6.len == 0:
    await network.transport6.closeWait()
    network.transport6 = nil

  if network.transport.isNil and network.transport6.isNil:
    network.onPacket = nil
    return err("Unable to start mDNS on IPv4 or IPv6")
  return ok()
