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
  const
    ipv4AddMembership = 12
    ipv4DropMembership = 13
    ipv4MulticastTtl = 10
    ipv6Protocol = 41
    ipv6MulticastInterface = 9
    ipv6MulticastHops = 10
    ipv6JoinGroup = 12
    ipv6LeaveGroup = 13
else:
  import std/posix
  when declared(posix.IP_ADD_MEMBERSHIP) and declared(posix.IP_MULTICAST_TTL):
    const
      membershipOption = posix.IP_ADD_MEMBERSHIP
      ttlOption = posix.IP_MULTICAST_TTL
      interfaceOption = posix.IP_MULTICAST_IF
      dropOption = posix.IP_DROP_MEMBERSHIP
  elif defined(linux) or defined(android):
    const
      membershipOption = cint(35)
      ttlOption = cint(33)
      interfaceOption = cint(32)
      dropOption = cint(36)
  elif defined(macosx) or defined(ios) or defined(freebsd) or defined(openbsd) or
      defined(netbsd) or defined(dragonfly):
    const
      membershipOption = cint(12)
      ttlOption = cint(10)
      interfaceOption = cint(9)
      dropOption = cint(13)
  else:
    {.error: "mDNS IPv4 multicast socket options are unavailable on this platform".}

const
  MdnsPort* = 5353
  MdnsMulticastHopLimit = 255.cint
  MdnsInterfaceRefreshInterval = 30.seconds
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
    interfaces4: seq[array[4, byte]]
    interfaces6: seq[uint32]
    multicastLock4: AsyncLock
    refresher: Future[void].Raising([CancelledError])
    refreshInterval: Duration
    multicastLock6: AsyncLock
    interfaceProvider: proc(): seq[NetworkInterface] {.gcsafe, raises: [].}
    addressProvider: NetworkInterfaceProvider
    onPacket: MdnsPacketReceived
    activeOperations: int
    idle: AsyncEvent
    closing: bool
    closeFut: Future[void].Raising([])

logScope:
  topics = "libp2p mdns network"

proc new*(
    T: typedesc[MdnsNetwork],
    addressProvider: NetworkInterfaceProvider = getAddresses,
    interfaceProvider: proc(): seq[NetworkInterface] {.gcsafe, raises: [].} =
      getInterfaces,
    refreshInterval: Duration = MdnsInterfaceRefreshInterval,
): T =
  T(
    multicastLock4: newAsyncLock(),
    multicastLock6: newAsyncLock(),
    addressProvider: addressProvider,
    interfaceProvider: interfaceProvider,
    refreshInterval: refreshInterval,
    idle: newAsyncEvent(),
  )

func isOpen*(network: MdnsNetwork): bool =
  not network.closing and (not network.transport.isNil or not network.transport6.isNil)

func isLegacyQuery*(context: MdnsReplyContext): bool =
  context.remote.port != Port(MdnsPort)

func isIpv6*(context: MdnsReplyContext): bool =
  context.remote.family == AddressFamily.IPv6

proc isLocalAddress*(network: MdnsNetwork, remote: TransportAddress): bool =
  ## Check whether the sender belongs to an active interface's subnet.
  if remote.family notin {AddressFamily.IPv4, AddressFamily.IPv6} or
      remote.isUnspecified() or remote.isMulticast():
    return false
  for iface in network.interfaceProvider():
    if iface.ifIndex <= 0 or
        (iface.state != StatusUp and iface.ifType != IfSoftwareLoopback):
      continue
    for address in iface.addresses:
      if address.host.family == remote.family and address.net.mask.prefix > 0 and
          address.net.contains(remote):
        return true
  false

proc isLocalSource*(network: MdnsNetwork, context: MdnsReplyContext): bool =
  network.isLocalAddress(context.remote)

proc expandAddresses*(
    network: MdnsNetwork, addresses: seq[MultiAddress]
): seq[MultiAddress] =
  ## Expand wildcard listen addresses using the configured interface provider.
  if network.addressProvider.isNil:
    return addresses
  expandWildcardAddresses(network.addressProvider, addresses)

template checkSocketOption(status: cint, option: string) =
  if status != 0:
    let code =
      when defined(windows):
        OSErrorCode(winlean.wsaGetLastError())
      else:
        osLastError()
    return err(option & " failed (OS error " & $code.int & "): " & osErrorMsg(code))

proc membership4(
    transport: DatagramTransport, address: array[4, byte], join: bool
): LPResult[void] =
  var membership: array[8, byte] = [224'u8, 0, 0, 251, 0, 0, 0, 0]
  for i in 0 .. 3:
    membership[i + 4] = address[i]
  when defined(windows):
    let status = winlean.setsockopt(
      winlean.SocketHandle(transport.fd),
      0,
      (if join: ipv4AddMembership else: ipv4DropMembership),
      addr membership,
      winlean.SockLen(sizeof(membership)),
    )
  else:
    let status = posix.setsockopt(
      posix.SocketHandle(transport.fd),
      posix.IPPROTO_IP,
      (if join: membershipOption else: dropOption),
      addr membership,
      posix.SockLen(sizeof(membership)),
    )
  checkSocketOption(status, "IPv4 multicast membership")
  ok()

proc configureMulticast(transport: DatagramTransport): LPResult[void] =
  var ttl = MdnsMulticastHopLimit
  when defined(windows):
    let status = winlean.setsockopt(
      winlean.SocketHandle(transport.fd),
      0,
      ipv4MulticastTtl,
      addr ttl,
      winlean.SockLen(sizeof(ttl)),
    )
  else:
    let status = posix.setsockopt(
      posix.SocketHandle(transport.fd),
      posix.IPPROTO_IP,
      ttlOption,
      addr ttl,
      posix.SockLen(sizeof(ttl)),
    )
  checkSocketOption(status, "IP_MULTICAST_TTL")
  ok()

proc selectMulticastInterface4(
    transport: DatagramTransport, address: array[4, byte]
): bool =
  var selected = address
  when defined(windows):
    winlean.setsockopt(
      winlean.SocketHandle(transport.fd),
      0,
      9,
      addr selected,
      winlean.SockLen(sizeof(selected)),
    ) == 0
  else:
    posix.setsockopt(
      posix.SocketHandle(transport.fd),
      posix.IPPROTO_IP,
      interfaceOption,
      addr selected,
      posix.SockLen(sizeof(selected)),
    ) == 0

proc configureMulticast6(transport: DatagramTransport): LPResult[void] =
  var hops = MdnsMulticastHopLimit
  when defined(windows):
    let status = winlean.setsockopt(
      winlean.SocketHandle(transport.fd),
      ipv6Protocol,
      ipv6MulticastHops,
      addr hops,
      winlean.SockLen(sizeof(hops)),
    )
  else:
    let status = posix.setsockopt(
      posix.SocketHandle(transport.fd),
      posix.IPPROTO_IPV6,
      posix.IPV6_MULTICAST_HOPS,
      addr hops,
      posix.SockLen(sizeof(hops)),
    )
  checkSocketOption(status, "IPV6_MULTICAST_HOPS")
  ok()

proc membership6(
    transport: DatagramTransport, index: uint32, join = true
): LPResult[void] =
  # ipv6_mreq contains the 16-byte group followed by the native interface index.
  type Ipv6Membership = object
    group: array[16, uint8]
    interfaceIndex: uint32

  var membership: Ipv6Membership
  membership.group = [0xff'u8, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb]
  membership.interfaceIndex = index
  when defined(windows):
    let socket = winlean.SocketHandle(transport.fd)
    let status = winlean.setsockopt(
      socket,
      ipv6Protocol,
      (if join: ipv6JoinGroup else: ipv6LeaveGroup),
      addr membership,
      winlean.SockLen(sizeof(membership)),
    )
  else:
    let socket = posix.SocketHandle(transport.fd)
    let status = posix.setsockopt(
      socket,
      posix.IPPROTO_IPV6,
      (if join: posix.IPV6_JOIN_GROUP else: posix.IPV6_LEAVE_GROUP),
      addr membership,
      posix.SockLen(sizeof(membership)),
    )
  checkSocketOption(status, (if join: "IPV6_JOIN_GROUP" else: "IPV6_LEAVE_GROUP"))
  ok()

proc selectMulticastInterface6*(transport: DatagramTransport, index: uint32): bool =
  ## Select the outgoing interface for IPv6 multicast on this transport.
  var interfaceIndex = index
  when defined(windows):
    winlean.setsockopt(
      winlean.SocketHandle(transport.fd),
      ipv6Protocol,
      ipv6MulticastInterface,
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

proc refreshInterfaces*(network: MdnsNetwork) =
  ## Reconcile multicast memberships with the current network interfaces.
  var wanted4: seq[array[4, byte]]
  var wanted6: seq[uint32]
  for iface in network.interfaceProvider():
    if iface.ifIndex <= 0 or
        (iface.state != StatusUp and iface.ifType != IfSoftwareLoopback):
      continue
    var has4 = false
    for address in iface.addresses:
      case address.host.family
      of AddressFamily.IPv4:
        if not has4:
          wanted4.add(address.host.address_v4)
          has4 = true
      of AddressFamily.IPv6:
        if uint32(iface.ifIndex) notin wanted6:
          wanted6.add(uint32(iface.ifIndex))
      else:
        discard
  var current4: seq[array[4, byte]]
  var current6: seq[uint32]
  if not network.transport.isNil:
    for address in network.interfaces4:
      if address notin wanted4:
        discard membership4(network.transport, address, false)
    for address in wanted4:
      if address in network.interfaces4 or
          membership4(network.transport, address, true).isOk:
        current4.add(address)
      else:
        debug "IPv4 mDNS multicast join failed", address = address
  if not network.transport6.isNil:
    for index in network.interfaces6:
      if index notin wanted6:
        discard membership6(network.transport6, index, false)
    for index in wanted6:
      if index in network.interfaces6 or membership6(network.transport6, index).isOk:
        current6.add(index)
      else:
        debug "IPv6 mDNS multicast join failed", interfaceIndex = index
  network.interfaces4 = current4
  network.interfaces6 = current6

proc refreshLoop(network: MdnsNetwork) {.async: (raises: [CancelledError]).} =
  while true:
    await sleepAsync(network.refreshInterval)
    network.refreshInterfaces()

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

proc multicast4(
    network: MdnsNetwork, packet: seq[byte]
): Future[bool] {.async: (raises: [CancelledError]).} =
  if network.transport.isNil:
    return false
  withLock network.multicastLock4:
    # A refresh can replace the interface list while a send is pending.
    let interfaces = network.interfaces4
    for address in interfaces:
      if selectMulticastInterface4(network.transport, address):
        if await network.transport.sendPacket(packet, MdnsDestination):
          return true
      else:
        debug "IPv4 mDNS multicast interface selection failed", address = address

proc multicast6(
    network: MdnsNetwork, packet: seq[byte]
): Future[bool] {.async: (raises: [CancelledError]).} =
  if network.transport6.isNil:
    return false
  # The interface is a socket-wide option; keep it stable until the queued send finishes.
  withLock network.multicastLock6:
    let interfaces = network.interfaces6
    for index in interfaces:
      if selectMulticastInterface6(network.transport6, index):
        if await network.transport6.sendPacket(packet, MdnsDestination6):
          return true
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
    let sent4 = await network.multicast4(packet)
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
    if not unicast:
      return await network.multicast4(packet)
    return await context.transport.sendPacket(packet, context.remote)

proc closeImpl(network: MdnsNetwork) {.async: (raises: []).} =
  network.closing = true
  if not network.refresher.isNil:
    await noCancel network.refresher.cancelAndWait()
    network.refresher = nil
  # Ignore new datagrams, but let queued sends and handlers finish before
  # closing their sockets. Chronos does not drain queued sends on close.
  if network.activeOperations > 0:
    await noCancel network.idle.wait()
  if not network.transport.isNil:
    await network.transport.closeWait()
    network.transport = nil
  if not network.transport6.isNil:
    await network.transport6.closeWait()
    network.transport6 = nil
  network.interfaces4.setLen(0)
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

  try:
    network.transport6 = newDatagramTransport6(
      received,
      local = MdnsBindAddress6,
      flags = {ReuseAddr, ReusePort},
      bufSize = 9000,
      dualstack = DualStackType.Disabled,
    )
    let configured = configureMulticast6(network.transport6)
    if configured.isErr:
      debug "IPv6 mDNS multicast configuration failed", err = configured.error
      await network.transport6.closeWait()
      network.transport6 = nil
  except TransportError as exc:
    debug "IPv6 mDNS unavailable", err = exc.msg

  network.refreshInterfaces()

  if network.transport.isNil and network.transport6.isNil:
    network.onPacket = nil
    return err("Unable to start mDNS on IPv4 or IPv6")
  network.refresher = network.refreshLoop()
  return ok()
