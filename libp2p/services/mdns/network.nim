# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## UDP multicast transport for mDNS. DNS records and discovery policy belong to
## the service; this module only receives, routes and sends packets.

{.push raises: [].}

import std/[os, sequtils]
import chronos, chronicles
import chronos/transports/osnet
import ../../[address_manager, ip_address, multiaddress, results]

import ./socketoptions

const
  MdnsPort* = 5353
  MdnsMulticastHopLimit = 255.cint
  MdnsInterfaceRefreshInterval = 30.seconds
  MdnsDestination = initTAddress("224.0.0.251:5353")
  MdnsBindAddress = initTAddress("0.0.0.0:5353")
  MdnsDestination6 = initTAddress("[ff02::fb]:5353")
  MdnsBindAddress6 = initTAddress("[::]:5353")

type
  MdnsLocalAddress = object
    index: uint32
    address: InterfaceAddress

  MdnsWantedInterfaces = object
    ipv4: seq[MdnsLocalAddress]
    ipv6: seq[MdnsLocalAddress]
    localAddresses: seq[MdnsLocalAddress]

  MdnsInterface = object
    transport: DatagramTransport
    address4: Ipv4Address
    index: uint32
    ingressPinned: bool
    activeOperations: int
    idle: AsyncEvent

  MdnsReplyContext* = object
    ## Identifies the receiving interface, socket and sender. A context becomes
    ## invalid when its interface is removed or the network is closed.
    iface: ref MdnsInterface
    remote: TransportAddress

  MdnsPacketReceived* = proc(
    packet: seq[byte], context: MdnsReplyContext
  ): Future[void].Raising([]) {.gcsafe, raises: [].}

  MdnsNetwork* = ref object
    opening: bool
    opened: bool
    interfaces4: seq[ref MdnsInterface]
    interfaces6: seq[ref MdnsInterface]
    retiring: seq[Future[void].Raising([])]
    localAddresses: seq[MdnsLocalAddress]
    refresher: Future[void].Raising([CancelledError])
    refreshInterval: Duration
    interfaceProvider: proc(): seq[NetworkInterface] {.gcsafe, raises: [].}
    addressProvider: NetworkInterfaceProvider
    onPacket: MdnsPacketReceived
    onInterfacesChanged: proc(indices: seq[uint32]) {.gcsafe, raises: [].}
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
    onInterfacesChanged: proc(indices: seq[uint32]) {.gcsafe, raises: [].} = nil,
): T =
  T(
    addressProvider: addressProvider,
    interfaceProvider: interfaceProvider,
    refreshInterval: refreshInterval,
    onInterfacesChanged: onInterfacesChanged,
    idle: newAsyncEvent(),
  )

func isOpen*(network: MdnsNetwork): bool =
  network.opened and not network.closing

func isLegacyQuery*(context: MdnsReplyContext): bool =
  context.remote.port != Port(MdnsPort)

func isIpv6*(context: MdnsReplyContext): bool =
  context.remote.family == AddressFamily.IPv6

func matchesSource(entry: MdnsLocalAddress, remote: TransportAddress): bool =
  remote.family in {AddressFamily.IPv4, AddressFamily.IPv6} and
    not remote.isUnspecified() and not remote.isMulticast() and
    entry.address.net.mask.prefix > 0 and entry.address.host.family == remote.family and
    entry.address.net.contains(remote)

func interfaceIndex*(context: MdnsReplyContext): uint32 =
  ## The interface on which the query arrived (zero for an empty context).
  if context.iface.isNil: 0'u32 else: context.iface.index

proc isLocalAddress*(network: MdnsNetwork, remote: TransportAddress): bool =
  ## Check whether the sender belongs to an active interface's subnet.
  for entry in network.localAddresses:
    if entry.matchesSource(remote):
      return true
  false

proc sourceInterfaceIndex*(network: MdnsNetwork, remote: TransportAddress): uint32 =
  ## Return the unique interface matching a source, or zero if none or ambiguous.
  var matched = 0'u32
  for entry in network.localAddresses:
    if entry.matchesSource(remote):
      if matched != 0 and matched != entry.index:
        return 0
      matched = entry.index
  return matched

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
    let code = socketLastError()
    return err(option & " failed (OS error " & $code.int & "): " & osErrorMsg(code))

proc membership4(
    transport: DatagramTransport, address: Ipv4Address, join: bool
): LPResult[void] =
  var membership: array[8, byte] = [224'u8, 0, 0, 251, 0, 0, 0, 0]
  for i in 0 .. 3:
    membership[i + 4] = address[i]
  let status = setSocketOption(
    toSocketHandle(transport.fd),
    ipv4Protocol,
    (if join: ipv4AddMembership else: ipv4DropMembership),
    membership,
  )
  checkSocketOption(status, "IPv4 multicast membership")
  ok()

proc configureMulticast(transport: DatagramTransport): LPResult[void] =
  let membershipStatus = restrictMulticastReception(toSocketHandle(transport.fd))
  if membershipStatus != 0:
    # Restricting reception only avoids duplicate multicast delivery across sockets.
    let code = socketLastError()
    warn "IPv4 multicast receive configuration failed",
      err = osErrorMsg(code), code = code.int
  var ttl = MulticastTtl(MdnsMulticastHopLimit)
  let status =
    setSocketOption(toSocketHandle(transport.fd), ipv4Protocol, ipv4MulticastTtl, ttl)
  checkSocketOption(status, "IP_MULTICAST_TTL")
  ok()

proc selectMulticastInterface4(
    transport: DatagramTransport, address: Ipv4Address
): bool =
  var selected = address
  setSocketOption(
    toSocketHandle(transport.fd), ipv4Protocol, ipv4MulticastInterface, selected
  ) == 0

proc configureMulticast6(transport: DatagramTransport): LPResult[void] =
  var hops = MdnsMulticastHopLimit
  let status =
    setSocketOption(toSocketHandle(transport.fd), ipv6Protocol, ipv6MulticastHops, hops)
  checkSocketOption(status, "IPV6_MULTICAST_HOPS")
  ok()

proc membership6(
    transport: DatagramTransport, index: uint32, join = true
): LPResult[void] =
  # ipv6_mreq contains the 16-byte group followed by the native interface index.
  type Ipv6Membership = object
    group: Ipv6Address
    interfaceIndex: uint32

  var membership: Ipv6Membership
  membership.group = [0xff'u8, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb]
  membership.interfaceIndex = index
  let status = setSocketOption(
    toSocketHandle(transport.fd),
    ipv6Protocol,
    (if join: ipv6JoinGroup else: ipv6LeaveGroup),
    membership,
  )
  checkSocketOption(status, (if join: "IPV6_JOIN_GROUP" else: "IPV6_LEAVE_GROUP"))
  ok()

proc selectMulticastInterface6*(transport: DatagramTransport, index: uint32): bool =
  ## Select the outgoing interface for IPv6 multicast on this transport.
  var interfaceIndex = index
  setSocketOption(
    toSocketHandle(transport.fd), ipv6Protocol, ipv6MulticastInterface, interfaceIndex
  ) == 0

proc configureMulticast(transport: DatagramTransport, ipv6: bool): LPResult[void] =
  if ipv6:
    configureMulticast6(transport)
  else:
    configureMulticast(transport)

proc joinMulticast(iface: ref MdnsInterface, ipv6: bool): LPResult[void] =
  if ipv6:
    membership6(iface.transport, iface.index)
  else:
    membership4(iface.transport, iface.address4, true)

proc selectMulticastInterface(iface: ref MdnsInterface, ipv6: bool): bool =
  if ipv6:
    selectMulticastInterface6(iface.transport, iface.index)
  else:
    selectMulticastInterface4(iface.transport, iface.address4)

template trackOperation(network: MdnsNetwork, body: untyped) =
  inc network.activeOperations
  network.idle.clear()
  try:
    body
  finally:
    dec network.activeOperations
    if network.activeOperations == 0:
      network.idle.fire()

template acquireInterface(iface: ref MdnsInterface) =
  inc iface.activeOperations
  iface.idle.clear()

template releaseInterface(iface: ref MdnsInterface) =
  dec iface.activeOperations
  if iface.activeOperations == 0:
    iface.idle.fire()

proc closeInterface(iface: ref MdnsInterface) {.async: (raises: []).} =
  await noCancel iface.transport.closeWait()
  # The transport's callback captures iface, so release it after closing.
  iface.transport = nil

proc retire(iface: ref MdnsInterface) {.async: (raises: []).} =
  # A send or handler may still hold this socket after an interface refresh.
  while iface.activeOperations > 0:
    await noCancel iface.idle.wait()
  await iface.closeInterface()

proc receivingInterface(
    network: MdnsNetwork, iface: ref MdnsInterface, remote: TransportAddress
): ref MdnsInterface =
  if iface.ingressPinned:
    return iface

  # Link-local IPv6 subnets overlap on every link and cannot identify ingress.
  # Use the receiving socket as a best-effort association in this fallback.
  if remote.family == AddressFamily.IPv6 and remote.isLinkLocal():
    return iface

  # Prefer a unique subnet match when its socket is available. Otherwise use
  # the receiving socket as a best-effort association, including overlapping LANs.
  let matched = network.sourceInterfaceIndex(remote)
  if matched == 0:
    return iface

  let interfaces =
    if remote.family == AddressFamily.IPv6: network.interfaces6 else: network.interfaces4
  for candidate in interfaces:
    if candidate.index == matched:
      return candidate
  iface

proc receivedOn(network: MdnsNetwork, iface: ref MdnsInterface): DatagramCallback =
  proc received(
      transport: DatagramTransport, remote: TransportAddress
  ) {.async: (raises: []).} =
    if not network.isOpen or
        (iface notin network.interfaces4 and iface notin network.interfaces6):
      return
    try:
      # Copy before the handler yields and Chronos reuses the receive buffer.
      let packet = transport.getMessage()
      let receiving = network.receivingInterface(iface, remote)
      if receiving.isNil:
        return
      trackOperation network:
        await network.onPacket(
          packet, MdnsReplyContext(iface: receiving, remote: remote)
        )
    except TransportError:
      debug "mDNS datagram ignored", err = getCurrentExceptionMsg()

  received

proc newInterfaceTransport(
    callback: DatagramCallback, ipv6: bool
): DatagramTransport {.raises: [TransportError].} =
  if ipv6:
    newDatagramTransport6(
      callback,
      local = MdnsBindAddress6,
      flags = {ReuseAddr, ReusePort},
      bufSize = 9000,
      dualstack = DualStackType.Disabled,
    )
  else:
    newDatagramTransport(
      callback, local = MdnsBindAddress, flags = {ReuseAddr, ReusePort}, bufSize = 9000
    )

proc openInterface(
    network: MdnsNetwork, address4: Ipv4Address, index: uint32, ipv6: bool
): ref MdnsInterface =
  let iface =
    (ref MdnsInterface)(address4: address4, index: index, idle: newAsyncEvent())
  try:
    let callback = network.receivedOn(iface)
    iface.transport = newInterfaceTransport(callback, ipv6)
    let binding = bindToInterface(toSocketHandle(iface.transport.fd), index, ipv6)
    if binding.isErr:
      warn "mDNS receive interface selection failed",
        interfaceIndex = index, err = osErrorMsg(binding.error)
      network.retiring.add(iface.closeInterface())
      return nil
    iface.ingressPinned = binding.get()
    let configured = configureMulticast(iface.transport, ipv6)
    if configured.isOk:
      let joined = joinMulticast(iface, ipv6)
      if joined.isErr:
        debug "mDNS multicast join failed",
          interfaceIndex = index, ipv6 = ipv6, err = joined.error
      let selected = selectMulticastInterface(iface, ipv6)
      if not selected:
        warn "mDNS multicast interface selection failed",
          interfaceIndex = index, ipv6 = ipv6, err = osErrorMsg(socketLastError())
      if joined.isOk and selected:
        return iface
    else:
      warn "mDNS multicast configuration failed",
        interfaceIndex = index, ipv6 = ipv6, err = configured.error
    network.retiring.add(iface.closeInterface())
  except TransportError as exc:
    debug "mDNS interface unavailable",
      interfaceIndex = index, ipv6 = ipv6, err = exc.msg
  return nil

proc wantedInterfaces(network: MdnsNetwork): MdnsWantedInterfaces =
  var wanted4: seq[MdnsLocalAddress]
  var wanted6: seq[MdnsLocalAddress]
  var localAddresses: seq[MdnsLocalAddress]
  for iface in network.interfaceProvider():
    if iface.ifIndex <= 0 or
        (iface.state != StatusUp and iface.ifType != IfSoftwareLoopback):
      continue
    var has4 = false
    for address in iface.addresses:
      localAddresses.add(
        MdnsLocalAddress(index: uint32(iface.ifIndex), address: address)
      )
      case address.host.family
      of AddressFamily.IPv4:
        if not has4:
          wanted4.add(MdnsLocalAddress(index: uint32(iface.ifIndex), address: address))
          has4 = true
      of AddressFamily.IPv6:
        if not wanted6.anyIt(it.index == uint32(iface.ifIndex)):
          wanted6.add(MdnsLocalAddress(index: uint32(iface.ifIndex), address: address))
      else:
        discard

  return
    MdnsWantedInterfaces(ipv4: wanted4, ipv6: wanted6, localAddresses: localAddresses)

proc currentInterfaces4(
    network: MdnsNetwork, wanted4: seq[MdnsLocalAddress]
): seq[ref MdnsInterface] =
  var current: seq[ref MdnsInterface]
  if network.isOpen:
    for wanted in wanted4:
      let address4 = wanted.address.host.address_v4
      var found: ref MdnsInterface
      for iface in network.interfaces4:
        if iface.address4 == address4 and iface.index == wanted.index:
          found = iface
          break
      if found.isNil:
        found = network.openInterface(address4, wanted.index, false)
      if not found.isNil:
        current.add(found)
  current

proc currentInterfaces6(
    network: MdnsNetwork, wanted6: seq[MdnsLocalAddress]
): seq[ref MdnsInterface] =
  var current: seq[ref MdnsInterface]
  if network.isOpen:
    for wanted in wanted6:
      var found: ref MdnsInterface
      for iface in network.interfaces6:
        if iface.index == wanted.index:
          found = iface
          break
      if found.isNil:
        found = network.openInterface(default(Ipv4Address), wanted.index, true)
      if not found.isNil:
        current.add(found)
  current

proc retireRemovedInterfaces(
    network: MdnsNetwork, current4, current6: seq[ref MdnsInterface]
) =
  # Leave immediately, but drain in-flight operations before closing the socket.
  for iface in network.interfaces4:
    if iface notin current4:
      discard membership4(iface.transport, iface.address4, false)
      network.retiring.add(iface.retire())
  for iface in network.interfaces6:
    if iface notin current6:
      discard membership6(iface.transport, iface.index, false)
      network.retiring.add(iface.retire())

proc refreshInterfacesImpl(network: MdnsNetwork): bool =
  # Return whether eligible interfaces exist, even if their sockets fail to open.
  if network.closing:
    return false
  let wanted = network.wantedInterfaces()
  let current4 = network.currentInterfaces4(wanted.ipv4)
  let current6 = network.currentInterfaces6(wanted.ipv6)
  network.retireRemovedInterfaces(current4, current6)
  network.interfaces4 = current4
  network.interfaces6 = current6
  network.localAddresses = wanted.localAddresses
  if not network.onInterfacesChanged.isNil:
    var indices: seq[uint32]
    for iface in current4 & current6:
      if iface.index notin indices:
        indices.add(iface.index)
    network.onInterfacesChanged(indices)
  var pending: seq[Future[void].Raising([])]
  for closing in network.retiring:
    if not closing.finished:
      pending.add(closing)
  network.retiring = pending
  return wanted.ipv4.len > 0 or wanted.ipv6.len > 0

proc refreshInterfaces*(network: MdnsNetwork) =
  ## Each socket joins one interface, retaining the ingress interface for replies.
  ## Its outgoing multicast interface stays fixed for its entire lifetime.
  discard network.refreshInterfacesImpl()

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

proc multicastInterfaces(
    interfaces: seq[ref MdnsInterface], packet: seq[byte], destination: TransportAddress
): Future[bool] {.async: (raises: [CancelledError]).} =
  var sent = false
  for iface in interfaces:
    # Keep sending after both successes and failures on earlier interfaces.
    if await iface.transport.sendPacket(packet, destination):
      sent = true
  return sent

proc multicast*(
    network: MdnsNetwork, packet: seq[byte]
): Future[bool] {.async: (raises: [CancelledError]).} =
  if not network.isOpen:
    return false
  trackOperation network:
    # Snapshot both families before a queued send allows a refresh to run.
    let interfaces4 = network.interfaces4
    let interfaces6 = network.interfaces6
    let targets = interfaces4 & interfaces6
    # Reserve every socket in both snapshots before the first send can yield.
    for iface in targets:
      iface.acquireInterface()
    try:
      let sent4 = await multicastInterfaces(interfaces4, packet, MdnsDestination)
      let sent6 = await multicastInterfaces(interfaces6, packet, MdnsDestination6)
      return sent4 or sent6
    finally:
      for iface in targets:
        iface.releaseInterface()

proc reply*(
    network: MdnsNetwork, packet: seq[byte], context: MdnsReplyContext, unicast: bool
): Future[bool] {.async: (raises: [CancelledError]).} =
  if not network.isOpen or context.iface.isNil or (
    context.iface notin network.interfaces4 and context.iface notin network.interfaces6
  ):
    return false
  trackOperation network:
    let destination =
      if unicast:
        context.remote
      elif context.isIpv6:
        MdnsDestination6
      else:
        MdnsDestination
    context.iface.acquireInterface()
    try:
      return await context.iface.transport.sendPacket(packet, destination)
    finally:
      context.iface.releaseInterface()

proc closeImpl(network: MdnsNetwork) {.async: (raises: []).} =
  network.closing = true
  # Remove the interfaces before yielding, so refresh cannot retire a socket
  # that shutdown is already closing. In-flight sends hold their own snapshots.
  let closingInterfaces = network.interfaces4 & network.interfaces6
  network.interfaces4.setLen(0)
  network.interfaces6.setLen(0)
  if not network.refresher.isNil:
    await noCancel network.refresher.cancelAndWait()
    network.refresher = nil
  # Ignore new datagrams, but let queued sends and handlers finish before
  # closing their sockets. Chronos does not drain queued sends on close.
  if network.activeOperations > 0:
    await noCancel network.idle.wait()
  for iface in closingInterfaces:
    await noCancel iface.closeInterface()
  for closing in network.retiring:
    await noCancel closing
  network.retiring.setLen(0)
  network.opened = false
  network.localAddresses.setLen(0)
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
  ## With eligible interfaces, at least one socket must open successfully.
  ## Without interfaces, startup succeeds and waits for a later refresh.
  if network.closing:
    return err("mDNS network is closing")
  if network.opening:
    return err("mDNS network is opening")
  if network.isOpen:
    return ok()
  doAssert not onPacket.isNil, "mDNS packet callback must not be nil"
  network.opening = true
  defer:
    network.opening = false
  network.closeFut = nil
  network.onPacket = onPacket
  network.opened = true
  let hasInterfaces = network.refreshInterfacesImpl()
  if hasInterfaces and network.interfaces4.len == 0 and network.interfaces6.len == 0:
    await network.close()
    return err("Unable to open mDNS sockets on any available interface")
  network.refresher = network.refreshLoop()
  return ok()

func ipv4InterfaceIndices*(network: MdnsNetwork): seq[uint32] =
  ## Interfaces with successfully configured IPv4 multicast sockets.
  var indices: seq[uint32]
  for iface in network.interfaces4:
    indices.add(iface.index)
  return indices

func ipv4IngressPinned*(network: MdnsNetwork): bool =
  ## Whether every configured IPv4 socket can identify its ingress interface.
  for iface in network.interfaces4:
    if not iface.ingressPinned:
      return false
  true
