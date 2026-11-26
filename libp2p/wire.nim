# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

## This module implements wire network connection procedures.
import chronos, stew/endians2
import multiaddress, multicodec, errors, utils/macroutils

export multiaddress, chronos

when defined(windows): import winlean else: import posix

const
  RTRANSPMA* = mapOr(TCP, WebSockets, UNIX)

  TRANSPMA* = mapOr(RTRANSPMA, QUIC, QUIC_V1, UDP)

proc initTAddress*(ma: MultiAddress): MaResult[TransportAddress] =
  ## Initialize ``TransportAddress`` with MultiAddress ``ma``.
  ##
  ## MultiAddress must be wire address, e.g. ``{IP4, IP6, UNIX}/{TCP, UDP}``.
  ##

  if mapOr(TCP_IP, WebSockets_IP, UNIX, UDP_IP, QUIC_V1_IP).match(ma):
    var pbuf: array[2, byte]
    let code = (?(?ma[0]).protoCode())
    if code == multiCodec("unix"):
      var res = TransportAddress(family: AddressFamily.Unix)
      if (?(?ma[0]).protoArgument(res.address_un)) == 0:
        err("Incorrect Unix domain address")
      else:
        res.port = Port(1)
        ok(res)
    elif code == multiCodec("ip4"):
      var res = TransportAddress(family: AddressFamily.IPv4)
      if (?(?ma[0]).protoArgument(res.address_v4)) == 0:
        err("Incorrect IPv4 address")
      else:
        if (?(?ma[1]).protoArgument(pbuf)) == 0:
          err("Incorrect port number")
        else:
          res.port = Port(fromBytesBE(uint16, pbuf))
          ok(res)
    else:
      var res = TransportAddress(family: AddressFamily.IPv6)
      if (?(?ma[0]).protoArgument(res.address_v6)) == 0:
        err("Incorrect IPv6 address")
      else:
        if (?(?ma[1]).protoArgument(pbuf)) == 0:
          err("Incorrect port number")
        else:
          res.port = Port(fromBytesBE(uint16, pbuf))
          ok(res)
  else:
    err($ma, "MultiAddress must be wire address (tcp, udp or unix)")

proc connect*(
    ma: MultiAddress,
    bufferSize = DefaultStreamBufferSize,
    child: StreamTransport = nil,
    flags = default(set[SocketFlags]),
    localAddress: Opt[MultiAddress] = Opt.none(MultiAddress),
): Future[StreamTransport] {.
    async: (raises: [MaInvalidAddress, TransportError, CancelledError, LPError])
.} =
  ## Open new connection to remote peer with address ``ma`` and create
  ## new transport object ``StreamTransport`` for established connection.
  ## ``bufferSize`` is size of internal buffer for transport.
  ##

  if not (TRANSPMA.match(ma)):
    raise newException(MaInvalidAddress, "Incorrect or unsupported address!")

  let transportAddress = initTAddress(ma).tryGet()

  compilesOr:
    return await connect(
      transportAddress,
      bufferSize,
      child,
      if localAddress.isSome():
        initTAddress(localAddress.expect("just checked")).tryGet()
      else:
        TransportAddress(),
      flags,
    )
  do:
    # support for older chronos versions
    return await connect(transportAddress, bufferSize, child)

proc createStreamServer*[T](
    ma: MultiAddress,
    cbproc: StreamCallback2,
    flags: set[ServerFlags] = {},
    udata: ref T,
    sock: AsyncFD = asyncInvalidSocket,
    backlog: int = 100,
    bufferSize: int = DefaultStreamBufferSize,
    child: StreamServer = nil,
    init: TransportInitCallback = nil,
): StreamServer {.raises: [LPError, MaInvalidAddress].} =
  ## Create new TCP stream server which bounds to ``ma`` address.
  if not (RTRANSPMA.match(ma)):
    raise newException(
      MaInvalidAddress, "Incorrect or unsupported address in createStreamServer"
    )

  try:
    return createStreamServer(
      initTAddress(ma).tryGet(),
      cbproc,
      flags,
      udata,
      sock,
      backlog,
      bufferSize,
      child,
      init,
    )
  except CatchableError as exc:
    raise newException(LPError, "failed createStreamServer: " & exc.msg, exc)

proc createStreamServer*[T](
    ma: MultiAddress,
    flags: set[ServerFlags] = {},
    udata: ref T,
    sock: AsyncFD = asyncInvalidSocket,
    backlog: int = 100,
    bufferSize: int = DefaultStreamBufferSize,
    child: StreamServer = nil,
    init: TransportInitCallback = nil,
): StreamServer {.raises: [LPError, MaInvalidAddress].} =
  ## Create new TCP stream server which bounds to ``ma`` address.
  ##

  if not (RTRANSPMA.match(ma)):
    raise newException(MaInvalidAddress, "Incorrect or unsupported address!")

  try:
    return createStreamServer(
      initTAddress(ma).tryGet(), flags, udata, sock, backlog, bufferSize, child, init
    )
  except CatchableError as exc:
    raise newException(LPError, "failed simpler createStreamServer: " & exc.msg, exc)

proc getLocalAddress*(sock: AsyncFD): TransportAddress =
  ## Retrieve local socket ``sock`` address.
  ##
  ## Note: This procedure only used in `go-libp2p-daemon` wrapper.
  var saddr: Sockaddr_storage
  var slen = SockLen(sizeof(Sockaddr_storage))
  var ta: TransportAddress

  if getsockname(SocketHandle(sock), cast[ptr SockAddr](addr saddr), addr slen) == 0:
    fromSAddr(addr saddr, slen, ta)
  ta

proc isGlobalMA*(ma: MultiAddress): bool =
  ## True only for a wire address with a globally routable IP, never for a name.
  let hostIP = initTAddress(ma).valueOr:
    return false

  hostIP.isGlobal()

proc isPublicMA*(ma: MultiAddress): bool =
  if DNS.matchPartial(ma):
    return true

  isGlobalMA(ma)

proc isCircuitRelayMA*(ma: MultiAddress): bool =
  if ma.contains(multiCodec("p2p-circuit")).get(false):
    return true

proc isLoopbackMA*(ma: MultiAddress): bool =
  let hostIP = initTAddress(ma).valueOr:
    return false

  return hostIP.isLoopback()

proc isPrivateMA*(ma: MultiAddress): bool =
  ## True for addresses on private/non-routable networks: RFC1918, CGNAT
  ## (RFC6598), link-local. These are the cases where a NAT port mapping is
  ## actually useful.
  let hostIP = initTAddress(ma).valueOr:
    return false

  hostIP.isPrivate() or hostIP.isShared() or hostIP.isLinkLocal()

const
  AnyAddressV4 = [0'u8, 0, 0, 0]
  AnyAddressV6 = [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  AnyAddressV4Mapped = [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]
    ## ``::ffff:0.0.0.0``, the IPv4-mapped spelling of the wildcard host.

proc portOf(ma: MultiAddress): Opt[Port] =
  for codec in [TcpMultiCodec, UdpMultiCodec]:
    let arg = ma.getProtocolArgument(codec).valueOr:
      continue
    if arg.len == 2:
      return Opt.some(Port(uint16.fromBytesBE(arg)))
  Opt.none(Port)

proc isDialableMA*(ma: MultiAddress): bool =
  ## False for a wildcard bind host (``0.0.0.0`` / ``::``) or an unresolved ephemeral port.
  if isCircuitRelayMA(ma):
    return true

  ma.portOf().ifValue(port):
    if port == Port(0):
      return false

  ma.getIp().ifValue(ip):
    case ip.family
    of IpAddressFamily.IPv4:
      return ip.address_v4 != AnyAddressV4
    of IpAddressFamily.IPv6:
      return ip.address_v6 != AnyAddressV6 and ip.address_v6 != AnyAddressV4Mapped

  true
