# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Tor transport implementation

{.push raises: [].}

import chronos, chronicles, strutils, results
import stew/[byteutils, endians2, objects]
import ../multicodec
import
  transport,
  tcptransport,
  ../switch,
  ../builders,
  ../stream/[lpstream, connection, chronosstream],
  ../multiaddress,
  ../upgrademngrs/upgrade

logScope:
  topics = "libp2p tor"

const
  IPTcp = mapAnd(IP, mapEq("tcp"))
  IPv4Tcp = mapAnd(IP4, mapEq("tcp"))
  IPv6Tcp = mapAnd(IP6, mapEq("tcp"))
  DnsTcp = mapAnd(DNSANY, mapEq("tcp"))

  Socks5ProtocolVersion = byte(5)
  NMethods = byte(1)
  MaxSocks5DomainLength = high(uint8).int

type
  TorTransport* = ref object of Transport
    transportAddress: TransportAddress
    tcpTransport: TcpTransport

  Socks5AuthMethod* {.pure.} = enum
    NoAuth = 0
    GSSAPI = 1
    UsernamePassword = 2
    NoAcceptableMethod = 0xff

  Socks5RequestCommand* {.pure.} = enum
    Connect = 1
    Bind = 2
    UdpAssoc = 3

  Socks5AddressType* {.pure.} = enum
    IPv4 = 1
    FQDN = 3
    IPv6 = 4

  Socks5ReplyType* {.pure.} = enum
    Succeeded = (0, "Succeeded")
    ServerFailure = (1, "Server Failure")
    ConnectionNotAllowed = (2, "Connection Not Allowed")
    NetworkUnreachable = (3, "Network Unreachable")
    HostUnreachable = (4, "Host Unreachable")
    ConnectionRefused = (5, "Connection Refused")
    TtlExpired = (6, "Ttl Expired")
    CommandNotSupported = (7, "Command Not Supported")
    AddressTypeNotSupported = (8, "Address Type Not Supported")

  TransportStartError* = transport.TransportStartError

  Socks5Error* = object of CatchableError
  Socks5AuthFailedError* = object of Socks5Error
  Socks5VersionError* = object of Socks5Error
  Socks5ServerReplyError* = object of Socks5Error

  Socks5Target = object
    atyp: byte
    dstAddr: seq[byte]
    dstPort: seq[byte]

  TorListenAddrs = object
    tcp: seq[MultiAddress]
    onion3: seq[MultiAddress]

proc new*(
    T: typedesc[TorTransport],
    transportAddress: TransportAddress,
    flags: set[ServerFlags] = {},
    upgrade: Upgrade,
): T =
  ## Creates a Tor transport

  let self = T(
    transportAddress: transportAddress,
    upgrader: upgrade,
    tcpTransport: TcpTransport.new(flags, upgrade),
  )
  procCall Transport(self).initialize()
  self

proc handlesDial(address: MultiAddress): bool {.gcsafe.} =
  return Onion3.match(address) or TCP.match(address) or DNSANY.match(address)

proc handlesStart(address: MultiAddress): bool {.gcsafe.} =
  return TcpOnion3.match(address)

func checkAuthReply(reply: array[2, byte]): LPResult[void] =
  if reply[0] != Socks5ProtocolVersion:
    return err("Unsupported socks version")
  if reply[1] != Socks5AuthMethod.NoAuth.byte:
    return err("Unsupported auth method")

  ok()

proc authenticate(
    transp: StreamTransport
): Future[LPResult[void]] {.async: (raises: [common.TransportError, CancelledError]).} =
  discard
    await transp.write(@[Socks5ProtocolVersion, NMethods, Socks5AuthMethod.NoAuth.byte])
  var serverReply: array[2, byte]
  await transp.readExactly(addr serverReply[0], serverReply.len)
  checkAuthReply(serverReply)

func checkReplyHeader(header: array[4, byte]): LPResult[void] =
  if header[0] != Socks5ProtocolVersion:
    return err("Unsupported socks version")
  if header[1] == Socks5ReplyType.Succeeded.byte:
    return ok()

  var socks5ReplyType: Socks5ReplyType
  if socks5ReplyType.checkedEnumAssign(header[1]):
    err("Server reply error: " & $socks5ReplyType)
  else:
    err("Unexpected server reply")

proc readServerReply(
    transp: StreamTransport
): Future[LPResult[void]] {.async: (raises: [common.TransportError, CancelledError]).} =
  ## The specification for this code is defined on
  ## [link text](https://www.rfc-editor.org/rfc/rfc1928#section-5)
  ## and [link text](https://www.rfc-editor.org/rfc/rfc1928#section-6).
  var header: array[4, byte]
  await transp.readExactly(addr header[0], header.len)
  ?checkReplyHeader(header)

  let addressLength =
    case header[3]
    of Socks5AddressType.IPv4.byte:
      4
    of Socks5AddressType.FQDN.byte:
      var length: byte
      await transp.readExactly(addr length, 1)
      int(length)
    of Socks5AddressType.IPv6.byte:
      16
    else:
      return err("Address not supported")
  var addressAndPort = newSeqUninit[byte](addressLength + 2)
  await transp.readExactly(addr addressAndPort[0], addressAndPort.len)
  ok()

func parseOnion3(address: MultiAddress): Socks5Target =
  ## `address` must match `Onion3`: one onion3 component, so the port sits at bytes 37..38.
  let addressStr = ($address).split('/')[2].split(':')[0] & ".onion"
  Socks5Target(
    atyp: Socks5AddressType.FQDN.byte,
    dstAddr: @(uint8(addressStr.len).toBytes()) & addressStr.toBytes(),
    dstPort: address.data.buffer[37 .. 38],
  )

func tcpPort(address: MultiAddress): LPResult[seq[byte]] =
  (?address[TcpMultiCodec]).protoArgument()

func parseIpTcp(address: MultiAddress): LPResult[Socks5Target] =
  let (codec, atyp) =
    if IPv4Tcp.match(address):
      (multiCodec("ip4"), Socks5AddressType.IPv4.byte)
    elif IPv6Tcp.match(address):
      (multiCodec("ip6"), Socks5AddressType.IPv6.byte)
    else:
      return err("IP address not supported")

  ok Socks5Target(
    atyp: atyp, dstAddr: ?(?address[codec]).protoArgument(), dstPort: ?address.tcpPort()
  )

func parseDnsTcp(address: MultiAddress): LPResult[Socks5Target] =
  let dnsAddress = ?(?address[multiCodec("dns")]).protoArgument()
  if dnsAddress.len > MaxSocks5DomainLength:
    return err("DNS address exceeds SOCKS5 domain length limit")

  ok Socks5Target(
    atyp: Socks5AddressType.FQDN.byte,
    dstAddr: @(uint8(dnsAddress.len).toBytes()) & dnsAddress,
    dstPort: ?address.tcpPort(),
  )

func parseTarget(address: MultiAddress): LPResult[Socks5Target] =
  if Onion3.match(address):
    ok parseOnion3(address)
  elif IPTcp.match(address):
    parseIpTcp(address)
  elif DnsTcp.match(address):
    parseDnsTcp(address)
  else:
    err("Address not supported")

proc dialPeer(
    transp: StreamTransport, address: MultiAddress
): Future[LPResult[void]] {.async: (raises: [common.TransportError, CancelledError]).} =
  let auth = await authenticate(transp)
  ?auth

  let target = ?parseTarget(address)
  let reserved = byte(0)
  let request =
    @[Socks5ProtocolVersion, Socks5RequestCommand.Connect.byte, reserved, target.atyp] &
    target.dstAddr & target.dstPort
  discard await transp.write(request)
  await readServerReply(transp)

method dial*(
    self: TorTransport,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  ## dial a peer
  ##
  if not handlesDial(address):
    raise newException(TransportDialError, "Address not supported")
  trace "Transport connection started", peerId, address = $address

  var transp: StreamTransport
  let handshake =
    try:
      transp = await connect(self.transportAddress)
      await dialPeer(transp, address)
    except CancelledError as e:
      safeCloseWait(transp)
      raise e
    except common.TransportError as e:
      safeCloseWait(transp)
      raise newException(
        transport.TransportDialError, "error in dial TorTransport: " & e.msg, e
      )

  handshake.isOkOr:
    safeCloseWait(transp)
    raise
      newException(transport.TransportDialError, "TorTransport.dial failed. " & error)

  self.tcpTransport.connHandler(
    transp, Opt.none(MultiAddress), Opt.none(MultiAddress), Direction.Out
  )

func splitListenAddrs(addrs: openArray[MultiAddress]): LPResult[TorListenAddrs] =
  if addrs.len == 0:
    return err("TorTransport.start called with no address.")

  var listenAddrs: TorListenAddrs
  for ma in addrs:
    if not handlesStart(ma):
      return err("TorTransport.start called with unsupported address: " & $ma)

    let
      tcp = ma[0 .. 1].valueOr:
        return err("TorTransport.start called with invalid tor address: " & $ma)
      onion3 = ma[multiCodec("onion3")].valueOr:
        return err("TorTransport.start called with invalid tor address: " & $ma)
    listenAddrs.tcp.add(tcp)
    listenAddrs.onion3.add(onion3)

  ok(listenAddrs)

method start*(
    self: TorTransport, addrs: seq[MultiAddress]
) {.async: (raises: [LPError, transport.TransportError, CancelledError]).} =
  if self.running:
    warn "Tor transport already started"
    return

  let listenAddrs = splitListenAddrs(addrs).valueOrRaise(TransportStartError)
  await procCall Transport(self).start(listenAddrs.onion3)
  await self.tcpTransport.start(listenAddrs.tcp)
  info "Tor transport started", addresses = self.addrs

method accept*(
    self: TorTransport
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  ## accept a new Tor connection
  ##
  let conn = await self.tcpTransport.accept()
  conn.observedAddr = Opt.none(MultiAddress)
  return conn

method stop*(self: TorTransport) {.async: (raises: []).} =
  ## stop the transport
  ##
  let wasRunning = self.running
  if not wasRunning:
    warn "Tor transport already stopped"
  await procCall Transport(self).stop() # call base
  await self.tcpTransport.stop()
  if wasRunning:
    info "Tor transport stopped", addresses = self.addrs

method handles*(t: TorTransport, address: MultiAddress): bool {.gcsafe, raises: [].} =
  if procCall Transport(t).handles(address):
    return handlesDial(address) or handlesStart(address)

type TorSwitch* = ref object of Switch

proc new*(
    T: typedesc[TorSwitch],
    torServer: TransportAddress,
    rng: Rng,
    addresses: seq[MultiAddress] = @[],
    flags: set[ServerFlags] = {},
): TorSwitch {.raises: [LPError].} =
  var builder = SwitchBuilder.new().withRng(rng).withTransport(
      proc(config: TransportConfig): Transport =
        TorTransport.new(torServer, flags, config.upgr)
    )
  if addresses.len != 0:
    builder = builder.withAddresses(addresses)
  let switch = builder.withMplex().withNoise().build()
  let torSwitch = T(
    peerInfo: switch.peerInfo,
    ms: switch.ms,
    transports: switch.transports,
    connManager: switch.connManager,
    peerStore: switch.peerStore,
    dialer: Dialer.new(
      switch.peerInfo.peerId, switch.connManager, switch.peerStore, switch.transports,
      switch.ms, nil,
    ),
    nameResolver: nil,
    addressManager: switch.addressManager,
  )

  torSwitch.connManager.peerStore = switch.peerStore
  return torSwitch

method addTransport*(s: TorSwitch, t: Transport) =
  doAssert(false, "[TorSwitch.addTransport ] abstract method not implemented!")

method getTorTransport*(s: TorSwitch): Transport {.base.} =
  return s.transports[0]
