# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements MultiAddress.

{.push raises: [].}

import pkg/[chronos, chronicles, results, protobuf_serialization]
import std/[nativesockets, net, hashes, unicode]
import tables, strutils, sets
import
  multicodec,
  multibase,
  transcoder,
  vbuffer,
  peerid,
  protobuf/minprotobuf,
  errors,
  utils/[opt, shortlog, conversion, collections]
import stew/[base32, endians2]
export results, vbuffer, errors, opt, shortlog, collections

logScope:
  topics = "libp2p multiaddress"

type
  MAKind* = enum
    None
    Fixed
    Length
    Path
    Marker

  MAProtocol* = object
    mcodec*: MultiCodec
    size*: int
    kind: MAKind
    coder*: Transcoder

  MultiAddress* = object
    data: VBuffer

  MaPatternOp* = enum
    Eq
    Or
    And

  MaPattern* = object
    operator*: MaPatternOp
    args*: seq[MaPattern]
    value*: MultiCodec

  MaPatResult* = object
    flag*: bool
    rem*: seq[MultiCodec]

  MaResult*[T] = LPResult[T]

  MaError* = object of LPError
  MaInvalidAddress* = object of MaError

  IpTransportProtocol* = enum
    tcpProtocol
    udpProtocol

func maErr*(msg: string): ref MaError =
  (ref MaError)(msg: msg)

const libp2p_multiaddress_exts* {.strdefine.} = ""

const
  # These are needed in order to avoid an ambiguity error stemming from
  # some cint constants with the same name defined in the posix modules
  IPPROTO_TCP = Protocol.IPPROTO_TCP
  IPPROTO_UDP = Protocol.IPPROTO_UDP
proc data*(ma: MultiAddress): VBuffer =
  ## Returns the data buffer of the MultiAddress.
  return ma.data

# Helper: create a lightweight cursor from a MultiAddress to avoid VBuffer copies
func initCursor(ma: MultiAddress): VBuffer =
  ## Creates a VBuffer cursor from a MultiAddress without copying the seq.
  ## This is used internally to avoid the overhead of copying the buffer seq
  ## when iterating/parsing a multiaddress.
  VBuffer(buffer: ma.data.buffer, offset: ma.data.offset)

proc hash*(a: MultiAddress): Hash =
  var h: Hash = 0
  h = h !& hash(a.data.buffer)
  h = h !& hash(a.data.offset)
  !$h

proc ip4StB(s: string, vb: var VBuffer): bool =
  ## IPv4 stringToBuffer() implementation.
  try:
    var a = parseIpAddress(s)
    if a.family == IpAddressFamily.IPv4:
      vb.writeArray(a.address_v4)
      return true
  except CatchableError:
    discard
  false

proc ip4BtS(vb: var VBuffer, s: var string): bool =
  ## IPv4 bufferToString() implementation.
  var a = IpAddress(family: IpAddressFamily.IPv4)
  if vb.readArray(a.address_v4) == 4:
    s = $a
    return true
  false

proc ip4VB(vb: var VBuffer): bool =
  ## IPv4 validateBuffer() implementation.
  var a = IpAddress(family: IpAddressFamily.IPv4)
  if vb.readArray(a.address_v4) == 4:
    return true
  false

proc ip6StB(s: string, vb: var VBuffer): bool =
  ## IPv6 stringToBuffer() implementation.
  try:
    var a = parseIpAddress(s)
    if a.family == IpAddressFamily.IPv6:
      vb.writeArray(a.address_v6)
      return true
  except CatchableError:
    discard
  false

proc ip6BtS(vb: var VBuffer, s: var string): bool =
  ## IPv6 bufferToString() implementation.
  var a = IpAddress(family: IpAddressFamily.IPv6)
  if vb.readArray(a.address_v6) == 16:
    s = $a
    return true
  false

proc ip6VB(vb: var VBuffer): bool =
  ## IPv6 validateBuffer() implementation.
  var a = IpAddress(family: IpAddressFamily.IPv6)
  if vb.readArray(a.address_v6) == 16:
    return true
  false

template pathStringToBuffer(s: string, vb: var VBuffer): bool =
  if len(s) > 0:
    vb.writeSeq(s)
    true
  else:
    false

template pathBufferToString(vb: var VBuffer, s: var string): bool =
  s = ""
  if (vb.readSeq(s) > 0) and (len(s) > 0): true else: false

template pathBufferToStringNoSlash(vb: var VBuffer, s: var string): bool =
  s = ""
  if (vb.readSeq(s) > 0) and (len(s) > 0) and (s.find('/') == -1): true else: false

template pathValidateBuffer(vb: var VBuffer): bool =
  var s = ""
  pathBufferToString(vb, s)

template pathValidateBufferNoSlash(vb: var VBuffer): bool =
  var s = ""
  pathBufferToStringNoSlash(vb, s)

proc ip6zoneStB(s: string, vb: var VBuffer): bool =
  ## IPv6 stringToBuffer() implementation.
  pathStringToBuffer(s, vb)

proc ip6zoneBtS(vb: var VBuffer, s: var string): bool =
  ## IPv6 bufferToString() implementation.
  pathBufferToStringNoSlash(vb, s)

proc ip6zoneVB(vb: var VBuffer): bool =
  ## IPv6 validateBuffer() implementation.
  pathValidateBufferNoSlash(vb)

proc memoryStB(s: string, vb: var VBuffer): bool =
  ## Memory stringToBuffer() implementation.
  pathStringToBuffer(s, vb)

proc memoryBtS(vb: var VBuffer, s: var string): bool =
  ## Memory bufferToString() implementation.
  pathBufferToString(vb, s)

proc memoryVB(vb: var VBuffer): bool =
  ## Memory validateBuffer() implementation.
  pathValidateBuffer(vb)

proc portStB(s: string, vb: var VBuffer): bool =
  ## Port number stringToBuffer() implementation.
  var port: array[2, byte]
  try:
    var nport = parseInt(s)
    if (nport >= 0) and (nport < 65536):
      port[0] = cast[byte]((nport shr 8) and 0xFF)
      port[1] = cast[byte](nport and 0xFF)
      vb.writeArray(port)
      return true
  except CatchableError:
    discard
  false

proc portBtS(vb: var VBuffer, s: var string): bool =
  ## Port number bufferToString() implementation.
  var port: array[2, byte]
  if vb.readArray(port) == 2:
    let nport = (safeConvert[uint16](port[0]) shl 8) or safeConvert[uint16](port[1])
    s = $nport
    return true
  false

proc portVB(vb: var VBuffer): bool =
  ## Port number validateBuffer() implementation.
  var port: array[2, byte]
  if vb.readArray(port) == 2:
    return true
  false

proc p2pStB(s: string, vb: var VBuffer): bool =
  ## P2P address stringToBuffer() implementation.
  let pid = PeerId.init(s).valueOr:
    return false
  vb.writeSeq(pid.data)
  true

proc p2pBtS(vb: var VBuffer, s: var string): bool =
  ## P2P address bufferToString() implementation.
  var address = newSeqUninit[byte](0)
  if vb.readSeq(address) > 0:
    let pid = PeerId.init(address).valueOr:
      return false
    s = $pid
    return true
  false

proc p2pVB(vb: var VBuffer): bool =
  ## P2P address validateBuffer() implementation.
  var address = newSeqUninit[byte](0)
  if vb.readSeq(address) > 0:
    return PeerId.init(address).isOk
  false

proc onionStB(s: string, vb: var VBuffer): bool =
  try:
    var parts = s.split(':')
    if len(parts) != 2:
      return false
    if len(parts[0]) != 16:
      return false
    var address = Base32Lower.decode(parts[0].toLowerAscii())
    var nport = parseInt(parts[1])
    if (nport > 0 and nport < 65536) and len(address) == 10:
      address.setLen(12)
      address[10] = cast[byte]((nport shr 8) and 0xFF)
      address[11] = cast[byte](nport and 0xFF)
      vb.writeArray(address)
      return true
  except CatchableError:
    discard
  false

proc onionBtS(vb: var VBuffer, s: var string): bool =
  ## ONION address bufferToString() implementation.
  var buf: array[12, byte]
  if vb.readArray(buf) == 12:
    let nport = (safeConvert[uint16](buf[10]) shl 8) or safeConvert[uint16](buf[11])
    s = Base32Lower.encode(buf.toOpenArray(0, 9))
    s.add(":")
    s.add($nport)
    return true
  false

proc onionVB(vb: var VBuffer): bool =
  ## ONION address validateBuffer() implementation.
  var buf: array[12, byte]
  if vb.readArray(buf) == 12:
    return true
  false

proc onion3StB(s: string, vb: var VBuffer): bool =
  try:
    var parts = s.split(':')
    if len(parts) != 2:
      return false
    if len(parts[0]) != 56:
      return false
    var address = Base32Lower.decode(parts[0].toLowerAscii())
    var nport = parseInt(parts[1])
    if (nport > 0 and nport < 65536) and len(address) == 35:
      address.setLen(37)
      address[35] = cast[byte]((nport shr 8) and 0xFF)
      address[36] = cast[byte](nport and 0xFF)
      vb.writeArray(address)
      return true
  except CatchableError:
    discard
  false

proc onion3BtS(vb: var VBuffer, s: var string): bool =
  ## ONION address bufferToString() implementation.
  var buf: array[37, byte]
  if vb.readArray(buf) == 37:
    var nport = (safeConvert[uint16](buf[35]) shl 8) or safeConvert[uint16](buf[36])
    s = Base32Lower.encode(buf.toOpenArray(0, 34))
    s.add(":")
    s.add($nport)
    return true
  false

proc onion3VB(vb: var VBuffer): bool =
  ## ONION address validateBuffer() implementation.
  var buf: array[37, byte]
  if vb.readArray(buf) == 37:
    return true
  false

proc unixStB(s: string, vb: var VBuffer): bool =
  ## Unix socket name stringToBuffer() implementation.
  pathStringToBuffer(s, vb)

proc unixBtS(vb: var VBuffer, s: var string): bool =
  ## Unix socket name bufferToString() implementation.
  pathBufferToString(vb, s)

proc unixVB(vb: var VBuffer): bool =
  ## Unix socket name validateBuffer() implementation.
  pathValidateBuffer(vb)

proc dnsStB(s: string, vb: var VBuffer): bool =
  ## DNS name stringToBuffer() implementation.
  pathStringToBuffer(s, vb)

proc dnsBtS(vb: var VBuffer, s: var string): bool =
  ## DNS name bufferToString() implementation.
  pathBufferToStringNoSlash(vb, s)

proc dnsVB(vb: var VBuffer): bool =
  ## DNS name validateBuffer() implementation.
  pathValidateBufferNoSlash(vb)

proc sniValid(s: string): bool =
  s.len > 0 and s.find('/') == -1 and validateUtf8(s) == -1

proc sniStB(s: string, vb: var VBuffer): bool =
  if not sniValid(s):
    return false
  vb.writeSeq(s)
  true

proc sniBtS(vb: var VBuffer, s: var string): bool =
  s = ""
  vb.readSeq(s) > 0 and sniValid(s)

proc sniVB(vb: var VBuffer): bool =
  var s = ""
  vb.readSeq(s) > 0 and sniValid(s)

proc mapEq*(codec: string): MaPattern =
  ## ``Equal`` operator for pattern
  MaPattern(operator: Eq, value: multiCodec(codec))

proc mapOr*(args: varargs[MaPattern]): MaPattern =
  ## ``Or`` operator for pattern
  MaPattern(operator: Or, args: @args)

proc mapAnd*(args: varargs[MaPattern]): MaPattern =
  ## ``And`` operator for pattern
  MaPattern(operator: And, args: @args)

const
  TranscoderIP4* =
    Transcoder(stringToBuffer: ip4StB, bufferToString: ip4BtS, validateBuffer: ip4VB)
  TranscoderIP6* =
    Transcoder(stringToBuffer: ip6StB, bufferToString: ip6BtS, validateBuffer: ip6VB)
  TranscoderIP6Zone* = Transcoder(
    stringToBuffer: ip6zoneStB, bufferToString: ip6zoneBtS, validateBuffer: ip6zoneVB
  )
  TranscoderUnix* =
    Transcoder(stringToBuffer: unixStB, bufferToString: unixBtS, validateBuffer: unixVB)
  TranscoderP2P* =
    Transcoder(stringToBuffer: p2pStB, bufferToString: p2pBtS, validateBuffer: p2pVB)
  TranscoderPort* =
    Transcoder(stringToBuffer: portStB, bufferToString: portBtS, validateBuffer: portVB)
  TranscoderOnion* = Transcoder(
    stringToBuffer: onionStB, bufferToString: onionBtS, validateBuffer: onionVB
  )
  TranscoderOnion3* = Transcoder(
    stringToBuffer: onion3StB, bufferToString: onion3BtS, validateBuffer: onion3VB
  )
  TranscoderDNS* =
    Transcoder(stringToBuffer: dnsStB, bufferToString: dnsBtS, validateBuffer: dnsVB)
  TranscoderSNI* =
    Transcoder(stringToBuffer: sniStB, bufferToString: sniBtS, validateBuffer: sniVB)
  TranscoderMemory* = Transcoder(
    stringToBuffer: memoryStB, bufferToString: memoryBtS, validateBuffer: memoryVB
  )

  ProtocolsList = [
    MAProtocol(mcodec: multiCodec("ip4"), kind: Fixed, size: 4, coder: TranscoderIP4),
    MAProtocol(mcodec: multiCodec("tcp"), kind: Fixed, size: 2, coder: TranscoderPort),
    MAProtocol(mcodec: multiCodec("udp"), kind: Fixed, size: 2, coder: TranscoderPort),
    MAProtocol(mcodec: multiCodec("ip6"), kind: Fixed, size: 16, coder: TranscoderIP6),
    MAProtocol(mcodec: multiCodec("dccp"), kind: Fixed, size: 2, coder: TranscoderPort),
    MAProtocol(mcodec: multiCodec("sctp"), kind: Fixed, size: 2, coder: TranscoderPort),
    MAProtocol(mcodec: multiCodec("udt"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("utp"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("http"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("https"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("quic"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("quic-v1"), kind: Marker, size: 0),
    MAProtocol(
      mcodec: multiCodec("ip6zone"), kind: Length, size: 0, coder: TranscoderIP6Zone
    ),
    MAProtocol(
      mcodec: multiCodec("onion"), kind: Fixed, size: 12, coder: TranscoderOnion
    ),
    MAProtocol(
      mcodec: multiCodec("onion3"), kind: Fixed, size: 37, coder: TranscoderOnion3
    ),
    MAProtocol(mcodec: multiCodec("ws"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("wss"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("tls"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("sni"), kind: Length, size: 0, coder: TranscoderSNI),
    MAProtocol(mcodec: multiCodec("ipfs"), kind: Length, size: 0, coder: TranscoderP2P),
    MAProtocol(mcodec: multiCodec("p2p"), kind: Length, size: 0, coder: TranscoderP2P),
    MAProtocol(mcodec: multiCodec("unix"), kind: Path, size: 0, coder: TranscoderUnix),
    MAProtocol(mcodec: multiCodec("dns"), kind: Length, size: 0, coder: TranscoderDNS),
    MAProtocol(mcodec: multiCodec("dns4"), kind: Length, size: 0, coder: TranscoderDNS),
    MAProtocol(mcodec: multiCodec("dns6"), kind: Length, size: 0, coder: TranscoderDNS),
    MAProtocol(
      mcodec: multiCodec("dnsaddr"), kind: Length, size: 0, coder: TranscoderDNS
    ),
    MAProtocol(mcodec: multiCodec("p2p-circuit"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("p2p-websocket-star"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("p2p-webrtc-star"), kind: Marker, size: 0),
    MAProtocol(mcodec: multiCodec("p2p-webrtc-direct"), kind: Marker, size: 0),
    MAProtocol(
      mcodec: multiCodec("memorytransport"),
      kind: Path,
      size: 0,
      coder: TranscoderMemory,
    ),
  ]

  DNSANY* = mapEq("dns")
  DNS4* = mapEq("dns4")
  DNS6* = mapEq("dns6")
  DNSADDR* = mapEq("dnsaddr")
  IP4* = mapEq("ip4")
  IP6* = mapEq("ip6")
  DNS* = mapOr(DNSANY, DNS4, DNS6, DNSADDR)
  IP* = mapOr(IP4, IP6)
  DNS_OR_IP* = mapOr(DNS, IP)
  TCP_DNS* = mapAnd(DNS, mapEq("tcp"))
  TCP_IP* = mapAnd(IP, mapEq("tcp"))
  TCP* = mapOr(TCP_DNS, TCP_IP)
  UDP_DNS* = mapAnd(DNS, mapEq("udp"))
  UDP_IP* = mapAnd(IP, mapEq("udp"))
  UDP* = mapOr(UDP_DNS, UDP_IP)
  UTP* = mapAnd(UDP, mapEq("utp"))
  QUIC_IP* = mapAnd(UDP_IP, mapEq("quic"))
  QUIC_DNS* = mapAnd(UDP_DNS, mapEq("quic"))
  QUIC* = mapOr(QUIC_DNS, QUIC_IP)
  QUIC_V1_IP* = mapAnd(UDP_IP, mapEq("quic-v1"))
  QUIC_V1_DNS* = mapAnd(UDP_DNS, mapEq("quic-v1"))
  QUIC_V1* = mapOr(QUIC_V1_DNS, QUIC_V1_IP)
  TCP_IP4* = mapAnd(IP4, mapEq("tcp"))
  TCP_IP6* = mapAnd(IP6, mapEq("tcp"))
  UDP_IP4* = mapAnd(IP4, mapEq("udp"))
  QUIC_V1_IP4* = mapAnd(UDP_IP4, mapEq("quic-v1"))
  UNIX* = mapEq("unix")
  WS_DNS* = mapAnd(TCP_DNS, mapEq("ws"))
  WS_IP* = mapAnd(TCP_IP, mapEq("ws"))
  WS* = mapAnd(TCP, mapEq("ws"))
  TLS* = mapEq("tls")
  SNI* = mapEq("sni")
  TLS_SNI* = mapAnd(TLS, SNI)
  TLS_WS* = mapOr(mapEq("wss"), mapAnd(mapOr(TLS, TLS_SNI), mapEq("ws")))
  WSS_DNS* = mapAnd(TCP_DNS, TLS_WS)
  WSS_IP* = mapAnd(TCP_IP, TLS_WS)
  WSS* = mapAnd(TCP, TLS_WS)
  WebSockets_DNS* = mapOr(WS_DNS, WSS_DNS)
  WebSockets_IP* = mapOr(WS_IP, WSS_IP)
  WebSockets* = mapOr(WS, WSS)
  Onion3* = mapEq("onion3")
  TcpOnion3* = mapAnd(TCP, Onion3)

  Unreliable* = mapOr(UDP)

  Reliable* = mapOr(TCP, UTP, QUIC, WebSockets)

  P2PPattern* = mapEq("p2p")

  IPFS* = mapAnd(Reliable, mapEq("ipfs"))

  HTTP* = mapOr(
    mapAnd(TCP, mapEq("http")), mapAnd(IP, mapEq("http")), mapAnd(DNS, mapEq("http"))
  )

  HTTPS* = mapOr(
    mapAnd(TCP, mapEq("https")), mapAnd(IP, mapEq("https")), mapAnd(DNS, mapEq("https"))
  )

  WebRTCDirect* = mapOr(
    mapAnd(HTTP, mapEq("p2p-webrtc-direct")), mapAnd(HTTPS, mapEq("p2p-webrtc-direct"))
  )

  CircuitRelay* = mapEq("p2p-circuit")

  Memory* = mapEq("memorytransport")

proc initMultiAddressCodeTable(
    protocols: openArray[MAProtocol]
): Table[MultiCodec, MAProtocol] {.compileTime.} =
  var res: Table[MultiCodec, MAProtocol]

  for protocol in protocols:
    res[protocol.mcodec] = protocol

  return res

when libp2p_multiaddress_exts != "":
  import ./utils/macroutils
  includeFile(libp2p_multiaddress_exts)
  const CodeAddresses = initMultiAddressCodeTable(@ProtocolsList & @AddressExts)
else:
  const CodeAddresses = initMultiAddressCodeTable(@ProtocolsList)

proc trimRight(s: string, ch: char): string =
  ## Consume trailing characters ``ch`` from string ``s`` and return result.
  var m = 0
  for i in countdown(s.high, 0):
    if s[i] == ch:
      inc(m)
    else:
      break
  s[0 .. (s.high - m)]

proc protoCode*(ma: MultiAddress): MaResult[MultiCodec] =
  ## Returns MultiAddress ``ma`` protocol code.
  var header: uint64
  var cursor = initCursor(ma)
  if cursor.readVarint(header) == -1:
    err("multiaddress: Malformed binary address!")
  else:
    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      err("multiaddress: Unsupported protocol '" & $header & "'")
    else:
      ok(proto.mcodec)

proc protoName*(ma: MultiAddress): MaResult[string] =
  ## Returns MultiAddress ``ma`` protocol name.
  var header: uint64
  var cursor = initCursor(ma)
  if cursor.readVarint(header) == -1:
    err("multiaddress: Malformed binary address!")
  else:
    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      err("multiaddress: Unsupported protocol '" & $header & "'")
    else:
      ok($(proto.mcodec))

proc protoArgument*(ma: MultiAddress, value: var openArray[byte]): MaResult[int] =
  ## Returns MultiAddress ``ma`` protocol argument value.
  ##
  ## If current MultiAddress do not have argument value, then result will be
  ## ``0``.
  var header: uint64
  var cursor = initCursor(ma)
  if cursor.readVarint(header) == -1:
    err("multiaddress: Malformed binary address!")
  else:
    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      err("multiaddress: Unsupported protocol '" & $header & "'")
    else:
      var res: int
      if proto.kind == Fixed:
        res = proto.size
        if len(value) >= res and
            cursor.readArray(value.toOpenArray(0, proto.size - 1)) != proto.size:
          err("multiaddress: Decoding protocol error")
        else:
          ok(res)
      elif proto.kind in {MAKind.Length, Path}:
        var temp: seq[byte]
        if cursor.readSeq(temp) == -1:
          err("multiaddress: Decoding protocol error")
        else:
          res = len(temp)
          if res > 0 and len(value) >= res:
            copyMem(addr value[0], addr temp[0], res)
          ok(res)
      else:
        ok(res)

proc protoAddress*(ma: MultiAddress): MaResult[seq[byte]] =
  ## Returns MultiAddress ``ma`` protocol address binary blob.
  ##
  ## If current MultiAddress do not have argument value, then result array will
  ## be empty.
  var buffer = newSeqUninit[byte](len(ma.data.buffer))
  let res = ?protoArgument(ma, buffer)
  buffer.setLen(res)
  ok(buffer)

proc protoArgument*(ma: MultiAddress): MaResult[seq[byte]] =
  ## Returns MultiAddress ``ma`` protocol address binary blob.
  ##
  ## If current MultiAddress do not have argument value, then result array will
  ## be empty.
  ma.protoAddress()

proc getPart(ma: MultiAddress, index: int): MaResult[MultiAddress] =
  var header: uint64
  var data = newSeqUninit[byte](0)
  var offset = 0
  var cursor = initCursor(ma)
  var res: MultiAddress
  res.data = initVBuffer(64)
    # initial capacity for a part buffer; larger parts may still reallocate

  if index < 0:
    return err("multiaddress: negative index gived to getPart")

  while offset <= index:
    if cursor.readVarint(header) == -1:
      return err("multiaddress: Malformed binary address!")

    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      return err("multiaddress: Unsupported protocol '" & $header & "'")
    elif proto.kind == Fixed:
      data.setLen(proto.size)
      if cursor.readArray(data) != proto.size:
        return err("multiaddress: Decoding protocol error")

      if offset == index:
        res.data.writeVarint(header)
        res.data.writeArray(data)
        res.data.finish()
    elif proto.kind in {MAKind.Length, Path}:
      if cursor.readSeq(data) == -1:
        return err("multiaddress: Decoding protocol error")

      if offset == index:
        res.data.writeVarint(header)
        res.data.writeSeq(data)
        res.data.finish()
    elif proto.kind == Marker:
      if offset == index:
        res.data.writeVarint(header)
        res.data.finish()
    inc(offset)
  ok(res)

proc getParts[U, V](ma: MultiAddress, slice: HSlice[U, V]): MaResult[MultiAddress] =
  when slice.a is BackwardsIndex or slice.b is BackwardsIndex:
    let maLength = ?len(ma)
  template normalizeIndex(index): int =
    when index is BackwardsIndex:
      maLength - int(index)
    else:
      int(index)

  let
    indexStart = normalizeIndex(slice.a)
    indexEnd = normalizeIndex(slice.b)
  var res: MultiAddress
  for i in indexStart .. indexEnd:
    ?res.append(?ma[i])
  ok(res)

proc `[]`*(ma: MultiAddress, i: int | BackwardsIndex): MaResult[MultiAddress] =
  ## Returns part with index ``i`` of MultiAddress ``ma``.
  when i is BackwardsIndex:
    let maLength = ?len(ma)
    ma.getPart(maLength - int(i))
  else:
    ma.getPart(i)

proc `[]`*(ma: MultiAddress, slice: HSlice): MaResult[MultiAddress] =
  ## Returns parts with slice ``slice`` of MultiAddress ``ma``.
  ma.getParts(slice)

iterator items*(ma: MultiAddress): MaResult[MultiAddress] =
  ## Iterates over all addresses inside of MultiAddress ``ma``.
  var header: uint64
  var cursor = initCursor(ma)
  while true:
    if cursor.isEmpty():
      break

    if cursor.readVarint(header) == -1:
      yield err(MaResult[MultiAddress], "Malformed binary address!")
      break

    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      yield err(MaResult[MultiAddress], "Unsupported protocol '" & $header & "'")
      break
    else:
      # preallocate enough capacity for common small parts; larger parts may
      # still require reallocation.# capacity should accommodate any part without reallocation
      var res = MultiAddress(data: initVBuffer(64))
      res.data.writeVarint(header)
      if proto.kind == Fixed:
        var buf: seq[byte]
        buf.setLen(proto.size)
        if cursor.readArray(buf) != proto.size:
          yield err(MaResult[MultiAddress], "Decoding protocol error")
          break
        else:
          res.data.writeArray(buf)
      elif proto.kind in {MAKind.Length, Path}:
        var temp: seq[byte]
        if cursor.readSeq(temp) == -1 or len(temp) == 0:
          yield err(MaResult[MultiAddress], "Decoding protocol error")
          break
        else:
          res.data.writeSeq(temp)
      # Marker: nothing more to write
      res.data.finish()
      yield ok(MaResult[MultiAddress], res)

proc len*(ma: MultiAddress): MaResult[int] =
  var counter: int
  for part in ma:
    if part.isErr:
      return err(part.error)
    counter.inc()
  ok(counter)

proc contains*(ma: MultiAddress, codec: MultiCodec): MaResult[bool] =
  ## Returns ``true``, if address with MultiCodec ``codec`` present in
  ## MultiAddress ``ma``.
  for item in ma.items:
    let code = ?(?item).protoCode()
    if code == codec:
      return ok(true)
  ok(false)

proc `[]`*(ma: MultiAddress, codec: MultiCodec): MaResult[MultiAddress] =
  ## Returns partial MultiAddress with MultiCodec ``codec`` and present in
  ## MultiAddress ``ma``.
  for item in ma.items:
    if ?(?item).protoCode == codec:
      return item
  err("multiaddress: Codec is not present in address")

proc toString*(value: MultiAddress): MaResult[string] =
  ## Return string representation of MultiAddress ``value``.
  var header: uint64
  var cursor = initCursor(value)
  var part: string
  # Pre-allocate result string with a reasonable initial capacity
  var res = newStringOfCap(64)
  while true:
    if cursor.isEmpty():
      break
    if cursor.readVarint(header) == -1:
      return err("multiaddress: Malformed binary address!")
    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      return err("multiaddress: Unsupported protocol '" & $header & "'")
    res.add('/')
    res.add($(proto.mcodec))
    if proto.kind in {Fixed, Length, Path}:
      if isNil(proto.coder.bufferToString):
        return err("multiaddress: Missing protocol '" & $(proto.mcodec) & "' coder")
      if not proto.coder.bufferToString(cursor, part):
        return err("multiaddress: Decoding protocol error")
      if len(part) > 0:
        if (proto.kind == Path) and (part[0] == '/'):
          res.add(part) # path includes the leading /
        else:
          res.add('/')
          res.add(part)
  ok(res)

proc `$`*(value: MultiAddress): string =
  ## Return string representation of MultiAddress ``value``.
  let s = value.toString()
  if s.isErr:
    s.error
  else:
    s.get()

proc protocols*(value: MultiAddress): MaResult[seq[MultiCodec]] =
  ## Returns list of protocol codecs inside of MultiAddress ``value``.
  var res = newSeq[MultiCodec]()
  for item in value.items():
    res.add(?(?item).protoCode())
  ok(res)

proc hex*(value: MultiAddress): string =
  ## Return hexadecimal string representation of MultiAddress ``value``.
  $(value.data)

proc write*(vb: var VBuffer, ma: MultiAddress) =
  ## Write MultiAddress value ``ma`` to buffer ``vb``.
  vb.writeArray(ma.data.buffer)

proc encode*(mbtype: typedesc[MultiBase], encoding: string, ma: MultiAddress): string =
  ## Get MultiBase encoded representation of ``ma`` using encoding
  ## ``encoding``.
  MultiBase.encode(encoding, ma.data.buffer)

proc validate*(ma: MultiAddress): bool =
  ## Returns ``true`` if MultiAddress ``ma`` is valid.
  var header: uint64
  var cursor = initCursor(ma)
  while true:
    if cursor.isEmpty():
      break
    if cursor.readVarint(header) == -1:
      return false
    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      return false
    if proto.kind in {Fixed, Length, Path}:
      if isNil(proto.coder.validateBuffer):
        return false
      if not proto.coder.validateBuffer(cursor):
        return false
    else:
      discard
  true

proc init*(
    mtype: typedesc[MultiAddress], protocol: MultiCodec, value: openArray[byte] = []
): MaResult[MultiAddress] =
  ## Initialize MultiAddress object from protocol id ``protocol`` and array
  ## of bytes ``value``.
  let proto = CodeAddresses.getOrDefault(protocol)
  if proto.kind == None:
    err("multiaddress: Protocol not found")
  else:
    var res: MultiAddress
    # Pre-allocate: varint(protocol) ≈ maxSize(proto.mcodec) + value size + overhead
    res.data = initVBuffer(32 + len(value))
    res.data.writeVarint(cast[uint64](proto.mcodec))
    case proto.kind
    of Fixed:
      if len(value) != proto.size:
        err("multiaddress: Incorrect fixed protocol value length")
      else:
        res.data.writeArray(value)
        res.data.finish()
        ok(res)
    of Length, Path:
      if len(value) == 0:
        err("multiaddress: Value must not be empty array")
      else:
        if protocol == multiCodec("sni"):
          var validation = initVBuffer(len(value) + 10)
          validation.writeSeq(value)
          validation.finish()
          if not proto.coder.validateBuffer(validation):
            return err("multiaddress: Invalid sni protocol value")

        res.data.writeSeq(value)
        res.data.finish()
        ok(res)
    of Marker:
      if len(value) != 0:
        err("multiaddress: Value must be empty for markers")
      else:
        res.data.finish()
        ok(res)
    of None:
      raiseAssert "None checked above"

proc init*(
    mtype: typedesc[MultiAddress], protocol: MultiCodec, value: PeerId
): MaResult[MultiAddress] =
  ## Initialize MultiAddress object from protocol id ``protocol`` and peer id
  ## ``value``.
  init(mtype, protocol, value.data)

proc init*(
    mtype: typedesc[MultiAddress], protocol: MultiCodec, value: int
): MaResult[MultiAddress] =
  ## Initialize MultiAddress object from protocol id ``protocol`` and integer
  ## ``value``. This procedure can be used to instantiate ``tcp``, ``udp``,
  ## ``dccp`` and ``sctp`` MultiAddresses.
  var allowed =
    [multiCodec("tcp"), multiCodec("udp"), multiCodec("dccp"), multiCodec("sctp")]
  if protocol notin allowed:
    err("multiaddress: Incorrect protocol for integer value")
  else:
    let proto = CodeAddresses.getOrDefault(protocol)
    var res: MultiAddress
    res.data = initVBuffer(10) # varint(protocol) + 2 bytes port + overhead
    res.data.writeVarint(cast[uint64](proto.mcodec))
    if value < 0 or value > 65535:
      err("multiaddress: Incorrect integer value")
    else:
      res.data.writeArray(toBytesBE(cast[uint16](value)))
      res.data.finish()
      ok(res)

proc getPart*(ma: MultiAddress, codec: MultiCodec): MaResult[MultiAddress] =
  ## Returns the first multiaddress in ``value`` with codec ``codec``
  for part in ma:
    let part = ?part
    if codec == ?part.protoCode:
      return ok(part)
  err("no such codec in multiaddress")

proc getProtocolArgument*(ma: MultiAddress, codec: MultiCodec): MaResult[seq[byte]] =
  ## Returns the raw byte argument of the first component in ``ma`` matching
  ## ``codec`` (e.g. the 2-byte port for ``/tcp/<port>``, the 4-byte address
  ## bytes for ``/ip4/<addr>``).
  for item in ma:
    let
      ritem = ?item
      code = ?ritem.protoCode()
    if code == codec:
      return ok(?ritem.protoAddress())
  err("Multiaddress codec has not been found")

proc getProtocol(name: string): MAProtocol =
  let mc = MultiCodec.codec(name)
  if mc != InvalidMultiCodec:
    CodeAddresses.getOrDefault(mc)
  else:
    default(MAProtocol)

proc init*(mtype: typedesc[MultiAddress], value: string): MaResult[MultiAddress] =
  ## Initialize MultiAddress object from string representation ``value``.
  if len(value) == 0 or value == "/":
    return err("multiaddress: Address must not be empty!")
  if value[0] != '/':
    return err("multiaddress: Invalid MultiAddress, must start with `/`")

  var
    trimmed = value.trimRight('/')
    parts = trimmed.split('/')
    offset = 1
    res: MultiAddress
  res.data = initVBuffer(len(trimmed))

  while offset < len(parts):
    let part = parts[offset]
    let proto = getProtocol(part)
    if proto.kind == None:
      return err("multiaddress: Unsupported protocol '" & part & "'")

    if proto.kind in {Fixed, Length, Path}:
      if isNil(proto.coder.stringToBuffer):
        return err("multiaddress: Missing protocol '" & part & "' transcoder")
      if offset + 1 >= len(parts):
        return err("multiaddress: Missing protocol '" & part & "' argument")

    if proto.kind in {Fixed, Length}:
      res.data.write(proto.mcodec)
      if not proto.coder.stringToBuffer(parts[offset + 1], res.data):
        return
          err("multiaddress: Error encoding `" & part & "/" & parts[offset + 1] & "`")
      offset += 2
    elif proto.kind == Path:
      # Reconstruct path from trimmed string to avoid seq slice + join overhead.
      # Find the position of the protocol name in trimmed, then take everything after.
      let protoStart = trimmed.find("/" & part & "/", 0)
      let path =
        if protoStart >= 0:
          trimmed.substr(protoStart + len(part) + 1)
            # +1 for the slash after protocol name
        else:
          # Fallback: reconstruct from parts (shouldn't normally happen)
          "/" & parts[(offset + 1) .. ^1].join("/")
      res.data.write(proto.mcodec)
      if not proto.coder.stringToBuffer(path, res.data):
        return err("multiaddress: Error encoding `" & part & "/" & path & "`")
      break
    elif proto.kind == Marker:
      res.data.write(proto.mcodec)
      offset += 1

  res.data.finish()
  ok(res)

proc init*(
    mtype: typedesc[MultiAddress], data: openArray[byte]
): MaResult[MultiAddress] =
  ## Initialize MultiAddress with array of bytes ``data``.
  if len(data) == 0:
    err("multiaddress: Address must not be empty!")
  else:
    var res: MultiAddress
    res.data = initVBuffer(data)
    if not res.validate():
      err("multiaddress: Incorrect MultiAddress!")
    else:
      ok(res)

proc init*(mtype: typedesc[MultiAddress]): MultiAddress =
  ## Initialize empty MultiAddress.
  MultiAddress(data: initVBuffer(256)) # should be enough to accommodate any multiaddress

proc init*(
    mtype: typedesc[MultiAddress],
    address: IpAddress,
    protocol: IpTransportProtocol,
    port: Port,
): MultiAddress =
  var res: MultiAddress
  res.data = initVBuffer(32) # varint + IPv4(4)/IPv6(16) + varint + port(2) + overhead
  let
    networkProto =
      case address.family
      of IpAddressFamily.IPv4:
        getProtocol("ip4")
      of IpAddressFamily.IPv6:
        getProtocol("ip6")

    transportProto =
      case protocol
      of tcpProtocol:
        getProtocol("tcp")
      of udpProtocol:
        getProtocol("udp")

  res.data.write(networkProto.mcodec)
  case address.family
  of IpAddressFamily.IPv4:
    res.data.writeArray(address.address_v4)
  of IpAddressFamily.IPv6:
    res.data.writeArray(address.address_v6)
  res.data.write(transportProto.mcodec)
  res.data.writeArray(toBytesBE(uint16(port)))
  res.data.finish()
  res

proc init*(
    mtype: typedesc[MultiAddress], address: TransportAddress, protocol = IPPROTO_TCP
): MaResult[MultiAddress] =
  ## Initialize MultiAddress using chronos.TransportAddress (IPv4/IPv6/Unix)
  ## and protocol information (UDP/TCP).
  var res: MultiAddress
  res.data = initVBuffer(64) # varint + address(4/16/unix) + varint + port + overhead
  let protoProto =
    case protocol
    of IPPROTO_TCP:
      getProtocol("tcp")
    of IPPROTO_UDP:
      getProtocol("udp")
    else:
      default(MAProtocol)
  if protoProto.size == 0:
    return err("multiaddress: protocol should be either TCP or UDP")
  if address.family == AddressFamily.IPv4:
    res.data.write(getProtocol("ip4").mcodec)
    res.data.writeArray(address.address_v4)
    res.data.write(protoProto.mcodec)
    discard protoProto.coder.stringToBuffer($address.port, res.data)
  elif address.family == AddressFamily.IPv6:
    res.data.write(getProtocol("ip6").mcodec)
    res.data.writeArray(address.address_v6)
    res.data.write(protoProto.mcodec)
    discard protoProto.coder.stringToBuffer($address.port, res.data)
  elif address.family == AddressFamily.Unix:
    res.data.write(getProtocol("unix").mcodec)
    res.data.writeSeq(address.address_un)
  res.data.finish()
  ok(res)

proc isEmpty*(ma: MultiAddress): bool =
  ## Returns ``true``, if MultiAddress ``ma`` is empty or non initialized.
  len(ma.data) == 0

proc concat*(m1, m2: MultiAddress): MaResult[MultiAddress] =
  var res: MultiAddress
  res.data = initVBuffer(m1.data.buffer & m2.data.buffer)
  if not res.validate():
    err("multiaddress: Incorrect MultiAddress!")
  else:
    ok(res)

proc append*(m1: var MultiAddress, m2: MultiAddress): MaResult[void] =
  m1.data.buffer &= m2.data.buffer
  if not m1.validate():
    err("multiaddress: Incorrect MultiAddress!")
  else:
    ok()

proc `&`*(m1, m2: MultiAddress): MultiAddress {.raises: [MaError].} =
  ## Concatenates two addresses ``m1`` and ``m2``, and returns result.
  ##
  ## This procedure performs validation of concatenated result and can raise
  ## exception on error.
  concat(m1, m2).valueOr:
    raise maErr error

proc `&=`*(m1: var MultiAddress, m2: MultiAddress) {.raises: [MaError].} =
  ## Concatenates two addresses ``m1`` and ``m2``.
  ##
  ## This procedure performs validation of concatenated result and can raise
  ## exception on error.
  m1.append(m2).isOkOr:
    raise maErr error

proc `==`*(m1: var MultiAddress, m2: MultiAddress): bool =
  ## Check of two MultiAddress are equal
  m1.data == m2.data

proc `<`*(a, b: MultiAddress): bool =
  let bytesA = a.data.buffer
  let bytesB = b.data.buffer

  if bytesA.len < bytesB.len:
    return true
  if bytesA.len > bytesB.len:
    return false

  for i in 0 ..< bytesA.len:
    if bytesA[i] != bytesB[i]:
      return bytesA[i] < bytesB[i]

proc matchPart(pat: MaPattern, protos: seq[MultiCodec]): MaPatResult =
  var empty: seq[MultiCodec]
  var pcs = protos
  case pat.operator
  of Or:
    var r = MaPatResult(flag: false, rem: empty)
    for a in pat.args:
      let res = a.matchPart(pcs)
      if res.flag:
        #Greedy Or
        if r.flag == false or r.rem.len > res.rem.len:
          r = res
    r
  of And:
    if len(pcs) < len(pat.args):
      return MaPatResult(flag: false, rem: empty)
    for i in 0 ..< len(pat.args):
      let res = pat.args[i].matchPart(pcs)
      if not res.flag:
        return MaPatResult(flag: false, rem: res.rem)
      pcs = res.rem
    MaPatResult(flag: true, rem: pcs)
  of Eq:
    if len(pcs) == 0:
      return MaPatResult(flag: false, rem: empty)
    if pcs[0] == pat.value:
      return MaPatResult(flag: true, rem: pcs[1 ..^ 1])
    MaPatResult(flag: false, rem: empty)

proc match*(pat: MaPattern, address: MultiAddress): bool =
  ## Match full ``address`` using pattern ``pat`` and return ``true`` if
  ## ``address`` satisfies pattern.
  let protos = address.protocols().valueOr:
    return false
  let res = matchPart(pat, protos)
  res.flag and (len(res.rem) == 0)

proc matchPartial*(pat: MaPattern, address: MultiAddress): bool =
  ## Match prefix part of ``address`` using pattern ``pat`` and return
  ## ``true`` if ``address`` starts with pattern.
  let protos = address.protocols().valueOr:
    return false
  let res = matchPart(pat, protos)
  res.flag

proc hasIp*(ma: MultiAddress): bool =
  ## Returns ``true`` if ``ma`` starts with an IP4 or IP6 component.
  IP.matchPartial(ma)

proc hasTransport*(ma: MultiAddress): bool =
  ## Returns ``true`` if ``ma`` carries a transport, as in ``/ip4/1.2.3.4/tcp/1``.
  Reliable.matchPartial(ma) or Unreliable.matchPartial(ma)

proc `$`*(pat: MaPattern): string =
  ## Return pattern ``pat`` as string.
  var sub = newSeq[string]()
  for a in pat.args:
    sub.add($a)
  case pat.operator
  of And:
    sub.join("/")
  of Or:
    "(" & sub.join("|") & ")"
  of Eq:
    $pat.value

proc bytes*(value: MultiAddress): seq[byte] =
  value.data.buffer

proc write*(pb: var ProtoBuffer, field: int, value: MultiAddress) =
  write(pb, field, value.data.buffer)

proc getField*(
    pb: ProtoBuffer, field: int, value: var MultiAddress
): ProtoResult[bool] =
  var buffer: seq[byte]
  let res = ?pb.getField(field, buffer)
  if not (res):
    ok(false)
  else:
    value = MultiAddress.init(buffer).valueOr:
      return err(ProtoError.IncorrectBlob)
    ok(true)

proc getRepeatedField*(
    pb: ProtoBuffer, field: int, value: var seq[MultiAddress]
): ProtoResult[bool] =
  ## Read repeated field from protobuf message. ``field`` is field number.
  ## If the message is malformed, an error is returned. If field is not present
  ## in message, then ``ok(false)`` is returned and value is empty. If field is
  ## present, but no items could be parsed, then
  ## ``err(ProtoError.IncorrectBlob)`` is returned and value is empty.
  ## If field is present and some item could be parsed, then ``true`` is
  ## returned and value contains the parsed values.
  var items: seq[seq[byte]]
  value.setLen(0)
  let res = ?pb.getRepeatedField(field, items)
  if not (res):
    ok(false)
  else:
    for item in items:
      let ma = MultiAddress.init(item).valueOr:
        debug "Unsupported MultiAddress in blob", address = item
        continue

      value.add(ma)
    if value.len == 0:
      err(ProtoError.IncorrectBlob)
    else:
      ok(true)

proc areAddrsConsistent*(a, b: MultiAddress): bool =
  ## Checks if two multiaddresses have the same protocol stack.
  let
    ip4 = multiCodec("ip4")
    ip6 = multiCodec("ip6")
    dns = multiCodec("dns")
    dns4 = multiCodec("dns4")
    dns6 = multiCodec("dns6")
    dnsaddr = multiCodec("dnsaddr")

  template isIp(proto: MultiCodec): bool =
    proto == ip4 or proto == ip6

  template isDnsAny(proto: MultiCodec): bool =
    proto == dns or proto == dnsaddr

  template isDnsIpEquivalent(protoA, protoB: MultiCodec): bool =
    (isDnsAny(protoA) and isIp(protoB)) or (isDnsAny(protoB) and isIp(protoA)) or
      (protoA == dns4 and protoB == ip4) or (protoA == ip4 and protoB == dns4) or
      (protoA == dns6 and protoB == ip6) or (protoA == ip6 and protoB == dns6)

  let protosA = a.protocols().get()
  let protosB = b.protocols().get()
  if protosA.len != protosB.len:
    return false

  for idx in 0 ..< protosA.len:
    let protoA = protosA[idx]
    let protoB = protosB[idx]

    if protoA != protoB:
      if idx == 0:
        # allow DNS ↔ IP at the first component
        if not isDnsIpEquivalent(protoA, protoB):
          return false
      else:
        return false
  true

proc getIp*(ma: MultiAddress): Opt[IpAddress] =
  ## Extract IpAddress from MultiAddress.
  ## Returns Opt.none if no IP4/IP6 component found.
  var header: uint64
  var cursor = initCursor(ma)

  while not cursor.isEmpty():
    if cursor.readVarint(header) == -1:
      return Opt.none(IpAddress)

    let proto = CodeAddresses.getOrDefault(MultiCodec(header))
    if proto.kind == None:
      return Opt.none(IpAddress)

    if proto.kind == Fixed:
      if proto.mcodec == multiCodec("ip4"):
        var addrV4: array[4, byte]
        if cursor.readArray(addrV4) == 4:
          var ip = IpAddress(family: IpAddressFamily.IPv4)
          ip.address_v4 = addrV4
          return Opt.some(ip)
        else:
          return Opt.none(IpAddress)
      elif proto.mcodec == multiCodec("ip6"):
        var addrV6: array[16, byte]
        if cursor.readArray(addrV6) == 16:
          var ip = IpAddress(family: IpAddressFamily.IPv6)
          ip.address_v6 = addrV6
          return Opt.some(ip)
        else:
          return Opt.none(IpAddress)
      else:
        # Skip this fixed-length field
        if not cursor.isEnough(proto.size):
          return Opt.none(IpAddress)
        cursor.offset += proto.size
    elif proto.kind in {MAKind.Length, Path}:
      # Skip variable-length field
      var length: uint64
      if cursor.readVarint(length) == -1:
        return Opt.none(IpAddress)

      let skipLen = int(length)
      if not cursor.isEnough(skipLen):
        return Opt.none(IpAddress)

      cursor.offset = cursor.offset + skipLen
    # Marker - nothing to skip

proc getIPs*(addrs: seq[MultiAddress]): seq[IpAddress] =
  ## Extract IP addresses from a list of multiaddresses.
  ## Multiaddresses without an IP4/IP6 component are skipped.
  var ips = newSeqOfCap[IpAddress](addrs.len)
  for ma in addrs:
    ma.getIp().ifValue(ip):
      ips.add(ip)
  ips

proc replaceIp*(ma: MultiAddress, ip: IpAddress): MaResult[MultiAddress] =
  ## Returns a copy of ``ma`` with its leading IP4/IP6 component replaced by
  ## ``ip``. If ``ip``'s family differs from the original, the IP codec is
  ## swapped accordingly (``/ip6/...`` becomes ``/ip4/...`` or vice versa).
  ## The remainder of the multiaddress (transport, port, and any suffix such
  ## as ``/quic-v1``, ``/ws``, ``/wss``, ``/tls/ws``) is preserved. Returns
  ## an error if ``ma`` has no IP component.
  let
    ip4 = multiCodec("ip4")
    ip6 = multiCodec("ip6")
    newIp =
      case ip.family
      of IpAddressFamily.IPv4:
        ?MultiAddress.init(ip4, ip.address_v4)
      of IpAddressFamily.IPv6:
        ?MultiAddress.init(ip6, ip.address_v6)

  var
    found = false
    res = MultiAddress.init()
  for item in ma.items:
    let part = ?item
    let code = ?part.protoCode
    if not found and (code == ip4 or code == ip6):
      ?res.append(newIp)
      found = true
    else:
      ?res.append(part)
  if not found:
    return err("multiaddress: no IP component to replace")
  ok(res)

const AvgMultiAddressStringLength = 32

func shortLog*(addrs: seq[MultiAddress]): string =
  ## Keeps this bounded formatter visible to Chronicles and the log-field audit;
  ## rendering itself is delegated to the generic collection formatter.
  shortLog[MultiAddress](addrs, averageItemLength = AvgMultiAddressStringLength)

chronicles.formatIt(seq[MultiAddress]):
  shortLog(it)

chronicles.formatIt(seq[MultiAddress]):
  shortLog(it)

## protobuf_serialization extension

Protobuf.extensionDefaults(MultiAddress, pbytes, defaultWriteSeq = true)

func computeFieldSize*(
    field: int,
    value: MultiAddress,
    ProtoType: type ProtobufExt,
    skipDefault: static bool,
): int =
  computeFieldSize(field, value.data.buffer, pbytes, skipDefault)

proc writeField*(
    stream: OutputStream,
    field: int,
    value: MultiAddress,
    ProtoType: type ProtobufExt,
    skipDefault: static bool = false,
) {.raises: [IOError].} =
  writeField(stream, field, value.data.buffer, pbytes, skipDefault)

proc readFieldInto*(
    stream: InputStream,
    value: var MultiAddress,
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  var data = default(seq[byte])

  if readFieldInto(stream, data, header, pbytes):
    if data.len == 0:
      return false

    value = MultiAddress.init(data).valueOr:
      raise newException(ProtobufValueError, "Invalid MultiAddress")
    true
  else:
    false

proc readFieldInto*(
    stream: InputStream,
    value: var seq[MultiAddress],
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  var data = default(seq[byte])

  if readFieldInto(stream, data, header, pbytes):
    let ma = MultiAddress.init(data).valueOr:
      return false

    value.add(ma)
    true
  else:
    false
