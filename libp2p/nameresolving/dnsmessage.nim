# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Minimal DNS message codec (RFC 1035).
##
## libp2p performs the UDP transport itself (see `dnsresolver` and the mDNS
## service), so this module only deals with the wire format. It is pure
## bytes-in/bytes-out and raises only `ValueError` on malformed input.

{.push raises: [].}

import std/[net, strutils]
import results
import stew/endians2
import ../utils/[conversion, opt]

const
  MaxLabelLength = 63 # RFC 1035, section 2.3.4
  MaxNameLength = 255 # RFC 1035, section 3.1
  MaxPacketSize = int(uint16.high) # DNS over TCP uses a two-byte length.
  DnsUdpPayloadSize* = 1232 # Fits the IPv6 minimum MTU without fragmentation.
  MaxNameJumps = 16 # compression pointers followed before we give up
  HeaderSize = 12
  CompressionMask = 0xC0'u8
  QrMask = 0x8000'u16 # header flags: QR bit (1 = response)
  ResponseFlags = 0x8400'u16 # QR + AA
  ClassIn = 0x0001'u16
  ClassAny = 0x00FF'u16 # QCLASS ANY, which an mDNS query may carry
  ClassTopBit = 0x8000'u16 # cache-flush in a record, unicast-reply in a question
  ClassMask = 0x7FFF'u16

template raiseErr(msg: string) =
  raise newException(ValueError, msg)

type
  DnsTruncatedError* = object of ValueError

  DnsRecordKind* = enum
    A = 1
    PTR = 12
    TXT = 16
    AAAA = 28
    SRV = 33

  DnsName* = seq[string]
    ## Labels, root excluded. A label can hold a `.`, so `.` never separates.

  DnsAnswer* = object
    kind*: DnsRecordKind
    value*: string ## IPv4/IPv6 textual form, or concatenated TXT strings

  DnsQuestion* = object
    name*: DnsName
    kind*: DnsRecordKind
    unicastResponse*: bool ## mDNS QU bit, the top bit of the question class

  DnsRecord* = object
    name*: DnsName
    kind*: DnsRecordKind
    ttl*: uint32
    cacheFlush*: bool ## mDNS cache-flush bit, the top bit of the record class
    address*: string ## A/AAAA textual form
    target*: DnsName ## PTR/SRV
    priority*: uint16 ## SRV only
    weight*: uint16 ## SRV only
    port*: uint16 ## SRV only
    strings*: seq[string] ## TXT only, one entry per character-string

  DnsMessage* = object
    id*: uint16
    response*: bool
    questions*: seq[DnsQuestion]
    answers*: seq[DnsRecord]
    additionals*: seq[DnsRecord]

  DnsHeader = object
    id: uint16
    flags: uint16
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

  DnsReader = object
    data: seq[byte]
    pos: int

func isResponse(h: DnsHeader): bool =
  (h.flags and QrMask) != 0

proc readByte(r: var DnsReader): uint8 {.raises: [ValueError].} =
  if r.pos >= r.data.len:
    raiseErr("Truncated DNS message")
  let value = r.data[r.pos]
  inc r.pos
  return value

proc readShort(r: var DnsReader): uint16 {.raises: [ValueError].} =
  if r.pos + 2 > r.data.len:
    raiseErr("Truncated DNS message")
  let value = fromBytesBE(uint16, r.data.toOpenArray(r.pos, r.pos + 1))
  inc r.pos, 2
  return value

proc readLong(r: var DnsReader): uint32 {.raises: [ValueError].} =
  if r.pos + 4 > r.data.len:
    raiseErr("Truncated DNS message")
  let value = fromBytesBE(uint32, r.data.toOpenArray(r.pos, r.pos + 3))
  inc r.pos, 4
  return value

proc readBytes(r: var DnsReader, n: int): seq[byte] {.raises: [ValueError].} =
  if n < 0 or r.pos + n > r.data.len:
    raiseErr("Truncated DNS message")
  let value = r.data[r.pos ..< r.pos + n]
  inc r.pos, n
  return value

func stringAt(data: seq[byte], pos, length: int): string =
  var text = newStringOfCap(length)
  for i in 0 ..< length:
    text &= char(data[pos + i])
  return text

proc readString(r: var DnsReader, n: int): string {.raises: [ValueError].} =
  if n < 0 or r.pos + n > r.data.len:
    raiseErr("Truncated DNS message")
  let text = r.data.stringAt(r.pos, n)
  inc r.pos, n
  return text

proc labelAt(data: seq[byte], pos, length: int): string {.raises: [ValueError].} =
  if pos + length > data.len:
    raiseErr("Truncated DNS name")
  return data.stringAt(pos, length)

proc pointerAt(data: seq[byte], pos: int, first: uint8): int {.raises: [ValueError].} =
  if pos >= data.len:
    raiseErr("Truncated DNS name")
  let offset = ((first and 0x3F'u8).int shl 8) or data[pos].int
  if offset >= data.len:
    raiseErr("DNS name pointer out of range")
  return offset

proc readName(r: var DnsReader): DnsName {.raises: [ValueError].} =
  ## The cursor lands after the name in this record, not after a pointer target.
  var
    labels: seq[string]
    pos = r.pos
    resume = -1
    jumps = 0
    consumed = 1 # the root label terminator

  while true:
    if pos >= r.data.len:
      raiseErr("Truncated DNS name")
    let first = r.data[pos]
    inc pos

    if first == 0:
      break

    if (first and CompressionMask) == CompressionMask:
      let offset = r.data.pointerAt(pos, first)
      inc pos
      if resume < 0:
        resume = pos
      inc jumps
      if jumps > MaxNameJumps:
        raiseErr("DNS name compression loop")
      pos = offset
      continue

    if (first and CompressionMask) != 0:
      # 0x40 / 0x80 are reserved label types (RFC 1035, section 4.1.4).
      raiseErr("Reserved DNS label type")

    # The top two bits being clear limits an ordinary label to 63 bytes.
    inc consumed, first.int + 1
    if consumed > MaxNameLength:
      raiseErr("DNS name too long")
    labels.add(r.data.labelAt(pos, first.int))
    inc pos, first.int

  r.pos = if resume >= 0: resume else: pos
  return labels

proc readTxt(r: var DnsReader, rdlength: int): seq[string] {.raises: [ValueError].} =
  ## TXT rdata is a sequence of length-prefixed character-strings.
  let stop = r.pos + rdlength
  if stop > r.data.len:
    raiseErr("Truncated TXT record")

  var strings: seq[string]
  while r.pos < stop:
    let length = r.readByte().int
    if r.pos + length > stop:
      raiseErr("Invalid TXT record")
    strings.add(r.readString(length))
  return strings

proc readAddress(
    r: var DnsReader, rdlength, size: int
): seq[byte] {.raises: [ValueError].} =
  let rdata = r.readBytes(rdlength)
  if rdata.len != size:
    raiseErr("Invalid address record")
  return rdata

proc readHeader(r: var DnsReader): DnsHeader {.raises: [ValueError].} =
  var h: DnsHeader
  h.id = r.readShort()
  h.flags = r.readShort()
  h.qdcount = r.readShort().int
  h.ancount = r.readShort().int
  h.nscount = r.readShort().int
  h.arcount = r.readShort().int
  return h

proc toRecordKind(rrType: uint16): Opt[DnsRecordKind] =
  case rrType
  of A.uint16:
    Opt.some(A)
  of PTR.uint16:
    Opt.some(PTR)
  of TXT.uint16:
    Opt.some(TXT)
  of AAAA.uint16:
    Opt.some(AAAA)
  of SRV.uint16:
    Opt.some(SRV)
  else:
    Opt.none(DnsRecordKind)

proc readRecord(r: var DnsReader): Opt[DnsRecord] {.raises: [ValueError].} =
  ## Returns `none` for an unmodelled type or class; the cursor moves past it.
  let
    name = r.readName()
    rrType = r.readShort()
    class = r.readShort()
    ttl = r.readLong()
    rdlength = r.readShort().int
    rdataEnd = r.pos + rdlength

  if rdataEnd > r.data.len:
    raiseErr("Truncated resource record")

  if (class and ClassMask) != ClassIn:
    r.pos = rdataEnd
    return Opt.none(DnsRecord)

  let kind = toRecordKind(rrType).valueOr:
    r.pos = rdataEnd
    return Opt.none(DnsRecord)

  var record = DnsRecord(
    name: name, kind: kind, ttl: ttl, cacheFlush: (class and ClassTopBit) != 0
  )
  case kind
  of A:
    record.address = ipv4ToString(r.readAddress(rdlength, 4))
  of AAAA:
    record.address = ipv6ToString(r.readAddress(rdlength, 16))
  of PTR:
    record.target = r.readName()
  of TXT:
    record.strings = r.readTxt(rdlength)
  of SRV:
    if rdlength < 7: # six fixed bytes plus at least the root label
      raiseErr("Invalid SRV record")
    record.priority = r.readShort()
    record.weight = r.readShort()
    record.port = r.readShort()
    record.target = r.readName()

  if r.pos != rdataEnd:
    raiseErr("Resource record data does not match its declared length")

  return Opt.some(record)

proc readQuestion(r: var DnsReader): Opt[DnsQuestion] {.raises: [ValueError].} =
  ## Returns `none` for an unmodelled type or class; the cursor moves past it.
  let
    name = r.readName()
    rrType = r.readShort()
    class = r.readShort()
    qclass = class and ClassMask

  if qclass != ClassIn and qclass != ClassAny:
    return Opt.none(DnsQuestion)

  let kind = toRecordKind(rrType).valueOr:
    return Opt.none(DnsQuestion)
  return Opt.some(
    DnsQuestion(name: name, kind: kind, unicastResponse: (class and ClassTopBit) != 0)
  )

proc addString(buf: var seq[byte], text: string) =
  for c in text:
    buf.add(c.byte)

func toDnsName*(name: string): DnsName =
  ## Splits a presentation-format name, where `.` does separate the labels.
  name.split('.')

proc writeName(buf: var seq[byte], name: DnsName) {.raises: [ValueError].} =
  if name.len < 1:
    raiseErr("A DNS name needs at least one label")

  var encoded = 1 # the root label terminator
  for label in name:
    if label.len < 1:
      raiseErr("Empty DNS label")
    if label.len > MaxLabelLength:
      raiseErr("DNS label longer than 63 bytes: " & label)
    encoded += label.len + 1 # label bytes plus the length octet
    if encoded > MaxNameLength:
      raiseErr("Encoded DNS name longer than 255 bytes")
    buf.add(label.len.uint8)
    buf.addString(label)
  buf.add(0x00'u8) # root label terminator

func questionClass(q: DnsQuestion): uint16 =
  if q.unicastResponse:
    ClassIn or ClassTopBit
  else:
    ClassIn

func recordClass(rec: DnsRecord): uint16 =
  if rec.cacheFlush:
    ClassIn or ClassTopBit
  else:
    ClassIn

proc writeQuestion(buf: var seq[byte], q: DnsQuestion) {.raises: [ValueError].} =
  buf.writeName(q.name)
  buf.add(toBytesBE(q.kind.uint16))
  buf.add(toBytesBE(q.questionClass()))

proc writeIp(
    buf: var seq[byte], text: string, family: IpAddressFamily
) {.raises: [ValueError].} =
  let ip = parseIpAddress(text)
  if ip.family != family:
    raiseErr(text & " does not match the record type")
  if family == IpAddressFamily.IPv4:
    buf.add(ip.address_v4)
  else:
    buf.add(ip.address_v6)

proc writeCharStrings(
    buf: var seq[byte], strings: seq[string]
) {.raises: [ValueError].} =
  for text in strings:
    if text.len > 255:
      raiseErr("TXT character-string longer than 255 bytes")
    buf.add(text.len.uint8)
    buf.addString(text)

proc writeRdata(buf: var seq[byte], rec: DnsRecord) {.raises: [ValueError].} =
  case rec.kind
  of A:
    buf.writeIp(rec.address, IpAddressFamily.IPv4)
  of AAAA:
    buf.writeIp(rec.address, IpAddressFamily.IPv6)
  of PTR:
    buf.writeName(rec.target)
  of TXT:
    buf.writeCharStrings(rec.strings)
  of SRV:
    buf.add(toBytesBE(rec.priority))
    buf.add(toBytesBE(rec.weight))
    buf.add(toBytesBE(rec.port))
    buf.writeName(rec.target)

proc writeRecord(buf: var seq[byte], rec: DnsRecord) {.raises: [ValueError].} =
  buf.writeName(rec.name)
  buf.add(toBytesBE(rec.kind.uint16))
  buf.add(toBytesBE(rec.recordClass()))
  buf.add(toBytesBE(rec.ttl))

  let lengthPos = buf.len
  buf.add(toBytesBE(0x0000'u16)) # rdlength, patched once the rdata is known

  buf.writeRdata(rec)

  let rdlength = buf.len - lengthPos - 2
  if rdlength > int(uint16.high):
    raiseErr("Resource record rdata too long")
  let encoded = toBytesBE(rdlength.uint16)
  buf[lengthPos] = encoded[0]
  buf[lengthPos + 1] = encoded[1]

proc encodeQuery*(
    id: uint16, name: string, kind: DnsRecordKind
): seq[byte] {.raises: [ValueError].} =
  ## Builds a recursive query advertising EDNS support for larger UDP answers.
  var query = newSeqOfCap[byte](HeaderSize + name.len + 6 + 11)

  query.add(toBytesBE(id)) # id
  query.add([0x01'u8, 0x00'u8]) # flags: rd=1 (recursion desired)
  query.add([0x00'u8, 0x01'u8]) # qdcount = 1
  query.add([0x00'u8, 0x00'u8]) # ancount = 0
  query.add([0x00'u8, 0x00'u8]) # nscount = 0
  query.add([0x00'u8, 0x01'u8]) # arcount = 1

  query.writeQuestion(DnsQuestion(name: name.toDnsName(), kind: kind))

  query.add(0x00'u8) # OPT owner is the root name.
  query.add(toBytesBE(41'u16)) # OPT record type
  query.add(toBytesBE(DnsUdpPayloadSize.uint16))
  query.add(toBytesBE(0'u32)) # extended rcode, EDNS version and flags
  query.add(toBytesBE(0'u16)) # no EDNS options

  return query

func sectionCount(n: int, section: string): uint16 {.raises: [ValueError].} =
  if n > int(uint16.high):
    raiseErr("Too many " & section & " in DNS message")
  return n.uint16

proc encodeMessage*(msg: DnsMessage): seq[byte] {.raises: [ValueError].} =
  ## A response is marked authoritative, which is what a responder sends.
  var buf = newSeqOfCap[byte](HeaderSize + 128)

  buf.add(toBytesBE(msg.id))
  buf.add(toBytesBE(if msg.response: ResponseFlags else: 0x0000'u16))
  buf.add(toBytesBE(sectionCount(msg.questions.len, "questions")))
  buf.add(toBytesBE(sectionCount(msg.answers.len, "answers")))
  buf.add(toBytesBE(0x0000'u16)) # nscount
  buf.add(toBytesBE(sectionCount(msg.additionals.len, "additional records")))

  for question in msg.questions:
    buf.writeQuestion(question)
  for record in msg.answers:
    buf.writeRecord(record)
  for record in msg.additionals:
    buf.writeRecord(record)

  return buf

proc parseMessage*(data: openArray[byte]): DnsMessage {.raises: [ValueError].} =
  ## Accepts a query as well as a response, and takes a packet above 512 bytes.
  if data.len < HeaderSize:
    raiseErr("DNS message shorter than header")

  var r = DnsReader(data: @data, pos: 0)
  let header = r.readHeader()

  var msg = DnsMessage(id: header.id, response: header.isResponse())

  for _ in 0 ..< header.qdcount:
    r.readQuestion().ifValue(question):
      msg.questions.add(question)

  for _ in 0 ..< header.ancount:
    r.readRecord().ifValue(record):
      msg.answers.add(record)

  for _ in 0 ..< header.nscount:
    discard r.readRecord()

  for _ in 0 ..< header.arcount:
    r.readRecord().ifValue(record):
      msg.additionals.add(record)

  return msg

proc parseAnswers*(
    data: openArray[byte], expectedId: uint16
): seq[DnsAnswer] {.raises: [ValueError].} =
  ## Decodes the `A`/`AAAA`/`TXT` answers of a response to query `expectedId`.
  ## Raises `DnsTruncatedError` before decoding answers when TCP retry is needed.
  if data.len < HeaderSize:
    raiseErr("DNS response shorter than header")
  if data.len > MaxPacketSize:
    raiseErr("DNS response exceeds 65535 bytes")

  var r = DnsReader(data: @data, pos: 0)
  let header = r.readHeader()

  if header.id != expectedId:
    raiseErr("DNS response id does not match the query")
  if not header.isResponse():
    raiseErr("DNS message is not a response")
  if (header.flags and 0x0200'u16) != 0:
    raise newException(DnsTruncatedError, "Truncated DNS response")
  if header.qdcount == 0:
    raiseErr("DNS response has no question")

  for _ in 0 ..< header.qdcount:
    discard r.readQuestion()

  var answers: seq[DnsAnswer]
  for _ in 0 ..< header.ancount:
    let record = r.readRecord().valueOr:
      continue
    case record.kind
    of A, AAAA:
      answers.add(DnsAnswer(kind: record.kind, value: record.address))
    of TXT:
      answers.add(DnsAnswer(kind: TXT, value: record.strings.join()))
    else:
      discard # PTR/SRV are not part of the resolver's contract

  return answers
