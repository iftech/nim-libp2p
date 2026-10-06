# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements minimal ASN.1 encoding/decoding primitives.

{.push raises: [].}

import stew/[endians2, ctops]
import results
export results
# We use `ncrutils` for constant-time hexadecimal encoding/decoding procedures.
import nimcrypto/utils as ncrutils
import ../utils/conversion

type
  Asn1Error* {.pure.} = enum
    Overflow
    Incomplete
    Indefinite
    Incorrect
    NoSupport
    Overrun

  Asn1Result*[T] = Result[T, Asn1Error]

  Asn1Class* {.pure.} = enum
    Universal = 0x00
    Application = 0x01
    ContextSpecific = 0x02
    Private = 0x03

  Asn1Tag* {.pure.} = enum
    ## Protobuf's field types enum
    NoSupport
    Boolean
    Integer
    BitString
    OctetString
    Null
    Oid
    Sequence
    Context

  Asn1Buffer* = object of RootObj ## ASN.1's message representation object
    buffer*: seq[byte]
    offset*: int
    length*: int

  Asn1Field* = object
    klass*: Asn1Class
    index*: int
    offset*: int
    length*: int
    buffer*: seq[byte]
    case kind*: Asn1Tag
    of Asn1Tag.Boolean:
      vbool*: bool
    of Asn1Tag.Integer:
      vint*: uint64
    of Asn1Tag.BitString:
      ubits*: int
    else:
      discard

  Asn1Composite* = object of Asn1Buffer
    tag*: Asn1Tag
    idx*: int

const
  Asn1OidSecp256r1* =
    [0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8, 0x3D'u8, 0x03'u8, 0x01'u8, 0x07'u8]
    ## Encoded OID for `secp256r1` curve (1.2.840.10045.3.1.7)
  Asn1OidSecp384r1* = [0x2B'u8, 0x81'u8, 0x04'u8, 0x00'u8, 0x22'u8]
    ## Encoded OID for `secp384r1` curve (1.3.132.0.34)
  Asn1OidSecp521r1* = [0x2B'u8, 0x81'u8, 0x04'u8, 0x00'u8, 0x23'u8]
    ## Encoded OID for `secp521r1` curve (1.3.132.0.35)
  Asn1OidSecp256k1* = [0x2B'u8, 0x81'u8, 0x04'u8, 0x00'u8, 0x0A'u8]
    ## Encoded OID for `secp256k1` curve (1.3.132.0.10)
  Asn1OidEcPublicKey* = [0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8, 0x3D'u8, 0x02'u8, 0x01'u8]
    ## Encoded OID for Elliptic Curve Public Key (1.2.840.10045.2.1)
  Asn1OidRsaEncryption* =
    [0x2A'u8, 0x86'u8, 0x48'u8, 0x86'u8, 0xF7'u8, 0x0D'u8, 0x01'u8, 0x01'u8, 0x01'u8]
    ## Encoded OID for RSA Encryption (1.2.840.113549.1.1.1)
  Asn1True* = [0x01'u8, 0x01'u8, 0xFF'u8] ## Encoded boolean ``TRUE``.
  Asn1False* = [0x01'u8, 0x01'u8, 0x00'u8] ## Encoded boolean ``FALSE``.
  Asn1Null* = [0x05'u8, 0x00'u8] ## Encoded ``NULL`` value.

template toOpenArray*(ab: Asn1Buffer): untyped =
  toOpenArray(ab.buffer, ab.offset, ab.buffer.high)

template toOpenArray*(ac: Asn1Composite): untyped =
  toOpenArray(ac.buffer, ac.offset, ac.buffer.high)

template toOpenArray*(af: Asn1Field): untyped =
  toOpenArray(af.buffer, af.offset, af.offset + af.length - 1)

template isEmpty*(ab: Asn1Buffer): bool =
  ab.offset >= len(ab.buffer)

template isEnough*(ab: Asn1Buffer, length: int64): bool =
  len(ab.buffer) >= ab.offset + length

proc len*[T: Asn1Buffer | Asn1Composite](abc: T): int =
  len(abc.buffer) - abc.offset

proc len*(field: Asn1Field): int =
  field.length

template getPtr*(field: untyped): pointer =
  cast[pointer](addr field.buffer[field.offset])

proc extend*[T: Asn1Buffer | Asn1Composite](abc: var T, length: int) =
  ## Extend buffer or composite's internal buffer by ``length`` octets.
  abc.buffer.setLen(len(abc.buffer) + length)

proc code*(tag: Asn1Tag): byte =
  ## Converts Nim ``tag`` enum to ASN.1 tag code.
  case tag
  of Asn1Tag.NoSupport: 0x00'u8
  of Asn1Tag.Boolean: 0x01'u8
  of Asn1Tag.Integer: 0x02'u8
  of Asn1Tag.BitString: 0x03'u8
  of Asn1Tag.OctetString: 0x04'u8
  of Asn1Tag.Null: 0x05'u8
  of Asn1Tag.Oid: 0x06'u8
  of Asn1Tag.Sequence: 0x30'u8
  of Asn1Tag.Context: 0xA0'u8

proc asn1EncodeLength*(dest: var openArray[byte], length: uint64): int =
  ## Encode ASN.1 DER length part of TLV triple and return number of bytes
  ## (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``length`` value, then result of encoding WILL NOT BE stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  if length < 0x80'u64:
    if len(dest) >= 1:
      dest[0] = byte(length and 0x7F'u64)
    1
  else:
    var res = 1'u64
    var z = length
    while z != 0:
      inc(res)
      z = z shr 8
    if uint64(len(dest)) >= res:
      dest[0] = byte((0x80'u64 + (res - 1'u64)) and 0xFF)
      var o = 1
      for j in countdown(res - 2, 0):
        dest[o] = byte((length shr (j shl 3)) and 0xFF'u64)
        inc(o)
    # Because our `length` argument is `uint64`, `res` could not be bigger
    # then 9, so it is safe to convert it to `int`.
    int(res)

proc asn1EncodeInteger*(dest: var openArray[byte], value: openArray[byte]): int =
  ## Encode big-endian binary representation of integer as ASN.1 DER `INTEGER`
  ## and return number of bytes (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding WILL NOT BE stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  var buffer: array[16, byte]
  var lenlen = 0

  let offset = block:
    var o = 0
    for i in 0 ..< len(value):
      if value[o] != 0x00:
        break
      inc(o)
    if o < len(value):
      o
    else:
      o - 1

  let destlen =
    if len(value) > 0:
      if value[offset] >= 0x80'u8:
        lenlen = asn1EncodeLength(buffer, uint64(len(value) - offset + 1))
        1 + lenlen + 1 + (len(value) - offset)
      else:
        lenlen = asn1EncodeLength(buffer, uint64(len(value) - offset))
        1 + lenlen + (len(value) - offset)
    else:
      2

  if len(dest) >= destlen:
    var shift = 1
    dest[0] = Asn1Tag.Integer.code()
    copyMem(addr dest[1], addr buffer[0], lenlen)
    # If ``destlen > 2`` it means that ``len(value) > 0`` too.
    if destlen > 2:
      if value[offset] >= 0x80'u8:
        dest[1 + lenlen] = 0x00'u8
        shift = 2
      copyMem(addr dest[shift + lenlen], addr value[offset], len(value) - offset)
  destlen

proc asn1EncodeInteger*[T: SomeUnsignedInt](dest: var openArray[byte], value: T): int =
  ## Encode Nim's unsigned integer as ASN.1 DER `INTEGER` and return number of
  ## bytes (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  dest.asn1EncodeInteger(value.toBytesBE())

proc asn1EncodeBoolean*(dest: var openArray[byte], value: bool): int =
  ## Encode Nim's boolean as ASN.1 DER `BOOLEAN` and return number of bytes
  ## (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  let res = 3
  if len(dest) >= res:
    dest[0] = Asn1Tag.Boolean.code()
    dest[1] = 0x01'u8
    dest[2] = if value: 0xFF'u8 else: 0x00'u8
  res

proc asn1EncodeNull*(dest: var openArray[byte]): int =
  ## Encode ASN.1 DER `NULL` and return number of bytes (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  let res = 2
  if len(dest) >= res:
    dest[0] = Asn1Tag.Null.code()
    dest[1] = 0x00'u8
  res

proc asn1EncodeOctetString*(dest: var openArray[byte], value: openArray[byte]): int =
  ## Encode array of bytes as ASN.1 DER `OCTET STRING` and return number of
  ## bytes (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  var buffer: array[16, byte]
  let lenlen = asn1EncodeLength(buffer, uint64(len(value)))
  let res = 1 + lenlen + len(value)
  if len(dest) >= res:
    dest[0] = Asn1Tag.OctetString.code()
    copyMem(addr dest[1], addr buffer[0], lenlen)
    if len(value) > 0:
      copyMem(addr dest[1 + lenlen], addr value[0], len(value))
  res

proc asn1EncodeBitString*(
    dest: var openArray[byte], value: openArray[byte], bits = 0
): int =
  ## Encode array of bytes as ASN.1 DER `BIT STRING` and return number of bytes
  ## (octets) used.
  ##
  ## ``bits`` number of unused bits in ``value``. If ``bits == 0``, all the bits
  ## from ``value`` will be used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  var buffer: array[16, byte]
  let bitlen =
    if bits != 0:
      (len(value) shl 3) - bits
    else:
      (len(value) shl 3)

  # Number of bytes used
  let bytelen = (bitlen + 7) shr 3
  # Number of unused bits
  let unused = (8 - (bitlen and 7)) and 7
  let mask = not ((1'u8 shl unused) - 1'u8)
  var lenlen = asn1EncodeLength(buffer, uint64(bytelen + 1))
  let res = 1 + lenlen + 1 + len(value)
  if len(dest) >= res:
    dest[0] = Asn1Tag.BitString.code()
    copyMem(addr dest[1], addr buffer[0], lenlen)
    dest[1 + lenlen] = byte(unused)
    if bytelen > 0:
      let lastbyte = value[bytelen - 1]
      copyMem(addr dest[2 + lenlen], addr value[0], bytelen)
      # Set unused bits to zero
      dest[2 + lenlen + bytelen - 1] = lastbyte and mask
  res

proc asn1EncodeOid*(dest: var openArray[byte], value: openArray[byte]): int =
  ## Encode array of bytes ``value`` as ASN.1 DER `OBJECT IDENTIFIER` and return
  ## number of bytes (octets) used.
  ##
  ## This procedure is useful to encode constant predefined identifiers such
  ## as ``asn1OidSecp256r1``, ``asn1OidRsaEncryption``.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  var buffer: array[16, byte]
  let lenlen = asn1EncodeLength(buffer, uint64(len(value)))
  let res = 1 + lenlen + len(value)
  if len(dest) >= res:
    dest[0] = Asn1Tag.Oid.code()
    copyMem(addr dest[1], addr buffer[0], lenlen)
    copyMem(addr dest[1 + lenlen], addr value[0], len(value))
  res

proc asn1EncodeSequence*(dest: var openArray[byte], value: openArray[byte]): int =
  ## Encode ``value`` as ASN.1 DER `SEQUENCE` and return number of bytes
  ## (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  var buffer: array[16, byte]
  let lenlen = asn1EncodeLength(buffer, uint64(len(value)))
  let res = 1 + lenlen + len(value)
  if len(dest) >= res:
    dest[0] = Asn1Tag.Sequence.code()
    copyMem(addr dest[1], addr buffer[0], lenlen)
    copyMem(addr dest[1 + lenlen], addr value[0], len(value))
  res

proc asn1EncodeComposite*(dest: var openArray[byte], value: Asn1Composite): int =
  ## Encode composite value and return number of bytes (octets) used.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  var buffer: array[16, byte]
  let lenlen = asn1EncodeLength(buffer, uint64(len(value.buffer)))
  let res = 1 + lenlen + len(value.buffer)
  if len(dest) >= res:
    dest[0] = value.tag.code()
    copyMem(addr dest[1], addr buffer[0], lenlen)
    copyMem(addr dest[1 + lenlen], addr value.buffer[0], len(value.buffer))
  res

proc asn1EncodeContextTag*(
    dest: var openArray[byte], value: openArray[byte], tag: int
): int =
  ## Encode ASN.1 DER `CONTEXT SPECIFIC TAG` ``tag`` for value ``value`` and
  ## return number of bytes (octets) used.
  ##
  ## Note: Only values in [0, 15] range can be used as context tag ``tag``
  ## values.
  ##
  ## If length of ``dest`` is less then number of required bytes to encode
  ## ``value``, then result of encoding will not be stored in ``dest``
  ## but number of bytes (octets) required will be returned.
  var buffer: array[16, byte]
  let lenlen = asn1EncodeLength(buffer, uint64(len(value)))
  let res = 1 + lenlen + len(value)
  if len(dest) >= res:
    dest[0] = 0xA0'u8 or (byte(tag and 0xFF) and 0x0F'u8)
    copyMem(addr dest[1], addr buffer[0], lenlen)
    copyMem(addr dest[1 + lenlen], addr value[0], len(value))
  res

proc getLength(ab: var Asn1Buffer): Asn1Result[int] =
  ## Decode length part of ASN.1 TLV triplet.
  if not ab.isEmpty():
    let b = ab.buffer[ab.offset]
    if (b and 0x80'u8) == 0x00'u8:
      let length = safeConvert[int](b)
      ab.offset += 1
      return ok(length)
    if b == 0x80'u8:
      return err(Asn1Error.Indefinite)
    if b == 0xFF'u8:
      return err(Asn1Error.Incorrect)
    let octets = safeConvert[int](b and 0x7F'u8)
    if octets > 8:
      return err(Asn1Error.Overflow)
    if ab.isEnough(octets + 1):
      var lengthU: uint64 = 0
      for i in 0 ..< octets:
        lengthU = (lengthU shl 8) or safeConvert[uint64](ab.buffer[ab.offset + i + 1])
      if lengthU > uint64(int64.high):
        return err(Asn1Error.Overflow)
      let length = int(lengthU)
      ab.offset = ab.offset + octets + 1
      return ok(length)
    else:
      return err(Asn1Error.Incomplete)
  else:
    return err(Asn1Error.Incomplete)

proc getTag(ab: var Asn1Buffer, tag: var int): Asn1Result[Asn1Class] =
  ## Decode tag part of ASN.1 TLV triplet.
  if not ab.isEmpty():
    let
      b = ab.buffer[ab.offset]
      c = safeConvert[int]((b and 0xC0'u8) shr 6)
    tag = safeConvert[int](b and 0x3F)
    ab.offset += 1
    if c >= 0 and c < 4:
      ok(cast[Asn1Class](c))
    else:
      err(Asn1Error.Incorrect)
  else:
    err(Asn1Error.Incomplete)

proc read*(ab: var Asn1Buffer): Asn1Result[Asn1Field] =
  ## Decode value part of ASN.1 TLV triplet.
  var
    field: Asn1Field
    tag, ttag, offset: int
    length, tlength: int
    aclass: Asn1Class
    inclass: bool

  inclass = false
  while true:
    offset = ab.offset
    aclass = ?ab.getTag(tag)

    case aclass
    of Asn1Class.ContextSpecific:
      if inclass:
        return err(Asn1Error.Incorrect)
      else:
        inclass = true
        ttag = tag and 0x1F
        tlength = ?ab.getLength()
    of Asn1Class.Universal:
      length = ?ab.getLength()

      if inclass:
        if length >= tlength:
          return err(Asn1Error.Incorrect)
        aclass = Asn1Class.ContextSpecific

      case byte(tag)
      of Asn1Tag.Boolean.code():
        # BOOLEAN
        if length != 1:
          return err(Asn1Error.Incorrect)

        if not ab.isEnough(length):
          return err(Asn1Error.Incomplete)

        let b = ab.buffer[ab.offset]
        if b != 0xFF'u8 and b != 0x00'u8:
          return err(Asn1Error.Incorrect)

        field = Asn1Field(
          kind: Asn1Tag.Boolean,
          klass: aclass,
          index: ttag,
          offset: ab.offset,
          length: 1,
          buffer: ab.buffer,
        )
        field.vbool = (b == 0xFF'u8)
        ab.offset += 1
        return ok(field)
      of Asn1Tag.Integer.code():
        # INTEGER
        if length == 0:
          return err(Asn1Error.Incorrect)

        if not ab.isEnough(length):
          return err(Asn1Error.Incomplete)

        # Count number of leading zeroes
        var zc = 0
        while (zc < length) and (ab.buffer[ab.offset + zc] == 0x00'u8):
          inc(zc)

        if zc > 1:
          return err(Asn1Error.Incorrect)

        if zc == 0:
          # Negative or Positive integer
          field = Asn1Field(
            kind: Asn1Tag.Integer,
            klass: aclass,
            index: ttag,
            offset: ab.offset,
            length: length,
            buffer: ab.buffer,
          )
          if (ab.buffer[ab.offset] and 0x80'u8) == 0x80'u8:
            # Negative integer
            if length <= 8:
              # We need this transformation because our field.vint is uint64.
              for i in 0 ..< 8:
                if i < 8 - length:
                  field.vint = (field.vint shl 8) or 0xFF'u64
                else:
                  let offset = ab.offset + i - (8 - length)
                  field.vint =
                    (field.vint shl 8) or safeConvert[uint64](ab.buffer[offset])
          else:
            # Positive integer
            if length <= 8:
              for i in 0 ..< length:
                field.vint =
                  (field.vint shl 8) or safeConvert[uint64](ab.buffer[ab.offset + i])
          ab.offset += length
          return ok(field)
        else:
          if length == 1:
            # Zero value integer
            field = Asn1Field(
              kind: Asn1Tag.Integer,
              klass: aclass,
              index: ttag,
              offset: ab.offset,
              length: length,
              vint: 0'u64,
              buffer: ab.buffer,
            )
            ab.offset += length
            return ok(field)
          else:
            # Positive integer with leading zero
            field = Asn1Field(
              kind: Asn1Tag.Integer,
              klass: aclass,
              index: ttag,
              offset: ab.offset + 1,
              length: length - 1,
              buffer: ab.buffer,
            )
            if length <= 9:
              for i in 1 ..< length:
                field.vint =
                  (field.vint shl 8) or safeConvert[uint64](ab.buffer[ab.offset + i])
            ab.offset += length
            return ok(field)
      of Asn1Tag.BitString.code():
        # BIT STRING
        if length == 0:
          # BIT STRING should include `unused` bits field, so length should be
          # bigger then 1.
          return err(Asn1Error.Incorrect)
        elif length == 1:
          if ab.buffer[ab.offset] != 0x00'u8:
            return err(Asn1Error.Incorrect)
          else:
            # Zero-length BIT STRING.
            field = Asn1Field(
              kind: Asn1Tag.BitString,
              klass: aclass,
              index: ttag,
              offset: ab.offset + 1,
              length: 0,
              ubits: 0,
              buffer: ab.buffer,
            )
            ab.offset += length
            return ok(field)
        else:
          if not ab.isEnough(length):
            return err(Asn1Error.Incomplete)

          let unused = ab.buffer[ab.offset]
          if unused > 0x07'u8:
            # Number of unused bits should not be bigger then `7`.
            return err(Asn1Error.Incorrect)

          let mask = (1'u8 shl safeConvert[int](unused)) - 1'u8
          if (ab.buffer[ab.offset + length - 1] and mask) != 0x00'u8:
            ## All unused bits should be set to `0`.
            return err(Asn1Error.Incorrect)

          field = Asn1Field(
            kind: Asn1Tag.BitString,
            klass: aclass,
            index: ttag,
            offset: ab.offset + 1,
            length: length - 1,
            ubits: safeConvert[int](unused),
            buffer: ab.buffer,
          )
          ab.offset += length
          return ok(field)
      of Asn1Tag.OctetString.code():
        # OCTET STRING
        if not ab.isEnough(length):
          return err(Asn1Error.Incomplete)

        field = Asn1Field(
          kind: Asn1Tag.OctetString,
          klass: aclass,
          index: ttag,
          offset: ab.offset,
          length: length,
          buffer: ab.buffer,
        )
        ab.offset += length
        return ok(field)
      of Asn1Tag.Null.code():
        # NULL
        if length != 0:
          return err(Asn1Error.Incorrect)

        field = Asn1Field(
          kind: Asn1Tag.Null,
          klass: aclass,
          index: ttag,
          offset: ab.offset,
          length: 0,
          buffer: ab.buffer,
        )
        ab.offset += length
        return ok(field)
      of Asn1Tag.Oid.code():
        # OID
        if not ab.isEnough(length):
          return err(Asn1Error.Incomplete)

        field = Asn1Field(
          kind: Asn1Tag.Oid,
          klass: aclass,
          index: ttag,
          offset: ab.offset,
          length: length,
          buffer: ab.buffer,
        )
        ab.offset += length
        return ok(field)
      of Asn1Tag.Sequence.code():
        # SEQUENCE
        if not ab.isEnough(length):
          return err(Asn1Error.Incomplete)

        field = Asn1Field(
          kind: Asn1Tag.Sequence,
          klass: aclass,
          index: ttag,
          offset: ab.offset,
          length: length,
          buffer: ab.buffer,
        )
        ab.offset += length
        return ok(field)
      else:
        return err(Asn1Error.NoSupport)
    else:
      return err(Asn1Error.NoSupport)

proc getBuffer*(field: Asn1Field): Asn1Buffer =
  ## Return ``field`` as Asn1Buffer to enter composite types.
  Asn1Buffer(buffer: field.buffer, offset: field.offset, length: field.length)

proc `==`*(field: Asn1Field, data: openArray[byte]): bool =
  ## Compares field ``field`` data with ``data`` and returns ``true`` if both
  ## buffers are equal.
  let length = len(field.buffer)
  if length == 0 and len(data) == 0:
    true
  else:
    if length > 0:
      if field.length == len(data):
        CT.isEqual(
          field.buffer.toOpenArray(field.offset, field.offset + field.length - 1),
          data.toOpenArray(0, field.length - 1),
        )
      else:
        false
    else:
      false

proc init*(t: typedesc[Asn1Buffer], data: openArray[byte]): Asn1Buffer =
  ## Initialize ``Asn1Buffer`` from array of bytes ``data``.
  Asn1Buffer(buffer: @data)

proc init*(t: typedesc[Asn1Buffer], data: string): Asn1Buffer =
  ## Initialize ``Asn1Buffer`` from hexadecimal string ``data``.
  Asn1Buffer(buffer: ncrutils.fromHex(data))

proc init*(t: typedesc[Asn1Buffer]): Asn1Buffer =
  ## Initialize empty ``Asn1Buffer``.
  Asn1Buffer(buffer: newSeqUninit[byte](0))

proc init*(t: typedesc[Asn1Composite], tag: Asn1Tag): Asn1Composite =
  ## Initialize ``Asn1Composite`` with tag ``tag``.
  Asn1Composite(tag: tag, buffer: newSeqUninit[byte](0))

proc init*(t: typedesc[Asn1Composite], idx: int): Asn1Composite =
  ## Initialize ``Asn1Composite`` with tag context-specific id ``id``.
  Asn1Composite(tag: Asn1Tag.Context, idx: idx, buffer: newSeqUninit[byte](0))

proc `$`*(buffer: Asn1Buffer): string =
  ## Return string representation of ``buffer``.
  ncrutils.toHex(buffer.toOpenArray())

proc `$`*(field: Asn1Field): string =
  ## Return string representation of ``field``.
  var res = "["
  res.add($field.kind)
  res.add("]")
  case field.kind
  of Asn1Tag.Boolean:
    res.add(" ")
    res.add($field.vbool)
    res
  of Asn1Tag.Integer:
    res.add(" ")
    if field.length <= 8:
      res.add($field.vint)
    else:
      res.add(ncrutils.toHex(field.toOpenArray()))
    res
  of Asn1Tag.BitString:
    res.add(" ")
    res.add("(")
    res.add($field.ubits)
    res.add(" bits) ")
    res.add(ncrutils.toHex(field.toOpenArray()))
    res
  of Asn1Tag.OctetString:
    res.add(" ")
    res.add(ncrutils.toHex(field.toOpenArray()))
    res
  of Asn1Tag.Null:
    res.add(" NULL")
    res
  of Asn1Tag.Oid:
    res.add(" ")
    res.add(ncrutils.toHex(field.toOpenArray()))
    res
  of Asn1Tag.Sequence:
    res.add(" ")
    res.add(ncrutils.toHex(field.toOpenArray()))
    res
  of Asn1Tag.Context:
    res.add(" ")
    res.add(ncrutils.toHex(field.toOpenArray()))
    res
  else:
    res.add(" ")
    res.add(ncrutils.toHex(field.toOpenArray()))
    res

proc write*[T: Asn1Buffer | Asn1Composite](abc: var T, tag: Asn1Tag) =
  ## Write empty value to buffer or composite with ``tag``.
  ##
  ## This procedure must be used to write `NULL`, `0` or empty `BIT STRING`,
  ## `OCTET STRING` types.
  doAssert(
    tag in {Asn1Tag.Null, Asn1Tag.Integer, Asn1Tag.BitString, Asn1Tag.OctetString}
  )
  var length: int
  if tag == Asn1Tag.Null:
    length = asn1EncodeNull(abc.toOpenArray())
    abc.extend(length)
    discard asn1EncodeNull(abc.toOpenArray())
  elif tag == Asn1Tag.Integer:
    length = asn1EncodeInteger(abc.toOpenArray(), 0'u64)
    abc.extend(length)
    discard asn1EncodeInteger(abc.toOpenArray(), 0'u64)
  elif tag == Asn1Tag.BitString:
    var tmp: array[1, byte]
    length = asn1EncodeBitString(abc.toOpenArray(), tmp.toOpenArray(0, -1))
    abc.extend(length)
    discard asn1EncodeBitString(abc.toOpenArray(), tmp.toOpenArray(0, -1))
  elif tag == Asn1Tag.OctetString:
    var tmp: array[1, byte]
    length = asn1EncodeOctetString(abc.toOpenArray(), tmp.toOpenArray(0, -1))
    abc.extend(length)
    discard asn1EncodeOctetString(abc.toOpenArray(), tmp.toOpenArray(0, -1))
  abc.offset += length

proc write*[T: Asn1Buffer | Asn1Composite](abc: var T, value: uint64) =
  ## Write uint64 ``value`` to buffer or composite as ASN.1 `INTEGER`.
  let length = asn1EncodeInteger(abc.toOpenArray(), value)
  abc.extend(length)
  discard asn1EncodeInteger(abc.toOpenArray(), value)
  abc.offset += length

proc write*[T: Asn1Buffer | Asn1Composite](abc: var T, value: bool) =
  ## Write bool ``value`` to buffer or composite as ASN.1 `BOOLEAN`.
  let length = asn1EncodeBoolean(abc.toOpenArray(), value)
  abc.extend(length)
  discard asn1EncodeBoolean(abc.toOpenArray(), value)
  abc.offset += length

proc write*[T: Asn1Buffer | Asn1Composite](
    abc: var T, tag: Asn1Tag, value: openArray[byte], bits = 0
) =
  ## Write array ``value`` using ``tag``.
  ##
  ## This procedure is used to write ASN.1 `INTEGER`, `OCTET STRING`,
  ## `BIT STRING` or `OBJECT IDENTIFIER`.
  ##
  ## For `BIT STRING` you can use ``bits`` argument to specify number of used
  ## bits.
  doAssert(
    tag in {Asn1Tag.Integer, Asn1Tag.OctetString, Asn1Tag.BitString, Asn1Tag.Oid}
  )
  var length: int
  if tag == Asn1Tag.Integer:
    length = asn1EncodeInteger(abc.toOpenArray(), value)
    abc.extend(length)
    discard asn1EncodeInteger(abc.toOpenArray(), value)
  elif tag == Asn1Tag.OctetString:
    length = asn1EncodeOctetString(abc.toOpenArray(), value)
    abc.extend(length)
    discard asn1EncodeOctetString(abc.toOpenArray(), value)
  elif tag == Asn1Tag.BitString:
    length = asn1EncodeBitString(abc.toOpenArray(), value, bits)
    abc.extend(length)
    discard asn1EncodeBitString(abc.toOpenArray(), value, bits)
  elif tag == Asn1Tag.Oid:
    length = asn1EncodeOid(abc.toOpenArray(), value)
    abc.extend(length)
    discard asn1EncodeOid(abc.toOpenArray(), value)
  abc.offset += length

proc write*[T: Asn1Buffer | Asn1Composite](abc: var T, value: Asn1Composite) =
  doAssert(len(value) > 0, "Composite value not finished")
  var length: int
  if value.tag == Asn1Tag.Sequence:
    length = asn1EncodeSequence(abc.toOpenArray(), value.buffer)
    abc.extend(length)
    discard asn1EncodeSequence(abc.toOpenArray(), value.buffer)
  elif value.tag == Asn1Tag.BitString:
    length = asn1EncodeBitString(abc.toOpenArray(), value.buffer)
    abc.extend(length)
    discard asn1EncodeBitString(abc.toOpenArray(), value.buffer)
  elif value.tag == Asn1Tag.Context:
    length = asn1EncodeContextTag(abc.toOpenArray(), value.buffer, value.idx)
    abc.extend(length)
    discard asn1EncodeContextTag(abc.toOpenArray(), value.buffer, value.idx)
  abc.offset += length

proc finish*[T: Asn1Buffer | Asn1Composite](abc: var T) =
  ## Finishes buffer or composite and prepares it for writing.
  abc.offset = 0
