# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import nimcrypto/utils as ncrutils
import ../../../libp2p/crypto/minasn1
import ../../tools/[unittest]

const Asn1EdgeValues = [
  0'u64,
  (1'u64 shl 7) - 1'u64,
  (1'u64 shl 7),
  (1'u64 shl 8) - 1'u64,
  (1'u64 shl 8),
  (1'u64 shl 16) - 1'u64,
  (1'u64 shl 16),
  (1'u64 shl 24) - 1'u64,
  (1'u64 shl 24),
  (1'u64 shl 32) - 1'u64,
  (1'u64 shl 32),
  (1'u64 shl 40) - 1'u64,
  (1'u64 shl 40),
  (1'u64 shl 48) - 1'u64,
  (1'u64 shl 48),
  (1'u64 shl 56) - 1'u64,
  (1'u64 shl 56),
  0xFFFF_FFFF_FFFF_FFFF'u64,
]

const Asn1EdgeExpects = [
  "00", "7F", "8180", "81FF", "820100", "82FFFF", "83010000", "83FFFFFF", "8401000000",
  "84FFFFFFFF", "850100000000", "85FFFFFFFFFF", "86010000000000", "86FFFFFFFFFFFF",
  "8701000000000000", "87FFFFFFFFFFFFFF", "880100000000000000", "88FFFFFFFFFFFFFFFF",
]

const Asn1UIntegerValues8 = [0x00'u8, 0x7F'u8, 0x80'u8, 0xFF'u8]

const Asn1UIntegerExpects8 = ["020100", "02017F", "02020080", "020200FF"]

const Asn1UIntegerValues16 =
  [0x00'u16, 0x7F'u16, 0x80'u16, 0xFF'u16, 0x7FFF'u16, 0x8000'u16, 0xFFFF'u16]

const Asn1UIntegerExpects16 =
  ["020100", "02017F", "02020080", "020200FF", "02027FFF", "0203008000", "020300FFFF"]

const Asn1UIntegerValues32 = [
  0x00'u32, 0x7F'u32, 0x80'u32, 0xFF'u32, 0x7FFF'u32, 0x8000'u32, 0xFFFF'u32,
  0x7FFF_FFFF'u32, 0x8000_0000'u32, 0xFFFF_FFFF'u32,
]

const Asn1UIntegerExpects32 = [
  "020100", "02017F", "02020080", "020200FF", "02027FFF", "0203008000", "020300FFFF",
  "02047FFFFFFF", "02050080000000", "020500FFFFFFFF",
]

const Asn1UIntegerValues64 = [
  0x00'u64, 0x7F'u64, 0x80'u64, 0xFF'u64, 0x7FFF'u64, 0x8000'u64, 0xFFFF'u64,
  0x7FFF_FFFF'u64, 0x8000_0000'u64, 0xFFFF_FFFF'u64, 0x7FFF_FFFF_FFFF_FFFF'u64,
  0x8000_0000_0000_0000'u64, 0xFFFF_FFFF_FFFF_FFFF'u64,
]

const Asn1UIntegerExpects64 = [
  "020100", "02017F", "02020080", "020200FF", "02027FFF", "0203008000", "020300FFFF",
  "02047FFFFFFF", "02050080000000", "020500FFFFFFFF", "02087FFFFFFFFFFFFFFF",
  "0209008000000000000000", "020900FFFFFFFFFFFFFFFF",
]

proc decodeHex(data: string): Asn1Result[Asn1Field] =
  var ab = Asn1Buffer.init(data)
  ab.read()

suite "Minimal ASN.1 encode/decode suite":
  test "Length encoding edge values":
    var empty = newSeq[byte](0)
    for i in 0 ..< len(Asn1EdgeValues):
      var value = newSeq[byte](9)
      let r1 = asn1EncodeLength(empty, Asn1EdgeValues[i])
      let r2 = asn1EncodeLength(value, Asn1EdgeValues[i])
      value.setLen(r2)
      check:
        r1 == (len(Asn1EdgeExpects[i]) shr 1)
        r2 == (len(Asn1EdgeExpects[i]) shr 1)
      check:
        ncrutils.fromHex(Asn1EdgeExpects[i]) == value

  test "ASN.1 DER long form length requires complete length octets":
    var ab = Asn1Buffer.init(@[0x30'u8, 0x81'u8])
    let res = ab.read()

    check:
      res.isErr()
      res.error == Asn1Error.Incomplete

  test "ASN.1 DER INTEGER encoding/decoding of native unsigned values test":
    proc decodeBuffer(data: openArray[byte]): uint64 =
      var ab = Asn1Buffer.init(data)
      let fres = ab.read()
      doAssert(fres.isOk() and fres.get().kind == Asn1Tag.Integer)
      fres.get().vint

    proc encodeInteger[T](value: T): seq[byte] =
      var buffer = newSeq[byte](16)
      let res = asn1EncodeInteger(buffer, value)
      buffer.setLen(res)
      buffer

    for i in 0 ..< len(Asn1UIntegerValues8):
      let buffer = encodeInteger(Asn1UIntegerValues8[i])
      check:
        toHex(buffer) == Asn1UIntegerExpects8[i]
        decodeBuffer(buffer) == uint64(Asn1UIntegerValues8[i])

    for i in 0 ..< len(Asn1UIntegerValues16):
      let buffer = encodeInteger(Asn1UIntegerValues16[i])
      check:
        toHex(buffer) == Asn1UIntegerExpects16[i]
        decodeBuffer(buffer) == uint64(Asn1UIntegerValues16[i])

    for i in 0 ..< len(Asn1UIntegerValues32):
      let buffer = encodeInteger(Asn1UIntegerValues32[i])
      check:
        toHex(buffer) == Asn1UIntegerExpects32[i]
        decodeBuffer(buffer) == uint64(Asn1UIntegerValues32[i])

    for i in 0 ..< len(Asn1UIntegerValues64):
      let buffer = encodeInteger(Asn1UIntegerValues64[i])
      check:
        toHex(buffer) == Asn1UIntegerExpects64[i]
        decodeBuffer(buffer) == uint64(Asn1UIntegerValues64[i])

  test "ASN.1 DER INTEGER incorrect values decoding test":
    check:
      decodeHex("0200").error == Asn1Error.Incorrect
      decodeHex("0201").error == Asn1Error.Incomplete
      decodeHex("02020000").error == Asn1Error.Incorrect
      decodeHex("0203000001").error == Asn1Error.Incorrect

  test "ASN.1 DER BITSTRING encoding/decoding with unused bits test":
    proc encodeBits(value: string, bitsUsed: int): seq[byte] =
      var buffer = newSeq[byte](16)
      let res = asn1EncodeBitString(buffer, fromHex(value), bitsUsed)
      buffer.setLen(res)
      buffer

    proc decodeBuffer(data: string): Asn1Field =
      var ab = Asn1Buffer.init(fromHex(data))
      let fres = ab.read()
      doAssert(fres.isOk() and fres.get().kind == Asn1Tag.BitString)
      fres.get()

    check:
      toHex(encodeBits("FF", 7)) == "03020780"
      toHex(encodeBits("FF", 6)) == "030206C0"
      toHex(encodeBits("FF", 5)) == "030205E0"
      toHex(encodeBits("FF", 4)) == "030204F0"
      toHex(encodeBits("FF", 3)) == "030203F8"
      toHex(encodeBits("FF", 2)) == "030202FC"
      toHex(encodeBits("FF", 1)) == "030201FE"
      toHex(encodeBits("FF", 0)) == "030200FF"

    let f0 = decodeBuffer("030200FF")
    let f0b = @(f0.buffer.toOpenArray(f0.offset, f0.offset + f0.length - 1))
    let f1 = decodeBuffer("030201FE")
    let f1b = @(f1.buffer.toOpenArray(f1.offset, f1.offset + f1.length - 1))
    let f2 = decodeBuffer("030202FC")
    let f2b = @(f2.buffer.toOpenArray(f2.offset, f2.offset + f2.length - 1))
    let f3 = decodeBuffer("030203F8")
    let f3b = @(f3.buffer.toOpenArray(f3.offset, f3.offset + f3.length - 1))
    let f4 = decodeBuffer("030204F0")
    let f4b = @(f4.buffer.toOpenArray(f4.offset, f4.offset + f4.length - 1))
    let f5 = decodeBuffer("030205E0")
    let f5b = @(f5.buffer.toOpenArray(f5.offset, f5.offset + f5.length - 1))
    let f6 = decodeBuffer("030206C0")
    let f6b = @(f6.buffer.toOpenArray(f6.offset, f6.offset + f6.length - 1))
    let f7 = decodeBuffer("03020780")
    let f7b = @(f7.buffer.toOpenArray(f7.offset, f7.offset + f7.length - 1))

    check:
      f0.ubits == 0
      toHex(f0b) == "FF"
      f1.ubits == 1
      toHex(f1b) == "FE"
      f2.ubits == 2
      toHex(f2b) == "FC"
      f3.ubits == 3
      toHex(f3b) == "F8"
      f4.ubits == 4
      toHex(f4b) == "F0"
      f5.ubits == 5
      toHex(f5b) == "E0"
      f6.ubits == 6
      toHex(f6b) == "C0"
      f7.ubits == 7
      toHex(f7b) == "80"

  test "ASN.1 DER BITSTRING incorrect values decoding test":
    check:
      decodeHex("0300").error == Asn1Error.Incorrect
      decodeHex("030180").error == Asn1Error.Incorrect
      decodeHex("030107").error == Asn1Error.Incorrect
      decodeHex("030200").error == Asn1Error.Incomplete
      decodeHex("030208FF").error == Asn1Error.Incorrect

  test "ASN.1 DER BOOLEAN decoding test":
    check:
      decodeHex("0101FF").get().vbool == true
      decodeHex("010100").get().vbool == false
      decodeHex("010101").error == Asn1Error.Incorrect
      decodeHex("01020000").error == Asn1Error.Incorrect
      decodeHex("0101").error == Asn1Error.Incomplete

  test "ASN.1 DER malformed TLV decoding test":
    check:
      decodeHex("").error == Asn1Error.Incomplete
      decodeHex("02").error == Asn1Error.Incomplete
      decodeHex("0280").error == Asn1Error.Indefinite
      decodeHex("02FF").error == Asn1Error.Incorrect
      decodeHex("0289").error == Asn1Error.Overflow
      decodeHex("0288FFFFFFFFFFFFFFFF").error == Asn1Error.Overflow
      decodeHex("0402AA").error == Asn1Error.Incomplete
      decodeHex("050100").error == Asn1Error.Incorrect
      decodeHex("030201FF").error == Asn1Error.Incorrect
      decodeHex("0C00").error == Asn1Error.NoSupport
      decodeHex("4100").error == Asn1Error.NoSupport
      decodeHex("A005A003020101").error == Asn1Error.Incorrect
      decodeHex("A00302030101").error == Asn1Error.Incorrect
      decodeHex("030100").get().length == 0
      decodeHex("0201FF").get().vint == 0xFFFF_FFFF_FFFF_FFFF'u64

  test "ASN.1 DER field string representation":
    check:
      $decodeHex("0101FF").get() == "[Boolean] true"
      $decodeHex("02017F").get() == "[Integer] 127"
      $decodeHex("02097F0102030405060708").get() == "[Integer] 7F0102030405060708"
      $decodeHex("030100").get() == "[BitString] (0 bits) "
      $decodeHex("03020780").get() == "[BitString] (7 bits) 80"
      $decodeHex("0401AA").get() == "[OctetString] AA"
      $decodeHex("0500").get() == "[Null] NULL"
      $decodeHex("06032A8648").get() == "[Oid] 2A8648"
      $decodeHex("3003020101").get() == "[Sequence] 020101"
      $Asn1Field(kind: Asn1Tag.Context, buffer: @[0x01'u8, 0x02], length: 2) ==
        "[Context] 0102"
      $Asn1Field(buffer: @[0x01'u8, 0x02], length: 2) == "[NoSupport] 0102"
      $Asn1Buffer.init("0500") == "0500"

  test "ASN.1 DER write of empty values":
    var b = Asn1Buffer.init()
    b.write(Asn1Tag.Integer)
    b.write(Asn1Tag.BitString)
    b.write(Asn1Tag.OctetString)
    b.write(Asn1Tag.Null)
    b.finish()

    check $b == "02010003010004000500"

  test "ASN.1 tag codes":
    check:
      Asn1Tag.NoSupport.code() == 0x00'u8
      Asn1Tag.Boolean.code() == 0x01'u8
      Asn1Tag.Integer.code() == 0x02'u8
      Asn1Tag.BitString.code() == 0x03'u8
      Asn1Tag.OctetString.code() == 0x04'u8
      Asn1Tag.Null.code() == 0x05'u8
      Asn1Tag.Oid.code() == 0x06'u8
      Asn1Tag.Sequence.code() == 0x30'u8
      Asn1Tag.Context.code() == 0xA0'u8

  test "ASN.1 field comparison with byte arrays":
    let oid = decodeHex("06032A8648").get()

    check:
      Asn1Field() == newSeq[byte]()
      Asn1Field() != [0x01'u8]
      oid == [0x2A'u8, 0x86, 0x48]
      oid != [0x2A'u8, 0x86]
      oid != [0x2A'u8, 0x86, 0x49]
