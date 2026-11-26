# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../libp2p/varint
import ../tools/[unittest]

const PBedgeValues = [
  0'u64,
  (1'u64 shl 7) - 1'u64,
  (1'u64 shl 7),
  (1'u64 shl 14) - 1'u64,
  (1'u64 shl 14),
  (1'u64 shl 21) - 1'u64,
  (1'u64 shl 21),
  (1'u64 shl 28) - 1'u64,
  (1'u64 shl 28),
  (1'u64 shl 35) - 1'u64,
  (1'u64 shl 35),
  (1'u64 shl 42) - 1'u64,
  (1'u64 shl 42),
  (1'u64 shl 49) - 1'u64,
  (1'u64 shl 49),
  (1'u64 shl 56) - 1'u64,
  (1'u64 shl 56),
  (1'u64 shl 63) - 1'u64,
  (1'u64 shl 63),
  0xFFFF_FFFF_FFFF_FFFF'u64,
]

const PBPositiveSignedEdgeValues = [
  0'u64, 0x3F'u64, 0x40'u64, 0x1FFF'u64, 0x2000'u64, 0xFFFFF'u64, 0x100000'u64,
  0x7FFFFFF'u64, 0x8000000'u64, 0x3FFFFFFFF'u64, 0x400000000'u64, 0x1FFFFFFFFFF'u64,
  0x20000000000'u64, 0xFFFFFFFFFFFF'u64, 0x1000000000000'u64, 0x7FFFFFFFFFFFFF'u64,
  0x80000000000000'u64, 0x3FFFFFFFFFFFFFFF'u64, 0x4000000000000000'u64,
  0x7FFFFFFFFFFFFFFF'u64,
]

const PBNegativeSignedEdgeValues = [
  0x0000000000000000'u64, 0xFFFFFFFFFFFFFFC0'u64, 0xFFFFFFFFFFFFFFBF'u64,
  0xFFFFFFFFFFFFE000'u64, 0xFFFFFFFFFFFFDFFF'u64, 0xFFFFFFFFFFF00000'u64,
  0xFFFFFFFFFFEFFFFF'u64, 0xFFFFFFFFF8000000'u64, 0xFFFFFFFFF7FFFFFF'u64,
  0xFFFFFFFC00000000'u64, 0xFFFFFFFBFFFFFFFF'u64, 0xFFFFFE0000000000'u64,
  0xFFFFFDFFFFFFFFFF'u64, 0xFFFF000000000000'u64, 0xFFFEFFFFFFFFFFFF'u64,
  0xFF80000000000000'u64, 0xFF7FFFFFFFFFFFFF'u64, 0xC000000000000000'u64,
  0xBFFFFFFFFFFFFFFF'u64, 0x8000000000000000'u64,
]

const PBPositiveSignedZigZagEdgeExpects = [
  "00", "7E", "8001", "FE7F", "808001", "FEFF7F", "80808001", "FEFFFF7F", "8080808001",
  "FEFFFFFF7F", "808080808001", "FEFFFFFFFF7F", "80808080808001", "FEFFFFFFFFFF7F",
  "8080808080808001", "FEFFFFFFFFFFFF7F", "808080808080808001", "FEFFFFFFFFFFFFFF7F",
  "80808080808080808001", "FEFFFFFFFFFFFFFFFF01",
]

const PBNegativeSignedZigZagEdgeExpects = [
  "00", "7F", "8101", "FF7F", "818001", "FFFF7F", "81808001", "FFFFFF7F", "8180808001",
  "FFFFFFFF7F", "818080808001", "FFFFFFFFFF7F", "81808080808001", "FFFFFFFFFFFF7F",
  "8180808080808001", "FFFFFFFFFFFFFF7F", "818080808080808001", "FFFFFFFFFFFFFFFF7F",
  "81808080808080808001", "FFFFFFFFFFFFFFFFFF01",
]

const PBPositiveSignedEdgeExpects = [
  "00", "3F", "40", "FF3F", "8040", "FFFF3F", "808040", "FFFFFF3F", "80808040",
  "FFFFFFFF3F", "8080808040", "FFFFFFFFFF3F", "808080808040", "FFFFFFFFFFFF3F",
  "80808080808040", "FFFFFFFFFFFFFF3F", "8080808080808040", "FFFFFFFFFFFFFFFF3F",
  "808080808080808040", "FFFFFFFFFFFFFFFF7F",
]

const PBNegativeSignedEdgeExpects = [
  "00", "C0FFFFFFFFFFFFFFFF01", "BFFFFFFFFFFFFFFFFF01", "80C0FFFFFFFFFFFFFF01",
  "FFBFFFFFFFFFFFFFFF01", "8080C0FFFFFFFFFFFF01", "FFFFBFFFFFFFFFFFFF01",
  "808080C0FFFFFFFFFF01", "FFFFFFBFFFFFFFFFFF01", "80808080C0FFFFFFFF01",
  "FFFFFFFFBFFFFFFFFF01", "8080808080C0FFFFFF01", "FFFFFFFFFFBFFFFFFF01",
  "808080808080C0FFFF01", "FFFFFFFFFFFFBFFFFF01", "80808080808080C0FF01",
  "FFFFFFFFFFFFFFBFFF01", "8080808080808080C001", "FFFFFFFFFFFFFFFFBF01",
  "80808080808080808001",
]

const PBedgeExpects = [
  "00", "7F", "8001", "FF7F", "808001", "FFFF7F", "80808001", "FFFFFF7F", "8080808001",
  "FFFFFFFF7F", "808080808001", "FFFFFFFFFF7F", "80808080808001", "FFFFFFFFFFFF7F",
  "8080808080808001", "FFFFFFFFFFFFFF7F", "808080808080808001", "FFFFFFFFFFFFFFFF7F",
  "80808080808080808001", "FFFFFFFFFFFFFFFFFF01",
]

const PBedgeSizes = [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10]

const PBEdgeSignedPositiveZigZagSizes =
  [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10]

const PBEdgeSignedNegativeZigZagSizes =
  [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10]

const PBEdgeSignedPositiveSizes =
  [1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 9]

const PBEdgeSignedNegativeSizes =
  [1, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]

const LPedgeValues = [
  0'u64,
  (1'u64 shl 7) - 1'u64,
  (1'u64 shl 7),
  (1'u64 shl 14) - 1'u64,
  (1'u64 shl 14),
  (1'u64 shl 21) - 1'u64,
  (1'u64 shl 21),
  (1'u64 shl 28) - 1'u64,
  (1'u64 shl 28),
  (1'u64 shl 35) - 1'u64,
  (1'u64 shl 35),
  (1'u64 shl 42) - 1'u64,
  (1'u64 shl 42),
  (1'u64 shl 49) - 1'u64,
  (1'u64 shl 49),
  (1'u64 shl 56) - 1'u64,
  (1'u64 shl 56),
  (1'u64 shl 63) - 1'u64,
]

const LPedgeSizes = [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9]

const LPedgeExpects = [
  "00", "7F", "8001", "FF7F", "808001", "FFFF7F", "80808001", "FFFFFF7F", "8080808001",
  "FFFFFFFF7F", "808080808001", "FFFFFFFFFF7F", "80808080808001", "FFFFFFFFFFFF7F",
  "8080808080808001", "FFFFFFFFFFFFFF7F", "808080808080808001", "FFFFFFFFFFFFFFFF7F",
]

proc hexChar*(c: byte, lowercase: bool = false): string =
  let alpha =
    if lowercase:
      ord('a')
    else:
      ord('A')
  var hex = newString(2)
  let t1 = ord(c) shr 4
  let t0 = ord(c) and 0x0F
  case t1
  of 0 .. 9:
    hex[0] = chr(t1 + ord('0'))
  else:
    hex[0] = chr(t1 - 10 + alpha)
  case t0
  of 0 .. 9:
    hex[1] = chr(t0 + ord('0'))
  else:
    hex[1] = chr(t0 - 10 + alpha)
  hex

proc toHex*(a: openArray[byte], lowercase: bool = false): string =
  var hex = ""
  for i in a:
    hex &= hexChar(i, lowercase)
  hex

suite "Variable integer test suite":
  test "vsizeof() edge cases test":
    for i in 0 ..< len(PBedgeValues):
      check vsizeof(PBedgeValues[i]) == PBedgeSizes[i]

    for i in 0 ..< len(PBPositiveSignedEdgeValues):
      check:
        vsizeof(hint64(PBPositiveSignedEdgeValues[i])) == PBEdgeSignedPositiveSizes[i]
        vsizeof(zint64(PBPositiveSignedEdgeValues[i])) ==
          PBEdgeSignedPositiveZigZagSizes[i]

    for i in 0 ..< len(PBNegativeSignedEdgeValues):
      check:
        vsizeof(cast[hint64](PBNegativeSignedEdgeValues[i])) ==
          PBEdgeSignedNegativeSizes[i]
        vsizeof(cast[zint64](PBNegativeSignedEdgeValues[i])) ==
          PBEdgeSignedNegativeZigZagSizes[i]

  test "[ProtoBuf] Success edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var uvalue = 0'u64
    var ivalue = hint64(0)
    var svalue = zint64(0)
    for i in 0 ..< len(PBedgeValues):
      buffer.setLen(PBedgeSizes[i])
      check:
        PB.putUVarint(buffer, length, PBedgeValues[i]).isOk()
        PB.getUVarint(buffer, length, uvalue).isOk()
        uvalue == PBedgeValues[i]
        toHex(buffer) == PBedgeExpects[i]

    for i in 0 ..< len(PBPositiveSignedEdgeValues):
      buffer.setLen(PBEdgeSignedPositiveSizes[i])
      check:
        putSVarint(buffer, length, hint64(PBPositiveSignedEdgeValues[i])).isOk()
        getSVarint(buffer, length, ivalue).isOk()
        int64(ivalue) == int64(PBPositiveSignedEdgeValues[i])
        toHex(buffer) == PBPositiveSignedEdgeExpects[i]

      buffer.setLen(PBEdgeSignedPositiveZigZagSizes[i])
      check:
        putSVarint(buffer, length, zint64(PBPositiveSignedEdgeValues[i])).isOk()
        getSVarint(buffer, length, svalue).isOk()
        int64(svalue) == int64(PBPositiveSignedEdgeValues[i])
        toHex(buffer) == PBPositiveSignedZigZagEdgeExpects[i]

    for i in 0 ..< len(PBNegativeSignedEdgeValues):
      buffer.setLen(PBEdgeSignedNegativeSizes[i])
      check:
        putSVarint(buffer, length, cast[hint64](PBNegativeSignedEdgeValues[i])).isOk()
        getSVarint(buffer, length, ivalue).isOk()
        int64(ivalue) == cast[int64](PBNegativeSignedEdgeValues[i])
        toHex(buffer) == PBNegativeSignedEdgeExpects[i]

      buffer.setLen(PBEdgeSignedNegativeZigZagSizes[i])
      check:
        putSVarint(buffer, length, cast[zint64](PBNegativeSignedEdgeValues[i])).isOk()
        getSVarint(buffer, length, svalue).isOk()

        int64(svalue) == cast[int64](PBNegativeSignedEdgeValues[i])
        toHex(buffer) == PBNegativeSignedZigZagEdgeExpects[i]

  test "[ProtoBuf] Buffer Overrun edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0 ..< len(PBedgeValues):
      buffer.setLen(PBedgeSizes[i] - 1)
      let res = PB.putUVarint(buffer, length, PBedgeValues[i])
      check:
        res.error() == VarintError.Overrun
        length == PBedgeSizes[i]

  test "[ProtoBuf] Buffer Incomplete edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var value = 0'u64
    for i in 0 ..< len(PBedgeValues):
      buffer.setLen(PBedgeSizes[i])
      check:
        PB.putUVarint(buffer, length, PBedgeValues[i]).isOk()
      buffer.setLen(buffer.high)
      check:
        PB.getUVarint(buffer, length, value).error() == VarintError.Incomplete

  test "[ProtoBuf] Integer Overflow 32bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0 ..< len(PBedgeValues):
      if PBedgeSizes[i] > 5:
        var value = 0'u32
        buffer.setLen(PBedgeSizes[i])
        check:
          PB.putUVarint(buffer, length, PBedgeValues[i]).isOk()
          PB.getUVarint(buffer, length, value).error() == VarintError.Overflow

  test "[ProtoBuf] Integer Overflow 64bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0 ..< len(PBedgeValues):
      if PBedgeSizes[i] > 9:
        var value = 0'u64
        buffer.setLen(PBedgeSizes[i] + 1)
        check:
          PB.putUVarint(buffer, length, PBedgeValues[i]).isOk()
        buffer[9] = buffer[9] or 0x80'u8
        buffer[10] = 0x01'u8
        check:
          PB.getUVarint(buffer, length, value).error() == VarintError.Overflow

  test "[ProtoBuf] Test vectors":
    # The test vectors which was obtained at:
    # https://github.com/dermesser/integer-encoding-rs/blob/master/src/varint_tests.rs
    # https://github.com/That3Percent/zigzag/blob/master/src/lib.rs
    check:
      PB.encodeVarint(0'u64).get() == @[0x00'u8]
      PB.encodeVarint(0'u32).get() == @[0x00'u8]
      PB.encodeVarint(hint64(0)).get() == @[0x00'u8]
      PB.encodeVarint(hint32(0)).get() == @[0x00'u8]
      PB.encodeVarint(zint64(0)).get() == @[0x00'u8]
      PB.encodeVarint(zint32(0)).get() == @[0x00'u8]
      PB.encodeVarint(zint32(-1)).get() == PB.encodeVarint(1'u32).get()
      PB.encodeVarint(zint64(150)).get() == PB.encodeVarint(300'u32).get()
      PB.encodeVarint(zint64(-150)).get() == PB.encodeVarint(299'u32).get()
      PB.encodeVarint(zint32(-2147483648)).get() == PB.encodeVarint(4294967295'u64).get()
      PB.encodeVarint(zint32(2147483647)).get() == PB.encodeVarint(4294967294'u64).get()

  test "[LibP2P] Success edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var value = 0'u64
    for i in 0 ..< len(LPedgeValues):
      buffer.setLen(LPedgeSizes[i])
      check:
        LP.putUVarint(buffer, length, LPedgeValues[i]).isOk()
        LP.getUVarint(buffer, length, value).isOk()
        value == LPedgeValues[i]
        toHex(buffer) == LPedgeExpects[i]

  test "[LibP2P] Buffer Overrun edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0 ..< len(LPedgeValues):
      buffer.setLen(PBedgeSizes[i] - 1)
      let res = LP.putUVarint(buffer, length, LPedgeValues[i])
      check:
        res.error() == VarintError.Overrun
        length == LPedgeSizes[i]

  test "[LibP2P] Buffer Incomplete edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var value = 0'u64
    for i in 0 ..< len(LPedgeValues):
      buffer.setLen(LPedgeSizes[i])
      check:
        LP.putUVarint(buffer, length, LPedgeValues[i]).isOk()
      buffer.setLen(buffer.high)
      check:
        LP.getUVarint(buffer, length, value).error() == VarintError.Incomplete

  test "[LibP2P] Integer Overflow 32bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0 ..< len(LPedgeValues):
      if LPedgeSizes[i] > 5:
        var value = 0'u32
        buffer.setLen(LPedgeSizes[i])
        check:
          LP.putUVarint(buffer, length, LPedgeValues[i]).isOk()
          LP.getUVarint(buffer, length, value).error() == VarintError.Overflow

  test "[LibP2P] Integer Overflow 64bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0 ..< len(LPedgeValues):
      if LPedgeSizes[i] > 8:
        var value = 0'u64
        buffer.setLen(LPedgeSizes[i] + 1)
        check:
          LP.putUVarint(buffer, length, LPedgeValues[i]).isOk()
        buffer[8] = buffer[8] or 0x80'u8
        buffer[9] = 0x01'u8
        check:
          LP.getUVarint(buffer, length, value).error() == VarintError.Overflow

  test "[LibP2P] Over 63bit test":
    var buffer = newSeq[byte](10)
    var length = 0
    check:
      LP.putUVarint(buffer, length, 0x7FFF_FFFF_FFFF_FFFF'u64).isOk()

      LP.putUVarint(buffer, length, 0x8000_0000_0000_0000'u64).error() ==
        VarintError.Overflow

      LP.putUVarint(buffer, length, 0xFFFF_FFFF_FFFF_FFFF'u64).error() ==
        VarintError.Overflow

  test "[LibP2P] encodeVarint for small widths and 64-bit overflow":
    check:
      LP.encodeVarint(1'u8).get() == @[0x01'u8]
      LP.encodeVarint(1'u16).get() == @[0x01'u8]
      LP.encodeVarint(1'u32).get() == @[0x01'u8]
      LP.encodeVarint(high(uint8)).get() == @[0xFF'u8, 0x01]
      LP.encodeVarint(1'u64 shl 63).error() == VarintError.Overflow

  test "[LibP2P] Overlong values test":
    const OverlongValues = [
      # Zero bytes at the end
      @[0x81'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      # Zero bytes at the middle and zero byte at the end
      @[0x81'u8, 0x80'u8, 0x81'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x00'u8],
      # Zero bytes at the middle and zero bytes at the end
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x80'u8, 0x80'u8, 0x00'u8],
      @[0x81'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8, 0x81'u8, 0x80'u8, 0x80'u8, 0x00'u8],
    ]
    var length = 0
    var value = 0'u64

    for item in OverlongValues:
      check:
        LP.getUVarint(item, length, value).error() == VarintError.Overlong
        length == 0
        value == 0

    # We still should be able to decode zero value
    check:
      LP.getUVarint(@[0x00'u8], length, value).isOk()
      length == 1
      value == 0

    # But not overlonged zero value
    check:
      LP.getUVarint(@[0x80'u8, 0x00'u8], length, value).error() == VarintError.Overlong
      length == 0
      value == 0

  test "getVarint/putVarint tests":
    proc `==`(a, b: zint32 | hint32): bool =
      int32(a) == int32(b)

    proc `==`(a, b: zint64 | hint64): bool =
      int64(a) == int64(b)

    template varintTest(ttype, vtype, value, expect: untyped) =
      var ovalue: vtype
      var buffer = newSeq[byte](10)
      var length = 0
      check ttype.putVarint(buffer, length, value).isOk()
      buffer.setLen(length)
      check:
        toHex(buffer) == expect
        ttype.getVarint(buffer, length, ovalue).isOk()
        ovalue == value

    varintTest(PB, uint64, high(uint64), "FFFFFFFFFFFFFFFFFF01")
    varintTest(PB, uint32, high(uint32), "FFFFFFFF0F")
    varintTest(PB, zint64, zint64(high(int64)), "FEFFFFFFFFFFFFFFFF01")
    varintTest(PB, zint32, zint32(high(int32)), "FEFFFFFF0F")
    varintTest(PB, zint64, zint64(low(int64)), "FFFFFFFFFFFFFFFFFF01")
    varintTest(PB, zint32, zint32(low(int32)), "FFFFFFFF0F")
    varintTest(PB, hint64, hint64(high(int64)), "FFFFFFFFFFFFFFFF7F")
    varintTest(PB, hint32, hint32(high(int32)), "FFFFFFFF07")
    varintTest(PB, hint64, hint64(low(int64)), "80808080808080808001")
    varintTest(PB, hint32, hint32(low(int32)), "8080808008")
    varintTest(LP, uint64, uint64(high(int64)), "FFFFFFFFFFFFFFFF7F")
    varintTest(LP, uint32, uint32(high(uint32)), "FFFFFFFF0F")
    varintTest(LP, uint16, uint16(high(uint16)), "FFFF03")
    varintTest(LP, uint8, uint8(high(uint8)), "FF01")
