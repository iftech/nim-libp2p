# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import stew/byteutils, strutils
import ../../libp2p/[protobuf/minprotobuf, varint]
import ../tools/[unittest]

suite "MinProtobuf test suite":
  const VarintVectors = [
    "0800", "0801", "08ffffffff07", "08ffffffff0f", "08ffffffffffffffff7f",
    "08ffffffffffffffffff01",
  ]

  const VarintValues = [
    0x0'u64, 0x1'u64, 0x7FFF_FFFF'u64, 0xFFFF_FFFF'u64, 0x7FFF_FFFF_FFFF_FFFF'u64,
    0xFFFF_FFFF_FFFF_FFFF'u64,
  ]

  const Fixed32Vectors =
    ["0d00000000", "0d01000000", "0dffffff7f", "0dddccbbaa", "0dffffffff"]

  const Fixed32Values =
    [0x0'u32, 0x1'u32, 0x7FFF_FFFF'u32, 0xAABB_CCDD'u32, 0xFFFF_FFFF'u32]

  const Fixed64Vectors = [
    "090000000000000000", "090100000000000000", "09ffffff7f00000000",
    "09ddccbbaa00000000", "09ffffffff00000000", "09ffffffffffffff7f",
    "099988ffeeddccbbaa", "09ffffffffffffffff",
  ]

  const Fixed64Values = [
    0x0'u64, 0x1'u64, 0x7FFF_FFFF'u64, 0xAABB_CCDD'u64, 0xFFFF_FFFF'u64,
    0x7FFF_FFFF_FFFF_FFFF'u64, 0xAABB_CCDD_EEFF_8899'u64, 0xFFFF_FFFF_FFFF_FFFF'u64,
  ]

  const LengthVectors =
    ["0a00", "0a0161", "0a026162", "0a0461626364", "0a086162636465666768"]

  const LengthValues = ["", "a", "ab", "abcd", "abcdefgh"]

  ## This vector values was tested with `protoc` and related proto file.

  ## syntax = "proto2";
  ## message testmsg {
  ##   repeated uint64 d = 1 [packed=true];
  ##   repeated uint64 d = 2 [packed=true];
  ## }
  const PackedVarintVector =
    "0a1f0001ffffffff07ffffffff0fffffffffffffffff7fffffffffffffffffff0112020001"
  ## syntax = "proto2";
  ## message testmsg {
  ##   repeated sfixed32 d = 1 [packed=true];
  ##   repeated sfixed32 d = 2 [packed=true];
  ## }
  const PackedFixed32Vector =
    "0a140000000001000000ffffff7fddccbbaaffffffff12080000000001000000"
  ## syntax = "proto2";
  ## message testmsg {
  ##   repeated sfixed64 d = 1 [packed=true];
  ##   repeated sfixed64 d = 2 [packed=true];
  ## }
  const PackedFixed64Vector =
    """0a4000000000000000000100000000000000ffffff7f00000000ddccbbaa00000000
       ffffffff00000000ffffffffffffff7f9988ffeeddccbbaaffffffffffffffff1210
       00000000000000000100000000000000"""

  proc getVarintEncodedValue(value: uint64): seq[byte] =
    var pb = initProtoBuffer()
    pb.write(1, value)
    pb.finish()
    return pb.buffer

  proc getVarintDecodedValue(data: openArray[byte]): uint64 =
    var value: uint64
    var pb = initProtoBuffer(data)
    let res = pb.getField(1, value)
    doAssert(res.isOk() == true and res.get() == true)
    value

  proc getFixed32EncodedValue(value: float32): seq[byte] =
    var pb = initProtoBuffer()
    pb.write(1, value)
    pb.finish()
    return pb.buffer

  proc getFixed32DecodedValue(data: openArray[byte]): uint32 =
    var value: float32
    var pb = initProtoBuffer(data)
    let res = pb.getField(1, value)
    doAssert(res.isOk() == true and res.get() == true)
    cast[uint32](value)

  proc getFixed64EncodedValue(value: float64): seq[byte] =
    var pb = initProtoBuffer()
    pb.write(1, value)
    pb.finish()
    return pb.buffer

  proc getFixed64DecodedValue(data: openArray[byte]): uint64 =
    var value: float64
    var pb = initProtoBuffer(data)
    let res = pb.getField(1, value)
    doAssert(res.isOk() == true and res.get() == true)
    cast[uint64](value)

  proc getLengthEncodedValue(value: string): seq[byte] =
    var pb = initProtoBuffer()
    pb.write(1, value)
    pb.finish()
    return pb.buffer

  proc getLengthEncodedValue(value: seq[byte]): seq[byte] =
    var pb = initProtoBuffer()
    pb.write(1, value)
    pb.finish()
    return pb.buffer

  proc getLengthDecodedValue(data: openArray[byte]): string =
    var value = newString(len(data))
    var valueLen = 0
    var pb = initProtoBuffer(data)
    let res = pb.getField(1, value, valueLen)
    doAssert(res.isOk() == true and res.get() == true)
    value.setLen(valueLen)
    value

  proc isFullZero[T: byte | char](data: openArray[T]): bool =
    for ch in data:
      if int(ch) != 0:
        return false
    return true

  proc corruptHeader(data: var openArray[byte], index: int) =
    var values = [3, 4, 6]
    data[0] = data[0] and 0xF8'u8
    data[0] = data[0] or byte(values[index mod len(values)])

  test "[varint] edge values test":
    for i in 0 ..< len(VarintValues):
      let data = getVarintEncodedValue(VarintValues[i])
      check:
        toHex(data) == VarintVectors[i]
        getVarintDecodedValue(data) == VarintValues[i]

  test "[varint] mixing many values with same field number test":
    for i in 0 ..< len(VarintValues):
      var pb = initProtoBuffer()
      for k in 0 ..< len(VarintValues):
        let index = (i + k + 1) mod len(VarintValues)
        pb.write(1, VarintValues[index])
      pb.finish()
      check getVarintDecodedValue(pb.buffer) == VarintValues[i]

  test "[varint] incorrect values test":
    for i in 0 ..< len(VarintValues):
      var value: uint64
      var data = getVarintEncodedValue(VarintValues[i])
      # corrupting
      data.setLen(len(data) - 1)
      var pb = initProtoBuffer(data)
      let res = pb.getField(1, value)
      check:
        res.isErr() == true

  test "[varint] non-existent field test":
    for i in 0 ..< len(VarintValues):
      var value: uint64
      var data = getVarintEncodedValue(VarintValues[i])
      var pb = initProtoBuffer(data)
      let res = pb.getField(2, value)
      check:
        res.isOk() == true
        res.get() == false

  test "[varint] corrupted header test":
    for i in 0 ..< len(VarintValues):
      for k in 0 ..< 3:
        var value: uint64
        var data = getVarintEncodedValue(VarintValues[i])
        data.corruptHeader(k)
        var pb = initProtoBuffer(data)
        let res = pb.getField(1, value)
        check:
          res.isErr() == true

  test "[varint] empty buffer test":
    var value: uint64
    var pb = initProtoBuffer()
    let res = pb.getField(1, value)
    check:
      res.isOk() == true
      res.get() == false

  test "[varint] Repeated field test":
    var pb1 = initProtoBuffer()
    pb1.write(1, VarintValues[1])
    pb1.write(1, VarintValues[2])
    pb1.write(2, VarintValues[3])
    pb1.write(1, VarintValues[4])
    pb1.write(1, VarintValues[5])
    pb1.finish()
    var pb2 = initProtoBuffer(pb1.buffer)
    var fieldarr1: seq[uint64]
    var fieldarr2: seq[uint64]
    var fieldarr3: seq[uint64]
    let r1 = pb2.getRepeatedField(1, fieldarr1)
    let r2 = pb2.getRepeatedField(2, fieldarr2)
    let r3 = pb2.getRepeatedField(3, fieldarr3)
    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r1.get() == true
      r2.get() == true
      r3.get() == false
      len(fieldarr3) == 0
      len(fieldarr2) == 1
      len(fieldarr1) == 4
      fieldarr1[0] == VarintValues[1]
      fieldarr1[1] == VarintValues[2]
      fieldarr1[2] == VarintValues[4]
      fieldarr1[3] == VarintValues[5]
      fieldarr2[0] == VarintValues[3]

  test "[varint] Repeated packed field test":
    var pb1 = initProtoBuffer()
    pb1.writePacked(1, VarintValues)
    pb1.writePacked(2, VarintValues[0 .. 1])
    pb1.finish()
    check:
      toHex(pb1.buffer) == PackedVarintVector

    var pb2 = initProtoBuffer(pb1.buffer)
    var fieldarr1: seq[uint64]
    var fieldarr2: seq[uint64]
    var fieldarr3: seq[uint64]
    let r1 = pb2.getPackedRepeatedField(1, fieldarr1)
    let r2 = pb2.getPackedRepeatedField(2, fieldarr2)
    let r3 = pb2.getPackedRepeatedField(3, fieldarr3)
    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r1.get() == true
      r2.get() == true
      r3.get() == false
      len(fieldarr3) == 0
      len(fieldarr2) == 2
      len(fieldarr1) == 6
      fieldarr1[0] == VarintValues[0]
      fieldarr1[1] == VarintValues[1]
      fieldarr1[2] == VarintValues[2]
      fieldarr1[3] == VarintValues[3]
      fieldarr1[4] == VarintValues[4]
      fieldarr1[5] == VarintValues[5]
      fieldarr2[0] == VarintValues[0]
      fieldarr2[1] == VarintValues[1]

  test "[fixed32] edge values test":
    for i in 0 ..< len(Fixed32Values):
      let data = getFixed32EncodedValue(cast[float32](Fixed32Values[i]))
      check:
        toHex(data) == Fixed32Vectors[i]
        getFixed32DecodedValue(data) == Fixed32Values[i]

  test "[fixed32] mixing many values with same field number test":
    for i in 0 ..< len(Fixed32Values):
      var pb = initProtoBuffer()
      for k in 0 ..< len(Fixed32Values):
        let index = (i + k + 1) mod len(Fixed32Values)
        pb.write(1, cast[float32](Fixed32Values[index]))
      pb.finish()
      check getFixed32DecodedValue(pb.buffer) == Fixed32Values[i]

  test "[fixed32] incorrect values test":
    for i in 0 ..< len(Fixed32Values):
      var value: float32
      var data = getFixed32EncodedValue(float32(Fixed32Values[i]))
      # corrupting
      data.setLen(len(data) - 1)
      var pb = initProtoBuffer(data)
      let res = pb.getField(1, value)
      check:
        res.isErr() == true

  test "[fixed32] non-existent field test":
    for i in 0 ..< len(Fixed32Values):
      var value: float32
      var data = getFixed32EncodedValue(float32(Fixed32Values[i]))
      var pb = initProtoBuffer(data)
      let res = pb.getField(2, value)
      check:
        res.isOk() == true
        res.get() == false

  test "[fixed32] corrupted header test":
    for i in 0 ..< len(Fixed32Values):
      for k in 0 ..< 3:
        var value: float32
        var data = getFixed32EncodedValue(float32(Fixed32Values[i]))
        data.corruptHeader(k)
        var pb = initProtoBuffer(data)
        let res = pb.getField(1, value)
        check:
          res.isErr() == true

  test "[fixed32] empty buffer test":
    var value: float32
    var pb = initProtoBuffer()
    let res = pb.getField(1, value)
    check:
      res.isOk() == true
      res.get() == false

  test "[fixed32] Repeated field test":
    var pb1 = initProtoBuffer()
    pb1.write(1, cast[float32](Fixed32Values[0]))
    pb1.write(1, cast[float32](Fixed32Values[1]))
    pb1.write(2, cast[float32](Fixed32Values[2]))
    pb1.write(1, cast[float32](Fixed32Values[3]))
    pb1.write(1, cast[float32](Fixed32Values[4]))
    pb1.finish()
    var pb2 = initProtoBuffer(pb1.buffer)
    var fieldarr1: seq[float32]
    var fieldarr2: seq[float32]
    var fieldarr3: seq[float32]
    let r1 = pb2.getRepeatedField(1, fieldarr1)
    let r2 = pb2.getRepeatedField(2, fieldarr2)
    let r3 = pb2.getRepeatedField(3, fieldarr3)
    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r1.get() == true
      r2.get() == true
      r3.get() == false
      len(fieldarr3) == 0
      len(fieldarr2) == 1
      len(fieldarr1) == 4
      cast[uint32](fieldarr1[0]) == Fixed64Values[0]
      cast[uint32](fieldarr1[1]) == Fixed64Values[1]
      cast[uint32](fieldarr1[2]) == Fixed64Values[3]
      cast[uint32](fieldarr1[3]) == Fixed64Values[4]
      cast[uint32](fieldarr2[0]) == Fixed64Values[2]

  test "[fixed32] Repeated packed field test":
    var pb1 = initProtoBuffer()
    var values = newSeq[float32](len(Fixed32Values))
    for i in 0 ..< len(values):
      values[i] = cast[float32](Fixed32Values[i])
    pb1.writePacked(1, values)
    pb1.writePacked(2, values[0 .. 1])
    pb1.finish()
    check:
      toHex(pb1.buffer) == PackedFixed32Vector

    var pb2 = initProtoBuffer(pb1.buffer)
    var fieldarr1: seq[float32]
    var fieldarr2: seq[float32]
    var fieldarr3: seq[float32]
    let r1 = pb2.getPackedRepeatedField(1, fieldarr1)
    let r2 = pb2.getPackedRepeatedField(2, fieldarr2)
    let r3 = pb2.getPackedRepeatedField(3, fieldarr3)
    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r1.get() == true
      r2.get() == true
      r3.get() == false
      len(fieldarr3) == 0
      len(fieldarr2) == 2
      len(fieldarr1) == 5
      cast[uint32](fieldarr1[0]) == Fixed32Values[0]
      cast[uint32](fieldarr1[1]) == Fixed32Values[1]
      cast[uint32](fieldarr1[2]) == Fixed32Values[2]
      cast[uint32](fieldarr1[3]) == Fixed32Values[3]
      cast[uint32](fieldarr1[4]) == Fixed32Values[4]
      cast[uint32](fieldarr2[0]) == Fixed32Values[0]
      cast[uint32](fieldarr2[1]) == Fixed32Values[1]

  test "[fixed64] edge values test":
    for i in 0 ..< len(Fixed64Values):
      let data = getFixed64EncodedValue(cast[float64](Fixed64Values[i]))
      check:
        toHex(data) == Fixed64Vectors[i]
        getFixed64DecodedValue(data) == Fixed64Values[i]

  test "[fixed64] mixing many values with same field number test":
    for i in 0 ..< len(Fixed64Values):
      var pb = initProtoBuffer()
      for k in 0 ..< len(Fixed64Values):
        let index = (i + k + 1) mod len(Fixed64Values)
        pb.write(1, cast[float64](Fixed64Values[index]))
      pb.finish()
      check getFixed64DecodedValue(pb.buffer) == Fixed64Values[i]

  test "[fixed64] incorrect values test":
    for i in 0 ..< len(Fixed64Values):
      var value: float32
      var data = getFixed64EncodedValue(cast[float64](Fixed64Values[i]))
      # corrupting
      data.setLen(len(data) - 1)
      var pb = initProtoBuffer(data)
      let res = pb.getField(1, value)
      check:
        res.isErr() == true

  test "[fixed64] non-existent field test":
    for i in 0 ..< len(Fixed64Values):
      var value: float64
      var data = getFixed64EncodedValue(cast[float64](Fixed64Values[i]))
      var pb = initProtoBuffer(data)
      let res = pb.getField(2, value)
      check:
        res.isOk() == true
        res.get() == false

  test "[fixed64] corrupted header test":
    for i in 0 ..< len(Fixed64Values):
      for k in 0 ..< 3:
        var value: float64
        var data = getFixed64EncodedValue(cast[float64](Fixed64Values[i]))
        data.corruptHeader(k)
        var pb = initProtoBuffer(data)
        let res = pb.getField(1, value)
        check:
          res.isErr() == true

  test "[fixed64] empty buffer test":
    var value: float64
    var pb = initProtoBuffer()
    let res = pb.getField(1, value)
    check:
      res.isOk() == true
      res.get() == false

  test "[fixed64] Repeated field test":
    var pb1 = initProtoBuffer()
    pb1.write(1, cast[float64](Fixed64Values[2]))
    pb1.write(1, cast[float64](Fixed64Values[3]))
    pb1.write(2, cast[float64](Fixed64Values[4]))
    pb1.write(1, cast[float64](Fixed64Values[5]))
    pb1.write(1, cast[float64](Fixed64Values[6]))
    pb1.finish()
    var pb2 = initProtoBuffer(pb1.buffer)
    var fieldarr1: seq[float64]
    var fieldarr2: seq[float64]
    var fieldarr3: seq[float64]
    let r1 = pb2.getRepeatedField(1, fieldarr1)
    let r2 = pb2.getRepeatedField(2, fieldarr2)
    let r3 = pb2.getRepeatedField(3, fieldarr3)
    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r1.get() == true
      r2.get() == true
      r3.get() == false
      len(fieldarr3) == 0
      len(fieldarr2) == 1
      len(fieldarr1) == 4
      cast[uint64](fieldarr1[0]) == Fixed64Values[2]
      cast[uint64](fieldarr1[1]) == Fixed64Values[3]
      cast[uint64](fieldarr1[2]) == Fixed64Values[5]
      cast[uint64](fieldarr1[3]) == Fixed64Values[6]
      cast[uint64](fieldarr2[0]) == Fixed64Values[4]

  test "[fixed64] Repeated packed field test":
    var pb1 = initProtoBuffer()
    var values = newSeq[float64](len(Fixed64Values))
    for i in 0 ..< len(values):
      values[i] = cast[float64](Fixed64Values[i])
    pb1.writePacked(1, values)
    pb1.writePacked(2, values[0 .. 1])
    pb1.finish()
    let expect = PackedFixed64Vector.multiReplace(("\n", ""), (" ", ""))
    check:
      toHex(pb1.buffer) == expect

    var pb2 = initProtoBuffer(pb1.buffer)
    var fieldarr1: seq[float64]
    var fieldarr2: seq[float64]
    var fieldarr3: seq[float64]
    let r1 = pb2.getPackedRepeatedField(1, fieldarr1)
    let r2 = pb2.getPackedRepeatedField(2, fieldarr2)
    let r3 = pb2.getPackedRepeatedField(3, fieldarr3)
    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r1.get() == true
      r2.get() == true
      r3.get() == false
      len(fieldarr3) == 0
      len(fieldarr2) == 2
      len(fieldarr1) == 8
      cast[uint64](fieldarr1[0]) == Fixed64Values[0]
      cast[uint64](fieldarr1[1]) == Fixed64Values[1]
      cast[uint64](fieldarr1[2]) == Fixed64Values[2]
      cast[uint64](fieldarr1[3]) == Fixed64Values[3]
      cast[uint64](fieldarr1[4]) == Fixed64Values[4]
      cast[uint64](fieldarr1[5]) == Fixed64Values[5]
      cast[uint64](fieldarr1[6]) == Fixed64Values[6]
      cast[uint64](fieldarr1[7]) == Fixed64Values[7]
      cast[uint64](fieldarr2[0]) == Fixed64Values[0]
      cast[uint64](fieldarr2[1]) == Fixed64Values[1]

  test "[length] edge values test":
    for i in 0 ..< len(LengthValues):
      let data1 = getLengthEncodedValue(LengthValues[i])
      let data2 = getLengthEncodedValue(cast[seq[byte]](LengthValues[i]))
      check:
        toHex(data1) == LengthVectors[i]
        toHex(data2) == LengthVectors[i]
      check:
        getLengthDecodedValue(data1) == LengthValues[i]
        getLengthDecodedValue(data2) == LengthValues[i]

  test "[length] mixing many values with same field number test":
    for i in 0 ..< len(LengthValues):
      var pb1 = initProtoBuffer()
      var pb2 = initProtoBuffer()
      for k in 0 ..< len(LengthValues):
        let index = (i + k + 1) mod len(LengthValues)
        pb1.write(1, LengthValues[index])
        pb2.write(1, cast[seq[byte]](LengthValues[index]))
      pb1.finish()
      pb2.finish()
      check getLengthDecodedValue(pb1.buffer) == LengthValues[i]
      check getLengthDecodedValue(pb2.buffer) == LengthValues[i]

  test "[length] incorrect values test":
    for i in 0 ..< len(LengthValues):
      var value = newSeq[byte](len(LengthValues[i]))
      var valueLen = 0
      var data = getLengthEncodedValue(LengthValues[i])
      # corrupting
      data.setLen(len(data) - 1)
      var pb = initProtoBuffer(data)
      let res = pb.getField(1, value, valueLen)
      check:
        res.isErr() == true

  test "[length] non-existent field test":
    for i in 0 ..< len(LengthValues):
      var value = newSeq[byte](len(LengthValues[i]))
      var valueLen = 0
      var data = getLengthEncodedValue(LengthValues[i])
      var pb = initProtoBuffer(data)
      let res = pb.getField(2, value, valueLen)
      check:
        res.isOk() == true
        res.get() == false
        valueLen == 0

  test "[length] corrupted header test":
    for i in 0 ..< len(LengthValues):
      for k in 0 ..< 3:
        var value = newSeq[byte](len(LengthValues[i]))
        var valueLen = 0
        var data = getLengthEncodedValue(LengthValues[i])
        data.corruptHeader(k)
        var pb = initProtoBuffer(data)
        let res = pb.getField(1, value, valueLen)
        check:
          res.isErr() == true

  test "[length] empty buffer test":
    var value = newSeq[byte](len(LengthValues[0]))
    var valueLen = 0
    var pb = initProtoBuffer()
    let res = pb.getField(1, value, valueLen)
    check:
      res.isOk() == true
      res.get() == false
      valueLen == 0

  test "[length] buffer overflow test":
    for i in 1 ..< len(LengthValues):
      let data = getLengthEncodedValue(LengthValues[i])

      var value = newString(len(LengthValues[i]) - 1)
      var valueLen = 0
      var pb = initProtoBuffer(data)
      let res = pb.getField(1, value, valueLen)
      check:
        res.isOk() == true
        res.get() == false
        valueLen == len(LengthValues[i])
        isFullZero(value) == true

  test "[length] mix of buffer overflow and normal fields test":
    var pb1 = initProtoBuffer()
    pb1.write(1, "TEST10")
    pb1.write(1, "TEST20")
    pb1.write(1, "TEST")
    pb1.write(1, "TEST30")
    pb1.write(1, "SOME")
    pb1.finish()
    var pb2 = initProtoBuffer(pb1.buffer)
    var value = newString(4)
    var valueLen = 0
    let res = pb2.getField(1, value, valueLen)
    check:
      res.isOk() == true
      res.get() == true
      value == "SOME"

  test "[length] invalid message length":
    let field = @[0x0a'u8]
    let data = @[1'u8, 2'u8, 3'u8]

    var value: string
    var valueLen = 0

    let invalidLength = LP.encodeVarint(uint64(int32.high) + 1'u64)
    var pb1 = initProtoBuffer(field & invalidLength.get() & data)
    let res1 = pb1.getField(1, value, valueLen)
    check:
      res1.isErr() == true
      res1.error() == MessageIncomplete

    let validLength = LP.encodeVarint(data.lenu64)
    var pb2 = initProtoBuffer(field & validLength.get() & data)
    let res2 = pb2.getField(1, value, valueLen)
    check:
      res2.isErr() == false

  test "[length] Repeated field test":
    var pb1 = initProtoBuffer()
    pb1.write(1, "TEST1")
    pb1.write(1, "TEST2")
    pb1.write(2, "TEST5")
    pb1.write(1, "TEST3")
    pb1.write(1, "TEST4")
    pb1.finish()
    var pb2 = initProtoBuffer(pb1.buffer)
    var fieldarr1: seq[seq[byte]]
    var fieldarr2: seq[seq[byte]]
    var fieldarr3: seq[seq[byte]]
    let r1 = pb2.getRepeatedField(1, fieldarr1)
    let r2 = pb2.getRepeatedField(2, fieldarr2)
    let r3 = pb2.getRepeatedField(3, fieldarr3)
    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r1.get() == true
      r2.get() == true
      r3.get() == false
      len(fieldarr3) == 0
      len(fieldarr2) == 1
      len(fieldarr1) == 4
      cast[string](fieldarr1[0]) == "TEST1"
      cast[string](fieldarr1[1]) == "TEST2"
      cast[string](fieldarr1[2]) == "TEST3"
      cast[string](fieldarr1[3]) == "TEST4"
      cast[string](fieldarr2[0]) == "TEST5"

  test "Different value types in one message with same field number test":
    proc getEncodedValue(): seq[byte] =
      var pb = initProtoBuffer()
      pb.write(1, VarintValues[1])
      pb.write(2, cast[float32](Fixed32Values[1]))
      pb.write(3, cast[float64](Fixed64Values[1]))
      pb.write(4, LengthValues[1])

      pb.write(1, VarintValues[2])
      pb.write(2, cast[float32](Fixed32Values[2]))
      pb.write(3, cast[float64](Fixed64Values[2]))
      pb.write(4, LengthValues[2])

      pb.write(1, cast[float32](Fixed32Values[3]))
      pb.write(2, cast[float64](Fixed64Values[3]))
      pb.write(3, LengthValues[3])
      pb.write(4, VarintValues[3])

      pb.write(1, cast[float64](Fixed64Values[4]))
      pb.write(2, LengthValues[4])
      pb.write(3, VarintValues[4])
      pb.write(4, cast[float32](Fixed32Values[4]))

      pb.write(1, VarintValues[1])
      pb.write(2, cast[float32](Fixed32Values[1]))
      pb.write(3, cast[float64](Fixed64Values[1]))
      pb.write(4, LengthValues[1])
      pb.finish()
      pb.buffer

    let msg = getEncodedValue()
    let pb = initProtoBuffer(msg)
    var varintValue: uint64
    var fixed32Value: float32
    var fixed64Value: float64
    var lengthValue = newString(10)
    var lengthSize: int

    let r1 = pb.getField(1, varintValue)
    let r2 = pb.getField(2, fixed32Value)
    let r3 = pb.getField(3, fixed64Value)
    let r4 = pb.getField(4, lengthValue, lengthSize)

    check:
      r1.isOk() == true
      r2.isOk() == true
      r3.isOk() == true
      r4.isOk() == true

    lengthValue.setLen(lengthSize)

    check:
      varintValue == VarintValues[1]
      cast[uint32](fixed32Value) == Fixed32Values[1]
      cast[uint64](fixed64Value) == Fixed64Values[1]
      lengthValue == LengthValues[1]

  test "Malformed input fails every getter":
    type MalformedCase = object
      name: string
      data: seq[byte]
      error: ProtoError

    let cases = [
      MalformedCase(name: "bad wire type", data: @[0x0F'u8], error: BadWireType),
      MalformedCase(
        name: "other field, truncated varint",
        data: @[0x10'u8, 0x80],
        error: VarintDecode,
      ),
      MalformedCase(
        name: "other field, truncated fixed32",
        data: @[0x15'u8, 0x01],
        error: MessageIncomplete,
      ),
      MalformedCase(
        name: "other field, truncated length",
        data: @[0x12'u8, 0x05, 0x01],
        error: MessageIncomplete,
      ),
      MalformedCase(
        name: "target field, truncated varint",
        data: @[0x08'u8, 0x80],
        error: VarintDecode,
      ),
      MalformedCase(
        name: "target field, truncated length",
        data: @[0x0A'u8, 0x05, 0x01],
        error: MessageIncomplete,
      ),
    ]

    for c in cases:
      checkpoint c.name
      let pb = initProtoBuffer(c.data)
      let expected = ProtoResult[bool].err(c.error)

      var bytesValue = @[1'u8, 2, 3]
      check:
        pb.getField(1, bytesValue) == expected
        bytesValue.len == 0

      var fixedBuf = [0xAA'u8, 0xAA, 0xAA, 0xAA]
      var outlen = 7
      check:
        pb.getField(1, fixedBuf, outlen) == expected
        outlen == 0
        fixedBuf == [0'u8, 0, 0, 0]

      var repeatedBytes = @[@[1'u8]]
      check:
        pb.getRepeatedField(1, repeatedBytes) == expected
        repeatedBytes.len == 0

      var repeatedVarint = @[1'u64]
      check:
        pb.getRepeatedField(1, repeatedVarint) == expected
        repeatedVarint.len == 0

      var packedVarint = @[1'u64]
      check:
        pb.getPackedRepeatedField(1, packedVarint) == expected
        packedVarint.len == 0

  test "Truncated fixed64 fails float64 getters":
    let pb = initProtoBuffer(@[0x09'u8, 0x01])
    let expected = ProtoResult[bool].err(MessageIncomplete)

    var value = 1.0'f64
    check:
      pb.getField(1, value) == expected
      value == 1.0'f64

    var repeated = @[1.0'f64]
    check:
      pb.getRepeatedField(1, repeated) == expected
      repeated.len == 0

    var packed = @[1.0'f64]
    check:
      pb.getPackedRepeatedField(1, packed) == expected
      packed.len == 0

  test "Target field with another scalar wire type is skipped":
    let pb = initProtoBuffer(@[0x09'u8, 1, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x05])

    var value = 1'u64
    check:
      pb.getField(1, value) == ProtoResult[bool].ok(true)
      value == 5'u64

    var repeated = @[1'u64]
    check:
      pb.getRepeatedField(1, repeated) == ProtoResult[bool].ok(true)
      repeated == @[5'u64]

    var repeatedFloat = @[1.0'f32]
    check:
      pb.getRepeatedField(1, repeatedFloat) == ProtoResult[bool].ok(false)
      repeatedFloat.len == 0
