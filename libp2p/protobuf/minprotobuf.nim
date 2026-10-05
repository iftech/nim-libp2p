# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements minimal Google's ProtoBuf primitives.

{.push raises: [].}

import ../varint, ../utils/[opt, shortlog, collections], stew/endians2, results
export results, opt, shortlog, collections

type
  ProtoFieldKind* = enum
    ## Protobuf's field types enum
    Varint
    Fixed64
    Length
    StartGroup
    EndGroup
    Fixed32

  ProtoBuffer* = object ## Protobuf's message representation object
    buffer*: seq[byte]
    offset*: int
    length*: int

  ProtoHeader* = object
    wire*: ProtoFieldKind
    index*: uint64

  ProtoField* = object ## Protobuf's message field representation object
    index*: int
    case kind*: ProtoFieldKind
    of Varint:
      vint*: uint64
    of Fixed64:
      vfloat64*: float64
    of Length:
      vbuffer*: seq[byte]
    of Fixed32:
      vfloat32*: float32
    of StartGroup, EndGroup:
      discard

  ProtoError* {.pure.} = enum
    VarintDecode
    MessageIncomplete
    BufferOverflow
    BadWireType
    IncorrectBlob
    RequiredFieldMissing

  ProtoResult*[T] = Result[T, ProtoError]

  ProtoScalar* =
    uint | uint32 | uint64 | zint | zint32 | zint64 | hint | hint32 | hint64 | float32 |
    float64

const SupportedWireTypes* = @[
  uint64(ProtoFieldKind.Varint),
  uint64(ProtoFieldKind.Fixed64),
  uint64(ProtoFieldKind.Length),
  uint64(ProtoFieldKind.Fixed32),
]

template checkFieldNumber*(i: int) =
  doAssert(
    (i > 0 and i < (1 shl 29)) and not (i >= 19000 and i <= 19999),
    "Incorrect or reserved field number",
  )

template getProtoHeader*(index: int, wire: ProtoFieldKind): uint64 =
  ## Get protobuf's field header integer for ``index`` and ``wire``.
  ((uint64(index) shl 3) or uint64(wire))

template getProtoHeader*(field: ProtoField): uint64 =
  ## Get protobuf's field header integer for ``field``.
  ((uint64(field.index) shl 3) or uint64(field.kind))

template toOpenArray*(pb: ProtoBuffer): untyped =
  toOpenArray(pb.buffer, pb.offset, len(pb.buffer) - 1)

template lenu64*(x: untyped): untyped =
  uint64(len(x))

template isEmpty*(pb: ProtoBuffer): bool =
  len(pb.buffer) - pb.offset <= 0

template isEnough*(pb: ProtoBuffer, length: uint64): bool =
  pb.offset <= len(pb.buffer) and length <= uint64(len(pb.buffer) - pb.offset)

template getPtr*(pb: ProtoBuffer): pointer =
  cast[pointer](addr pb.buffer[pb.offset])

template getLen*(pb: ProtoBuffer): int =
  len(pb.buffer) - pb.offset

proc vsizeof*(field: ProtoField): int =
  ## Returns number of bytes required to store protobuf's field ``field``.
  case field.kind
  of ProtoFieldKind.Varint:
    vsizeof(getProtoHeader(field)) + vsizeof(field.vint)
  of ProtoFieldKind.Fixed64:
    vsizeof(getProtoHeader(field)) + sizeof(field.vfloat64)
  of ProtoFieldKind.Fixed32:
    vsizeof(getProtoHeader(field)) + sizeof(field.vfloat32)
  of ProtoFieldKind.Length:
    vsizeof(getProtoHeader(field)) + vsizeof(uint64(len(field.vbuffer))) +
      len(field.vbuffer)
  else:
    0

func initProtoBuffer*(data: seq[byte], offset = 0): ProtoBuffer =
  ## Initialize ProtoBuffer with shallow copy of ``data``.
  ProtoBuffer(buffer: data, offset: offset)

func initProtoBuffer*(data: openArray[byte], offset = 0): ProtoBuffer =
  ## Initialize ProtoBuffer with copy of ``data``.
  ProtoBuffer(buffer: @data, offset: offset)

func initProtoBuffer*(): ProtoBuffer =
  ProtoBuffer()

proc write*[T: ProtoScalar](pb: var ProtoBuffer, field: int, value: T) =
  checkFieldNumber(field)
  var length = 0
  when (T is uint64) or (T is uint32) or (T is uint) or (T is zint64) or (T is zint32) or
      (T is zint) or (T is hint64) or (T is hint32) or (T is hint):
    let flength = vsizeof(getProtoHeader(field, ProtoFieldKind.Varint)) + vsizeof(value)
    let header = ProtoFieldKind.Varint
  elif T is float32:
    let flength = vsizeof(getProtoHeader(field, ProtoFieldKind.Fixed32)) + sizeof(T)
    let header = ProtoFieldKind.Fixed32
  elif T is float64:
    let flength = vsizeof(getProtoHeader(field, ProtoFieldKind.Fixed64)) + sizeof(T)
    let header = ProtoFieldKind.Fixed64

  pb.buffer.setLen(len(pb.buffer) + flength)

  let hres = PB.putUVarint(pb.toOpenArray(), length, getProtoHeader(field, header))
  doAssert(hres.isOk())
  pb.offset += length
  when (T is uint64) or (T is uint32) or (T is uint):
    let vres = PB.putUVarint(pb.toOpenArray(), length, value)
    doAssert(vres.isOk())
    pb.offset += length
  elif (T is zint64) or (T is zint32) or (T is zint) or (T is hint64) or (T is hint32) or
      (T is hint):
    let vres = putSVarint(pb.toOpenArray(), length, value)
    doAssert(vres.isOk())
    pb.offset += length
  elif T is float32:
    doAssert(pb.isEnough(uint64(sizeof(T))))
    let u32 = cast[uint32](value)
    pb.buffer[pb.offset ..< pb.offset + sizeof(T)] = u32.toBytesLE()
    pb.offset += sizeof(T)
  elif T is float64:
    doAssert(pb.isEnough(uint64(sizeof(T))))
    let u64 = cast[uint64](value)
    pb.buffer[pb.offset ..< pb.offset + sizeof(T)] = u64.toBytesLE()
    pb.offset += sizeof(T)

proc write*(pb: var ProtoBuffer, field: int, value: bool) =
  pb.write(field, uint64(value))

proc write*(pb: var ProtoBuffer, field: int, value: Opt[bool]) =
  value.ifValue(boolValue):
    pb.write(field, uint64(boolValue))

proc writePacked*[T: ProtoScalar](
    pb: var ProtoBuffer, field: int, value: openArray[T]
) =
  checkFieldNumber(field)
  var length = 0
  let dlength =
    when (T is uint64) or (T is uint32) or (T is uint) or (T is zint64) or (T is zint32) or
        (T is zint) or (T is hint64) or (T is hint32) or (T is hint):
      var res = 0
      for item in value:
        res += vsizeof(item)
      res
    elif (T is float32) or (T is float64):
      len(value) * sizeof(T)

  let header = getProtoHeader(field, ProtoFieldKind.Length)
  let flength = vsizeof(header) + vsizeof(uint64(dlength)) + dlength
  pb.buffer.setLen(len(pb.buffer) + flength)
  let hres = PB.putUVarint(pb.toOpenArray(), length, header)
  doAssert(hres.isOk())
  pb.offset += length
  length = 0
  let lres = PB.putUVarint(pb.toOpenArray(), length, uint64(dlength))
  doAssert(lres.isOk())
  pb.offset += length
  for item in value:
    when (T is uint64) or (T is uint32) or (T is uint):
      length = 0
      let vres = PB.putUVarint(pb.toOpenArray(), length, item)
      doAssert(vres.isOk())
      pb.offset += length
    elif (T is zint64) or (T is zint32) or (T is zint) or (T is hint64) or (T is hint32) or
        (T is hint):
      length = 0
      let vres = PB.putSVarint(pb.toOpenArray(), length, item)
      doAssert(vres.isOk())
      pb.offset += length
    elif T is float32:
      doAssert(pb.isEnough(uint64(sizeof(T))))
      let u32 = cast[uint32](item)
      pb.buffer[pb.offset ..< pb.offset + sizeof(T)] = u32.toBytesLE()
      pb.offset += sizeof(T)
    elif T is float64:
      doAssert(pb.isEnough(uint64(sizeof(T))))
      let u64 = cast[uint64](item)
      pb.buffer[pb.offset ..< pb.offset + sizeof(T)] = u64.toBytesLE()
      pb.offset += sizeof(T)

proc write*[T: byte | char](pb: var ProtoBuffer, field: int, value: openArray[T]) =
  checkFieldNumber(field)
  var length = 0
  let flength =
    vsizeof(getProtoHeader(field, ProtoFieldKind.Length)) + vsizeof(uint64(len(value))) +
    len(value)
  pb.buffer.setLen(len(pb.buffer) + flength)
  let hres = PB.putUVarint(
    pb.toOpenArray(), length, getProtoHeader(field, ProtoFieldKind.Length)
  )
  doAssert(hres.isOk())
  pb.offset += length
  let lres = PB.putUVarint(pb.toOpenArray(), length, uint64(len(value)))
  doAssert(lres.isOk())
  pb.offset += length
  if len(value) > 0:
    doAssert(pb.isEnough(value.lenu64))
    copyMem(addr pb.buffer[pb.offset], addr value[0], len(value))
    pb.offset += len(value)

proc write*(pb: var ProtoBuffer, field: int, value: ProtoBuffer) =
  ## Encode Protobuf's sub-message ``value`` and store it to protobuf's buffer
  ## ``pb`` with field number ``field``.
  write(pb, field, value.buffer)

func finish*(pb: var ProtoBuffer) =
  ## Prepare protobuf's buffer ``pb`` for writing to stream.
  pb.offset = 0

proc getHeader(data: var ProtoBuffer, header: var ProtoHeader): ProtoResult[void] =
  var length = 0
  var hdr = 0'u64
  if PB.getUVarint(data.toOpenArray(), length, hdr).isOk():
    let index = uint64(hdr shr 3)
    let wire = hdr and 0x07
    if wire in SupportedWireTypes:
      data.offset += length
      header = ProtoHeader(index: index, wire: cast[ProtoFieldKind](wire))
      ok()
    else:
      err(ProtoError.BadWireType)
  else:
    err(ProtoError.VarintDecode)

proc skipValue(data: var ProtoBuffer, header: ProtoHeader): ProtoResult[void] =
  case header.wire
  of ProtoFieldKind.Varint:
    var length = 0
    var value = 0'u64
    if PB.getUVarint(data.toOpenArray(), length, value).isOk():
      data.offset += length
      ok()
    else:
      err(ProtoError.VarintDecode)
  of ProtoFieldKind.Fixed32:
    if data.isEnough(uint64(sizeof(uint32))):
      data.offset += sizeof(uint32)
      ok()
    else:
      err(ProtoError.VarintDecode)
  of ProtoFieldKind.Fixed64:
    if data.isEnough(uint64(sizeof(uint64))):
      data.offset += sizeof(uint64)
      ok()
    else:
      err(ProtoError.VarintDecode)
  of ProtoFieldKind.Length:
    var length = 0
    var bsize = 0'u64
    if PB.getUVarint(data.toOpenArray(), length, bsize).isOk():
      data.offset += length
      if data.isEnough(bsize):
        data.offset += int(bsize)
        ok()
      else:
        err(ProtoError.MessageIncomplete)
    else:
      err(ProtoError.VarintDecode)
  of ProtoFieldKind.StartGroup, ProtoFieldKind.EndGroup:
    err(ProtoError.BadWireType)

proc getValue[T: ProtoScalar](
    data: var ProtoBuffer, header: ProtoHeader, outval: var T
): ProtoResult[void] =
  when (T is uint64) or (T is uint32) or (T is uint):
    doAssert(header.wire == ProtoFieldKind.Varint)
    var length = 0
    var value = T(0)
    if PB.getUVarint(data.toOpenArray(), length, value).isOk():
      data.offset += length
      outval = value
      ok()
    else:
      err(ProtoError.VarintDecode)
  elif (T is zint64) or (T is zint32) or (T is zint) or (T is hint64) or (T is hint32) or
      (T is hint):
    doAssert(header.wire == ProtoFieldKind.Varint)
    var length = 0
    var value = T(0)
    if getSVarint(data.toOpenArray(), length, value).isOk():
      data.offset += length
      outval = value
      ok()
    else:
      err(ProtoError.VarintDecode)
  elif T is float32:
    doAssert(header.wire == ProtoFieldKind.Fixed32)
    if data.isEnough(uint64(sizeof(float32))):
      outval = cast[float32](fromBytesLE(uint32, data.toOpenArray()))
      data.offset += sizeof(float32)
      ok()
    else:
      err(ProtoError.MessageIncomplete)
  elif T is float64:
    doAssert(header.wire == ProtoFieldKind.Fixed64)
    if data.isEnough(uint64(sizeof(float64))):
      outval = cast[float64](fromBytesLE(uint64, data.toOpenArray()))
      data.offset += sizeof(float64)
      ok()
    else:
      err(ProtoError.MessageIncomplete)

proc getValue[T: byte | char](
    data: var ProtoBuffer,
    header: ProtoHeader,
    outBytes: var openArray[T],
    outLength: var int,
): ProtoResult[void] =
  doAssert(header.wire == ProtoFieldKind.Length)
  var length = 0
  var bsize = 0'u64

  outLength = 0
  if PB.getUVarint(data.toOpenArray(), length, bsize).isOk():
    data.offset += length
    if data.isEnough(bsize):
      outLength = int(bsize)
      if len(outBytes) >= int(bsize):
        if bsize > 0'u64:
          copyMem(addr outBytes[0], addr data.buffer[data.offset], int(bsize))
        data.offset += int(bsize)
        ok()
      else:
        # Buffer overflow should not be critical failure
        data.offset += int(bsize)
        err(ProtoError.BufferOverflow)
    else:
      err(ProtoError.MessageIncomplete)
  else:
    err(ProtoError.VarintDecode)

proc getValue[T: seq[byte] | string](
    data: var ProtoBuffer, header: ProtoHeader, outBytes: var T
): ProtoResult[void] =
  doAssert(header.wire == ProtoFieldKind.Length)
  var length = 0
  var bsize = 0'u64
  outBytes.setLen(0)

  if PB.getUVarint(data.toOpenArray(), length, bsize).isOk():
    data.offset += length
    if data.isEnough(bsize):
      outBytes.setLen(bsize)
      if bsize > 0'u64:
        copyMem(addr outBytes[0], addr data.buffer[data.offset], int(bsize))
      data.offset += int(bsize)
      ok()
    else:
      err(ProtoError.MessageIncomplete)
  else:
    err(ProtoError.VarintDecode)

proc getField*[T: ProtoScalar](
    data: ProtoBuffer, field: int, output: var T
): ProtoResult[bool] =
  checkFieldNumber(field)
  var current: T
  var res = false
  var pb = data

  while not (pb.isEmpty()):
    var header: ProtoHeader
    ?pb.getHeader(header)
    let wireCheck =
      when (T is uint64) or (T is uint32) or (T is uint) or (T is zint64) or
          (T is zint32) or (T is zint) or (T is hint64) or (T is hint32) or (T is hint):
        header.wire == ProtoFieldKind.Varint
      elif T is float32:
        header.wire == ProtoFieldKind.Fixed32
      elif T is float64:
        header.wire == ProtoFieldKind.Fixed64
    if header.index == uint64(field):
      if wireCheck:
        var value: T
        let vres = pb.getValue(header, value)
        if vres.isOk():
          res = true
          current = value
        else:
          return err(vres.error)
      else:
        # We are ignoring wire types different from what we expect, because it
        # is how `protoc` is working.
        ?pb.skipValue(header)
    else:
      ?pb.skipValue(header)

  if res:
    output = current
    ok(true)
  else:
    ok(false)

proc getField*[T: byte | char](
    data: ProtoBuffer, field: int, output: var openArray[T], outlen: var int
): ProtoResult[bool] =
  checkFieldNumber(field)
  var pb = data
  var res = false

  outlen = 0

  while not (pb.isEmpty()):
    var header: ProtoHeader
    let hres = pb.getHeader(header)
    if hres.isErr():
      if len(output) > 0:
        zeroMem(addr output[0], len(output))
      outlen = 0
      return err(hres.error)
    if header.index == uint64(field):
      if header.wire == ProtoFieldKind.Length:
        let vres = pb.getValue(header, output, outlen)
        if vres.isOk():
          res = true
        else:
          # Buffer overflow error is not critical error, we still can get
          # field values with proper size.
          if vres.error != ProtoError.BufferOverflow:
            if len(output) > 0:
              zeroMem(addr output[0], len(output))
            outlen = 0
            return err(vres.error)
      else:
        # We are ignoring wire types different from ProtoFieldKind.Length,
        # because it is how `protoc` is working.
        let sres = pb.skipValue(header)
        if sres.isErr():
          if len(output) > 0:
            zeroMem(addr output[0], len(output))
          outlen = 0
          return err(sres.error)
    else:
      let sres = pb.skipValue(header)
      if sres.isErr():
        if len(output) > 0:
          zeroMem(addr output[0], len(output))
        outlen = 0
        return err(sres.error)

  if res:
    ok(true)
  else:
    ok(false)

proc getField*[T: seq[byte] | string](
    data: ProtoBuffer, field: int, output: var T
): ProtoResult[bool] =
  checkFieldNumber(field)
  var res = false
  var pb = data

  while not (pb.isEmpty()):
    var header: ProtoHeader
    let hres = pb.getHeader(header)
    if hres.isErr():
      output.setLen(0)
      return err(hres.error)
    if header.index == uint64(field):
      if header.wire == ProtoFieldKind.Length:
        let vres = pb.getValue(header, output)
        if vres.isOk():
          res = true
        else:
          output.setLen(0)
          return err(vres.error)
      else:
        # We are ignoring wire types different from ProtoFieldKind.Length,
        # because it is how `protoc` is working.
        let sres = pb.skipValue(header)
        if sres.isErr():
          output.setLen(0)
          return err(sres.error)
    else:
      let sres = pb.skipValue(header)
      if sres.isErr():
        output.setLen(0)
        return err(sres.error)
  if res:
    ok(true)
  else:
    ok(false)

proc getField*(
    pb: ProtoBuffer, field: int, output: var ProtoBuffer
): ProtoResult[bool] =
  var buffer: seq[byte]
  if ?pb.getField(field, buffer):
    output = initProtoBuffer(buffer)
    ok(true)
  else:
    ok(false)

proc getField*(pb: ProtoBuffer, field: int, output: var bool): ProtoResult[bool] =
  var boolValue: uint64
  if ?pb.getField(field, boolValue):
    output = bool(boolValue)
    ok(true)
  else:
    output = false
    ok(false)

proc getField*(pb: ProtoBuffer, field: int, output: var Opt[bool]): ProtoResult[bool] =
  var boolValue: uint64
  if ?pb.getField(field, boolValue):
    output = Opt.some(bool(boolValue))
    ok(true)
  else:
    output = Opt.none(bool)
    ok(false)

proc getRequiredField*[T](
    pb: ProtoBuffer, field: int, output: var T
): ProtoResult[void] =
  if ?pb.getField(field, output):
    ok()
  else:
    err(RequiredFieldMissing)

proc getRepeatedField*[T: seq[byte] | string](
    data: ProtoBuffer, field: int, output: var seq[T]
): ProtoResult[bool] =
  checkFieldNumber(field)
  var pb = data
  output.setLen(0)

  while not (pb.isEmpty()):
    var header: ProtoHeader
    let hres = pb.getHeader(header)
    if hres.isErr():
      output.setLen(0)
      return err(hres.error)
    if header.index == uint64(field):
      if header.wire == ProtoFieldKind.Length:
        var item: T
        let vres = pb.getValue(header, item)
        if vres.isOk():
          output.add(item)
        else:
          output.setLen(0)
          return err(vres.error)
      else:
        let sres = pb.skipValue(header)
        if sres.isErr():
          output.setLen(0)
          return err(sres.error)
    else:
      let sres = pb.skipValue(header)
      if sres.isErr():
        output.setLen(0)
        return err(sres.error)

  if len(output) > 0:
    ok(true)
  else:
    ok(false)

proc getRepeatedField*[T: ProtoScalar](
    data: ProtoBuffer, field: int, output: var seq[T]
): ProtoResult[bool] =
  checkFieldNumber(field)
  var pb = data
  output.setLen(0)

  while not (pb.isEmpty()):
    var header: ProtoHeader
    let hres = pb.getHeader(header)
    if hres.isErr():
      output.setLen(0)
      return err(hres.error)

    if header.index == uint64(field):
      if header.wire in
          {ProtoFieldKind.Varint, ProtoFieldKind.Fixed32, ProtoFieldKind.Fixed64}:
        var item: T
        let vres = getValue(pb, header, item)
        if vres.isOk():
          output.add(item)
        else:
          output.setLen(0)
          return err(vres.error)
      else:
        let sres = skipValue(pb, header)
        if sres.isErr():
          output.setLen(0)
          return err(sres.error)
    else:
      let sres = skipValue(pb, header)
      if sres.isErr():
        output.setLen(0)
        return err(sres.error)

  if len(output) > 0:
    ok(true)
  else:
    ok(false)

proc getRequiredRepeatedField*[T](
    pb: ProtoBuffer, field: int, output: var seq[T]
): ProtoResult[void] =
  if ?pb.getRepeatedField(field, output):
    ok()
  else:
    err(RequiredFieldMissing)

proc getPackedRepeatedField*[T: ProtoScalar](
    data: ProtoBuffer, field: int, output: var seq[T]
): ProtoResult[bool] =
  checkFieldNumber(field)
  var pb = data
  output.setLen(0)

  while not (pb.isEmpty()):
    var header: ProtoHeader
    let hres = pb.getHeader(header)
    if hres.isErr():
      output.setLen(0)
      return err(hres.error)

    if header.index == uint64(field):
      if header.wire == ProtoFieldKind.Length:
        var arritem: seq[byte]
        let ares = getValue(pb, header, arritem)
        if ares.isOk():
          var pbarr = initProtoBuffer(arritem)
          let itemHeader =
            when (T is uint64) or (T is uint32) or (T is uint) or (T is zint64) or
                (T is zint32) or (T is zint) or (T is hint64) or (T is hint32) or
                (T is hint):
              ProtoHeader(wire: ProtoFieldKind.Varint)
            elif T is float32:
              ProtoHeader(wire: ProtoFieldKind.Fixed32)
            elif T is float64:
              ProtoHeader(wire: ProtoFieldKind.Fixed64)
          while not (pbarr.isEmpty()):
            var item: T
            let vres = getValue(pbarr, itemHeader, item)
            if vres.isOk():
              output.add(item)
            else:
              output.setLen(0)
              return err(vres.error)
        else:
          output.setLen(0)
          return err(ares.error)
      else:
        let sres = skipValue(pb, header)
        if sres.isErr():
          output.setLen(0)
          return err(sres.error)
    else:
      let sres = skipValue(pb, header)
      if sres.isErr():
        output.setLen(0)
        return err(sres.error)

  if len(output) > 0:
    ok(true)
  else:
    ok(false)
