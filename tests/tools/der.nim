# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import stew/endians2
import ../../libp2p/crypto/minasn1

proc derTlv(code: byte, content: openArray[byte]): seq[byte] =
  var length = newSeq[byte](9)
  length.setLen(asn1EncodeLength(length, uint64(len(content))))
  @[code] & length & @content

proc derField*(tag: Asn1Tag, value: openArray[byte]): seq[byte] =
  var b = Asn1Buffer.init()
  b.write(tag, value)
  b.finish()
  doAssert len(b.buffer) > 0, "unsupported tag for derField: " & $tag
  b.buffer

proc derUint*(value: uint64): seq[byte] =
  derField(Asn1Tag.Integer, value.toBytesBE())

proc derNull*(): seq[byte] =
  @Asn1Null

proc derBitString*(content: openArray[byte]): seq[byte] =
  derTlv(Asn1Tag.BitString.code(), @[0x00'u8] & @content)

proc concat(parts: openArray[seq[byte]]): seq[byte] =
  var content: seq[byte]
  for part in parts:
    content.add(part)
  content

proc derSequence*(parts: openArray[seq[byte]]): seq[byte] =
  derTlv(Asn1Tag.Sequence.code(), concat(parts))

proc derContext*(index: int, parts: openArray[seq[byte]]): seq[byte] =
  derTlv(Asn1Tag.Context.code() or byte(index), concat(parts))
