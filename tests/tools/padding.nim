# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import protobuf_serialization

type Padding {.proto3.} = object
  padding {.fieldNumber: 15.}: string

proc pad*(encoded: seq[byte], paddingBytes: int): seq[byte] =
  ## Grows the encoded message with a field the decoder skips, so only its
  ## incoming length reveals the padding.
  let padding = Protobuf.encode(Padding(padding: newString(paddingBytes)))
  var res = newSeqOfCap[byte](encoded.len + padding.len)
  res.add(encoded)
  res.add(padding)
  return res
