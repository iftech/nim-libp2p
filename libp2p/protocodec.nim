# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/hashes
import chronicles, protobuf_serialization
import ./utils/shortlog

type ProtoCodec* = distinct string

func `==`*(a, b: ProtoCodec): bool {.borrow.}
func hash*(c: ProtoCodec): Hash {.borrow.}
func `$`*(c: ProtoCodec): string {.borrow.}
func len*(c: ProtoCodec): int {.borrow.}
func `&`*(a, b: ProtoCodec): ProtoCodec {.borrow.}
func `&`*(a: ProtoCodec, b: string): ProtoCodec {.borrow.}
func `&`*(a: string, b: ProtoCodec): ProtoCodec {.borrow.}

func isSet*(c: ProtoCodec): bool =
  c.len > 0

func shortLog*(c: ProtoCodec): string =
  $c

func shortLog*(codecs: openArray[ProtoCodec]): string =
  shortLog[ProtoCodec](codecs)

chronicles.formatIt(ProtoCodec):
  shortLog(it)

chronicles.formatIt(seq[ProtoCodec]):
  shortLog(it)

const UnsetProtoCodec* = ProtoCodec("")

Protobuf.extensionDefaults(ProtoCodec, pstring, defaultSeq = true)

func computeFieldSize*(
    field: int, value: ProtoCodec, ProtoType: type ProtobufExt, skipDefault: static bool
): int =
  computeFieldSize(field, string(value), pstring, skipDefault)

proc writeField*(
    stream: OutputStream,
    field: int,
    value: ProtoCodec,
    ProtoType: type ProtobufExt,
    skipDefault: static bool = false,
) {.raises: [IOError].} =
  writeField(stream, field, string(value), pstring, skipDefault)

proc readFieldInto*(
    stream: InputStream,
    value: var ProtoCodec,
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  var data = default(string)
  if readFieldInto(stream, data, header, pstring):
    value = ProtoCodec(data)
    true
  else:
    false
