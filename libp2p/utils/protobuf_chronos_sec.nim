# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, protobuf_serialization, protobuf_serialization/extension

Protobuf.extensionDefaults(Duration, pint64, defaultSeq = true)

const
  MaxSeconds = high(int64) div Second.nanoseconds
  MinSeconds = low(int64) div Second.nanoseconds

proc toDurationSeconds(v: int64): Duration {.raises: [SerializationError].} =
  ## Reject wire values whose nanosecond representation overflows int64.
  if v < MinSeconds or v > MaxSeconds:
    raise (ref ProtobufValueError)(msg: "Duration out of range: " & $v)
  v.seconds

func computeFieldSize*(
    field: int, value: Duration, ProtoType: type ProtobufExt, skipDefault: static bool
): int =
  computeFieldSize(field, value.seconds, pint64, skipDefault)

proc writeField*(
    stream: OutputStream,
    field: int,
    value: Duration,
    ProtoType: type ProtobufExt,
    skipDefault: static bool = false,
) {.raises: [IOError].} =
  writeField(stream, field, value.seconds, pint64, skipDefault)

proc readFieldInto*(
    stream: InputStream,
    value: var Duration,
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  if header.kind() == wireKind(pint64):
    let intValue = stream.readValue(pint64).int64
    value = intValue.toDurationSeconds
    return true
  else:
    false

func computeFieldSizePacked*(
    field: int, value: seq[Duration], ProtoType: type ProtobufExt
): int =
  computeFieldSizePackedIt(field, value, pint64, it.seconds)

proc writeFieldPacked*(
    stream: OutputStream, field: int, value: seq[Duration], ProtoType: type ProtobufExt
) {.raises: [IOError].} =
  writeFieldPackedIt(stream, field, value, pint64, it.seconds)

proc readFieldPackedInto*(
    stream: InputStream,
    value: var seq[Duration],
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  readFieldPackedIntoIt(stream, value, header, pint64):
    value.add it.toDurationSeconds
