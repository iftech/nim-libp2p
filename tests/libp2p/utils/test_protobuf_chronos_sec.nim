# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import protobuf_serialization
import ../../../libp2p/utils/protobuf_chronos_sec
import ../../tools/[unittest]

type
  DurationMsg {.proto3.} = object
    dur {.fieldNumber: 1, ext.}: Duration

  DurationSeqMsg {.proto3.} = object
    durs {.fieldNumber: 1, ext.}: seq[Duration]

  IntMsg {.proto3.} = object
    v {.fieldNumber: 1, pint.}: int64

  IntSeqMsg {.proto3.} = object
    vs {.fieldNumber: 1, pint.}: seq[int64]

const
  maxSecs = high(int64) div 1_000_000_000
  minSecs = low(int64) div 1_000_000_000

suite "protobuf_chronos_sec":
  test "Duration zero round-trips":
    let enc = Protobuf.encode(DurationMsg(dur: 0.seconds))
    let dec = Protobuf.decode(enc, DurationMsg)
    check dec.dur == 0.seconds

  test "Duration large value round-trips":
    let orig = 24.hours + 30.minutes + 15.seconds
    let enc = Protobuf.encode(DurationMsg(dur: orig))
    let dec = Protobuf.decode(enc, DurationMsg)
    check dec.dur == orig

  test "seq[Duration] empty round-trips":
    let enc = Protobuf.encode(DurationSeqMsg(durs: @[]))
    let dec = Protobuf.decode(enc, DurationSeqMsg)
    check dec.durs.len == 0

  test "seq[Duration] multiple elements round-trips":
    let orig = @[1.seconds, 2.minutes, 3.hours]
    let enc = Protobuf.encode(DurationSeqMsg(durs: orig))
    let dec = Protobuf.decode(enc, DurationSeqMsg)
    check dec.durs == orig

  test "Duration seconds at int64 nanosecond bounds decode":
    check Protobuf.decode(Protobuf.encode(IntMsg(v: maxSecs)), DurationMsg).dur ==
      maxSecs.seconds
    check Protobuf.decode(Protobuf.encode(IntMsg(v: minSecs)), DurationMsg).dur ==
      minSecs.seconds
    check Protobuf.decode(
      Protobuf.encode(IntSeqMsg(vs: @[minSecs, maxSecs])), DurationSeqMsg
    ).durs == @[minSecs.seconds, maxSecs.seconds]

  test "Duration seconds overflowing int64 nanoseconds are rejected":
    for v in [maxSecs + 1, minSecs - 1, 1'i64 shl 62, high(int64), low(int64)]:
      expect SerializationError:
        discard Protobuf.decode(Protobuf.encode(IntMsg(v: v)), DurationMsg)

  test "seq[Duration] seconds overflowing int64 nanoseconds are rejected":
    for v in [maxSecs + 1, minSecs - 1, 1'i64 shl 62, high(int64), low(int64)]:
      expect SerializationError:
        discard Protobuf.decode(Protobuf.encode(IntSeqMsg(vs: @[1, v])), DurationSeqMsg)
