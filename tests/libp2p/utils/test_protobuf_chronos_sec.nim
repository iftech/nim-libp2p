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

  test "Duration 1 second round-trips":
    let enc = Protobuf.encode(DurationMsg(dur: 1.seconds))
    let dec = Protobuf.decode(enc, DurationMsg)
    check dec.dur == 1.seconds

  test "Duration large value round-trips":
    let orig = 24.hours + 30.minutes + 15.seconds
    let enc = Protobuf.encode(DurationMsg(dur: orig))
    let dec = Protobuf.decode(enc, DurationMsg)
    check dec.dur == orig

  test "Duration underlying int64 preserved":
    let ns: int64 = 1_234_567_890
    let enc = Protobuf.encode(DurationMsg(dur: ns.seconds))
    let dec = Protobuf.decode(enc, DurationMsg)
    check dec.dur.seconds == ns

  test "multiple Duration re-encodes to same bytes":
    let msg = DurationMsg(dur: 42.seconds)
    check Protobuf.encode(msg) == Protobuf.encode(msg)

  test "distinct Duration values encode to distinct bytes":
    let enc1 = Protobuf.encode(DurationMsg(dur: 1.seconds))
    let enc2 = Protobuf.encode(DurationMsg(dur: 2.seconds))
    check enc1 != enc2

  test "seq[Duration] empty round-trips":
    let enc = Protobuf.encode(DurationSeqMsg(durs: @[]))
    let dec = Protobuf.decode(enc, DurationSeqMsg)
    check dec.durs.len == 0

  test "seq[Duration] single element round-trips":
    let enc = Protobuf.encode(DurationSeqMsg(durs: @[5.seconds]))
    let dec = Protobuf.decode(enc, DurationSeqMsg)
    check dec.durs == @[5.seconds]

  test "seq[Duration] multiple elements round-trips":
    let orig = @[1.seconds, 2.minutes, 3.hours]
    let enc = Protobuf.encode(DurationSeqMsg(durs: orig))
    let dec = Protobuf.decode(enc, DurationSeqMsg)
    check dec.durs == orig

  test "seq[Duration] large values round-trip":
    let ns1: int64 = 1_234_567_890
    let ns2: int64 = 9_123_456_789
    let orig = @[ns1.seconds, ns2.seconds]
    let enc = Protobuf.encode(DurationSeqMsg(durs: orig))
    let dec = Protobuf.decode(enc, DurationSeqMsg)
    check dec.durs[0].seconds == ns1
    check dec.durs[1].seconds == ns2

  test "seq[Duration] order preserved":
    let orig = @[3.seconds, 1.seconds, 2.seconds]
    let enc = Protobuf.encode(DurationSeqMsg(durs: orig))
    let dec = Protobuf.decode(enc, DurationSeqMsg)
    check dec.durs[0] == 3.seconds
    check dec.durs[1] == 1.seconds
    check dec.durs[2] == 2.seconds

  test "distinct seq[Duration] encode to distinct bytes":
    let enc1 = Protobuf.encode(DurationSeqMsg(durs: @[1.seconds, 2.seconds]))
    let enc2 = Protobuf.encode(DurationSeqMsg(durs: @[2.seconds, 1.seconds]))
    check enc1 != enc2

  test "seq[Duration] re-encodes to same bytes":
    let msg = DurationSeqMsg(durs: @[1.seconds, 2.seconds])
    check Protobuf.encode(msg) == Protobuf.encode(msg)

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
