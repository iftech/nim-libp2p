# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import sequtils
import ../../../libp2p/utils/idseq
import ../../tools/[unittest]

func filled(values: openArray[int]): IdSeq[int] =
  var o = IdSeq[int]()
  for v in values:
    o.add(v)
  o

suite "IdSeq":
  test "add gives each element the next id":
    var o = filled([10, 20, 30])

    check:
      o.ids == @[0, 1, 2]
      o.low() == 0
      o.high() == 2
      o[1] == 20

  test "an empty seq has low one past high":
    let o = IdSeq[int]()

    check:
      o.low() == 0
      o.high() == -1

  test "keepItIf drops elements anywhere and keeps the ids of the rest":
    var o = filled([1, 20, 3, 40, 5])

    o.keepItIf(it >= 10)

    check:
      o.s == @[20, 40]
      o.ids == @[1, 3]
      o.low() == 1
      o.high() == 4
      o[3] == 40
      0 notin o
      2 notin o
      3 in o

  test "keepItIf on every element leaves low at the next id":
    var o = filled([1, 2])

    o.keepItIf(false)
    o.add(7)

    check:
      o.ids == @[2]
      o.low() == 2
      o[2] == 7

  test "idsFrom starts at the first id not below the argument":
    var o = filled([1, 20, 3, 40])
    o.keepItIf(it >= 10)

    check:
      toSeq(o.idsFrom(0)) == @[1, 3]
      toSeq(o.idsFrom(2)) == @[3]
      toSeq(o.idsFrom(4)).len == 0
