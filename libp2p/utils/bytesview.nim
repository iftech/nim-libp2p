# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

type BytesView* = object
  data: seq[byte]
  rpos: int

proc init*(t: typedesc[BytesView], data: sink seq[byte]): BytesView =
  BytesView(data: data, rpos: 0)

func len*(v: BytesView): int =
  v.data.len - v.rpos

func consume*(v: var BytesView, n: int) =
  doAssert v.data.len >= v.rpos + n
  v.rpos += n

template toOpenArray*(v: BytesView, b, e: int): openArray[byte] =
  v.data.toOpenArray(v.rpos + b, v.rpos + e)

template data*(v: BytesView): openArray[byte] =
  v.data.toOpenArray(v.rpos, v.data.len - 1)
