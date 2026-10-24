# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import algorithm

type IdSeq*[T] = object
  ## Elements in insertion order, each with a stable id that only grows.
  s*: seq[T]
  ids*: seq[int]
  nextId*: int

func add*[T](o: var IdSeq[T], v: T) =
  o.s.add(v)
  o.ids.add(o.nextId)
  o.nextId.inc()

func contains*[T](o: IdSeq[T], id: int): bool =
  o.ids.binarySearch(id) >= 0

func `[]`*[T](o: var IdSeq[T], id: int): var T =
  o.s[o.ids.binarySearch(id)]

func low*[T](o: IdSeq[T]): int =
  if o.ids.len == 0:
    o.nextId
  else:
    o.ids[0]

func high*[T](o: IdSeq[T]): int =
  o.nextId - 1

template keepItIf*(o: var IdSeq, pred: untyped) =
  var kept = 0
  for i in 0 ..< o.s.len:
    let it {.inject.} = o.s[i]
    if not pred:
      continue
    if kept != i:
      o.s[kept] = move(o.s[i])
      o.ids[kept] = o.ids[i]
    kept.inc()

  o.s.setLen(kept)
  o.ids.setLen(kept)

iterator idsFrom*[T](o: IdSeq[T], first: int): int =
  for i in o.ids.lowerBound(first) ..< o.ids.len:
    yield o.ids[i]
