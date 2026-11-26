# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/deques

type Chunk = ref object
  data: seq[byte]
  start: int

template newChunk(b: sink seq[byte]): Chunk =
  Chunk(data: b, start: 0)

template len(c: Chunk): int =
  c.data.len - c.start

type ZeroQueue* = object
  # ZeroQueue is queue structure optimized for efficient pushing and popping of 
  # byte sequences `seq[byte]` (called chunks). This type is useful for streaming or buffering 
  # scenarios where chunks of binary data are accumulated and consumed incrementally.
  chunks: Deque[Chunk]
  queuedBytes: int64

proc clear*(q: var ZeroQueue) =
  q.chunks.clear()
  q.queuedBytes = 0

proc isEmpty*(q: ZeroQueue): bool =
  q.chunks.len() == 0

proc len*(q: ZeroQueue): int64 =
  q.queuedBytes

proc push*(q: var ZeroQueue, b: sink seq[byte]) =
  if b.len > 0:
    q.queuedBytes += b.len.int64
    q.chunks.addLast(newChunk(b))

func nextReadLen(q: ZeroQueue, count: int): int =
  min(q.chunks.peekFirst().len(), count)

proc consumeFirst(q: var ZeroQueue, dest: pointer, count: int) =
  let first = q.chunks.peekFirst()
  doAssert(count > 0 and count <= first.len(), "count must fit in the first chunk")
  copyMem(dest, first.data[first.start].addr, count)
  first.start += count
  q.queuedBytes -= count.int64
  if first.len() == 0:
    q.chunks.shrink(fromFirst = 1)

proc consumeTo*(q: var ZeroQueue, pbytes: pointer, nbytes: int): int =
  var consumed = 0
  while consumed < nbytes and not q.isEmpty():
    let count = q.nextReadLen(nbytes - consumed)
    q.consumeFirst(cast[pointer](cast[uint](pbytes) + consumed.uint), count)
    consumed += count

  return consumed

proc popChunkSeq*(q: var ZeroQueue, count: int): seq[byte] =
  doAssert(count >= 0, "count must be non-negative integer")
  if count == 0 or q.isEmpty:
    return @[]

  var dest = newSeqUninit[byte](q.nextReadLen(count))
  q.consumeFirst(dest[0].addr, dest.len)

  return dest
