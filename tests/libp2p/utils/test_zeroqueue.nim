# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[monotimes, times]
import ../../../libp2p/utils/zeroqueue
import ../../tools/[unittest]

proc toSeq(p: pointer, length: int): seq[byte] =
  var res = newSeq[byte](length)
  copyMem(res[0].addr, p, length)
  return res

suite "ZeroQueue":
  test "push-pop":
    var q: ZeroQueue
    check q.len() == 0
    check q.isEmpty()
    check q.popChunkSeq(1).len == 0 # pop empty seq when queue is empty

    q.push(@[1'u8, 2, 3])
    q.push(@[4'u8, 5])
    check q.len() == 5
    check not q.isEmpty()

    check q.popChunkSeq(0) == newSeq[byte]()
    expect AssertionDefect:
      discard q.popChunkSeq(-1)
    check q.len() == 5
    check q.popChunkSeq(3) == @[1'u8, 2, 3] # pop eactly the size of the chunk
    check q.popChunkSeq(1) == @[4'u8] # pop less then size of the chunk
    check q.popChunkSeq(5) == @[5'u8] # pop more then size of the chunk
    check q.isEmpty()

    # should not push empty seq
    q.push(@[])
    q.push(@[])
    check q.isEmpty()

  test "clear":
    var q: ZeroQueue
    q.push(@[1'u8, 2, 3])
    check not q.isEmpty()
    q.clear()
    check q.isEmpty()
    check q.len() == 0

  test "consumeTo":
    var q: ZeroQueue
    let nbytes = 20
    var pbytes = alloc(nbytes)
    defer:
      dealloc(pbytes)

    # consumeTo: on empty queue
    check q.consumeTo(pbytes, nbytes) == 0

    # consumeTo: zero-length reads do not need a destination pointer
    q.push(@[9'u8])
    check q.consumeTo(nil, 0) == 0
    check q.len() == 1
    check q.consumeTo(pbytes, 1) == 1
    check toSeq(pbytes, 1) == @[9'u8]
    check q.isEmpty()

    # consumeTo: emptying whole queue (multiple pushes)
    q.push(@[1'u8, 2, 3])
    q.push(@[4'u8, 5])
    q.push(@[6'u8, 7])
    check q.consumeTo(pbytes, nbytes) == 7
    check toSeq(pbytes, 7) == @[1'u8, 2, 3, 4, 5, 6, 7]
    check q.isEmpty()

    # consumeTo: consuming one chunk of data in two steps
    q.push(@[1'u8, 2, 3])
    # first consume
    check q.consumeTo(pbytes, 1) == 1
    check toSeq(pbytes, 1) == @[1'u8]
    check q.len() == 2
    # second consime
    check q.consumeTo(pbytes, nbytes) == 2
    check toSeq(pbytes, 2) == @[2'u8, 3]
    check q.isEmpty()

    # consumeTo: consuming multiple chunks of data in two steps
    q.clear()
    q.push(@[4'u8, 5])
    q.push(@[1'u8, 2, 3])
    # first consume
    check q.consumeTo(pbytes, 3) == 3
    check toSeq(pbytes, 3) == @[4'u8, 5, 1]
    check q.len() == 2
    # second consume
    check q.consumeTo(pbytes, nbytes) == 2
    check toSeq(pbytes, 2) == @[2'u8, 3]
    check q.isEmpty()

    # consumeTo: parially consume big push multiple times
    q.clear()
    q.push(newSeq[byte](20))
    for i in 1 .. 10:
      check q.consumeTo(pbytes, 2) == 2
    check q.isEmpty()
    check q.consumeTo(pbytes, 2) == 0

    # consumeTo: parially consuming while pushing
    q.push(@[1'u8, 2, 3])
    check q.consumeTo(pbytes, 2) == 2
    check toSeq(pbytes, 2) == @[1'u8, 2]
    q.push(@[1'u8, 2, 3])
    check q.consumeTo(pbytes, 2) == 2
    check toSeq(pbytes, 2) == @[3'u8, 1]
    q.push(@[1'u8, 2, 3])
    check q.consumeTo(pbytes, 2) == 2
    check toSeq(pbytes, 2) == @[2'u8, 3]
    check q.consumeTo(pbytes, 2) == 2
    check toSeq(pbytes, 2) == @[1'u8, 2]
    check q.consumeTo(pbytes, 2) == 1
    check toSeq(pbytes, 1) == @[3'u8]
    check q.isEmpty()

  test "consumeTo after partial popChunkSeq crosses chunk boundary":
    const
      bufLen = 8
      readLen = 3
    var q: ZeroQueue
    var buf: array[bufLen, byte]
    q.push(@[1'u8, 2, 3])
    q.push(@[4'u8, 5, 6])

    check q.popChunkSeq(1) == @[1'u8]
    check q.consumeTo(buf[0].addr, readLen) == readLen
    check buf[0 ..< readLen] == @[2'u8, 3, 4]
    check q.len() == 2
    check q.popChunkSeq(bufLen) == @[5'u8, 6]
    check q.isEmpty()

  test "popChunkSeq after partial consumeTo returns the unread remainder":
    const bufLen = 2
    var q: ZeroQueue
    var buf: array[bufLen, byte]
    q.push(@[1'u8, 2, 3, 4])
    q.push(@[5'u8])

    check q.consumeTo(buf[0].addr, bufLen) == bufLen
    check buf == [1'u8, 2]
    check q.popChunkSeq(1) == @[3'u8]
    check q.len() == 2
    check q.popChunkSeq(bufLen) == @[4'u8]
    check q.popChunkSeq(bufLen) == @[5'u8]
    check q.isEmpty()

  test "consumeTo with negative nbytes reads nothing":
    var q: ZeroQueue
    q.push(@[1'u8, 2])
    check q.consumeTo(nil, -1) == 0
    check q.len() == 2

  test "byte-at-a-time reads of one large chunk stay linear":
    const
      chunkSize = 1024 * 1024
      patternPeriod = 251
      # a copy of the remaining chunk per read takes minutes at this size
      timeBudget = initDuration(seconds = 5)

    var data = newSeqUninit[byte](chunkSize)
    for i in 0 ..< chunkSize:
      data[i] = byte(i mod patternPeriod)

    var q: ZeroQueue
    q.push(data)

    var got = newSeqUninit[byte](chunkSize)
    var consumed = 0
    let startTime = getMonoTime()
    for i in 0 ..< chunkSize:
      if i mod 2 == 0:
        consumed += q.consumeTo(got[i].addr, 1)
      else:
        let s = q.popChunkSeq(1)
        got[i] = s[0]
        consumed += s.len
    let elapsed = getMonoTime() - startTime

    check consumed == chunkSize
    check got == data
    check q.isEmpty()
    check q.len() == 0
    check elapsed < timeBudget
