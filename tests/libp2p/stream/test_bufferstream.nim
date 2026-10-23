# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import ../../../libp2p/stream/[bufferstream, lpstream]
import ../../tools/[unittest, futures]

suite "BufferStream":
  teardown:
    checkTrackers()

  asyncTest "push and wait":
    let buff = BufferStream.new()
    check buff.len == 0

    let fut0 = buff.pushData("1234".toBytes())
    let fut1 = buff.pushData("5".toBytes())
    check buff.len == 4 # the second write should not be visible yet

    var data: array[1, byte]
    check:
      1 == await buff.readOnce(addr data[0], data.len)

    check ['1'] == string.fromBytes(data)
    await fut0
    await fut1
    check buff.len == 4
    await buff.close()

  asyncTest "readExactly":
    let buff = BufferStream.new()
    check buff.len == 0

    await buff.pushData("12345".toBytes())
    check buff.len == 5
    var data: array[2, byte]
    await buff.readExactly(addr data[0], data.len)
    check string.fromBytes(data) == ['1', '2']
    await buff.close()

  asyncTest "readExactly raises":
    let buff = BufferStream.new()
    check buff.len == 0

    await buff.pushData("123".toBytes())
    var data: array[5, byte]
    var readFut = buff.readExactly(addr data[0], data.len)
    await buff.close()

    expect LPStreamIncompleteError:
      await readFut

  asyncTest "readOnce":
    let buff = BufferStream.new()
    check buff.len == 0

    var data: array[3, byte]
    let readFut = buff.readOnce(addr data[0], data.len)
    await buff.pushData("123".toBytes())
    check buff.len == 3

    check (await readFut) == 3
    check string.fromBytes(data) == ['1', '2', '3']
    await buff.close()

  asyncTest "reads should happen in order":
    let buff = BufferStream.new()
    check buff.len == 0

    proc writer1() {.async.} =
      await buff.pushData("Msg 1".toBytes())
      await buff.pushData("Msg 2".toBytes())
      await buff.pushData("Msg 3".toBytes())

    let writerFut1 = writer1()
    var data: array[5, byte]
    await buff.readExactly(addr data[0], data.len)

    check string.fromBytes(data) == "Msg 1"

    await buff.readExactly(addr data[0], data.len)
    check string.fromBytes(data) == "Msg 2"

    await buff.readExactly(addr data[0], data.len)
    check string.fromBytes(data) == "Msg 3"

    await writerFut1

    proc writer2() {.async.} =
      await buff.pushData("Msg 4".toBytes())
      await buff.pushData("Msg 5".toBytes())
      await buff.pushData("Msg 6".toBytes())

    let writerFut2 = writer2()

    await buff.readExactly(addr data[0], data.len)
    check string.fromBytes(data) == "Msg 4"

    await buff.readExactly(addr data[0], data.len)
    check string.fromBytes(data) == "Msg 5"

    await buff.readExactly(addr data[0], data.len)
    check string.fromBytes(data) == "Msg 6"

    await buff.close()
    await writerFut2

  asyncTest "small reads":
    let buff = BufferStream.new()
    check buff.len == 0

    var str: string
    proc writer() {.async.} =
      for i in 0 ..< 10:
        await buff.pushData("123".toBytes())
        str &= "123"
      await buff.close() # all data should still be read after close

    var str2: string

    proc reader() {.async.} =
      var data: array[2, byte]
      expect LPStreamEOFError:
        while true:
          let x = await buff.readOnce(addr data[0], data.len)
          str2 &= string.fromBytes(data[0 ..< x])

    let readerFut = reader()
    let writerFut = writer()

    await allFuturesRaising(readerFut, writerFut)

    check str == str2
    await buff.close()

  asyncTest "read all data after eof":
    let buff = BufferStream.new()
    check buff.len == 0

    await buff.pushData("12345".toBytes())
    var data: array[2, byte]
    check:
      (await buff.readOnce(addr data[0], data.len)) == 2

    await buff.pushEof()

    check:
      not buff.atEof()
      (await buff.readOnce(addr data[0], data.len)) == 2
      not buff.atEof()
      (await buff.readOnce(addr data[0], data.len)) == 1
      buff.atEof()
      # exactly one 0-byte read
      (await buff.readOnce(addr data[0], data.len)) == 0

    expect LPStreamEOFError:
      discard (await buff.readOnce(addr data[0], data.len))

    await buff.close() # all data should still be read after close

  asyncTest "read more data after eof":
    let buff = BufferStream.new()
    check buff.len == 0

    await buff.pushData("12345".toBytes())
    var data: array[5, byte]
    check:
      (await buff.readOnce(addr data[0], 1)) == 1
      # 4 bytes in readBuf

    await buff.pushEof()

    check:
      not buff.atEof()
      (await buff.readOnce(addr data[0], 1)) == 1
        # 3 bytes in readBuf, eof marker processed
      not buff.atEof()
      (await buff.readOnce(addr data[0], data.len)) == 3 # 0 bytes in readBuf
      buff.atEof()
      # exactly one 0-byte read
      (await buff.readOnce(addr data[0], data.len)) == 0

    expect LPStreamEOFError:
      discard (await buff.readOnce(addr data[0], data.len))

    await buff.close() # all data should still be read after close

  asyncTest "shouldn't get stuck on close":
    var stream = BufferStream.new()
    var
      fut = stream.pushData(toBytes("hello"))
      fut2 = stream.pushData(toBytes("again"))
    await stream.close()

    # Both writes should be completed on close (technically, the should maybe
    # be cancelled, at least the second one...
    check await fut.withTimeout(100.milliseconds)
    check await fut2.withTimeout(100.milliseconds)

    await stream.close()

  asyncTest "no push after close":
    var stream = BufferStream.new()
    await stream.pushData("123".toBytes())
    var data: array[3, byte]
    await stream.readExactly(addr data[0], data.len)
    await stream.close()

    expect LPStreamEOFError:
      await stream.pushData("123".toBytes())

  asyncTest "no concurrent pushes":
    var stream = BufferStream.new()
    await stream.pushData("123".toBytes())
    let push = stream.pushData("123".toBytes())

    expect AssertionDefect:
      await stream.pushData("123".toBytes())

    await stream.closeWithEOF()
    await push

  asyncTest "close wakes a reader parked on an empty queue":
    let stream = BufferStream.new()

    var data: array[1, byte]
    let readFut = stream.readOnce(addr data[0], data.len)
    check stream.reading

    await stream.close()

    check await readFut.withTimeout(100.milliseconds)
    check (await readFut) == 0

    expect LPStreamEOFError:
      discard await stream.readOnce(addr data[0], data.len)

  asyncTest "close wakes both a parked reader and a parked pusher":
    let stream = BufferStream.new()
    await stream.pushData("123".toBytes())

    let pushFut = stream.pushData("456".toBytes())
    # Empty the queue under the parked pusher, so `pushing` outlives the item.
    discard stream.readQueue.popFirstNoWait()

    var data: array[1, byte]
    let readFut = stream.readOnce(addr data[0], data.len)
    check:
      stream.reading
      stream.pushing
      stream.readQueue.empty()

    await stream.close()

    check await readFut.withTimeout(100.milliseconds)
    check (await readFut) == 0
    check await pushFut.withTimeout(100.milliseconds)

  asyncTest "close does not remove data reserved for an active reader":
    let stream = BufferStream.new()
    await stream.pushData("123".toBytes())

    let pushFut = stream.pushData("456".toBytes())
    discard stream.readQueue.popFirstNoWait()

    var data: array[3, byte]
    let readFut = stream.readOnce(addr data[0], data.len)
    check:
      stream.reading
      stream.pushing
      stream.readQueue.empty()

    proc closeStream(udata: pointer) {.gcsafe, raises: [].} =
      discard cast[BufferStream](udata).close()

    # Run close after the parked pusher resumes, so the queue holds its item.
    callSoon(closeStream, cast[pointer](stream))

    let readCompleted = await readFut.withTimeout(100.milliseconds)
    if not readCompleted:
      await readFut.cancelAndWait()

    check readCompleted
    check await pushFut.withTimeout(100.milliseconds)

  asyncTest "close does not strand a push after the reader dequeues data":
    let stream = BufferStream.new()

    var data: array[1, byte]
    let readFut = stream.readOnce(addr data[0], data.len)
    await stream.pushData("A".toBytes())
    let pushFut = stream.pushData("B".toBytes())

    proc closeStream(udata: pointer) {.gcsafe, raises: [].} =
      discard cast[BufferStream](udata).close()

    # The queue getter runs before close, while the outer read resumes later.
    callSoon(closeStream, cast[pointer](stream))

    check await readFut.withTimeout(100.milliseconds)
    check (await readFut) == 1
    check ['A'] == string.fromBytes(data)
    check await pushFut.withTimeout(100.milliseconds)
    await pushFut

  asyncTest "close does not strand a push after reader cancellation":
    let stream = BufferStream.new()
    await stream.pushData("A".toBytes())
    let pushFut = stream.pushData("B".toBytes())

    var first: array[1, byte]
    let firstRead = stream.readOnce(addr first[0], first.len)
    check firstRead.finished()
    check (await firstRead) == 1

    var second: array[1, byte]
    let secondRead = stream.readOnce(addr second[0], second.len)
    check:
      stream.reading
      stream.pushing
      stream.readQueue.empty()

    secondRead.cancelSoon()
    await stream.close()
    await secondRead.cancelAndWait()

    check await pushFut.withTimeout(100.milliseconds)
    await pushFut

  asyncTest "reset is terminal and closeWithEOF returns immediately after reset":
    let stream = BufferStream.new()

    var data: array[1, byte]
    let readFut = stream.readOnce(addr data[0], data.len)

    await stream.reset()

    check await readFut.withTimeout(100.milliseconds)
    check (await readFut) == 0
    check stream.closed
    check await stream.closeWithEOF().withTimeout(100.milliseconds)

  asyncTest "close clears the read buffer":
    let stream = BufferStream.new()
    await stream.pushData("12345".toBytes())

    var first: array[1, byte]
    check 1 == await stream.readOnce(addr first[0], first.len)
    check stream.len == 4

    await stream.close()

    check stream.len == 0
    check stream.atEof()

  asyncTest "close completes a parked reader with EOF":
    let stream = BufferStream.new()
    await stream.pushData("12345".toBytes())

    var first: array[1, byte]
    check 1 == await stream.readOnce(addr first[0], first.len)

    var rest: array[10, byte]
    let readFut = stream.readOnce(addr rest[0], rest.len)

    await stream.close()

    check await readFut.withTimeout(100.milliseconds)
    check (await readFut) == 0
