# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import strformat, random, sequtils, chronos, nimcrypto/utils, stew/byteutils
import
  ../../../libp2p/[
    errors,
    stream/connection,
    stream/bufferstream,
    transports/tcptransport,
    transports/transport,
    multiaddress,
    muxers/mplex/mplex,
    muxers/mplex/coder,
    muxers/mplex/lpchannel,
    upgrademngrs/upgrade,
    vbuffer,
    varint,
  ]
import ../../tools/[unittest, trackers, futures, bufferstream, compare, multiaddress]

proc noopWriteHandler(
    data: sink seq[byte]
) {.async: (raises: [CancelledError, LPStreamError]).} =
  discard

proc encodeMessage(id: uint64, msgType: MessageType, data: seq[byte]): seq[byte] =
  var buf = initVBuffer()
  buf.writePBVarint(id shl 3 or ord(msgType).uint64)
  buf.writeSeq(data)
  buf.buffer

suite "Mplex":
  teardown:
    checkTrackers()

  suite "channel encoding":
    asyncTest "encode header with channel id 0":
      proc encHandler(
          msg: sink seq[byte]
      ) {.async: (raises: [CancelledError, LPStreamError]).} =
        check msg == fromHex("000873747265616d2031")

      let conn = TestBufferStream.new(encHandler)
      await conn.writeMsg(0, MessageType.New, ("stream 1").toBytes)
      await conn.close()

    asyncTest "encode header with channel id other than 0":
      proc encHandler(
          msg: sink seq[byte]
      ) {.async: (raises: [CancelledError, LPStreamError]).} =
        check msg == fromHex("88010873747265616d2031")

      let conn = TestBufferStream.new(encHandler)
      await conn.writeMsg(17, MessageType.New, ("stream 1").toBytes)
      await conn.close()

    asyncTest "encode header and body with channel id 0":
      proc encHandler(
          msg: sink seq[byte]
      ) {.async: (raises: [CancelledError, LPStreamError]).} =
        check msg == fromHex("020873747265616d2031")

      let conn = TestBufferStream.new(encHandler)
      await conn.writeMsg(0, MessageType.MsgOut, ("stream 1").toBytes)
      await conn.close()

    asyncTest "encode header and body with channel id other than 0":
      proc encHandler(
          msg: sink seq[byte]
      ) {.async: (raises: [CancelledError, LPStreamError]).} =
        check msg == fromHex("8a010873747265616d2031")

      let conn = TestBufferStream.new(encHandler)
      await conn.writeMsg(17, MessageType.MsgOut, ("stream 1").toBytes)
      await conn.close()

    asyncTest "decode header with channel id 0":
      let stream = BufferStream.new()
      let conn = stream
      await stream.pushData(fromHex("000873747265616d2031"))
      let msg = await conn.readMsg()

      check msg.id == 0
      check msg.msgType == MessageType.New
      await conn.close()

    asyncTest "decode header and body with channel id 0":
      let stream = BufferStream.new()
      let conn = stream
      await stream.pushData(fromHex("021668656C6C6F2066726F6D206368616E6E656C20302121"))
      let msg = await conn.readMsg()

      check msg.id == 0
      check msg.msgType == MessageType.MsgOut
      check string.fromBytes(msg.data) == "hello from channel 0!!"
      await conn.close()

    asyncTest "decode header and body with channel id other than 0":
      let stream = BufferStream.new()
      let conn = stream
      await stream.pushData(
        fromHex("8a011668656C6C6F2066726F6D206368616E6E656C20302121")
      )
      let msg = await conn.readMsg()

      check msg.id == 17
      check msg.msgType == MessageType.MsgOut
      check string.fromBytes(msg.data) == "hello from channel 0!!"
      await conn.close()

  suite "channel half-closed":
    asyncTest "(local close) - should close for write":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.close()
      expect LPStreamClosedError:
        await chann.write("Hello")

      await chann.reset()
      await conn.close()

    asyncTest "(local close) - should allow reads until remote closes":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushData(("Hello!").toBytes)

      var data = newSeq[byte](6)
      await chann.close() # closing channel
      # should be able to read on local clsoe
      await chann.readExactly(addr data[0], 3)
      # closing remote end
      let closeFut = chann.pushEof()
      # should still allow reading until buffer EOF
      await chann.readExactly(addr data[3], 3)

      expect LPStreamRemoteClosedError:
        # this should fail now
        await chann.readExactly(addr data[0], 3)

      await chann.close()
      await conn.close()
      await closeFut

    asyncTest "(remote close) - channel should close for reading by remote":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushData(("Hello!").toBytes)

      var data = newSeq[byte](6)
      await chann.readExactly(addr data[0], 3)
      let closeFut = chann.pushEof() # closing channel
      let readFut = chann.readExactly(addr data[3], 3)
      await allFutures(closeFut, readFut)

      expect LPStreamRemoteClosedError:
        await chann.readExactly(addr data[0], 6) # this should fail now

      await chann.close()
      await conn.close()

    asyncTest "(remote close) - channel should allow writing on remote close":
      let
        testData = "Hello!".toBytes
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushEof() # closing channel
      try:
        await chann.writeLp(testData)
      finally:
        await chann.reset() # there's nobody reading the EOF!
        await conn.close()

    asyncTest "should not allow pushing data to channel when remote end closed":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)
      await chann.pushEof()
      var buf: array[1, byte]
      check:
        (await chann.readOnce(addr buf[0], 1)) == 0
        # EOF marker read

      expect LPStreamClosedError:
        await chann.pushData(@[byte(1)])

      await chann.close()
      await conn.close()

    asyncTest "(connection down) - should read buffered data and EOF":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushData(("Hello!").toBytes)
      let closeFut = chann.pushEof() # queue is full, so the marker waits
      await conn.close()

      var data = newSeq[byte](6)
      await chann.readExactly(addr data[0], 6)
      check string.fromBytes(data) == "Hello!"

      var buf: array[1, byte]
      check (await chann.readOnce(addr buf[0], 1)) == 0

      await chann.close()
      await closeFut

    asyncTest "(connection down) - canceled EOF push should not stall reads":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushData(("Hello!").toBytes)
      let eofFut = chann.pushEof() # blocks, queue is full
      check not eofFut.finished()
      await eofFut.cancelAndWait()

      var data = newSeq[byte](6)
      await chann.readExactly(addr data[0], 6)
      check string.fromBytes(data) == "Hello!"

      await conn.close()
      var buf: array[1, byte]
      expect LPStreamConnDownError:
        discard await chann.readOnce(addr buf[0], 1)

      await chann.reset()

    asyncTest "(connection down) - should drain a partial read buffer":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushData(("Hello!").toBytes)
      var prefix: array[3, byte]
      await chann.readExactly(addr prefix[0], 3)
      check string.fromBytes(prefix) == "Hel"

      await conn.close() # 3 bytes left in readBuf

      var remainder: array[4, byte]
      check:
        (await chann.readOnce(addr remainder[0], 4)) == 3
        string.fromBytes(remainder[0 ..< 3]) == "lo!"

      var buf: array[1, byte]
      expect LPStreamConnDownError:
        discard await chann.readOnce(addr buf[0], 1)

      await chann.reset()

  suite "channel reset":
    asyncTest "cleanup waits for the reset message":
      let
        resetStarted = Future[void].Raising([]).init(
            "mplex-reset-started", {FutureFlag.OwnCancelSchedule}
          )
        releaseReset = Future[void].Raising([]).init(
          "mplex-release-reset", {FutureFlag.OwnCancelSchedule}
        )

      proc blockingWriteHandler(
          data: sink seq[byte]
      ) {.async: (raises: [CancelledError, LPStreamError]).} =
        resetStarted.complete()
        await releaseReset

      let
        conn = TestBufferStream.new(blockingWriteHandler)
        mplex = Mplex.new(conn)
        chann = mplex.newStreamInternal(timeout = 1.seconds)

      chann.isOpen = true
      await chann.reset()
      await resetStarted

      await sleepAsync(10.millis) # sleep needed for negative assertion
      check not chann.cleanupFut.finished()
      check chann in mplex.getStreams()

      releaseReset.complete()
      await chann.cleanupFut
      check chann notin mplex.getStreams()
      await conn.close()

    asyncTest "channel should fail reading":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.reset()
      var data = newSeq[byte](1)
      expect LPStreamClosedError:
        await chann.readExactly(addr data[0], 1)

      await conn.close()

    asyncTest "reset should complete read":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      var data = newSeq[byte](1)
      let fut = chann.readExactly(addr data[0], 1)

      await chann.reset()
      expect LPStreamClosedError:
        await fut

      await conn.close()

    asyncTest "reset should complete pushData":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      proc pushes() {.async.} = # pushes don't hang on reset
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])

      let push = pushes()
      await chann.reset()
      check await allFutures(push).withTimeout(100.millis)
      await conn.close()

    asyncTest "reset should complete both read and push":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      var data = newSeq[byte](1)
      let futs = [chann.readExactly(addr data[0], 1), chann.pushData(@[0'u8])]
      await chann.reset()
      check await allFutures(futs).withTimeout(100.millis)
      await conn.close()

    asyncTest "reset should complete both read and pushes":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      var data = newSeq[byte](1)
      let read = chann.readExactly(addr data[0], 1)
      proc pushes() {.async.} =
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])

      await chann.reset()
      check await allFutures(read, pushes()).withTimeout(100.millis)
      await conn.close()

    asyncTest "reset should complete both read and push with cancel":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      var data = newSeq[byte](1)
      let rfut = chann.readExactly(addr data[0], 1)
      rfut.cancelSoon()
      let xfut = chann.reset()

      check await allFutures(rfut, xfut).withTimeout(100.millis)
      await conn.close()

    asyncTest "should complete both read and push after reset":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      var data = newSeq[byte](1)
      let rfut = chann.readExactly(addr data[0], 1)
      let rfut2 = sleepAsync(1.millis) or rfut

      await sleepAsync(5.millis)

      let wfut = chann.pushData(@[0'u8])
      let wfut2 = chann.pushData(@[0'u8])
      await chann.reset()
      check await allFutures(rfut, rfut2, wfut, wfut2).withTimeout(100.millis)
      await conn.close()

    asyncTest "reset should complete ongoing push without reader":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushData(@[0'u8])
      let push1 = chann.pushData(@[0'u8])
      await chann.reset()
      check await allFutures(push1).withTimeout(100.millis)
      await conn.close()

    asyncTest "reset should complete ongoing read without a push":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      var data = newSeq[byte](1)
      let rfut = chann.readExactly(addr data[0], 1)
      await chann.reset()
      check await allFutures(rfut).withTimeout(100.millis)
      await conn.close()

    asyncTest "reset should allow all reads and pushes to complete":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      var data = newSeq[byte](1)
      proc writer() {.async.} =
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])
        await chann.pushData(@[0'u8])

      proc reader() {.async.} =
        await chann.readExactly(addr data[0], 1)
        await chann.readExactly(addr data[0], 1)
        await chann.readExactly(addr data[0], 1)

      let readerFut = reader()
      let writerFut = writer()

      await chann.close()
      check await chann.reset()
      # this would hang
        .withTimeout(100.millis)

      check await allFuturesRaising(readerFut, writerFut).withTimeout(100.millis)

      await conn.close()

    asyncTest "channel should fail writing":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)
      await chann.reset()

      expect LPStreamClosedError:
        await chann.write(("Hello!").toBytes)

      await conn.close()

    asyncTest "reset should clear buffered data":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true)

      await chann.pushData(@[0'u8, 1, 2, 3, 4])
      var first: array[1, byte]
      check 1 == await chann.readOnce(addr first[0], first.len)
      check chann.len == 4

      await chann.reset()

      check chann.len == 0
      check chann.atEof()

      await conn.close()

    asyncTest "channel should reset on timeout":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        chann = LPChannel.init(1, conn, true, timeout = 100.millis)

      check await chann.join().withTimeout(1.minutes)
      await conn.close()

  suite "mplex limits":
    asyncTest "does not retain remote stream names":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        mplex = Mplex.new(conn)
        handleFut = mplex.handle()
        remoteName = "attacker-controlled-name"

      await conn.pushData(encodeMessage(0, MessageType.New, remoteName.toBytes()))

      checkUntilTimeoutCustom(1.seconds, 10.millis):
        mplex.getStreams().len == 1

      check LPChannel(mplex.getStreams()[0]).name != remoteName

      await mplex.close()
      await handleFut

    asyncTest "resets a stream that exceeds the connection buffer limit":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        mplex = Mplex.new(conn, maxBufferedBytes = 4)

      mplex.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
        await noCancel stream.join()

      let handleFut = mplex.handle()
      await conn.pushData(
        encodeMessage(0, MessageType.New, @[]) &
          encodeMessage(0, MessageType.MsgOut, @[0'u8, 1, 2, 3]) &
          encodeMessage(1, MessageType.New, @[]) &
          encodeMessage(1, MessageType.MsgOut, @[4'u8])
      )

      checkUntilTimeoutCustom(1.seconds, 10.millis):
        mplex.getStreams().len == 1
        LPChannel(mplex.getStreams()[0]).len == 4

      await mplex.close()
      await handleFut

    asyncTest "does not limit negotiated stream buffers":
      let
        conn = TestBufferStream.new(noopWriteHandler)
        mplex = Mplex.new(conn, maxBufferedBytes = 4)

      mplex.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
        await noCancel stream.join()

      let handleFut = mplex.handle()
      await conn.pushData(encodeMessage(0, MessageType.New, @[]))

      checkUntilTimeoutCustom(1.seconds, 10.millis):
        mplex.getStreams().len == 1

      let stream = LPChannel(mplex.getStreams()[0])
      stream.protocol = "/test/1.0.0"
      await conn.pushData(encodeMessage(0, MessageType.MsgOut, @[0'u8, 1, 2, 3, 4]))

      checkUntilTimeoutCustom(1.seconds, 10.millis):
        stream.len == 5

      check not stream.localReset

      await mplex.close()
      await handleFut

  suite "mplex e2e":
    asyncTest "read/write receiver", timeout = 20.seconds:
      let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let listenFut = transport1.start(@[TcpWildcardAddress])

      let received = newFuture[void]()
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          try:
            let msg = await stream.readLp(1024)
            check string.fromBytes(msg) == "HELLO"
            received.complete()
          except CancelledError, LPStreamError:
            return
          finally:
            await stream.close()

        await mplexListen.handle()
        await mplexListen.close()

      let acceptFut = acceptHandler()
      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      let stream = await mplexDial.newStream()
      await stream.writeLp("HELLO")
      check LPChannel(stream).isOpen # not lazy
      await stream.close()
      await received

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await acceptFut
      await listenFut
      await mplexDialFut

    asyncTest "read/write receiver lazy", timeout = 20.seconds:
      let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let listenFut = transport1.start(@[TcpWildcardAddress])

      let received = newFuture[void]()
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          try:
            let msg = await stream.readLp(1024)
            check string.fromBytes(msg) == "HELLO"
            received.complete()
          except CancelledError, LPStreamError:
            return
          finally:
            await stream.close()

        await mplexListen.handle()
        await mplexListen.close()

      let acceptFut = acceptHandler()
      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let stream = await mplexDial.newStream(lazy = true)
      let mplexDialFut = mplexDial.handle()
      check not LPChannel(stream).isOpen # assert lazy
      await stream.writeLp("HELLO")
      check LPChannel(stream).isOpen # assert lazy
      await stream.close()
      await received

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await acceptFut
      await listenFut
      await mplexDialFut

    asyncTest "write fragmented":
      let listenJob = newFuture[void]()

      var bigseq = newSeqOfCap[uint8](MaxMsgSize * 2)
      for _ in 0 ..< MaxMsgSize:
        bigseq.add(uint8(rand(uint('A') .. uint('z'))))

      let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let listenFut = transport1.start(@[TcpWildcardAddress])

      proc acceptHandler() {.async.} =
        try:
          let conn = await transport1.accept()
          let mplexListen = Mplex.new(conn)
          mplexListen.streamHandler = proc(
              stream: MuxedStream
          ) {.async: (raises: []).} =
            try:
              let msg = await stream.readLp(MaxMsgSize)
              check msg == bigseq
            except CancelledError, LPStreamError:
              return
            finally:
              await stream.close()
            listenJob.complete()

          await mplexListen.handle()
          await sleepAsync(500.millis) # give chronos some slack to process things
          await mplexListen.close()
        except CancelledError as exc:
          raise exc
        except transport.TransportError:
          raiseAssert "Transport error"

      let acceptFut = acceptHandler()
      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      let stream = await mplexDial.newStream()

      await stream.writeLp(bigseq)
      await listenJob

      await stream.close()
      await mplexDial.close()
      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await acceptFut
      await mplexDialFut

      await listenFut

    asyncTest "read/write initiator":
      let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let listenFut = transport1.start(@[TcpWildcardAddress])

      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          try:
            await stream.writeLp("Hello from stream!")
          except CancelledError, LPStreamError:
            return
          finally:
            await stream.close()

        await mplexListen.handle()
        await mplexListen.close()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let acceptFut = acceptHandler()
      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      let stream = await mplexDial.newStream("DIALER")
      let msg = string.fromBytes(await stream.readLp(1024))
      await stream.close()
      check msg == "Hello from stream!"

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await acceptFut
      await mplexDialFut
      await listenFut

    asyncTest "multiple streams":
      let transport1 = TcpTransport.new(upgrade = Upgrade())
      let listenFut = transport1.start(@[TcpWildcardAddress])

      let done = newFuture[void]()
      proc acceptHandler() {.async.} =
        var count = 1
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          try:
            let msg = await stream.readLp(1024)
            try:
              check string.fromBytes(msg) == &"stream {count}!"
            except ValueError as exc:
              raiseAssert(exc.msg)
            count.inc
            if count == 11:
              done.complete()
          except CancelledError, LPStreamError:
            return
          finally:
            await stream.close()

        await mplexListen.handle()
        await mplexListen.close()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let acceptFut = acceptHandler()
      let mplexDial = Mplex.new(conn)
      # TODO: Reenable once half-closed is working properly
      let mplexDialFut = mplexDial.handle()
      for i in 1 .. 10:
        let stream = await mplexDial.newStream()
        await stream.writeLp(&"stream {i}!")
        await stream.close()

      await done
      await conn.close()
      await acceptFut
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await listenFut

    asyncTest "multiple read/write streams":
      let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let listenFut = transport1.start(@[TcpWildcardAddress])

      let done = newFuture[void]()
      proc acceptHandler() {.async.} =
        var count = 1
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          try:
            let msg = await stream.readLp(1024)
            try:
              check string.fromBytes(msg) == &"stream {count} from dialer!"
              await stream.writeLp(&"stream {count} from listener!")
            except ValueError as exc:
              raiseAssert(exc.msg)
            count.inc
            if count == 11:
              done.complete()
          except CancelledError, LPStreamError:
            return
          finally:
            await stream.close()

        await mplexListen.handle()
        await mplexListen.close()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let acceptFut = acceptHandler()
      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      for i in 1 .. 10:
        let stream = await mplexDial.newStream("dialer stream")
        await stream.writeLp(&"stream {i} from dialer!")
        let msg = await stream.readLp(1024)
        check string.fromBytes(msg) == &"stream {i} from listener!"
        await stream.close()

      await done
      await conn.close()
      await mplexDial.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await acceptFut
      await mplexDialFut
      await listenFut

    asyncTest "channel closes listener with EOF":
      let transport1 = TcpTransport.new(upgrade = Upgrade())
      var listenStreams: seq[MuxedStream]
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)

        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          listenStreams.add(stream)
          try:
            discard await stream.readLp(1024)
          except CancelledError, LPStreamError:
            return
          finally:
            await stream.close()

          raiseAssert "Channel not closed"

        await mplexListen.handle()
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()
      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      var dialStreams = toSeq(0 .. 9).mapIt(await mplexDial.newStream())

      check:
        unorderedCompare(dialStreams, mplexDial.getStreams())

      for i, s in dialStreams:
        await s.closeWithEOF()
        check listenStreams[i].closed
        check s.closed

      checkTracker(LPChannelTrackerName)

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    asyncTest "channel closes dialer with EOF":
      let transport1 = TcpTransport.new(upgrade = Upgrade())

      var count = 0
      var done = newFuture[void]()
      var listenStreams: seq[MuxedStream]
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          listenStreams.add(stream)
          count.inc()
          if count == 10:
            done.complete()

          await noCancel stream.join()

        await mplexListen.handle()
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      var dialStreams = toSeq(0 .. 9).mapIt(await mplexDial.newStream())

      check:
        unorderedCompare(dialStreams, mplexDial.getStreams())

      proc dialReadLoop() {.async.} =
        for s in dialStreams:
          expect LPStreamEOFError:
            discard await s.readLp(1024)
          await s.close()

      await done
      let readLoop = dialReadLoop()
      for s in listenStreams:
        await s.closeWithEOF()
        check s.closed

      await readLoop
      await allFuturesRaising((dialStreams & listenStreams).mapIt(it.join()))

      checkTracker(LPChannelTrackerName)

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    asyncTest "Connection.reset aborts the dialer stream":
      let transport1 = TcpTransport.new(upgrade = Upgrade())

      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          await stream.reset()

        await mplexListen.handle()
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      let stream = await mplexDial.newStream()

      expect LPStreamResetError:
        discard await stream.readLp(1024)
      expect LPStreamResetError:
        await stream.writeLp("HELLO")

      await stream.close()

      checkTracker(LPChannelTrackerName)

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    asyncTest "dialing mplex closes both ends":
      let transport1 = TcpTransport.new(upgrade = Upgrade())

      var listenStreams: seq[MuxedStream]
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          listenStreams.add(stream)
          await noCancel stream.join()

        await mplexListen.handle()
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      var dialStreams = toSeq(0 .. 9).mapIt(await mplexDial.newStream())

      check:
        unorderedCompare(dialStreams, mplexDial.getStreams())

      await mplexDial.close()
      await allFuturesRaising((dialStreams & listenStreams).mapIt(it.join()))

      checkTracker(LPChannelTrackerName)

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    asyncTest "listening mplex closes both ends":
      let transport1 = TcpTransport.new(upgrade = Upgrade())

      var mplexListen: Mplex
      var listenStreams: seq[MuxedStream]
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          listenStreams.add(stream)
          await noCancel stream.join()

        await mplexListen.handle()
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      var dialStreams = toSeq(0 .. 9).mapIt(await mplexDial.newStream())

      check:
        unorderedCompare(dialStreams, mplexDial.getStreams())

      checkUntilTimeout:
        listenStreams.len == 10 and dialStreams.len == 10

      await mplexListen.close()
      await allFuturesRaising((dialStreams & listenStreams).mapIt(it.join()))

      checkTracker(LPChannelTrackerName)

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    asyncTest "canceling mplex handler closes both ends":
      let transport1 = TcpTransport.new(upgrade = Upgrade())

      var mplexHandle: Future[void]
      var listenStreams: seq[MuxedStream]
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          listenStreams.add(stream)
          await noCancel stream.join()

        mplexHandle = mplexListen.handle()
        await mplexHandle
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      var dialStreams = toSeq(0 .. 9).mapIt(await mplexDial.newStream())

      check:
        unorderedCompare(dialStreams, mplexDial.getStreams())

      checkUntilTimeout:
        listenStreams.len == 10 and dialStreams.len == 10

      mplexHandle.cancelSoon()
      await allFuturesRaising((dialStreams & listenStreams).mapIt(it.join()))

      checkTracker(LPChannelTrackerName)

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    asyncTest "closing dialing connection should close both ends":
      let transport1 = TcpTransport.new(upgrade = Upgrade())

      var listenStreams: seq[MuxedStream]
      proc acceptHandler() {.async.} =
        let conn = await transport1.accept()
        let mplexListen = Mplex.new(conn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          listenStreams.add(stream)
          await noCancel stream.join()

        await mplexListen.handle()
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      var dialStreams = toSeq(0 .. 9).mapIt(await mplexDial.newStream())

      check:
        unorderedCompare(dialStreams, mplexDial.getStreams())

      checkUntilTimeout:
        listenStreams.len == 10 and dialStreams.len == 10

      await conn.close()
      await allFuturesRaising((dialStreams & listenStreams).mapIt(it.join()))

      checkTracker(LPChannelTrackerName)

      await conn.closeWithEOF()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    asyncTest "canceling listening connection should close both ends":
      let transport1 = TcpTransport.new(upgrade = Upgrade())

      var listenConn: MuxedStream
      var listenStreams: seq[MuxedStream]
      proc acceptHandler() {.async.} =
        listenConn = await transport1.accept()
        let mplexListen = Mplex.new(listenConn)
        mplexListen.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
          listenStreams.add(stream)
          await noCancel stream.join()

        await mplexListen.handle()
        await mplexListen.close()

      await transport1.start(@[TcpWildcardAddress])
      let acceptFut = acceptHandler()

      let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      let conn = await transport2.dial(transport1.addrs[0])

      let mplexDial = Mplex.new(conn)
      let mplexDialFut = mplexDial.handle()
      var dialStreams = toSeq(0 .. 9).mapIt(await mplexDial.newStream())

      check:
        unorderedCompare(dialStreams, mplexDial.getStreams())

      checkUntilTimeout:
        listenStreams.len == 10 and dialStreams.len == 10

      await listenConn.closeWithEOF()
      await allFuturesRaising((dialStreams & listenStreams).mapIt(it.join()))

      checkTracker(LPChannelTrackerName)

      await conn.close()
      await allFuturesRaising(transport1.stop(), transport2.stop())
      await mplexDialFut
      await acceptFut

    suite "jitter":
      asyncTest "channel should be able to handle erratic read/writes":
        let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
        let listenFut = transport1.start(@[TcpWildcardAddress])

        var complete = newFuture[void]()
        const MsgSize = 1024
        proc acceptHandler() {.async.} =
          let conn = await transport1.accept()
          let mplexListen = Mplex.new(conn)
          mplexListen.streamHandler = proc(
              stream: MuxedStream
          ) {.async: (raises: []).} =
            try:
              let msg = await stream.readLp(MsgSize)
              check msg.len == MsgSize
            except CancelledError as e:
              echo e.msg
            except LPStreamError as e:
              echo e.msg
            await stream.close()
            complete.complete()

          await mplexListen.handle()
          await mplexListen.close()

        let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
        let conn = await transport2.dial(transport1.addrs[0])

        let acceptFut = acceptHandler()
        let mplexDial = Mplex.new(conn)
        let mplexDialFut = mplexDial.handle()
        let stream = await mplexDial.newStream()
        var bigseq = newSeqOfCap[uint8](MaxMsgSize + 1)
        for _ in 0 ..< MsgSize: # write one less than max size
          bigseq.add(uint8(rand(uint('A') .. uint('z'))))

        ## create length prefixed libp2p frame
        var buf = initVBuffer()
        buf.writeSeq(bigseq)
        buf.finish()

        ## create mplex header
        var mplexBuf = initVBuffer()
        mplexBuf.writePBVarint((1.uint shl 3) or ord(MessageType.MsgOut).uint)
        mplexBuf.writePBVarint(buf.buffer.len.uint) # size should be always sent

        await conn.write(mplexBuf.buffer)
        proc writer() {.async.} =
          var sent = 0
          randomize()
          let total = buf.buffer.len
          const min = 20
          const max = 50
          while sent < total:
            var size = rand(min .. max)
            size = if size > buf.buffer.len: buf.buffer.len else: size
            var send = buf.buffer[0 ..< size]
            await conn.write(send)
            sent += size
            buf.buffer = buf.buffer[size ..^ 1]

        await writer()
        await complete
        await stream.close()
        await mplexDial.close()
        await conn.close()
        await allFuturesRaising(transport1.stop(), transport2.stop())
        await acceptFut
        await mplexDialFut
        await listenFut

      asyncTest "channel should handle 1 byte read/write":
        let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
        let listenFut = transport1.start(@[TcpWildcardAddress])

        var complete = newFuture[void]()
        const MsgSize = 512
        proc acceptHandler() {.async.} =
          let conn = await transport1.accept()
          let mplexListen = Mplex.new(conn)
          mplexListen.streamHandler = proc(
              stream: MuxedStream
          ) {.async: (raises: []).} =
            try:
              let msg = await stream.readLp(MsgSize)
              check msg.len == MsgSize
            except CancelledError, LPStreamError:
              return
            finally:
              await stream.close()
            complete.complete()

          await mplexListen.handle()
          await mplexListen.close()

        let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
        let conn = await transport2.dial(transport1.addrs[0])

        let acceptFut = acceptHandler()
        let mplexDial = Mplex.new(conn)
        let stream = await mplexDial.newStream()
        let mplexDialFut = mplexDial.handle()
        var bigseq = newSeqOfCap[uint8](MsgSize + 1)
        for _ in 0 ..< MsgSize: # write one less than max size
          bigseq.add(uint8(rand(uint('A') .. uint('z'))))

        ## create length prefixed libp2p frame
        var buf = initVBuffer()
        buf.writeSeq(bigseq)
        buf.finish()

        ## create mplex header
        var mplexBuf = initVBuffer()
        mplexBuf.writePBVarint((1.uint shl 3) or ord(MessageType.MsgOut).uint)
        mplexBuf.writePBVarint(buf.buffer.len.uint) # size should be always sent

        await conn.write(mplexBuf.buffer)
        proc writer() {.async.} =
          for i in buf.buffer:
            await conn.write(@[i])

        await writer()

        await complete
        await stream.close()
        await mplexDial.close()
        await conn.close()
        await allFuturesRaising(transport1.stop(), transport2.stop())
        await acceptFut
        await mplexDialFut
        await listenFut
