# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils, std/random, nimcrypto/utils as ncrutils
import
  ../../../libp2p/[stream/connection, transports/transport, muxers/muxer, multiaddress]
import ../../tools/[stream, sync]
import ./utils

const
  serverMessage = "Privacy is necessary for an open society in the electronic age."
  clientMessage = "We can be decentralised yet cooperative."

template runTransportTest(
    transportProvider: TransportProvider,
    streamProvider: StreamProvider,
    address: MultiAddress,
) =
  proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
    noExceptionWithStreamClose(stream):
      check (await stream.readExactlyAsStr(clientMessage.len)) == clientMessage

      await stream.write(serverMessage)

  proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
    noExceptionWithStreamClose(stream):
      await stream.write(clientMessage)

      check (await stream.readExactlyAsStr(serverMessage.len)) == serverMessage

  await runSingleStreamScenario(
    @[address],
    transportProvider,
    streamProvider,
    serverStreamHandler,
    clientStreamHandler,
  )

template streamTransportTest*(
    transportProvider: TransportProvider,
    addressIP4: MultiAddress,
    addressIP6: Opt[MultiAddress],
    streamProvider: StreamProvider,
) =
  asyncTest "transport::ipv4":
    runTransportTest(transportProvider, streamProvider, addressIP4)

  asyncTest "transport::ipv6":
    if addressIP6.isNone:
      skip() # ipv6 not supported
      return

    runTransportTest(transportProvider, streamProvider, addressIP6.get())

  asyncTest "start binds both IPv4 and IPv6 addresses":
    if addressIP6.isNone:
      skip() # ipv6 not supported
      return

    let server = transportProvider()
    await server.start(@[addressIP4, addressIP6.get()])
    defer:
      await server.stop()

    check:
      server.addrs.len == 2
      extractPort(server.addrs.addrByFamily(IP4)) > 0
      extractPort(server.addrs.addrByFamily(IP6)) > 0

  asyncTest "dual-stack server exchanges data with IPv4 and IPv6 clients":
    if addressIP6.isNone:
      skip() # ipv6 not supported
      return

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        check (await stream.readExactlyAsStr(clientMessage.len)) == clientMessage
        await stream.write(serverMessage)

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.write(clientMessage)

        check (await stream.readExactlyAsStr(serverMessage.len)) == serverMessage

    await dualStackStreamScenario(
      @[addressIP4, addressIP6.get()],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "dial cancellation leaves established connection working":
    if addressIP6.isNone:
      skip() # scoped to dual-stack transports (tcp, quic)
      return

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        check (await stream.readExactlyAsStr(clientMessage.len)) == clientMessage
        await stream.write(serverMessage)

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.write(clientMessage)
        check (await stream.readExactlyAsStr(serverMessage.len)) == serverMessage

    let server = transportProvider()
    await server.start(@[addressIP4, addressIP6.get()])
    defer:
      await server.stop()
    let serverTask =
      serverHandlerSingleStream(server, streamProvider, serverStreamHandler)

    # establish a connection on the first address
    let client = transportProvider()
    let conn = await client.dial("", server.addrs[0])
    let muxer = streamProvider(conn)

    # a completed exchange proves the server has accepted the connection and is
    # now serving its streams
    await runStreamHandler(muxer, clientStreamHandler)

    # serverTask calls accept() only once and already used it on the established
    # connection, so this dial is never accepted on the server side.
    # cancelAndWait runs before the dial coroutine can resume, so the in-flight
    # dial is cancelled rather than completed
    let dialer = transportProvider()
    let connFut = dialer.dial("", server.addrs[1])
    await connFut.cancelAndWait()
    check connFut.cancelled

    # the established connection still exchanges data after the cancellation
    await runStreamHandler(muxer, clientStreamHandler)

    # closing the muxer ends the session so serverTask returns
    await muxer.close()
    await conn.close()
    await allFutures(client.stop(), dialer.stop())
    await serverTask

  asyncTest "accept cancellation leaves established connection working":
    if addressIP6.isNone:
      skip() # scoped to dual-stack transports (tcp, quic)
      return

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        check (await stream.readExactlyAsStr(clientMessage.len)) == clientMessage
        await stream.write(serverMessage)

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.write(clientMessage)
        check (await stream.readExactlyAsStr(serverMessage.len)) == serverMessage

    let server = transportProvider()
    await server.start(@[addressIP4, addressIP6.get()])
    defer:
      await server.stop()
    let serverTask =
      serverHandlerSingleStream(server, streamProvider, serverStreamHandler)

    let client = transportProvider()
    let conn = await client.dial("", server.addrs[0])
    let muxer = streamProvider(conn)

    # serverTask has accepted the connection and moved on to serving its
    # streams, so the only in-flight accept below is the one we start and cancel
    await runStreamHandler(muxer, clientStreamHandler)

    # a fresh accept with nobody dialing, cancelling it must not disturb
    # the established connection, and no new connection forms
    let acceptFut = server.accept()
    await acceptFut.cancelAndWait()
    check acceptFut.cancelled

    # the established connection still exchanges data after the cancellation
    await runStreamHandler(muxer, clientStreamHandler)

    await muxer.close()
    await conn.close()
    await client.stop()
    await serverTask

  asyncTest "read/write Lp":
    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        check (await stream.readLp(100)) == ncrutils.fromHex("1234")
        await stream.writeLp(ncrutils.fromHex("5678"))

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.writeLp(ncrutils.fromHex("1234"))
        check (await stream.readLp(100)) == ncrutils.fromHex("5678")

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "Connection.reset aborts the initiator stream":
    let serverResetDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverResetDone):
        let msg = await stream.readLp(100)
        check msg == ncrutils.fromHex("1234")
        await stream.reset()

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.writeLp(ncrutils.fromHex("1234"))
        await serverResetDone

        var buffer: array[1, byte]
        # EOF until this side reads the RST frame, reset once it lands
        try:
          check (await stream.readOnce(addr buffer[0], 1)) == 0
        except LPStreamResetError:
          discard

        expect LPStreamResetError:
          await stream.writeLp(ncrutils.fromHex("1234"))

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "EOF handling - first readOnce at EOF + repeated reads":
    let serverHandlerDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverHandlerDone):
        check (await stream.readExactlyAsStr(serverMessage.len)) == serverMessage

        var buffer: array[1, byte]
        # First readOnce after EOF
        let bytesRead = await stream.readOnce(addr buffer, 1)
        check bytesRead == 0

        # Attempting second readOnce at EOF
        expect LPStreamRemoteClosedError:
          discard await stream.readOnce(addr buffer, 1)

        # # Attempting readExactly at EOF
        expect LPStreamRemoteClosedError:
          await stream.readExactly(addr buffer, 1)

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.write(serverMessage)
        await stream.closeWrite()
        await serverHandlerDone

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "server writes after EOF":
    let listenAddrs = addressIP4
    var clientHandlerDone = newFuture[void]()
    var serverReadDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        # step 2: read message from client (ensure connection is established)
        check (await stream.readExactlyAsStr(serverMessage.len)) == serverMessage
        # and notify this to client
        serverReadDone.complete()

        # step 5: server waits for client to close and attempts to write
        await clientHandlerDone

        if isTcpTransport(listenAddrs) or isTorTransport(listenAddrs) or
            isWsTransport(listenAddrs):
          # For TCP/Tor/WS: after client.stop(), the OS sends FIN but the server
          # socket enters CLOSE_WAIT. In this state, the OS still accepts writes
          # to the send buffer and returns success until it receives a reset.
          # The mplex handle loop detects the underlying EOF asynchronously (when
          # readMsg() fails) and calls m.close() -> channel.reset(). Subsequent
          # writes raise LPStreamEOFError (often LPStreamClosedError or
          # LPStreamResetError).
          expect LPStreamEOFError:
            let expiration = Moment.now() + 10.seconds
            while Moment.now() < expiration:
              await stream.write(clientMessage)
        else:
          # For other transports check is trivial.
          expect LPStreamEOFError:
            await stream.write(clientMessage)

    proc runClient(server: Transport) {.async.} =
      let client = transportProvider()
      let conn = await client.dial("", server.addrs[0])
      let muxer = streamProvider(conn)

      # step 1: send some message to server
      let stream = await muxer.newStream()
      await stream.write(serverMessage)
      await stream.closeWrite() # flush message

      # step 3: wait for server to read message
      # (closing stream too early risk data not being transmitted)
      await serverReadDone
      # then close connection
      await stream.close()
      await muxer.close()
      await conn.close()
      await client.stop()

      # step 4: client has fully closed, tell server to write now.
      clientHandlerDone.complete()

    let server = transportProvider()
    await server.start(@[listenAddrs])
    let serverTask =
      serverHandlerSingleStream(server, streamProvider, serverStreamHandler)

    await runClient(server)
    await serverTask
    await server.stop()

  asyncTest "incomplete read":
    let serverHandlerDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverHandlerDone):
        var buffer: array[2 * serverMessage.len, byte]

        expect LPStreamIncompleteError:
          await stream.readExactly(addr buffer, 2 * serverMessage.len)

        # Verify that partial data was read before EOF
        check string.fromBytes(buffer[0 ..< serverMessage.len]) == serverMessage

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.write(serverMessage)
        await stream.closeWrite()
        await serverHandlerDone

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "client closeWrite - server can still write":
    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        # Client reads server data
        check (await stream.readExactlyAsStr(serverMessage.len)) == serverMessage

        # Server has closed write side, so further reads should EOF
        var buffer: array[1, byte]
        let bytesRead = await stream.readOnce(addr buffer, 1)
        check bytesRead == 0

        # Client should still be able to write back to server
        await stream.write(clientMessage)

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        # Server sends data and closes its write side
        await stream.write(serverMessage)
        await stream.closeWrite()

        # Verify that write after closeWrite fails
        expect LPStreamEOFError:
          await stream.write("should fail")

        # Server should still be able to read from client
        check (await stream.readExactlyAsStr(clientMessage.len)) == clientMessage

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "multiple empty writes before closeWrite":
    let serverHandlerDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverHandlerDone):
        # Even with multiple empty writes, reading should eventually get EOF
        var buffer: array[1, byte]
        let bytesRead = await stream.readOnce(addr buffer[0], 1)
        check bytesRead == 0 # Should get EOF

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        # Multiple empty writes
        await stream.write(@[])
        await stream.write(@[])
        await stream.write(@[])
        await stream.closeWrite()
        await serverHandlerDone

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "closeWrite immediately after newStream":
    let serverHandlerDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverHandlerDone):
        # Should get EOF immediately
        var buffer: array[1, byte]
        let bytesRead = await stream.readOnce(addr buffer[0], 1)
        check bytesRead == 0

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        # Close write immediately without any data
        await stream.closeWrite()
        await serverHandlerDone

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "closing session should close all streams":
    const numStreams = 20
    const numIncomplete = 10
    const numComplete = numStreams - numIncomplete
    let successfulReadsWG = newWaitGroup(numComplete)

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        try:
          check (await stream.readExactlyAsStr(clientMessage.len)) == clientMessage

          successfulReadsWG.done()
        except LPStreamIncompleteError, LPStreamResetError:
          # Error is expected when muxer is closed while waiting in readExactly
          discard

    proc runClient(server: Transport) {.async.} =
      let client = transportProvider()
      let conn = await client.dial(server.addrs[0])
      let muxer = streamProvider(conn)

      # Send incomplete messages (will block)
      const incompleteClientMessage = clientMessage[0 ..< 10]
      for i in 0 ..< numIncomplete:
        let stream = await muxer.newStream()
        await stream.write(incompleteClientMessage)

      # Send complete messages (will finish successfully)
      for i in 0 ..< numComplete:
        let stream = await muxer.newStream()
        await stream.write(clientMessage)

      # Wait for all complete handlers to finish
      await successfulReadsWG.wait()

      # Will cause EOF on the waiting handlers 
      # Intentionally do not close streams, they should be closed with muxer
      await muxer.close()
      await conn.close()
      await client.stop()

    let server = transportProvider()
    await server.start(@[addressIP4])
    let serverTask =
      serverHandlerSingleStream(server, streamProvider, serverStreamHandler)

    await runClient(server)
    await serverTask
    await server.stop()

  asyncTest "stream caching with multiple partial reads":
    const messageSize = 2048
    const chunkSize = 256
    let message = newData(messageSize)
    let serverHandlerDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverHandlerDone):
        let receivedData =
          await readStreamByChunkTillEOF(stream, chunkSize, messageSize)
        check receivedData == message

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.write(message)
        await serverHandlerDone

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "stream with multiple parallel writes":
    const messageSize = 20 * 1024
    const chunkSize = 256 * 1024
    const parallelWrites = 10
    let serverHandlerDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverHandlerDone):
        const expectedSize = messageSize * parallelWrites
        let receivedData =
          await readStreamByChunkTillEOF(stream, chunkSize, expectedSize)
        check receivedData.len == expectedSize

        # each task sends unique data, but the arrival order is unpredictable.
        # we verify that all consecutive segments of the data stream contain identical values.
        # example: valid → `aaaaabbbbbccccc`; invalid → `aaabbbbbccaaccc`
        for i in 0 ..< parallelWrites:
          let offset = i * messageSize
          let expectedValue = receivedData[offset]
          # all elements of same data have to be the same
          for j in 0 ..< messageSize:
            check receivedData[offset + j] == expectedValue
            if receivedData[offset + j] != expectedValue:
              break # stop on first mismatch (not to pollute stdout)

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        var writeFuts: seq[Future[void]] = @[]
        for i in 0 ..< parallelWrites:
          # each write has to have unique data
          let message = newData(messageSize, uint8(i + 1))
          let fut = stream.write(message)
          writeFuts.add(fut)
        await allFutures(writeFuts)
        await serverHandlerDone

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "single large write":
    const messageSize = 2 * 1024 * 1024
    const chunkSize = 256 * 1024
    let serverHandlerDone = newFuture[void]()

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream, serverHandlerDone):
        let receivedData =
          await readStreamByChunkTillEOF(stream, chunkSize, messageSize)
        check receivedData == newData(messageSize)

    proc clientStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        await stream.write(newData(messageSize))
        await serverHandlerDone

    await runSingleStreamScenario(
      @[addressIP4],
      transportProvider,
      streamProvider,
      serverStreamHandler,
      clientStreamHandler,
    )

  asyncTest "connection with multiple parallel streams":
    const chunkSize = 64
    const chunkCount = 32
    const messageSize = chunkSize * chunkCount
    const numStreams = 5
    var serverReadOrder: seq[byte] = @[]
    let serverHandlerWG = newWaitGroup(numStreams)

    proc serverStreamHandler(stream: MuxedStream) {.async: (raises: []).} =
      noExceptionWithStreamClose(stream):
        var receivedData: seq[byte] = @[]

        while receivedData.len < messageSize:
          var chunk = newSeq[byte](chunkSize)
          let bytesRead = await stream.readOnce(addr chunk[0], chunkSize)
          if bytesRead == 0:
            break
          receivedData.add(chunk[0 ..< bytesRead])
          serverReadOrder.add(chunk[0])
          # Random delay between reads to allow parallel data transition between streams.
          await sleepAsync(rand(20 .. 100).milliseconds)

        check receivedData.len == messageSize

        # Send back the stream ID (first byte of received data)
        await stream.write(@[byte(receivedData[0])])

        serverHandlerWG.done()

    proc runClient(server: Transport) {.async.} =
      let client = transportProvider()
      let conn = await client.dial(server.addrs[0])
      let muxer = streamProvider(conn)

      var futs: seq[Future[void]]
      for i in 0 ..< numStreams:
        let stream = await muxer.newStream()

        # Use a capturing proc to properly bind loop variables
        proc startWriteAndClose(
            stream: MuxedStream, streamId: int
        ): Future[void] {.async.} =
          # Write data in chunks with random delays
          for j in 0 ..< chunkCount:
            let chunkMessage = newData(chunkSize, byte(streamId))
            await stream.write(chunkMessage)
            await sleepAsync(rand(20 .. 100).milliseconds)

          # Read response from server to verify stream independence
          var buffer: array[1, byte]
          await stream.readExactly(addr buffer, 1)

          # Verify we got back our own stream ID
          check buffer[0] == byte(streamId)

          await stream.close()

        futs.add(startWriteAndClose(stream, i))

      await allFutures(futs)

      # Wait for server to process all streams before closing muxer
      await serverHandlerWG.wait()

      await muxer.close()
      await conn.close()
      await client.stop()

    let server = transportProvider()
    await server.start(@[addressIP4])
    let serverTask =
      serverHandlerSingleStream(server, streamProvider, serverStreamHandler)

    await runClient(server)
    await serverTask
    await server.stop()

    # Assert parallelism by counting transitions between different stream IDs
    # Total reads: 5 streams × 32 chunks = 160
    # Max possible transitions: 159 (change on every read except the first)
    # Sequential execution would have only 4 transitions [0,0,0,1,1,1,3,3,3,2,2,2,4,4,4]
    # We expect at least 50%
    check countTransitions(serverReadOrder) >= (numStreams * chunkCount) div 2
    echo serverReadOrder

  asyncTest "server with multiple parallel connections":
    const chunkSize = 64
    const chunkCount = 32
    const messageSize = chunkSize * chunkCount
    const numConnections = 5
    var serverReadOrder: seq[byte] = @[]

    # Track when stream handlers complete
    var serverStreamHandlerFuts: array[numConnections, Future[void]]
    for i in 0 ..< numConnections:
      serverStreamHandlerFuts[i] = newFuture[void]()

    proc serverHandler(server: Transport) {.async.} =
      # Accept multiple connections and handle them
      var futs: seq[Future[void]]
      for i in 0 ..< numConnections:
        # Use a proc to properly capture loop index
        proc setupConnection(conn: RawConn, handlerIndex: int) =
          let muxer = streamProvider(conn, false)
          muxer.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
            noExceptionWithStreamClose(stream):
              # Read data in chunks with random delay
              var receivedData: seq[byte] = @[]
              while receivedData.len < messageSize:
                var chunk = newSeq[byte](chunkSize)
                let bytesRead = await stream.readOnce(addr chunk[0], chunkSize)
                if bytesRead == 0:
                  break
                receivedData.add(chunk[0 ..< bytesRead])
                serverReadOrder.add(chunk[0])
                # Random delay between reads (20-100ms)
                # Will block current future (stream handler) and give opportunity to next future to execute. 
                # Doing this improves likelihood of parallel data transition on the connections.
                await sleepAsync(rand(20 .. 100).milliseconds)

              # Concurrent transports may accept clients in a different order.
              require receivedData.len > 0
              let clientId = receivedData[0]
              check:
                clientId.int < numConnections
                receivedData == newData(messageSize, clientId)

              # Send back ID
              await stream.write(@[clientId])

              # Signal that this stream handler is done
              serverStreamHandlerFuts[handlerIndex].complete()

          let startStreamHandlerAndCleanup = proc() {.async.} =
            await muxer.handle()

            # Wait for the stream handler to complete before closing
            await serverStreamHandlerFuts[handlerIndex]

            await muxer.close()
            await conn.close()

          futs.add(startStreamHandlerAndCleanup())

        let conn = await server.accept()
        setupConnection(conn, i)
      await allFutures(futs)

    proc runClient(server: Transport, connectionId: int) {.async.} =
      let client = transportProvider()
      let conn = await client.dial(server.addrs[0])
      let muxer = streamProvider(conn)

      let stream = await muxer.newStream()

      # Write data in chunks with random delay
      let message = newData(chunkSize, byte(connectionId))
      for i in 0 ..< chunkCount:
        await stream.write(message)
        # Random delay between writes (20-100ms)
        await sleepAsync(rand(20 .. 100).milliseconds)

      var buffer: array[1, byte]
      await stream.readExactly(addr buffer, 1)

      # Verify we got back our own connection ID
      check buffer[0] == byte(connectionId)

      await stream.close()
      await muxer.close()
      await conn.close()
      await client.stop()

    let server = transportProvider()
    await server.start(@[addressIP4])
    let serverTask = serverHandler(server)

    # Start multiple concurrent clients
    var clientFuts: seq[Future[void]]
    for i in 0 ..< numConnections:
      clientFuts.add(runClient(server, i))

    await allFutures(clientFuts)
    await serverTask
    await server.stop()

    # Assert parallelism by counting transitions between different connection IDs
    # Total reads: 5 connections × 32 chunks = 160
    # Max possible transitions: 159 (change on every read except the first)
    # Sequential execution would have only 4 transitions [0,0,0,1,1,1,3,3,3,2,2,2,4,4,4]
    # We expect at least 50%
    # TODO: nim-libp2p#1859 Tor transport: Server with multiple connections processes data sequentially in the tests
    if not (isTorTransport(addressIP4)):
      check countTransitions(serverReadOrder) >= (numConnections * chunkCount) div 2
    echo serverReadOrder
