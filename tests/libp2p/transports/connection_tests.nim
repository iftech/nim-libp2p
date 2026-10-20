# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, stew/byteutils
import
  ../../../libp2p/
    [stream/connection, transports/transport, upgrademngrs/upgrade, multiaddress]
import ../../tools/[unittest, multiaddress]
import ./utils

template connectionTransportTest*(
    provider: TransportProvider, ma1: string, ma2: string = ""
) =
  block:
    let transportProvider = provider
    const message =
      "Transparent, immutable records, as we will see, are critical to good governance"

    asyncTest "handle write":
      proc serverHandler(server: Transport) {.async.} =
        let conn = await server.accept()
        defer:
          await conn.close()

        await conn.write(message)

      proc runClient(server: Transport) {.async.} =
        let client = transportProvider()
        let conn = await client.dial(server.addrs[0])
        defer:
          await conn.close()
          await client.stop()

        var buffer = newSeq[byte](message.len)
        await conn.readExactly(addr buffer[0], message.len)

        check string.fromBytes(buffer) == message

      let server = transportProvider()
      await server.start(@[ma(ma1)])
      let serverFut = serverHandler(server)

      await runClient(server)
      await serverFut
      await server.stop()

    asyncTest "handle read":
      proc serverHandler(server: Transport) {.async.} =
        let conn = await server.accept()
        defer:
          await conn.close()

        var buffer = newSeq[byte](message.len)
        await conn.readExactly(addr buffer[0], message.len)

        check string.fromBytes(buffer) == message

      proc runClient(server: Transport) {.async.} =
        let client = transportProvider()
        let conn = await client.dial(server.addrs[0])
        defer:
          await conn.close()
          await client.stop()

        await conn.write(message)

      let server = transportProvider()
      await server.start(@[ma(ma1)])
      let serverFut = serverHandler(server)

      await runClient(server)
      await serverFut
      await server.stop()

    asyncTest "should allow multiple local addresses":
      let addrs = @[ma(ma1), ma(if ma2 == "": ma1 else: ma2)]

      proc serverHandler(server: Transport) {.async.} =
        while true:
          let conn = await server.accept()
          await conn.write(message)
          await conn.close()

      proc runClient(server: Transport) {.async.} =
        let client = transportProvider()
        defer:
          await client.stop()

        check:
          server.addrs.len == 2
          server.addrs[0] != server.addrs[1]

        proc dialAndVerify(maddr: MultiAddress) {.async.} =
          let conn = await client.dial(maddr)
          defer:
            await conn.close()

          var buffer = newSeq[byte](message.len)
          await conn.readExactly(addr buffer[0], message.len)

          check string.fromBytes(buffer) == message

        # Dial the same server multiple time in a row
        await dialAndVerify(server.addrs[0])
        await dialAndVerify(server.addrs[0])
        await dialAndVerify(server.addrs[0])

        # Dial the same server on different addresses
        await dialAndVerify(server.addrs[1])
        await dialAndVerify(server.addrs[0])
        await dialAndVerify(server.addrs[1])

      let server = transportProvider()
      await server.start(addrs)
      let serverFut = serverHandler(server)

      await runClient(server)
      await serverFut.cancelAndWait()
      await server.stop()

    asyncTest "read or write on closed connection":
      proc serverHandler(server: Transport) {.async.} =
        let conn = await server.accept()
        await conn.close()

      proc runClient(server: Transport) {.async.} =
        let client = transportProvider()
        let conn = await client.dial(server.addrs[0])
        defer:
          await conn.close()
          await client.stop()

        var buffer = newSeq[byte](1)
        expect LPStreamEOFError:
          await conn.readExactly(addr buffer[0], 1)

        if isWsTransport(server.addrs[0]):
          # WS throws on write after EOF
          expect LPStreamEOFError:
            await conn.write(buffer)
        else:
          await conn.write(buffer)

      let server = transportProvider()
      await server.start(@[ma(ma1)])
      let serverFut = serverHandler(server)

      await runClient(server)
      await serverFut
      await server.stop()

    asyncTest "write after remote half-close":
      let server = transportProvider()
      await server.start(@[ma(ma1)])
      let acceptFut = server.accept()
      let client = transportProvider()
      let clientConn = await client.dial(server.addrs[0])
      let serverConn = await acceptFut
      defer:
        await clientConn.close()
        await serverConn.close()
        await client.stop()
        await server.stop()

      if isWsTransport(server.addrs[0]):
        # WebSocket has no half-close: closeWrite fully closes the session.
        # Read concurrently so the WS close handshake completes, then the read
        # fails with EOF and subsequent writes also fail with EOF.
        var wb: byte
        let readFut = clientConn.readExactly(addr wb, 1)
        await serverConn.closeWrite()
        expect LPStreamEOFError:
          await readFut
        expect LPStreamEOFError:
          await clientConn.write(@[1'u8])
        return

      await serverConn.closeWrite()

      var b: byte
      expect LPStreamEOFError:
        await clientConn.readExactly(addr b, 1)

      # Remote EOF only closes our read half. We still can write
      await clientConn.write(@[1'u8])
      await serverConn.readExactly(addr b, 1)
      check b == 1
