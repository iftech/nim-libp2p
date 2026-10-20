# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}
{.push raises: [].}

import chronos, stew/byteutils
import ../../../libp2p/[transports/memorytransport, transports/transport, multiaddress]
import ../../tools/[unittest, crypto, multiaddress]
import ./cancellation_tests

proc memoryTransProvider(): Transport =
  MemoryTransport.new(rng = rng())

suite "Memory transport":
  teardown:
    checkTrackers()

  asyncTest "a dial has no cancellation point":
    # It pairs the two ends with no await in between, so a cancel never splits them.
    let server = MemoryTransport.new(rng = rng())
    await server.start(@[ma(MemoryAutoAddress)])
    let client = MemoryTransport.new(rng = rng())
    defer:
      await allFutures(client.stop(), server.stop())

    let acceptFut = server.accept()
    let dialFut = client.dial("", server.addrs[0])
    await dialFut.cancelAndWait()

    check dialFut.completed()
    await dialFut.value().close()

    # Closing one end closes the other, so the accepted side goes with it.
    let accepted = await acceptFut
    check accepted.closed()

  asyncTest "a dial cancelled at any point leaves no socket open":
    check (await countCancelledDials(memoryTransProvider, MemoryAutoAddress)) == 0

  upgradeCancellationTransportTest(memoryTransProvider, MemoryAutoAddress)

  asyncTest "memory multiaddress":
    let maddr = ma("/memorytransport/addr-1")
    check $maddr == "/memorytransport/addr-1"

  asyncTest "can handle local address":
    let transport: MemoryTransport = MemoryTransport.new(rng = rng())
    await transport.start(@[ma("/memorytransport/addr-1")])
    check transport.handles(transport.addrs[0])
    await transport.stop()

  asyncTest "send receive":
    let maddr = @[ma("/memorytransport/addr-1")]
    let server = MemoryTransport.new(rng = rng())
    await server.start(maddr)

    proc runClient() {.async.} =
      let client = MemoryTransport.new(rng = rng())
      let conn = await client.dial("", maddr[0])

      await conn.write("client")
      var resp: array[6, byte]
      await conn.readExactly(addr resp, resp.len)
      await conn.close()

      check string.fromBytes(resp) == "server"
      await client.stop()

    proc serverAcceptHandler() {.async.} =
      let conn = await server.accept()
      var resp: array[6, byte]
      await conn.readExactly(addr resp, resp.len)
      check string.fromBytes(resp) == "client"

      await conn.write("server")
      await conn.close()
      await server.stop()

    asyncSpawn serverAcceptHandler()
    await runClient()

  asyncTest "server already started":
    let maddr = @[ma("/memorytransport/addr-1")]
    let server = MemoryTransport.new(rng = rng())
    await server.start(maddr)

    proc serverAcceptHandler() {.async.} =
      let conn = await server.accept()
      await conn.close()

    asyncSpawn serverAcceptHandler()

    # accept by server2 should not succeed
    let server2 = MemoryTransport.new(rng = rng())
    await server2.start(maddr)
    expect MemoryTransportError:
      discard await server2.accept()

    # dial to pass through server.accept()
    let conn = await server2.dial("", maddr[0])
    await conn.close()

    await server.stop()
    await server2.stop()

  asyncTest "server stopping - should drop accept":
    let maddr = @[ma("/memorytransport/addr-1")]
    let server = MemoryTransport.new(rng = rng())
    await server.start(maddr)

    proc serverAcceptHandler() {.async.} =
      # should throw error when stopped
      expect MemoryTransportAcceptStopped:
        discard await server.accept()

    asyncSpawn serverAcceptHandler()
    await server.stop()

  asyncTest "server conn close propagated to client":
    let maddr = @[ma("/memorytransport/addr-1")]
    let server = MemoryTransport.new(rng = rng())
    await server.start(maddr)

    proc serverAcceptHandler() {.async.} =
      let conn = await server.accept()
      var resp: array[6, byte]
      await conn.readExactly(addr resp, resp.len)
      check string.fromBytes(resp) == "client"

      await conn.close()
      await server.stop()

    proc runClient() {.async.} =
      let client = MemoryTransport.new(rng = rng())
      let conn = await client.dial("", maddr[0])

      await conn.write("client")
      var resp: array[6, byte]
      expect LPStreamEOFError:
        await conn.readExactly(addr resp, resp.len)

      await conn.close() # already closed
      await client.stop()

    asyncSpawn serverAcceptHandler()
    await runClient()

  asyncTest "client conn close propagated to server":
    let maddr = @[ma("/memorytransport/addr-1")]
    let server = MemoryTransport.new(rng = rng())
    await server.start(maddr)

    proc serverAcceptHandler() {.async.} =
      let conn = await server.accept()
      expect LPStreamEOFError:
        await conn.write("server") # already closed

      await conn.close()
      await server.stop()

    proc runClient() {.async.} =
      let client = MemoryTransport.new(rng = rng())
      let conn = await client.dial("", maddr[0])
      await conn.close()
      await client.stop()

    asyncSpawn serverAcceptHandler()
    await runClient()
