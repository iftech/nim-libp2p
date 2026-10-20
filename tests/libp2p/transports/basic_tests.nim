# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}
import chronos, results
import
  ../../../libp2p/[stream/connection, transports/transport, multiaddress, multicodec]
import ../../tools/[unittest, multiaddress]
import ./utils

template basicTransportTest*(
    provider: TransportProvider,
    address: string,
    validWireAddresses: seq[string],
    validNonWireAddresses: seq[string],
    invalidAddresses: seq[string],
) =
  block:
    let transportProvider = provider
    let maddr = ma(address)

    asyncTest "can handle local address":
      let transport = transportProvider()
      await transport.start(@[maddr])
      defer:
        await transport.stop()

      check transport.handles(transport.addrs[0])

    asyncTest "handle dial cancellation":
      let server = transportProvider()
      await server.start(@[maddr])
      let client = transportProvider()
      defer:
        await allFutures(client.stop(), server.stop())

      let connFut = client.dial(server.addrs[0])
      await connFut.cancelAndWait()

      check connFut.cancelled

    asyncTest "handle accept cancellation":
      let server = transportProvider()
      await server.start(@[maddr])
      defer:
        await server.stop()

      let acceptFut = server.accept()
      await acceptFut.cancelAndWait()

      check acceptFut.cancelled

    asyncTest "stopping transport kills connections":
      let server = transportProvider()
      await server.start(@[maddr])
      let client = transportProvider()

      let acceptFut = server.accept()
      let clientConn = await client.dial(server.addrs[0])
      let serverConn = await acceptFut

      await allFutures(client.stop(), server.stop())

      check:
        clientConn.closed()
        serverConn.closed()

    asyncTest "stopping transport unblocks a pending accept":
      # TODO: nim-libp2p#2713
      let server = transportProvider()
      await server.start(@[maddr])

      # park an accept with nothing dialing, then stop the transport under it
      let acceptFut = server.accept()
      await server.stop()

      expect TransportClosedError:
        discard await acceptFut

    asyncTest "accept on a stopped transport reports it closed without waiting":
      let server = transportProvider()
      await server.start(@[maddr])
      await server.stop()

      let acceptFut = server.accept()
      check:
        await acceptFut.withTimeout(200.milliseconds)
        acceptFut.failed()

    asyncTest "accept on a never-started transport reports it closed without waiting":
      let server = transportProvider()
      let acceptFut = server.accept()
      check:
        await acceptFut.withTimeout(200.milliseconds)
        acceptFut.failed()

    asyncTest "transport start/stop events":
      let transport = transportProvider()

      await transport.start(@[maddr])
      check await transport.onRunning.wait().withTimeout(1.seconds)

      await transport.stop()
      check await transport.onStop.wait().withTimeout(1.seconds)

    asyncTest "start succeeds for valid wire addresses":
      for maddr in validWireAddresses:
        let transport = transportProvider()
        await transport.start(@[ma(maddr)])
        await transport.stop()

    asyncTest "start fails when no address is provided":
      let transport = transportProvider()
      expect TransportStartError:
        await transport.start(@[])

    asyncTest "start fails for valid non-wire addresses":
      for addrs in validNonWireAddresses:
        let transport = transportProvider()
        let maddr = ma(addrs)

        expect TransportStartError:
          await transport.start(@[maddr])

    asyncTest "start behaviour for invalid addresses":
      for addrs in invalidAddresses:
        let transport = transportProvider()
        let maddr = ma(addrs)

        expect TransportStartError:
          await transport.start(@[maddr])

    asyncTest "multiaddress validation - accept valid addresses":
      let transport = transportProvider()

      for validAddress in validWireAddresses & validNonWireAddresses:
        check transport.handles(ma(validAddress))

    asyncTest "multiaddress validation - reject invalid addresses":
      let transport = transportProvider()

      for invalidAddress in invalidAddresses:
        check not transport.handles(ma(invalidAddress))

    asyncTest "address normalization - port assignment":
      # Start with port 0 and verify it gets assigned a real port
      if isTorTransport(maddr):
        # The advertised address is the onion3 address with a fixed, pre-configured port
        skip()
        return

      let transport = transportProvider()
      await transport.start(@[maddr])
      defer:
        await transport.stop()

      let assignedPort = extractPort(transport.addrs[0])

      check:
        assignedPort > 0
        # Ensure IP address is the same
        transport.addrs[0][multiCodec("ip4")].get() == maddr[multiCodec("ip4")].get()

    asyncTest "cannot bind second listener to same port":
      if isTcpTransport(maddr):
        #TODO: Find out why doesn't throw for TCP
        skip()
        return

      let server = transportProvider()
      await server.start(@[maddr])
      defer:
        await server.stop()

      # Try to bind client transport to same address
      let server2 = transportProvider()
      expect LPError:
        await server2.start(@[server.addrs[0]])

    asyncTest "dial with malformed multiaddresses":
      let client = transportProvider() # not started
      let server = transportProvider()
      await server.start(@[maddr])
      defer:
        await server.stop()

      let invalid = ma("/ip4/127.0.0.1")
      expect LPError:
        discard await server.dial("", invalid)
      expect LPError:
        discard await client.dial("", invalid)

    asyncTest "observedAddr and localAddr are populated on connections":
      if isTorTransport(maddr):
        # Tor transport doesn't provide observedAddr for privacy reasons
        skip()
        return

      let server = transportProvider()
      await server.start(@[maddr])
      let client = transportProvider()

      let acceptFut = server.accept()
      let clientConn = await client.dial(server.addrs[0])
      let serverConn = await acceptFut

      defer:
        await allFutures(clientConn.close(), serverConn.close())
        await allFutures(client.stop(), server.stop())

      # Verify all addresses are populated
      check:
        clientConn.observedAddr.isSome()
        clientConn.localAddr.isSome()
        serverConn.observedAddr.isSome()
        serverConn.localAddr.isSome()

      # Verify address symmetry and correctness
      check:
        clientConn.observedAddr.get() == serverConn.localAddr.get()
        serverConn.localAddr.get() == server.addrs[0]
        server.handles(clientConn.observedAddr.get())
        client.handles(serverConn.observedAddr.get())
