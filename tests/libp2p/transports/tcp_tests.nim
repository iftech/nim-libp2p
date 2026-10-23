# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    stream/connection,
    transports/tcptransport,
    upgrademngrs/upgrade,
    multiaddress,
    multicodec,
    wire,
  ]
import ../../tools/[multiaddress, unittest]
import ./utils

const zeroMAStrIP4 = "/ip4/0.0.0.0/tcp/0"

template tcpTests*() =
  block:
    let listenMA = ma(zeroMAStrIP4)

    asyncTest "starting with duplicate but zero ports addresses must NOT fail":
      let transport = TcpTransport.new(upgrade = Upgrade())

      await transport.start(@[listenMA, listenMA])
      await transport.stop()

    asyncTest "bind to listening port when not reachable":
      let transport1 = TcpTransport.new(upgrade = Upgrade())
      await transport1.start(@[listenMA])

      let transport2 = TcpTransport.new(upgrade = Upgrade())
      await transport2.start(@[listenMA])

      let transport3 = TcpTransport.new(upgrade = Upgrade())
      await transport3.start(@[listenMA])

      let listeningPortTransport1 = transport1.addrs[0][multiCodec("tcp")].get()

      discard await transport1.dial(transport2.addrs[0])
      let acceptedConn = await transport2.accept()
      let acceptedPort2 = acceptedConn.observedAddr.get()[multiCodec("tcp")].get()
      check listeningPortTransport1 != acceptedPort2

      transport1.networkReachability = NetworkReachability.NotReachable

      discard await transport1.dial(transport3.addrs[0])
      let acceptedConn3 = await transport3.accept()
      let acceptedPort3 = acceptedConn3.observedAddr.get()[multiCodec("tcp")].get()
      check listeningPortTransport1 == acceptedPort3

      await allFutures(transport1.stop(), transport2.stop(), transport3.stop())

    asyncTest "custom timeout":
      let server =
        TcpTransport.new(upgrade = Upgrade(), connectionsTimeout = 1.milliseconds)
      await server.start(@[listenMA])

      proc serverHandler() {.async.} =
        let conn = await server.accept()
        await conn.join()

      let handlerFut = serverHandler()

      let streamTransport = await connect(server.addrs[0])
      await handlerFut
      await streamTransport.closeWait()
      await server.stop()

    asyncTest "NotReachable dual-stack dialer reuses port within target family":
      let dialer = TcpTransport.new(upgrade = Upgrade())
      await dialer.start(@[TcpAutoAddressIP4, TcpAutoAddressIP6])
      defer:
        await dialer.stop()

      # addrs keeps start order, so addrs[0] is IPv4 and addrs[1] is IPv6.
      check IP4.matchPartial(dialer.addrs[0])
      check IP6.matchPartial(dialer.addrs[1])

      let serverV6 = TcpTransport.new(upgrade = Upgrade())
      await serverV6.start(@[TcpAutoAddressIP6])
      defer:
        await serverV6.stop()

      dialer.networkReachability = NetworkReachability.NotReachable

      discard await dialer.dial(serverV6.addrs[0])
      let acceptedConn = await serverV6.accept()
      let acceptedPort = acceptedConn.observedAddr.get()[multiCodec("tcp")].get()
      let listeningPort = dialer.addrs[1][multiCodec("tcp")].get()
      check acceptedPort == listeningPort

    asyncTest "start cleans up bound servers when a later bind fails":
      let unbindable = ma("/ip4/192.0.2.1/tcp/0")
      let transport = TcpTransport.new(upgrade = Upgrade())

      expect TcpTransportError:
        await transport.start(@[TcpAutoAddressIP4, unbindable])

      check transport.servers.len == 0

    asyncTest "dial of a non-wire address is a TcpTransportError":
      let transport = TcpTransport.new(upgrade = Upgrade())

      expect TcpTransportError:
        discard await transport.dial("", ma("/dns/example.com/tcp/1234"))
      await transport.stop()
