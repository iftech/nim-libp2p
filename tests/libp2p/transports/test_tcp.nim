# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    transports/transport,
    transports/tcptransport,
    upgrademngrs/upgrade,
    muxers/muxer,
    muxers/mplex/mplex,
    muxers/yamux/yamux,
  ]
import ../../tools/[unittest, multiaddress]
import ./basic_tests
import ./cancellation_tests
import ./connection_tests
import ./stream_tests
import ./tcp_tests

proc tcpTransProvider(): Transport =
  TcpTransport.new(upgrade = Upgrade())

proc mplexStreamProvider(conn: RawConn, handle: bool = true): Muxer =
  let muxer = Mplex.new(conn)
  if handle:
    asyncSpawn muxer.handle()
  muxer

proc yamuxStreamProvider(conn: RawConn, handle: bool = true): Muxer =
  let muxer = Yamux.new(conn)
  if handle:
    asyncSpawn muxer.handle()
  muxer

const
  addressIP4 = "/ip4/127.0.0.1/tcp/0"
  addressIP6 = "/ip6/::/tcp/0"
  validWireAddresses = @["/ip4/127.0.0.1/tcp/1234", "/ip6/::1/tcp/1234"]
  validNonWireAddresses = @[
    "/dns/example.com/tcp/1234", "/dns4/example.com/tcp/1234",
    "/dns6/example.com/tcp/1234",
  ]
  invalidAddresses = @[
    "/ip4/127.0.0.1/udp/1234", # UDP instead of TCP
    "/ip4/127.0.0.1/tcp/1234/ws", # TCP with ws (should be handled by WsTransport)
    "/ip4/127.0.0.1/tcp/1234/wss", # TCP with wss (should be handled by WsTransport)
    "/ip4/127.0.0.1", # Missing port
  ]

suite "TCP transport":
  teardown:
    checkTrackers()

  # shared tests with other transports
  basicTransportTest(
    tcpTransProvider, addressIP4, validWireAddresses, validNonWireAddresses,
    invalidAddresses,
  )
  cancellationTransportTest(tcpTransProvider, addressIP4)
  upgradeCancellationTransportTest(tcpTransProvider, addressIP4)
  # tcp specific tests
  tcpTests()

suite "TCP transport: ipv4":
  teardown:
    checkTrackers()

  connectionTransportTest(tcpTransProvider, addressIP4)

suite "TCP transport: ipv6":
  teardown:
    checkTrackers()

  connectionTransportTest(tcpTransProvider, addressIP6)

suite "TCP transport: mplex":
  teardown:
    checkTrackers()

  streamTransportTest(
    tcpTransProvider, ma(addressIP4), Opt.some(ma(addressIP6)), mplexStreamProvider
  )

suite "TCP transport: yamux":
  teardown:
    checkTrackers()

  streamTransportTest(
    tcpTransProvider, ma(addressIP4), Opt.some(ma(addressIP6)), yamuxStreamProvider
  )
