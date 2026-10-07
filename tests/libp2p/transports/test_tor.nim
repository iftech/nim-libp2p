# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}
{.push raises: [].}

import tables, chronos, stew/[byteutils]
import std/strutils except fromHex
import
  ../../../libp2p/[
    stream/connection,
    transports/transport,
    transports/tortransport,
    transports/tcptransport,
    upgrademngrs/upgrade,
    multiaddress,
    muxers/muxer,
    muxers/mplex/mplex,
    builders,
  ]
import ../../tools/[unittest, crypto, multiaddress]
import ../../stubs/torstub
import ./basic_tests
import ./cancellation_tests
import ./connection_tests
import ./stream_tests

suite "Tor transport":
  const torServer = initTAddress("127.0.0.1", 9050.Port)
  var stub: TorServerStub
  var startFut: Future[void]

  proc torTransProvider(): Transport =
    TorTransport.new(torServer, {ReuseAddr}, Upgrade())

  proc streamProvider(conn: RawConn, handle: bool = true): Muxer =
    let muxer = Mplex.new(conn)
    if handle:
      asyncSpawn muxer.handle()
    muxer

  const
    address =
      "/ip4/127.0.0.1/tcp/8080/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad:80"
    address2 =
      "/ip4/127.0.0.1/tcp/8081/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcae:81"
    validWireAddresses = @[
      # Addresses for listening (TcpOnion3)
      "/ip4/127.0.0.1/tcp/0/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad:80",
      "/ip6/::1/tcp/0/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad:80",
    ]
    validNonWireAddresses = @[
      # Addresses for dialing
      "/ip4/127.0.0.1/tcp/1234", # TCP
      "/ip6/::1/tcp/1234", # TCP over IPv6
      "/dns/example.com/tcp/1234", # TCP with DNS
      "/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad:80", # Onion3
    ]
    invalidAddresses = @[
      "/ip4/127.0.0.1/udp/1234", # UDP not supported
      "/ip4/127.0.0.1/tcp/1234/ws", # WebSocket not supported
      "/ip4/127.0.0.1/tcp/1234/quic-v1", # QUIC not supported
      "/ip4/127.0.0.1/tcp/1234/wss", # WSS not supported
    ]

  setup:
    stub = TorServerStub.new()
    stub.registerAddr("127.0.0.1:8080", "/ip4/127.0.0.1/tcp/8080")
    stub.registerAddr("libp2p.nim:8080", "/ip4/127.0.0.1/tcp/8080")
    stub.registerAddr("::1:8080", "/ip6/::1/tcp/8080")
    stub.registerAddr(
      "a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad.onion:80",
      "/ip4/127.0.0.1/tcp/8080",
    )
    stub.registerAddr(
      "a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcae.onion:81",
      "/ip4/127.0.0.1/tcp/8081",
    )
    startFut = stub.start(torServer)

  teardown:
    waitFor startFut.cancelAndWait()
    waitFor stub.stop()
    checkTrackers()

  basicTransportTest(
    torTransProvider, address, validWireAddresses, validNonWireAddresses,
    invalidAddresses,
  )
  connectionTransportTest(torTransProvider, address, address2)
  cancellationTransportTest(torTransProvider, address)
  upgradeCancellationTransportTest(torTransProvider, address)
  streamTransportTest(
    torTransProvider, ma(address), Opt.none(MultiAddress), streamProvider
  )

  proc test(lintesAddr: string, dialAddr: string) {.async.} =
    let server = TcpTransport.new({ReuseAddr}, Upgrade())
    let ma2 = @[ma(lintesAddr)]
    await server.start(ma2)

    proc runClient() {.async.} =
      let client = TorTransport.new(transportAddress = torServer, upgrade = Upgrade())
      let conn = await client.dial("", ma(dialAddr))

      await conn.write("client")
      var resp: array[6, byte]
      await conn.readExactly(addr resp, 6)
      await conn.close()

      check string.fromBytes(resp) == "server"
      await client.stop()

    proc serverAcceptHandler() {.async.} =
      let conn = await server.accept()
      var resp: array[6, byte]
      await conn.readExactly(addr resp, 6)
      check string.fromBytes(resp) == "client"

      await conn.write("server")
      await conn.close()
      await server.stop()

    asyncSpawn serverAcceptHandler()
    await runClient()

  asyncTest "test start and dial using ipv4":
    await test("/ip4/127.0.0.1/tcp/8080", "/ip4/127.0.0.1/tcp/8080")

  asyncTest "test start and dial using ipv6":
    await test("/ip6/::1/tcp/8080", "/ip6/::1/tcp/8080")

  asyncTest "test start and dial using dns":
    await test("/ip4/127.0.0.1/tcp/8080", "/dns/libp2p.nim/tcp/8080")

  asyncTest "SOCKS5 DNS address length boundary":
    let
      maxDnsAddress = repeat('a', 255)
      oversizedDnsAddress = repeat('a', 256)
      client = TorTransport.new(transportAddress = torServer, upgrade = Upgrade())
    stub.registerAddr(maxDnsAddress & ":8080", "/ip4/127.0.0.1/tcp/8080")

    let server = TcpTransport.new({ReuseAddr}, Upgrade())
    await server.start(@[ma("/ip4/127.0.0.1/tcp/8080")])
    let acceptFut = server.accept()

    let conn = await client.dial("", ma("/dns/" & maxDnsAddress & "/tcp/8080"))
    let serverConn = await acceptFut
    await conn.close()
    await serverConn.close()
    await server.stop()

    expect TransportDialError:
      discard await client.dial("", ma("/dns/" & oversizedDnsAddress & "/tcp/8080"))
    await client.stop()

  asyncTest "test start and dial usion onion3 and builder":
    const TestCodec = "/test/proto/1.0.0" # custom protocol string identifier

    type TestProto = ref object of LPProtocol # declare a custom protocol

    proc new(T: typedesc[TestProto]): T =
      # every incoming connections will be in handled in this closure
      proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
        try:
          var resp: array[6, byte]
          await stream.readExactly(addr resp, 6)
          check string.fromBytes(resp) == "client"
          await stream.write("server")
        except LPStreamError:
          raiseAssert "Unexpected LPStreamError in Tor onion3 test handler"
        finally:
          await stream.close()

      return T.new(codecs = @[TestCodec], handler = handle)

    let maddr = MultiAddress
      .init(
        "/ip4/127.0.0.1/tcp/8080/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad:80"
      )
      .tryGet()

    let serverSwitch = TorSwitch.new(torServer, rng(), @[maddr], {ReuseAddr})

    # setup the custom proto
    let testProto = TestProto.new()

    serverSwitch.mount(testProto)
    await serverSwitch.start()

    let serverPeerId = serverSwitch.peerInfo.peerId
    let serverAddress = serverSwitch.peerInfo.addrs

    proc startClient() {.async.} =
      let clientSwitch =
        TorSwitch.new(torServer = torServer, rng = rng(), flags = {ReuseAddr})

      let conn = await clientSwitch.dial(serverPeerId, serverAddress, TestCodec)

      await conn.write("client")

      var resp: array[6, byte]
      await conn.readExactly(addr resp, 6)
      check string.fromBytes(resp) == "server"
      await conn.close()
      await clientSwitch.stop()

    await startClient()

    await serverSwitch.stop()

  test "It's not possible to add another transport in TorSwitch":
    let torSwitch =
      TorSwitch.new(torServer = torServer, rng = rng(), flags = {ReuseAddr})
    expect(AssertionDefect):
      torSwitch.addTransport(TcpTransport.new(upgrade = Upgrade()))
    waitFor torSwitch.stop()

suite "Tor authentication":
  teardown:
    checkTrackers()

  asyncTest "rejected authentication closes the proxy socket":
    let server = createStreamServer(initTAddress("127.0.0.1:0"))
    let transport = TorTransport.new(server.localAddress, upgrade = Upgrade())
    let dialing = transport.dial("", ma("/ip4/127.0.0.1/tcp/1234"))
    let peer = await server.accept()
    defer:
      await peer.closeWait()
      await server.closeWait()
      await transport.stop()
    var greeting: array[3, byte]
    await peer.readExactly(addr greeting[0], greeting.len)
    discard await peer.write(@[5'u8, 255])
    expect TransportDialError:
      discard await dialing
    var reply: array[1, byte]
    check (await peer.readOnce(addr reply[0], 1)) == 0

  asyncTest "cancelled authentication closes the proxy socket":
    let server = createStreamServer(initTAddress("127.0.0.1:0"))
    let transport = TorTransport.new(server.localAddress, upgrade = Upgrade())
    let dialing = transport.dial("", ma("/ip4/127.0.0.1/tcp/1234"))
    let peer = await server.accept()
    defer:
      await peer.closeWait()
      await server.closeWait()
      await transport.stop()
    var greeting: array[3, byte]
    await peer.readExactly(addr greeting[0], greeting.len)
    await dialing.cancelAndWait()
    var reply: array[1, byte]
    check (await peer.readOnce(addr reply[0], 1)) == 0

  asyncTest "truncated authentication is a dial error":
    let server = createStreamServer(initTAddress("127.0.0.1:0"))
    let transport = TorTransport.new(server.localAddress, upgrade = Upgrade())
    let dialing = transport.dial("", ma("/ip4/127.0.0.1/tcp/1234"))
    let peer = await server.accept()
    defer:
      await peer.closeWait()
      await server.closeWait()
      await transport.stop()
    var greeting: array[3, byte]
    await peer.readExactly(addr greeting[0], greeting.len)
    discard await peer.write(@[5'u8])
    await peer.shutdownWait()
    expect TransportDialError:
      discard await dialing

suite "Tor CONNECT reply":
  teardown:
    checkTrackers()

  proc checkRejectedReply(response: seq[byte], reason = "") {.async.} =
    let server = createStreamServer(initTAddress("127.0.0.1:0"))
    let transport = TorTransport.new(server.localAddress, upgrade = Upgrade())
    let dialing = transport.dial("", ma("/ip4/127.0.0.1/tcp/1234"))
    let peer = await server.accept()
    defer:
      await peer.closeWait()
      await server.closeWait()
      await transport.stop()
    var greeting: array[3, byte]
    await peer.readExactly(addr greeting[0], greeting.len)
    discard await peer.write(@[5'u8, 0])
    var request: array[10, byte]
    await peer.readExactly(addr request[0], request.len)
    discard await peer.write(response)
    # Signal EOF while keeping the read side open to observe client cleanup.
    await peer.shutdownWait()
    expectMsgContains TransportDialError, reason:
      discard await dialing
    var reply: array[1, byte]
    check (await peer.readOnce(addr reply[0], 1)) == 0

  asyncTest "truncated CONNECT header closes the proxy socket":
    await checkRejectedReply(@[5'u8, 0, 0])

  asyncTest "missing CONNECT FQDN length closes the proxy socket":
    await checkRejectedReply(@[5'u8, 0, 0, 3])

  asyncTest "truncated CONNECT IPv4 address closes the proxy socket":
    await checkRejectedReply(@[5'u8, 0, 0, 1, 127, 0, 0])

  asyncTest "truncated CONNECT IPv4 port closes the proxy socket":
    await checkRejectedReply(@[5'u8, 0, 0, 1, 127, 0, 0, 1, 0])

  asyncTest "truncated CONNECT IPv6 port closes the proxy socket":
    await checkRejectedReply(@[5'u8, 0, 0, 4] & newSeq[byte](17))

  asyncTest "truncated CONNECT FQDN port closes the proxy socket":
    await checkRejectedReply(@[5'u8, 0, 0, 3, 3, 97, 98, 99, 0])

  asyncTest "CONNECT reply with another socks version is a dial error":
    await checkRejectedReply(@[4'u8, 0, 0, 1], "Unsupported socks version")

  asyncTest "CONNECT reply with a failure code is a dial error":
    await checkRejectedReply(@[5'u8, 5, 0, 1], "Server reply error: Connection Refused")

  asyncTest "CONNECT reply with an unknown code is a dial error":
    await checkRejectedReply(@[5'u8, 42, 0, 1], "Unexpected server reply")

  asyncTest "CONNECT reply with an unknown address type is a dial error":
    await checkRejectedReply(@[5'u8, 0, 0, 2], "Address not supported")
