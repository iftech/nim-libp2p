# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/tables
import chronos, stew/byteutils, protobuf_serialization
import
  ../../../libp2p/[
    errors,
    stream/bufferstream,
    stream/connection,
    transports/tcptransport,
    multiaddress,
    peerinfo,
    crypto/crypto,
    protocols/protocol,
    protocols/secure/noise,
    protocols/secure/plaintext,
    protocols/secure/secure,
  ]
import ../../tools/[unittest, crypto, futures, multiaddress, switch_builder]

const TestCodec = "/test/proto/1.0.0"

type TestProto = ref object of LPProtocol

{.push raises: [].}

method init(p: TestProto) {.gcsafe.} =
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    try:
      let msg = string.fromBytes(await stream.readLp(1024))
      check "Hello!" == msg
      await stream.writeLp("Hello!")
    except LPStreamError:
      raiseAssert "LPStreamError while handling connection"
    finally:
      await stream.close()

  p.codec = TestCodec
  p.handler = handle

{.pop.}

proc makeSwitch(ma: MultiAddress, outgoing: bool, plaintext: bool = false): Switch =
  let switch = makeStandardSwitchBuilder(ma).build()
  switch.muxedUpgrade.secureManagers =
    if plaintext:
      @[Secure(PlainText.new())]
    else:
      @[Secure(Noise.new(rng(), switch.peerInfo.privateKey, outgoing = outgoing))]
  switch

suite "Noise":
  teardown:
    checkTrackers()

  let maddr = TcpWildcardAddress

  test "stream muxers use the registered Noise extension field":
    let
      muxer = "/yamux/1.0.0"
      encoded = Protobuf.encode(NoiseExtensionsMsg(streamMuxers: @[muxer]))
      expected = @[0x12'u8, 0x0C'u8] & muxer.toBytes()

    check encoded == expected
    check Protobuf.decode(expected, NoiseExtensionsMsg).streamMuxers == @[muxer]

  asyncTest "e2e: handle write + noise":
    let
      server = @[maddr]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverInfo = PeerInfo.new(serverPrivKey, server)
      serverNoise = Noise.new(rng(), serverPrivKey, outgoing = false)

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(server)

    proc acceptHandler() {.async.} =
      let conn = await transport1.accept()
      let sconn = await serverNoise.secure(conn, Opt.none(PeerId))
      try:
        await sconn.write("Hello!")
      finally:
        await sconn.close()
        await conn.close()

    let
      acceptFut = acceptHandler()
      transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      clientPrivKey = PrivateKey.random(ECDSA, rng()).get()
      clientNoise = Noise.new(rng(), clientPrivKey, outgoing = true)
      conn = await transport2.dial(transport1.addrs[0])

    let sconn = await clientNoise.secure(conn, Opt.some(serverInfo.peerId))

    var msg = newSeq[byte](6)
    await sconn.readExactly(addr msg[0], 6)

    await sconn.close()
    await conn.close()
    await acceptFut
    await transport1.stop()
    await transport2.stop()

    check string.fromBytes(msg) == "Hello!"

  asyncTest "e2e: handle write + noise (wrong prologue)":
    let
      server = @[maddr]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverNoise = Noise.new(rng(), serverPrivKey, outgoing = false)

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())

    asyncSpawn transport1.start(server)

    proc acceptHandler() {.async.} =
      var conn: RawConn
      expect LPStreamError:
        conn = await transport1.accept()
        discard await serverNoise.secure(conn, Opt.none(PeerId))
      await conn.close()

    let
      handlerWait = acceptHandler()
      transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      clientPrivKey = PrivateKey.random(ECDSA, rng()).get()
      clientNoise = Noise.new(
        rng(), clientPrivKey, outgoing = true, commonPrologue = @[1'u8, 2'u8, 3'u8]
      )
      conn = await transport2.dial(transport1.addrs[0])

    var sconn: SecureConn = nil
    expect NoiseDecryptTagError:
      sconn = await clientNoise.secure(conn, Opt.some(conn.peerId))

    await conn.close()
    await handlerWait
    await transport1.stop()
    await transport2.stop()

  asyncTest "e2e: handle read + noise":
    let
      server = @[maddr]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverInfo = PeerInfo.new(serverPrivKey, server)
      serverNoise = Noise.new(rng(), serverPrivKey, outgoing = false)

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(server)

    proc acceptHandler() {.async.} =
      let conn = await transport1.accept()
      let sconn = await serverNoise.secure(conn, Opt.none(PeerId))
      defer:
        await sconn.close()
        await conn.close()

      var msg = newSeq[byte](6)
      await sconn.readExactly(addr msg[0], 6)
      check string.fromBytes(msg) == "Hello!"

    let
      acceptFut = acceptHandler()
      transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      clientPrivKey = PrivateKey.random(ECDSA, rng()).get()
      clientNoise = Noise.new(rng(), clientPrivKey, outgoing = true)
      conn = await transport2.dial(transport1.addrs[0])
    let sconn = await clientNoise.secure(conn, Opt.some(serverInfo.peerId))

    await sconn.write("Hello!")
    await acceptFut
    await sconn.close()
    await conn.close()
    await transport1.stop()
    await transport2.stop()

  asyncTest "e2e: handle read + noise fragmented":
    let
      server = @[maddr]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverInfo = PeerInfo.new(serverPrivKey, server)
      serverNoise = Noise.new(rng(), serverPrivKey, outgoing = false)
      readTask = newFuture[void]()

    var hugePayload = newSeq[byte](0xFFFFF)
    rng().generate(hugePayload)

    let
      transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      listenFut = transport1.start(server)

    proc acceptHandler() {.async.} =
      let conn = await transport1.accept()
      let sconn = await serverNoise.secure(conn, Opt.none(PeerId))
      defer:
        await sconn.close()
      let msg = await sconn.readLp(1024 * 1024)
      check msg == hugePayload
      readTask.complete()

    let
      acceptFut = acceptHandler()
      transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      clientPrivKey = PrivateKey.random(ECDSA, rng()).get()
      clientNoise = Noise.new(rng(), clientPrivKey, outgoing = true)
      conn = await transport2.dial(transport1.addrs[0])
    let sconn = await clientNoise.secure(conn, Opt.some(serverInfo.peerId))

    await sconn.writeLp(hugePayload)
    await readTask

    await sconn.close()
    await conn.close()
    await acceptFut
    await transport2.stop()
    await transport1.stop()
    await listenFut

  asyncTest "e2e: use switch dial proto string":
    var switch1 = makeSwitch(maddr, false)
    var switch2 = makeSwitch(maddr, true)

    let testProto = new TestProto
    testProto.init()
    testProto.codec = TestCodec
    switch1.mount(testProto)
    await switch1.start()
    await switch2.start()
    let conn = await switch2.dial(switch1, TestCodec)
    await conn.writeLp("Hello!")
    let msg = string.fromBytes(await conn.readLp(1024))
    check "Hello!" == msg
    await conn.close()

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e: early muxer negotiation uses initiator preference":
    var switch1 = makeStandardSwitchBuilder(maddr).withYamux().build()
    var switch2 = SwitchBuilder
      .new()
      .withRng(rng())
      .withNoise()
      .withAddress(maddr)
      .withTcpTransport()
      .withYamux()
      .withMplex()
      .build()

    let testProto = new TestProto
    testProto.init()
    switch1.mount(testProto)
    await switch1.start()
    await switch2.start()

    let conn =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)
    await conn.writeLp("Hello!")
    check string.fromBytes(await conn.readLp(1024)) == "Hello!"
    await conn.close()

    let
      initiatorMuxer = switch2.connManager.getConnections()[switch1.peerInfo.peerId][0]
      responderMuxer = switch1.connManager.getConnections()[switch2.peerInfo.peerId][0]
    check SecureConn(initiatorMuxer.connection).earlyMuxer == "/yamux/1.0.0"
    check SecureConn(responderMuxer.connection).earlyMuxer == "/yamux/1.0.0"

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e: early muxer negotiation over WebSocket":
    var switch1 = makeStandardSwitchBuilder(WsAutoAddress).build()
    var switch2 = makeStandardSwitchBuilder(WsAutoAddress).build()

    let testProto = new TestProto
    testProto.init()
    switch1.mount(testProto)
    await switch1.start()
    await switch2.start()

    let conn =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)
    await conn.writeLp("Hello!")
    let msg = string.fromBytes(await conn.readLp(1024))
    check "Hello!" == msg
    await conn.close()
    let muxer = switch2.connManager.getConnections()[switch1.peerInfo.peerId][0]
    check SecureConn(muxer.connection).earlyMuxer == "/mplex/6.7.0"

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e: early muxer negotiation falls back without advertised muxers":
    var switch1 = makeStandardSwitchBuilder(maddr).build()
    var switch2 = makeSwitch(maddr, true)

    let testProto = new TestProto
    testProto.init()
    switch1.mount(testProto)
    await switch1.start()
    await switch2.start()

    let conn =
      await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)
    await conn.writeLp("Hello!")
    let msg = string.fromBytes(await conn.readLp(1024))
    check "Hello!" == msg
    await conn.close()
    let
      initiatorMuxer = switch2.connManager.getConnections()[switch1.peerInfo.peerId][0]
      responderMuxer = switch1.connManager.getConnections()[switch2.peerInfo.peerId][0]
    check SecureConn(initiatorMuxer.connection).earlyMuxer.len == 0
    check SecureConn(responderMuxer.connection).earlyMuxer.len == 0

    await allFuturesRaising(switch1.stop(), switch2.stop())

  asyncTest "e2e: test wrong secure negotiation":
    var switch1 = makeSwitch(maddr, false)
    var switch2 = makeSwitch(maddr, true, true)
      # PlainText enabled; mismatched with Noise, so we want this to fail

    let testProto = new TestProto
    testProto.init()
    testProto.codec = TestCodec
    switch1.mount(testProto)
    await switch1.start()
    await switch2.start()
    expect DialFailedError:
      discard await switch2.dial(switch1, TestCodec)

    await allFuturesRaising(switch1.stop(), switch2.stop())
