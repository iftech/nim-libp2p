# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    protocols/ping,
    multiaddress,
    peerinfo,
    peerid,
    stream/connection,
    multistream,
    transports/transport,
    transports/tcptransport,
    crypto/crypto,
    upgrademngrs/upgrade,
  ]
import ../../tools/[unittest, crypto, multiaddress]

suite "Ping":
  var
    maddr {.threadvar.}: MultiAddress
    serverFut {.threadvar.}: Future[void]
    acceptFut {.threadvar.}: Future[void]
    pingProto1 {.threadvar.}: Ping
    pingProto2 {.threadvar.}: Ping
    transport1 {.threadvar.}: Transport
    transport2 {.threadvar.}: Transport
    msListen {.threadvar.}: MultistreamSelect
    msDial {.threadvar.}: MultistreamSelect
    stream {.threadvar.}: Stream
    pingReceivedCount {.threadvar.}: int

  asyncSetup:
    maddr = TcpWildcardAddress

    transport1 = TcpTransport.new(upgrade = Upgrade())
    transport2 = TcpTransport.new(upgrade = Upgrade())

    let handlePing = proc(peer: PeerId): Future[void] {.async: (raises: []), gcsafe.} =
      inc pingReceivedCount

    pingProto1 = Ping.new(rng = rng())
    pingProto2 = Ping.new(handlePing, rng = rng())

    msListen = MultistreamSelect.new()
    msDial = MultistreamSelect.new()

    pingReceivedCount = 0

  asyncTeardown:
    await stream.close()
    await acceptFut
    await transport1.stop()
    await serverFut
    await transport2.stop()
    checkTrackers()

  asyncTest "simple ping":
    msListen.addHandler(pingProto1)
    serverFut = transport1.start(@[maddr])
    proc acceptHandler(): Future[void] {.async.} =
      let c = await transport1.accept()
      await msListen.handle(c)

    acceptFut = acceptHandler()
    stream = await transport2.dial(transport1.addrs[0])

    discard await msDial.select(stream, PingCodec)
    let first = await pingProto2.ping(stream)
    let second = await pingProto2.ping(stream)

    check not first.isZero()
    check not second.isZero()

  asyncTest "ping callback":
    msDial.addHandler(pingProto2)
    serverFut = transport1.start(@[maddr])
    proc acceptHandler(): Future[void] {.async.} =
      let c = await transport1.accept()
      discard await msListen.select(c, PingCodec)
      discard await pingProto1.ping(c)
      await c.close()

    acceptFut = acceptHandler()
    stream = await transport2.dial(transport1.addrs[0])

    await msDial.handle(stream)
    check pingReceivedCount == 1

  asyncTest "bad ping data ack":
    type FakePing = ref object of LPProtocol
    let fakePingProto = FakePing()
    proc fakeHandle(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      try:
        var
          buf: array[32, byte]
          fakebuf: array[32, byte]
        await stream.readExactly(addr buf[0], 32)
        await stream.write(@fakebuf)
      except LPStreamError:
        raiseAssert "LPStreamError while handling connection"

    fakePingProto.codec = PingCodec
    fakePingProto.handler = fakeHandle

    msListen.addHandler(fakePingProto)
    serverFut = transport1.start(@[maddr])
    proc acceptHandler(): Future[void] {.async.} =
      let c = await transport1.accept()
      await msListen.handle(c)

    acceptFut = acceptHandler()
    stream = await transport2.dial(transport1.addrs[0])

    discard await msDial.select(stream, PingCodec)

    expect WrongPingAckError:
      discard await pingProto2.ping(stream)
