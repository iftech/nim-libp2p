# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/strutils, bearssl, chronos, stew/byteutils
import
  ../../../libp2p/[
    protocols/connectivity/relay/relay,
    protocols/connectivity/relay/client,
    protocols/connectivity/relay/messages,
    protocols/connectivity/relay/utils,
    protocols/connectivity/relay/rtransport,
    multiaddress,
    peerinfo,
    peerid,
    stream/connection,
    switch,
    builders,
    upgrademngrs/upgrade,
    varint,
  ]
import ../../tools/[unittest, switch_builder, multiaddress]

suite "Circuit Relay":
  asyncTeardown:
    await allFutures(src.stop(), dst.stop(), srelay.stop())
    checkTrackers()

  var
    protos {.threadvar.}: seq[string]
    customProto {.threadvar.}: LPProtocol
    maddr {.threadvar.}: MultiAddress
    src {.threadvar.}: Switch
    dst {.threadvar.}: Switch
    srelay {.threadvar.}: Switch
    clSrc {.threadvar.}: RelayClient
    clDst {.threadvar.}: RelayClient
    r {.threadvar.}: Relay
    stream {.threadvar.}: Stream
    msg {.threadvar.}: seq[byte]
    rcv {.threadvar.}: Opt[RelayMessage]

  proc createMsg(
      msgType: Opt[RelayType] = Opt.none(RelayType),
      status: Opt[StatusV1] = Opt.none(StatusV1),
      src: Opt[RelayPeer] = Opt.none(RelayPeer),
      dst: Opt[RelayPeer] = Opt.none(RelayPeer),
  ): seq[byte] =
    encode(RelayMessage(msgType: msgType, srcPeer: src, dstPeer: dst, status: status))

  proc checkMsg(
      msg: Opt[RelayMessage],
      msgType: Opt[RelayType] = Opt.none(RelayType),
      status: Opt[StatusV1] = Opt.none(StatusV1),
      src: Opt[RelayPeer] = Opt.none(RelayPeer),
      dst: Opt[RelayPeer] = Opt.none(RelayPeer),
  ) =
    check:
      msg.isSome
    let m = msg.get()
    check:
      m.msgType == msgType
    check:
      m.status == status
    check:
      m.srcPeer == src
    check:
      m.dstPeer == dst

  proc customHandler(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    try:
      check "line1" == string.fromBytes(await stream.readLp(1024))
      await stream.writeLp("line2")
      check "line3" == string.fromBytes(await stream.readLp(1024))
      await stream.writeLp("line4")
    except LPStreamError:
      raiseAssert "LPStreamError while handling connection"
    finally:
      await stream.close()

  asyncSetup:
    # Create a custom prototype
    protos = @["/customProto", RelayV1Codec]
    customProto = new LPProtocol
    customProto.handler = customHandler
    customProto.codec = protos[0]

    maddr = TcpWildcardAddress
    clSrc = RelayClient.new()
    clDst = RelayClient.new()
    r = Relay.new(circuitRelayV1 = true)
    src = makeStandardSwitchBuilder(TcpAutoAddress).withCircuitRelay(clSrc).build()
    dst = makeStandardSwitchBuilder(TcpAutoAddress).withCircuitRelay(clDst).build()
    srelay = makeStandardSwitchBuilder(TcpAutoAddress).withCircuitRelay(r).build()

    dst.mount(customProto)

    await src.start()
    await dst.start()
    await srelay.start()

  asyncTest "Handle CanHop":
    msg = createMsg(Opt.some(CanHop))
    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(StatusV1.Success))

    stream = await src.dial(dst.peerInfo.peerId, dst.peerInfo.addrs, RelayV1Codec)
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopCantSpeakRelay))

    await stream.close()

  asyncTest "Malformed":
    stream = await srelay.dial(dst.peerInfo.peerId, dst.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(Opt.some(RelayType.Status))
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    await stream.close()
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(StatusV1.MalformedMessage))

  asyncTest "Handle Stop Error":
    stream = await srelay.dial(dst.peerInfo.peerId, dst.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Stop),
      Opt.none(StatusV1),
      Opt.none(RelayPeer),
      Opt.some(RelayPeer(peerId: dst.peerInfo.peerId, addrs: dst.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(StopSrcMultiaddrInvalid))

    stream = await srelay.dial(dst.peerInfo.peerId, dst.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Stop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: src.peerInfo.peerId, addrs: src.peerInfo.addrs)),
      Opt.none(RelayPeer),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(StopDstMultiaddrInvalid))

    stream = await srelay.dial(dst.peerInfo.peerId, dst.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Stop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: dst.peerInfo.peerId, addrs: dst.peerInfo.addrs)),
      Opt.some(RelayPeer(peerId: src.peerInfo.peerId, addrs: src.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    await stream.close()
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(StopDstMultiaddrInvalid))

  asyncTest "Handle Hop Error":
    stream = await src.dial(dst.peerInfo.peerId, dst.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(Opt.some(RelayType.Hop))
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopCantSpeakRelay))

    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Hop),
      Opt.none(StatusV1),
      Opt.none(RelayPeer),
      Opt.some(RelayPeer(peerId: dst.peerInfo.peerId, addrs: dst.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopSrcMultiaddrInvalid))

    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Hop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: dst.peerInfo.peerId, addrs: dst.peerInfo.addrs)),
      Opt.some(RelayPeer(peerId: dst.peerInfo.peerId, addrs: dst.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopSrcMultiaddrInvalid))

    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Hop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: src.peerInfo.peerId, addrs: src.peerInfo.addrs)),
      Opt.none(RelayPeer),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopDstMultiaddrInvalid))

    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Hop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: src.peerInfo.peerId, addrs: src.peerInfo.addrs)),
      Opt.some(RelayPeer(peerId: srelay.peerInfo.peerId, addrs: srelay.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopCantRelayToSelf))

    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Hop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: src.peerInfo.peerId, addrs: src.peerInfo.addrs)),
      Opt.some(RelayPeer(peerId: srelay.peerInfo.peerId, addrs: srelay.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopCantRelayToSelf))

    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Hop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: src.peerInfo.peerId, addrs: src.peerInfo.addrs)),
      Opt.some(RelayPeer(peerId: dst.peerInfo.peerId, addrs: dst.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopNoConnToDst))

    await srelay.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)

    var tmp = r.maxCircuit
    r.maxCircuit = 0
    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopCantSpeakRelay))
    r.maxCircuit = tmp
    await stream.close()

    tmp = r.maxCircuitPerPeer
    r.maxCircuitPerPeer = 0
    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopCantSpeakRelay))
    r.maxCircuitPerPeer = tmp
    await stream.close()

    let dst2 = makeStandardSwitch(TcpAutoAddress)
    await dst2.start()
    await srelay.connect(dst2.peerInfo.peerId, dst2.peerInfo.addrs)

    stream = await src.dial(srelay.peerInfo.peerId, srelay.peerInfo.addrs, RelayV1Codec)
    msg = createMsg(
      Opt.some(RelayType.Hop),
      Opt.none(StatusV1),
      Opt.some(RelayPeer(peerId: src.peerInfo.peerId, addrs: src.peerInfo.addrs)),
      Opt.some(RelayPeer(peerId: dst2.peerInfo.peerId, addrs: dst2.peerInfo.addrs)),
    )
    await stream.writeLp(msg)
    rcv = Opt.some(RelayMessage.decode(await stream.readLp(1024)).get())
    rcv.checkMsg(Opt.some(RelayType.Status), Opt.some(HopCantDialDst))
    await allFutures(dst2.stop())

  asyncTest "Dial Peer":
    let maStr =
      $srelay.peerInfo.addrs[0] & "/p2p/" & $srelay.peerInfo.peerId & "/p2p-circuit"
    let maddr = ma(maStr)
    await src.connect(srelay.peerInfo.peerId, srelay.peerInfo.addrs)
    await srelay.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)
    stream = await src.dial(dst.peerInfo.peerId, @[maddr], protos[0])

    await stream.writeLp("line1")
    check string.fromBytes(await stream.readLp(1024)) == "line2"

    await stream.writeLp("line3")
    check string.fromBytes(await stream.readLp(1024)) == "line4"

  asyncTest "Bad MultiAddress":
    await src.connect(srelay.peerInfo.peerId, srelay.peerInfo.addrs)
    await srelay.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)
    expect DialFailedError:
      let maStr =
        $srelay.peerInfo.addrs[0] & "/p2p/" & $srelay.peerInfo.peerId & "/p2p/" &
        $dst.peerInfo.peerId
      let maddr = ma(maStr)
      stream = await src.dial(dst.peerInfo.peerId, @[maddr], protos[0])

    expect DialFailedError:
      let maStr = $srelay.peerInfo.addrs[0] & "/p2p/" & $srelay.peerInfo.peerId
      let maddr = ma(maStr)
      stream = await src.dial(dst.peerInfo.peerId, @[maddr], protos[0])

    expect DialFailedError:
      let maStr = "/ip4/127.0.0.1"
      let maddr = ma(maStr)
      stream = await src.dial(dst.peerInfo.peerId, @[maddr], protos[0])

  asyncTest "tryDial rejects an address that does not name a relay":
    let transport = RelayTransport.new(clSrc, src.transports[0].upgrader)

    let tooShort = await transport.tryDial(ma("/ip4/127.0.0.1/tcp/1"))
    check:
      tooShort.isErr()
      tooShort.error.startsWith("dial address not valid")

    let noRelay = await transport.tryDial(
      ma("/ip4/127.0.0.1/tcp/1/p2p-circuit/p2p/" & $dst.peerInfo.peerId)
    )
    check:
      noRelay.isErr()
      noRelay.error.contains("Relay doesn't exist")

    let noCircuit = await transport.tryDial(
      ma(
        "/ip4/127.0.0.1/tcp/1/p2p/" & $srelay.peerInfo.peerId & "/p2p/" &
          $dst.peerInfo.peerId
      )
    )
    check:
      noCircuit.isErr()
      noCircuit.error.contains("missing p2p-circuit")
