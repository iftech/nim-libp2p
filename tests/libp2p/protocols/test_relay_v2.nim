# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import bearssl, chronos, std/times, stew/byteutils
import
  ../../../libp2p/[
    builders,
    switch,
    protocols/connectivity/relay/relay,
    protocols/connectivity/relay/messages,
    protocols/connectivity/relay/utils,
    protocols/connectivity/relay/client,
    signed_envelope,
    peerid,
  ]
import ../../tools/[unittest, crypto, switch_builder, multiaddress]

proc createSwitch(r: Relay = nil, useYamux: bool = false): Switch =
  var builder = makeStandardSwitchBuilder(TcpWildcardAddress).withCircuitRelay(r)

  if useYamux:
    builder = builder.withYamux()

  return builder.build()

suite "Circuit Relay V2":
  test "Relay v1 hop is opt-in":
    check:
      Relay.new().codecs == @[RelayV2HopCodec]
      Relay.new(circuitRelayV1 = true).codecs == @[RelayV1Codec]

  suite "Voucher":
    test "Reject signed vouchers with missing required fields":
      let
        relayKey = PrivateKey.random(rng()).tryGet()
        relayPeerId = PeerId.init(relayKey).tryGet()
        reservingPeerId = PeerId.init(PrivateKey.random(rng()).tryGet()).tryGet()
        expiration = 123'u64

      let valid = SignedVoucher
        .init(relayKey, Voucher.init(relayPeerId, reservingPeerId, expiration))
        .tryGet()
        .encode()

      let missingRelay = SignedVoucher
        .init(
          relayKey,
          Voucher(
            reservingPeerId: Opt.some(reservingPeerId), expiration: Opt.some(expiration)
          ),
        )
        .tryGet()
        .encode()

      let missingPeer = SignedVoucher
        .init(
          relayKey,
          Voucher(relayPeerId: Opt.some(relayPeerId), expiration: Opt.some(expiration)),
        )
        .tryGet()
        .encode()

      let missingExpiration = SignedVoucher
        .init(
          relayKey,
          Voucher(
            relayPeerId: Opt.some(relayPeerId),
            reservingPeerId: Opt.some(reservingPeerId),
          ),
        )
        .tryGet()
        .encode()

      check:
        SignedVoucher.decode(valid).isOk
        SignedVoucher.decode(missingRelay).error == EnvelopeFieldMissing
        SignedVoucher.decode(missingPeer).error == EnvelopeFieldMissing
        SignedVoucher.decode(missingExpiration).error == EnvelopeFieldMissing

  suite "Reservation":
    asyncTeardown:
      await allFutures(src1.stop(), src2.stop(), rel.stop())
      checkTrackers()
    var
      ttl {.threadvar.}: int
      ldur {.threadvar.}: uint32
      ldata {.threadvar.}: uint64
      cl1 {.threadvar.}: RelayClient
      cl2 {.threadvar.}: RelayClient
      rv2 {.threadvar.}: Relay
      src1 {.threadvar.}: Switch
      src2 {.threadvar.}: Switch
      rel {.threadvar.}: Switch
      rsvp {.threadvar.}: Rsvp
      range {.threadvar.}: HSlice[times.DateTime, times.DateTime]

    asyncSetup:
      ttl = 3
      ldur = 60
      ldata = 2048
      cl1 = RelayClient.new()
      cl2 = RelayClient.new()
      rv2 = Relay.new(
        reservationTTL = initDuration(seconds = ttl),
        limitDuration = ldur,
        limitData = ldata,
        maxCircuit = 1,
      )
      src1 = createSwitch(cl1)
      src2 = createSwitch(cl2)
      rel = createSwitch(rv2)

      await src1.start()
      await src2.start()
      await rel.start()
      await src1.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
      await src2.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
      rsvp = await cl1.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
      range = now().utc + (ttl - 3).seconds .. now().utc + (ttl + 3).seconds
      check:
        rsvp.expire.int64.fromUnix.utc in range
        rsvp.limitDuration == ldur
        rsvp.limitData == ldata

    asyncTest "Too many reservations":
      let stream =
        await cl2.switch.dial(rel.peerInfo.peerId, rel.peerInfo.addrs, RelayV2HopCodec)
      let pb = encode(HopMessage(msgType: Opt.some(HopMessageType.Reserve)))
      await stream.writeLp(pb)
      let msg = HopMessage.decode(await stream.readLp(RelayMsgSize)).get()
      check:
        msg.msgType == Opt.some(HopMessageType.Status)
        msg.status == Opt.some(StatusV2.ReservationRefused)

    asyncTest "tryReserve returns a refused reservation as an error":
      let res = await cl2.tryReserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
      check:
        res.isErr()
        res.error == "Reservation failed"

    asyncTest "Too many reservations + Reconnect":
      expect ReservationError:
        discard await cl2.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
      await rel.disconnect(src1.peerInfo.peerId)
      rsvp = await cl2.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
      range = now().utc + (ttl - 3).seconds .. now().utc + (ttl + 3).seconds
      check:
        rsvp.expire.int64.fromUnix.utc in range
        rsvp.limitDuration == ldur
        rsvp.limitData == ldata

    asyncTest "Reservation ttl expires":
      await sleepAsync(chronos.timer.seconds(ttl + 1))
      rsvp = await cl1.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
      range = now().utc + (ttl - 3).seconds .. now().utc + (ttl + 3).seconds
      check:
        rsvp.expire.int64.fromUnix.utc in range
        rsvp.limitDuration == ldur
        rsvp.limitData == ldata

    asyncTest "Reservation over relay":
      let
        rv2add = Relay.new()
        addrs = @[
          MultiAddress
            .init(
              $rel.peerInfo.addrs[0] & "/p2p/" & $rel.peerInfo.peerId & "/p2p-circuit"
            )
            .get()
        ]
      rv2add.setup(src2)
      await rv2add.start()
      src2.mount(rv2add)
      rv2.maxCircuit.inc()

      rsvp = await cl2.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
      range = now().utc + (ttl - 3).seconds .. now().utc + (ttl + 3).seconds
      check:
        rsvp.expire.int64.fromUnix.utc in range
        rsvp.limitDuration == ldur
        rsvp.limitData == ldata
      expect ReservationError:
        discard await cl1.reserve(src2.peerInfo.peerId, addrs)

  for (useYamux, muxName) in [(false, "Mplex"), (true, "Yamux")]:
    let (useYamux, muxName) = (useYamux, muxName) # capture loop vars for the closures
    suite "Circuit Relay V2 Connection using " & muxName:
      asyncTeardown:
        checkTrackers()
      var
        customProtoCodec {.threadvar.}: string
        proto {.threadvar.}: LPProtocol
        ttl {.threadvar.}: int
        ldur {.threadvar.}: uint32
        ldata {.threadvar.}: uint64
        srcCl {.threadvar.}: RelayClient
        dstCl {.threadvar.}: RelayClient
        rv2 {.threadvar.}: Relay
        src {.threadvar.}: Switch
        dst {.threadvar.}: Switch
        rel {.threadvar.}: Switch
        rsvp {.threadvar.}: Rsvp
        stream {.threadvar.}: Stream

      asyncSetup:
        customProtoCodec = "/test"
        proto = new LPProtocol
        proto.codec = customProtoCodec
        ttl = 60
        ldur = 120
        ldata = 16384
        srcCl = RelayClient.new()
        dstCl = RelayClient.new()
        src = createSwitch(srcCl, useYamux)
        dst = createSwitch(dstCl, useYamux)
        rel = createSwitch(nil, useYamux)

      asyncTest "Connection succeed":
        proto.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            check:
              "test1" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("test2")
            check:
              "test3" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("test4")
          except LPStreamError:
            raiseAssert "LPStreamError while handling connection"
          finally:
            await stream.close()
        rv2 = Relay.new(
          reservationTTL = initDuration(seconds = ttl),
          limitDuration = ldur,
          limitData = ldata,
        )
        rv2.setup(rel)
        rel.mount(rv2)
        dst.mount(proto)

        await rel.start()
        await src.start()
        await dst.start()

        let addrs = MultiAddress
          .init(
            $rel.peerInfo.addrs[0] & "/p2p/" & $rel.peerInfo.peerId & "/p2p-circuit"
          )
          .get()

        await src.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
        await dst.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)

        rsvp = await dstCl.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)

        stream = await src.dial(dst.peerInfo.peerId, @[addrs], customProtoCodec)
        await stream.writeLp("test1")
        check:
          "test2" == string.fromBytes(await stream.readLp(1024))
        await stream.writeLp("test3")
        check:
          "test4" == string.fromBytes(await stream.readLp(1024))
        await allFutures(stream.close())
        await allFutures(src.stop(), dst.stop(), rel.stop())

      asyncTest "Connection duration exceeded":
        ldur = 3
        proto.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            check "wanna sleep?" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("yeah!")
            check "go!" == string.fromBytes(await stream.readLp(1024))
          except LPStreamError:
            raiseAssert "Unexpected LPStreamError when writing"

          await sleepAsync(chronos.timer.seconds(ldur + 1))

          expect LPStreamError:
            await stream.writeLp("that was a cool power nap")
          await stream.close()
        rv2 = Relay.new(
          reservationTTL = initDuration(seconds = ttl),
          limitDuration = ldur,
          limitData = ldata,
        )
        rv2.setup(rel)
        rel.mount(rv2)
        dst.mount(proto)

        await rel.start()
        await src.start()
        await dst.start()

        let addrs = MultiAddress
          .init(
            $rel.peerInfo.addrs[0] & "/p2p/" & $rel.peerInfo.peerId & "/p2p-circuit"
          )
          .get()

        await src.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
        await dst.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)

        rsvp = await dstCl.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
        stream = await src.dial(dst.peerInfo.peerId, @[addrs], customProtoCodec)
        await stream.writeLp("wanna sleep?")
        check:
          "yeah!" == string.fromBytes(await stream.readLp(1024))
        await stream.writeLp("go!")
        expect LPStreamEOFError:
          discard await stream.readLp(1024)
        await allFutures(stream.close())
        await allFutures(src.stop(), dst.stop(), rel.stop())

      asyncTest "Connection data exceeded":
        ldata = 1000
        proto.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            check "count me the better story you know" ==
              string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("do you expect a lorem ipsum or...?")
            check "surprise me!" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp(
              """Call me Ishmael. Some years ago--never mind how long
    precisely--having little or no money in my purse, and nothing
    particular to interest me on shore, I thought I would sail about a
    little and see the watery part of the world. It is a way I have of
    driving off the spleen and regulating the circulation. Whenever I
    find myself growing grim about the mouth; whenever it is a damp,
    drizzly November in my soul; whenever I find myself involuntarily
    pausing before coffin warehouses, and bringing up the rear of every
    funeral I meet; and especially whenever my hypos get such an upper
    hand of me, that it requires a strong moral principle to prevent me
    from deliberately stepping into the street, and methodically knocking
    people's hats off--then, I account it high time to get to sea as soon
    as I can. This is my substitute for pistol and ball. With a
    philosophical flourish Cato throws himself upon his sword; I quietly
    take to the ship."""
            )
          except LPStreamError:
            discard # will get here after data exceeded
          finally:
            await stream.close()
        rv2 = Relay.new(
          reservationTTL = initDuration(seconds = ttl),
          limitDuration = ldur,
          limitData = ldata,
        )
        rv2.setup(rel)
        rel.mount(rv2)
        dst.mount(proto)

        await rel.start()
        await src.start()
        await dst.start()

        let addrs = MultiAddress
          .init(
            $rel.peerInfo.addrs[0] & "/p2p/" & $rel.peerInfo.peerId & "/p2p-circuit"
          )
          .get()

        await src.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
        await dst.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)

        rsvp = await dstCl.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
        stream = await src.dial(dst.peerInfo.peerId, @[addrs], customProtoCodec)
        await stream.writeLp("count me the better story you know")
        check:
          "do you expect a lorem ipsum or...?" ==
            string.fromBytes(await stream.readLp(1024))
        await stream.writeLp("surprise me!")
        expect LPStreamEOFError:
          discard await stream.readLp(1024)
        await allFutures(stream.close())
        await allFutures(src.stop(), dst.stop(), rel.stop())

      asyncTest "Reservation ttl expire during connection":
        ttl = 3
        proto.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            check:
              "test1" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("test2")
            check:
              "test3" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("test4")
          except LPStreamError:
            raiseAssert "LPStreamError while handling connection"
          finally:
            await stream.close()
        rv2 = Relay.new(
          reservationTTL = initDuration(seconds = ttl),
          limitDuration = ldur,
          limitData = ldata,
        )
        rv2.setup(rel)
        rel.mount(rv2)
        dst.mount(proto)

        await rel.start()
        await src.start()
        await dst.start()

        let addrs = MultiAddress
          .init(
            $rel.peerInfo.addrs[0] & "/p2p/" & $rel.peerInfo.peerId & "/p2p-circuit"
          )
          .get()

        await src.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
        await dst.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)

        rsvp = await dstCl.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
        stream = await src.dial(dst.peerInfo.peerId, @[addrs], customProtoCodec)
        await stream.writeLp("test1")
        check:
          "test2" == string.fromBytes(await stream.readLp(1024))
        await stream.writeLp("test3")
        check:
          "test4" == string.fromBytes(await stream.readLp(1024))
        await src.disconnect(rel.peerInfo.peerId)
        await sleepAsync(chronos.timer.seconds(ttl + 1))

        expect DialFailedError:
          await stream.close()
          await src.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
          stream = await src.dial(dst.peerInfo.peerId, @[addrs], customProtoCodec)
        await allFutures(stream.close())
        await allFutures(src.stop(), dst.stop(), rel.stop())

      asyncTest "Connection over relay":
        # src => rel => rel2 => dst
        # rel2 reserve rel
        # dst reserve rel2
        # src try to connect with dst
        proto.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          raiseAssert "Should not receive connection"

        let
          rel2Cl = RelayClient.new(canHop = true)
          rel2 = createSwitch(rel2Cl, useYamux)
          rv2 = Relay.new()
        rv2.setup(rel)
        rel.mount(rv2)
        dst.mount(proto)
        await rel.start()
        await rel2.start()
        await src.start()
        await dst.start()

        let addrs = @[
          MultiAddress
            .init(
              $rel.peerInfo.addrs[0] & "/p2p/" & $rel.peerInfo.peerId &
                "/p2p-circuit/p2p/" & $rel2.peerInfo.peerId & "/p2p/" &
                $rel2.peerInfo.peerId & "/p2p-circuit"
            )
            .get()
        ]

        await src.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
        await rel2.connect(rel.peerInfo.peerId, rel.peerInfo.addrs)
        await dst.connect(rel2.peerInfo.peerId, rel2.peerInfo.addrs)

        rsvp = await rel2Cl.reserve(rel.peerInfo.peerId, rel.peerInfo.addrs)
        discard await dstCl.reserve(rel2.peerInfo.peerId, rel2.peerInfo.addrs)

        expect DialFailedError:
          stream = await src.dial(dst.peerInfo.peerId, addrs, customProtoCodec)
        if not stream.isNil():
          await allFutures(stream.close())
        await allFutures(src.stop(), dst.stop(), rel.stop(), rel2.stop())

      asyncTest "Connection using ClientRelay":
        var
          protoABC = new LPProtocol
          protoBCA = new LPProtocol
          protoCAB = new LPProtocol
        protoABC.codec = "/abctest"
        protoABC.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            check:
              "testABC1" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("testABC2")
            check:
              "testABC3" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("testABC4")
          except LPStreamError:
            raiseAssert "LPStreamError while handling connection"
          finally:
            await stream.close()
        protoBCA.codec = "/bcatest"
        protoBCA.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            check:
              "testBCA1" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("testBCA2")
            check:
              "testBCA3" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("testBCA4")
          except LPStreamError:
            raiseAssert "LPStreamError while handling connection"
          finally:
            await stream.close()
        protoCAB.codec = "/cabtest"
        protoCAB.handler = proc(
            stream: Stream, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            check:
              "testCAB1" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("testCAB2")
            check:
              "testCAB3" == string.fromBytes(await stream.readLp(1024))
            await stream.writeLp("testCAB4")
          except LPStreamError:
            raiseAssert "LPStreamError while handling connection"
          finally:
            await stream.close()

        let
          clientA = RelayClient.new(canHop = true)
          clientB = RelayClient.new(canHop = true)
          clientC = RelayClient.new(canHop = true)
          switchA = createSwitch(clientA, useYamux)
          switchB = createSwitch(clientB, useYamux)
          switchC = createSwitch(clientC, useYamux)

        switchA.mount(protoBCA)
        switchB.mount(protoCAB)
        switchC.mount(protoABC)

        await switchA.start()
        await switchB.start()
        await switchC.start()

        let
          addrsABC = MultiAddress
            .init(
              $switchB.peerInfo.addrs[0] & "/p2p/" & $switchB.peerInfo.peerId &
                "/p2p-circuit"
            )
            .get()
          addrsBCA = MultiAddress
            .init(
              $switchC.peerInfo.addrs[0] & "/p2p/" & $switchC.peerInfo.peerId &
                "/p2p-circuit"
            )
            .get()
          addrsCAB = MultiAddress
            .init(
              $switchA.peerInfo.addrs[0] & "/p2p/" & $switchA.peerInfo.peerId &
                "/p2p-circuit"
            )
            .get()

        await switchA.connect(switchB.peerInfo.peerId, switchB.peerInfo.addrs)
        await switchB.connect(switchC.peerInfo.peerId, switchC.peerInfo.addrs)
        await switchC.connect(switchA.peerInfo.peerId, switchA.peerInfo.addrs)
        discard await clientA.reserve(switchC.peerInfo.peerId, switchC.peerInfo.addrs)
        discard await clientB.reserve(switchA.peerInfo.peerId, switchA.peerInfo.addrs)
        discard await clientC.reserve(switchB.peerInfo.peerId, switchB.peerInfo.addrs)
        let connABC =
          await switchA.dial(switchC.peerInfo.peerId, @[addrsABC], "/abctest")
        let connBCA =
          await switchB.dial(switchA.peerInfo.peerId, @[addrsBCA], "/bcatest")
        let connCAB =
          await switchC.dial(switchB.peerInfo.peerId, @[addrsCAB], "/cabtest")

        await connABC.writeLp("testABC1")
        await connBCA.writeLp("testBCA1")
        await connCAB.writeLp("testCAB1")
        check:
          "testABC2" == string.fromBytes(await connABC.readLp(1024))
          "testBCA2" == string.fromBytes(await connBCA.readLp(1024))
          "testCAB2" == string.fromBytes(await connCAB.readLp(1024))
        await connABC.writeLp("testABC3")
        await connBCA.writeLp("testBCA3")
        await connCAB.writeLp("testCAB3")
        check:
          "testABC4" == string.fromBytes(await connABC.readLp(1024))
          "testBCA4" == string.fromBytes(await connBCA.readLp(1024))
          "testCAB4" == string.fromBytes(await connCAB.readLp(1024))
        await allFutures(connABC.close(), connBCA.close(), connCAB.close())
        await allFutures(switchA.stop(), switchB.stop(), switchC.stop())
