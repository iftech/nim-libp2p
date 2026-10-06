# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, protobuf_serialization, sets
import
  ../../../libp2p/[
    protocols/identify,
    protocols/ping,
    protocols/protocol,
    multiaddress,
    peerinfo,
    peerid,
    stream/connection,
    multistream,
    transports/transport,
    connmanager,
    dialer,
    switch,
    builders,
    transports/tcptransport,
    transports/quictransport,
    crypto/crypto,
    upgrademngrs/upgrade,
    peerstore,
    muxers/mplex/mplex,
    stream/bridgestream,
  ]
import ../../tools/[unittest, crypto, multiaddress, switch_builder]

type IdentifyMsgNoPubKey {.proto2.} = object
  protocols {.fieldNumber: 3.}: seq[string]

suite "Identify":
  teardown:
    checkTrackers()

  suite "handle identify message":
    var
      maddr {.threadvar.}: seq[MultiAddress]
      remoteSecKey {.threadvar.}: PrivateKey
      remotePeerInfo {.threadvar.}: PeerInfo
      serverFut {.threadvar.}: Future[void]
      acceptFut {.threadvar.}: Future[void]
      identifyProto1 {.threadvar.}: Identify
      identifyProto2 {.threadvar.}: Identify
      transport1 {.threadvar.}: Transport
      transport2 {.threadvar.}: Transport
      msListen {.threadvar.}: MultistreamSelect
      msDial {.threadvar.}: MultistreamSelect
      conn {.threadvar.}: RawConn

    asyncSetup:
      maddr = @[TcpWildcardAddress, TcpWildcardAddressIP6]
      remoteSecKey = PrivateKey.random(ECDSA, rng()).get()
      remotePeerInfo =
        PeerInfo.new(remoteSecKey, maddr, ["/test/proto1/1.0.0", "/test/proto2/1.0.0"])

      transport1 = TcpTransport.new(upgrade = Upgrade())
      transport2 = TcpTransport.new(upgrade = Upgrade())

      identifyProto1 = Identify.new(remotePeerInfo)
      identifyProto2 = Identify.new(remotePeerInfo)

      msListen = MultistreamSelect.new()
      msDial = MultistreamSelect.new()

      serverFut = transport1.start(maddr)
      await remotePeerInfo.update()

    asyncTeardown:
      await conn.close()
      await acceptFut
      await transport1.stop()
      await serverFut
      await transport2.stop()

    asyncTest "default agent version":
      msListen.addHandler(identifyProto1)
      proc acceptHandler(): Future[void] {.async.} =
        let c = await transport1.accept()
        await msListen.handle(c)

      acceptFut = acceptHandler()
      conn = await transport2.dial(transport1.addrs[0])

      discard await msDial.select(conn, IdentifyCodec)
      let id = await identifyProto2.identify(conn, remotePeerInfo.peerId)

      check id.pubkey.get() == remoteSecKey.getPublicKey().get()
      check id.addrs == maddr
      check id.protoVersion.get() == ProtoVersion
      check id.agentVersion.get() == AgentVersion
      check id.protos == @["/test/proto1/1.0.0", "/test/proto2/1.0.0"]
      check id.signedPeerRecord.isNone()

    asyncTest "custom agent version":
      const customAgentVersion = "MY CUSTOM AGENT STRING"
      remotePeerInfo.agentVersion = customAgentVersion
      msListen.addHandler(identifyProto1)

      proc acceptHandler(): Future[void] {.async.} =
        let c = await transport1.accept()
        await msListen.handle(c)

      acceptFut = acceptHandler()
      conn = await transport2.dial(transport1.addrs[0])

      discard await msDial.select(conn, IdentifyCodec)
      let id = await identifyProto2.identify(conn, remotePeerInfo.peerId)

      check id.pubkey.get() == remoteSecKey.getPublicKey().get()
      check id.addrs == maddr
      check id.protoVersion.get() == ProtoVersion
      check id.agentVersion.get() == customAgentVersion
      check id.protos == @["/test/proto1/1.0.0", "/test/proto2/1.0.0"]
      check id.signedPeerRecord.isNone()

    asyncTest "identify without publicKey falls back to remotePeerId":
      # A minimal peer (e.g. eth-p2p-z over QUIC) may omit the optional publicKey field.
      # The security handshake already authenticated the remote, so identify
      # must accept the message and fall back to remotePeerId instead of rejecting.
      const testProtos = @["/test/proto1/1.0.0"]
      proc noPubKeyHandler(
          stream: Stream, proto: string
      ) {.async: (raises: [CancelledError]).} =
        try:
          await stream.writeLp(
            Protobuf.encode(IdentifyMsgNoPubKey(protocols: testProtos))
          )
        except LPError as e:
          raiseAssert "failed to write pubkey-less identify: " & e.msg
        finally:
          await stream.closeWithEOF()

      msListen.addHandler(LPProtocol.new(@[IdentifyCodec], noPubKeyHandler))
      proc acceptHandler(): Future[void] {.async.} =
        let c = await transport1.accept()
        await msListen.handle(c)

      acceptFut = acceptHandler()
      conn = await transport2.dial(transport1.addrs[0])

      discard await msDial.select(conn, IdentifyCodec)
      let id = await identifyProto2.identify(conn, remotePeerInfo.peerId)

      check id.pubkey.isNone()
      check id.peerId == remotePeerInfo.peerId
      check id.protos == testProtos

    asyncTest "handle failed identify":
      msListen.addHandler(identifyProto1)

      proc acceptHandler() {.async: (raises: [CancelledError]).} =
        var conn: RawConn
        try:
          conn = await transport1.accept()
          await msListen.handle(conn)
        except transport.TransportError as e:
          raiseAssert "unexpected error: " & e.msg
        finally:
          await conn.close()

      acceptFut = acceptHandler()
      conn = await transport2.dial(transport1.addrs[0])

      expect IdentityNoMatchError:
        let pi2 = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get())
        discard await msDial.select(conn, IdentifyCodec)
        discard await identifyProto2.identify(conn, pi2.peerId)

    asyncTest "tryIdentify reports a message that does not decode":
      proc truncatedHandler(
          stream: Stream, proto: string
      ) {.async: (raises: [CancelledError]).} =
        try:
          await stream.writeLp(@[0x0a'u8, 0x05, 0x01])
        except LPError as e:
          raiseAssert "failed to write truncated identify: " & e.msg
        finally:
          await stream.closeWithEOF()

      msListen.addHandler(LPProtocol.new(@[IdentifyCodec], truncatedHandler))
      proc acceptHandler(): Future[void] {.async.} =
        let c = await transport1.accept()
        await msListen.handle(c)

      acceptFut = acceptHandler()
      conn = await transport2.dial(transport1.addrs[0])

      discard await msDial.select(conn, IdentifyCodec)
      let identified = await identifyProto2.tryIdentify(conn, remotePeerInfo.peerId)

      check identified.isErrOf(IdentityInvalidMsgError)

    asyncTest "can send signed peer record":
      msListen.addHandler(identifyProto1)
      identifyProto1.sendSignedPeerRecord = true
      proc acceptHandler(): Future[void] {.async.} =
        let c = await transport1.accept()
        await msListen.handle(c)

      acceptFut = acceptHandler()
      conn = await transport2.dial(transport1.addrs[0])

      discard await msDial.select(conn, IdentifyCodec)
      let id = await identifyProto2.identify(conn, remotePeerInfo.peerId)

      check id.pubkey.get() == remoteSecKey.getPublicKey().get()
      check id.addrs == maddr
      check id.protoVersion.get() == ProtoVersion
      check id.agentVersion.get() == AgentVersion
      check id.protos == @["/test/proto1/1.0.0", "/test/proto2/1.0.0"]
      check id.signedPeerRecord.get() == remotePeerInfo.signedPeerRecord.envelope

  suite "handle push identify message":
    var
      switch1 {.threadvar.}: Switch
      switch2 {.threadvar.}: Switch
      identifyPush1 {.threadvar.}: IdentifyPush
      identifyPush2 {.threadvar.}: IdentifyPush
      stream {.threadvar.}: Stream

    asyncSetup:
      let maddr = @[TcpWildcardAddress, TcpWildcardAddressIP6]
      switch1 = makeStandardSwitchBuilder(maddr).withSignedPeerRecord(true).build()
      switch2 = makeStandardSwitchBuilder(maddr).withSignedPeerRecord(true).build()

      proc updateStore1(info: IdentifyInfo) {.async.} =
        switch1.peerStore.updatePeerInfo(info)

      proc updateStore2(info: IdentifyInfo) {.async.} =
        switch2.peerStore.updatePeerInfo(info)

      identifyPush1 = IdentifyPush.new(updateStore1)
      identifyPush2 = IdentifyPush.new(updateStore2)

      switch1.mount(identifyPush1)
      switch2.mount(identifyPush2)

      await switch1.start()
      await switch2.start()

      stream = await switch2.dial(
        switch1.peerInfo.peerId, switch1.peerInfo.addrs, IdentifyPushCodec
      )

      check:
        # ensure both IPv4 and IPv6 addresses are used in switch.
        countAddressesWithPattern(switch1.peerInfo.addrs, TCP_IP4) > 1
        countAddressesWithPattern(switch1.peerInfo.addrs, TCP_IP6) > 1
        countAddressesWithPattern(switch2.peerInfo.addrs, TCP_IP4) > 1
        countAddressesWithPattern(switch2.peerInfo.addrs, TCP_IP6) > 1

        # ensure all addresses are advertized.
        # that is, peer store will have all address of other peer.
        toHashSet(switch1.peerStore[AddressBook][switch2.peerInfo.peerId]) ==
          toHashSet(switch2.peerInfo.addrs)
        toHashSet(switch2.peerStore[AddressBook][switch1.peerInfo.peerId]) ==
          toHashSet(switch1.peerInfo.addrs)

        switch1.peerStore[KeyBook][switch2.peerInfo.peerId] == switch2.peerInfo.publicKey
        switch2.peerStore[KeyBook][switch1.peerInfo.peerId] == switch1.peerInfo.publicKey

        switch1.peerStore[AgentBook][switch2.peerInfo.peerId] ==
          switch2.peerInfo.agentVersion
        switch2.peerStore[AgentBook][switch1.peerInfo.peerId] ==
          switch1.peerInfo.agentVersion

        switch1.peerStore[ProtoVersionBook][switch2.peerInfo.peerId] ==
          switch2.peerInfo.protoVersion
        switch2.peerStore[ProtoVersionBook][switch1.peerInfo.peerId] ==
          switch1.peerInfo.protoVersion

        switch1.peerStore[ProtoBook][switch2.peerInfo.peerId] ==
          switch2.peerInfo.protocols
        switch2.peerStore[ProtoBook][switch1.peerInfo.peerId] ==
          switch1.peerInfo.protocols

        switch1.peerStore[SPRBook][switch2.peerInfo.peerId] ==
          switch2.peerInfo.signedPeerRecord.envelope
        switch2.peerStore[SPRBook][switch1.peerInfo.peerId] ==
          switch1.peerInfo.signedPeerRecord.envelope

    proc closeAll() {.async.} =
      await stream.close()

      await switch1.stop()
      await switch2.stop()

    asyncTest "simple push identify":
      switch2.peerInfo.protocols.add("/newprotocol/")
      switch2.peerInfo.addrs.add(ma("/ip4/127.0.0.1/tcp/5555"))

      check:
        toHashSet(switch1.peerStore[AddressBook][switch2.peerInfo.peerId]) !=
          toHashSet(switch2.peerInfo.addrs)
        switch1.peerStore[ProtoBook][switch2.peerInfo.peerId] !=
          switch2.peerInfo.protocols

      await identifyPush2.push(switch2.peerInfo, stream)

      checkUntilTimeout:
        switch1.peerStore[ProtoBook][switch2.peerInfo.peerId] ==
          switch2.peerInfo.protocols
      checkUntilTimeout:
        toHashSet(switch1.peerStore[AddressBook][switch2.peerInfo.peerId]) ==
          toHashSet(switch2.peerInfo.addrs)

      await closeAll()

    asyncTest "wrong peer id push identify":
      switch2.peerInfo.protocols.add("/newprotocol/")
      switch2.peerInfo.addrs.add(ma("/ip4/127.0.0.1/tcp/5555"))

      check:
        toHashSet(switch1.peerStore[AddressBook][switch2.peerInfo.peerId]) !=
          toHashSet(switch2.peerInfo.addrs)
        switch1.peerStore[ProtoBook][switch2.peerInfo.peerId] !=
          switch2.peerInfo.protocols

      let oldPeerId = switch2.peerInfo.peerId
      let wrongPeerInfo = PeerInfo.new(PrivateKey.random(rng()).get())
      await wrongPeerInfo.update()

      await identifyPush2.push(wrongPeerInfo, stream)

      # We have no way to know when the message will is received
      # because it will fail validation inside push identify itself
      #
      # So no choice but to sleep
      await sleepAsync(10.milliseconds)

      await closeAll()

      # Wait the very end to be sure that the push has been processed
      check:
        switch1.peerStore[ProtoBook][oldPeerId] != wrongPeerInfo.protocols
        switch1.peerStore[AddressBook][oldPeerId] != wrongPeerInfo.addrs

  asyncTest "identify exposes QUIC transport addresses":
    let
      # Server switch with both QUIC and TCP
      server = makeStandardSwitch(@[QuicAutoAddress, TcpAutoAddress])
      # Client switch to dial and identify
      client = makeStandardSwitch(TcpAutoAddress)

    await server.start()
    await client.start()
    defer:
      await server.stop()
      await client.stop()

    check:
      countAddressesWithPattern(server.peerInfo.addrs, TCP_IP4) == 1
      countAddressesWithPattern(server.peerInfo.addrs, QUIC_V1) == 1

    # Connect and request identify
    await client.connect(server.peerInfo.peerId, server.peerInfo.addrs)

    # The client's peerStore should now have the server's info including addresses via identify
    let storedAddrs = client.peerStore[AddressBook][server.peerInfo.peerId]
    check countAddressesWithPattern(storedAddrs, QUIC_V1) == 1

  asyncTest "outgoing identify resets when the peer answers `na`":
    let (connDialer, connListener) = bridgedConnections(
      closeTogether = false, dirA = Direction.Out, dirB = Direction.In
    )
    let
      muxDialer = Mplex.new(connDialer)
      muxListener = Mplex.new(connListener)
      handleDialer = muxDialer.handle()
      handleListener = muxListener.handle()
    defer:
      await allFutures(
        connDialer.close(),
        connListener.close(),
        muxDialer.close(),
        muxListener.close(),
        handleDialer,
        handleListener,
      )

    # Listener serves ping only, so identify is answered with `na`. It blocks
    # before closing to model a peer that leaves the stream open after `na`.
    let blocker = newFuture[void]()
    muxListener.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
      try:
        discard await MultistreamSelect.handle(stream, @[PingCodec])
      except CancelledError, LPStreamError, MultiStreamError:
        discard
      try:
        await blocker
      except CatchableError:
        discard
      await noCancel stream.close()

    let
      remoteInfo = PeerInfo.new(PrivateKey.random(PKScheme.Ed25519, rng()).get())
      peerStore = PeerStore.new(Identify.new(remoteInfo))
    let identifyFut = peerStore.identify(muxDialer, Direction.Out)

    check await identifyFut.withTimeout(1.seconds)
    await identifyFut

    # Let the listener handler finish so the test cleans up deterministically.
    blocker.complete()

  asyncTest "failed protocol negotiations reset the stream":
    let (connDialer, connListener) = bridgedConnections(
      closeTogether = false, dirA = Direction.Out, dirB = Direction.In
    )
    let
      muxDialer = Mplex.new(connDialer)
      muxListener = Mplex.new(connListener)
      handleDialer = muxDialer.handle()
      handleListener = muxListener.handle()
    defer:
      await allFutures(
        connDialer.close(),
        connListener.close(),
        muxDialer.close(),
        muxListener.close(),
        handleDialer,
        handleListener,
      )

    # Leave the stream open after rejecting the requested protocol. A
    # multistream responder may continue waiting for another protocol token.
    let blocker = newFuture[void]()
    muxListener.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
      try:
        discard await MultistreamSelect.handle(stream, @[PingCodec])
      except CancelledError, LPStreamError, MultiStreamError:
        discard
      try:
        await blocker
      except CatchableError:
        discard
      await noCancel stream.close()

    let
      localInfo = PeerInfo.new(PrivateKey.random(PKScheme.Ed25519, rng()).get())
      peerStore = PeerStore.new(Identify.new(localInfo))
      ms = MultistreamSelect.new()

    proc unusedHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      discard

    let limitedPing =
      LPProtocol.new(@[PingCodec], unusedHandler, maxOutgoingStreamsTotal = 0)
    ms.addHandler(limitedPing)

    let connManager = ConnManager.new()
    defer:
      await connManager.stop()

    let
      dialer = Dialer.new(localInfo.peerId, connManager, peerStore, @[], ms, nil)
      stream = await muxDialer.newStream()
      negotiateFut = dialer.negotiateStream(stream, @[IdentifyCodec])

    check await negotiateFut.withTimeout(1.seconds)
    expect DialFailedError:
      discard await negotiateFut

    let
      budgetStream = await muxDialer.newStream()
      budgetFut = dialer.negotiateStream(budgetStream, @[PingCodec])
    check await budgetFut.withTimeout(1.seconds)
    expect DialFailedError:
      discard await budgetFut

    # Let the listener handler finish so the test cleans up deterministically.
    blocker.complete()
