# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
from times import now
import
  ../../../libp2p/[
    autotls/service,
    autotls/mockservice,
    stream/connection,
    transports/transport,
    transports/wstransport,
    upgrademngrs/upgrade,
    multiaddress,
    wire,
    errors,
    muxers/muxer,
    muxers/mplex/mplex,
  ]
import ../../tools/[crypto, unittest, multiaddress]
import ./basic_tests
import ./cancellation_tests
import ./connection_tests
import ./stream_tests

proc wsTransProvider(): Transport =
  WsTransport.new(Upgrade(), rng())

# Generate cert only once to reduce execution time
var secureKey {.threadvar.}: TLSPrivateKey
var secureCert {.threadvar.}: TLSCertificate
(secureKey, secureCert) = tlsCertGenerator()

proc wsSecureTransProvider(): Transport {.gcsafe, raises: [].} =
  WsTransport.new(
    Upgrade(),
    secureKey,
    secureCert,
    Opt.none(AutotlsService),
    rng(),
    tlsFlags = {TLSFlags.NoVerifyHost, TLSFlags.NoVerifyServerName},
  )

proc streamProvider(conn: RawConn, handle: bool = true): Muxer =
  let muxer = Mplex.new(conn)
  if handle:
    asyncSpawn muxer.handle()
  muxer

const
  wsAddress = "/ip4/127.0.0.1/tcp/0/ws"
  wsSecureAddress = "/ip4/127.0.0.1/tcp/0/wss"
  validPlainWireAddresses = @["/ip4/127.0.0.1/tcp/1234/ws", "/ip6/::1/tcp/1234/ws"]
  validWireAddresses = @[
    # Plain WebSocket
    "/ip4/127.0.0.1/tcp/1234/ws",
    "/ip6/::1/tcp/1234/ws",
    # Secure WebSocket
    "/ip4/127.0.0.1/tcp/1234/wss",
    "/ip4/127.0.0.1/tcp/1234/tls/ws",
    "/ip4/127.0.0.1/tcp/1234/tls/sni/example.com/ws",
    "/ip6/::1/tcp/1234/wss",
  ]
  validNonWireAddresses = @[
    # Plain WebSocket 
    "/dns/example.com/tcp/1234/ws",
    # Secure WebSocket
    "/dns/example.com/tcp/1234/wss",
    "/dns/example.com/tcp/1234/tls/ws",
    "/dns/example.com/tcp/1234/tls/sni/ws.example.com/ws",
  ]
  invalidAddresses = @[
    "/ip4/127.0.0.1/tcp/1234", # Missing /ws or /wss
    "/ip4/127.0.0.1/udp/1234/ws", # UDP instead of TCP
    "/ip4/127.0.0.1/udp/1234/wss", # UDP instead of TCP
    "/ip4/127.0.0.1/tcp/1234/quic-v1", # QUIC instead of WebSocket
    "/ip4/127.0.0.1/tcp/1234/sni/example.com/ws", # SNI without TLS
    "/ip4/127.0.0.1/tcp/1234/tls/ws/sni/example.com", # SNI after WebSocket
    "/ip4/127.0.0.1/tcp/1234/wss/sni/example.com", # SNI with deprecated alias
    "/ip4/127.0.0.1/tcp/1234/tls/sni/one/sni/two/ws", # Repeated SNI
    "/ip4/127.0.0.1/tcp/1234/tls/sni/example.com", # Missing WebSocket
  ]

suite "WebSocket transport":
  teardown:
    checkTrackers()

  basicTransportTest(
    wsTransProvider, wsAddress, validPlainWireAddresses, validNonWireAddresses,
    invalidAddresses,
  )
  basicTransportTest(
    wsSecureTransProvider, wsSecureAddress, validWireAddresses, validNonWireAddresses,
    invalidAddresses,
  )

  connectionTransportTest(wsTransProvider, wsAddress)
  connectionTransportTest(wsSecureTransProvider, wsSecureAddress)

  cancellationTransportTest(wsTransProvider, wsAddress)
  cancellationTransportTest(wsSecureTransProvider, wsSecureAddress)

  asyncTest "slow WebSocket headers do not block valid accepts":
    let headersTimeout = 3.seconds
    let acceptTimeout = headersTimeout div 3
    let server = WsTransport.new(
      Upgrade(), rng(), headersTimeout = headersTimeout, concurrentAccepts = 2
    )
    await server.start(@[ma(wsAddress)])
    defer:
      await server.stop()

    let rawAddr = server.addrs[0].initTAddress().tryGet()
    let slow = await connect(rawAddr)
    var slowClosed = false
    proc closeSlow() {.async: (raises: []).} =
      if slowClosed:
        return

      slowClosed = true
      try:
        await noCancel slow.closeWait()
      except CatchableError:
        discard

    defer:
      await closeSlow()

    # Keep this raw stream open with incomplete headers while a valid
    # WebSocket handshake is accepted.
    discard await slow.write("GET / HTTP/1.1\r\nUpgrade: websocket\r\n")

    let client = wsTransProvider()
    defer:
      await client.stop()

    # The valid WebSocket handshake must not wait for the slow one to time out.
    let outboundFut = client.dial(server.addrs[0])
    # Keep accept() future bounded so a serialized accept 
    # cannot hide behind headersTimeout
    let inbound = await server.accept().wait(acceptTimeout)
    let outbound = await outboundFut

    await closeSlow()

    let outboundClosing = outbound.close()
    await inbound.close()
    await outboundClosing

  streamTransportTest(
    wsTransProvider, ma(wsAddress), Opt.none(MultiAddress), streamProvider
  )
  streamTransportTest(
    wsSecureTransProvider, ma(wsSecureAddress), Opt.none(MultiAddress), streamProvider
  )

  asyncTest "Hostname verification":
    # Generate cert with known keypair so we can derive the PeerId (used as CN in cert)
    let testKeyPair = KeyPair.random(PKScheme.RSA, rng()).get()
    let expectedPeerId = PeerId.init(testKeyPair.pubkey).tryGet()
    let (secureKey, secureCert) = tlsCertGenerator(Opt.some(testKeyPair))

    let transport1 = WsTransport.new(
      Upgrade(),
      secureKey,
      secureCert,
      Opt.none(AutotlsService),
      rng(),
      tlsFlags = {TLSFlags.NoVerifyHost},
    )

    const correctPattern = mapAnd(TCP, mapEq("wss"))
    await transport1.start(@[ma("/ip4/0.0.0.0/tcp/0/wss")])
    defer:
      await transport1.stop()
    check correctPattern.match(transport1.addrs[0])
    proc acceptHandler() {.async.} =
      while true:
        let conn = await transport1.accept()
        if not isNil(conn):
          await conn.close()

    let handlerWait = acceptHandler()
    defer:
      await handlerWait.cancelAndWait()

    # PeerId is used as CN in the certificate, so it should work as hostname
    let conn = await transport1.dial($expectedPeerId, transport1.addrs[0])
    await conn.close()

    expect TransportDialError:
      discard await transport1.dial("ws.wronghostname", transport1.addrs[0])

  asyncTest "handles tls/ws":
    let transport1 = wsSecureTransProvider()
    const correctPattern = mapAnd(TCP, mapEq("tls"), mapEq("ws"))
    await transport1.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])
    check transport1.handles(transport1.addrs[0])
    check correctPattern.match(transport1.addrs[0])

    # Would raise somewhere if this wasn't handled:
    let
      inboundConn = transport1.accept()
      outboundConn = await transport1.dial(transport1.addrs[0])
      closing = outboundConn.close()
    await (await inboundConn).close()
    await closing

    await transport1.stop()

  asyncTest "explicit SNI is preserved and controls hostname verification":
    let testKeyPair = KeyPair.random(PKScheme.RSA, rng()).get()
    let expectedPeerId = PeerId.init(testKeyPair.pubkey).tryGet()
    let (secureKey, secureCert) = tlsCertGenerator(Opt.some(testKeyPair))

    let transport1 = WsTransport.new(
      Upgrade(),
      secureKey,
      secureCert,
      Opt.none(AutotlsService),
      rng(),
      tlsFlags = {TLSFlags.NoVerifyHost},
    )
    let
      sniSuffix = ma("/tls/sni/" & $expectedPeerId & "/ws")
      listenAddr = TcpAutoAddress & sniSuffix
    await transport1.start(@[listenAddr])
    defer:
      await transport1.stop()

    let
      base = ma(transport1.addrs[0].initTAddress().tryGet())
      wrongAddress = base & ma("/tls/sni/ws.wronghostname/ws")
    check transport1.addrs[0][2 .. ^1].tryGet() == sniSuffix

    let inboundFut = transport1.accept()
    let outbound = await transport1.dial("different.http.host", transport1.addrs[0])
    let inbound = await inboundFut
    await allFutures(outbound.close(), inbound.close())

    expect TransportDialError:
      discard await transport1.dial("different.http.host", wrongAddress)

  asyncTest "a failed start closes the servers it already opened":
    let transport = WsTransport.new(Upgrade(), rng())

    expect WsTransportError:
      await transport.start(@[ma(wsAddress), ma("/ip4/192.0.2.1/tcp/0/ws")])

  asyncTest "dial of a non-wire address is a TransportDialError":
    let transport = WsTransport.new(Upgrade(), rng())

    expect TransportDialError:
      discard await transport.dial("", ma("/dns/example.com/tcp/1234/ws"))

suite "WebSocket transport with autotls":
  teardown:
    checkTrackers()

  asyncTest "autotls certificate is used when manual tlscertificate is not specified":
    let key = KeyPair.random(PKScheme.RSA, rng()).get()
    let (privkey, cert) = tlsCertGenerator(Opt.some(key))
    let autotls = MockAutotlsService.new(rng())
    autotls.mockedKey = privkey
    autotls.mockedCert = cert
    await autotls.setup()

    let wstransport = WsTransport.new(
      Upgrade(),
      nil, # TLSPrivateKey
      nil, # TLSCertificate
      Opt.some(AutotlsService(autotls)),
      rng(),
    )
    await wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])
    defer:
      await wstransport.stop()

    # TLSPrivateKey and TLSCertificate should be set
    check wstransport.secure

    # autotls should be used
    let autotlsCert = (await autotls.getCertWhenReady()).get()
    check wstransport.tlsCertificate == autotlsCert.cert
    check wstransport.tlsPrivateKey == autotlsCert.privkey

  asyncTest "manually set tlscertificate is preferred over autotls when both are specified":
    let key = KeyPair.random(PKScheme.RSA, rng()).get()
    let (privkey, cert) = tlsCertGenerator(Opt.some(key))
    let autotls = MockAutotlsService.new(rng())
    autotls.mockedKey = privkey
    autotls.mockedCert = cert
    await autotls.setup()

    # Use different cert from autotls to verify manual cert is preferred
    let (manualKey, manualCert) = tlsCertGenerator()

    let wstransport = WsTransport.new(
      Upgrade(), manualKey, manualCert, Opt.some(AutotlsService(autotls)), rng()
    )
    await wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])
    defer:
      await wstransport.stop()

    # TLSPrivateKey and TLSCertificate should be set
    check wstransport.secure

    # autotls should be ignored - manual cert should be used
    check wstransport.tlsCertificate == manualCert
    check wstransport.tlsPrivateKey == manualKey

  asyncTest "start fails for WSS without manual TLS credentials or autotls":
    let wstransport = WsTransport.new(
      Upgrade(),
      nil, # TLSPrivateKey
      nil, # TLSCertificate
      Opt.none(AutotlsService),
      rng(),
    )

    expectMsgContains TransportStartError, "WSS requires TLS credentials or AutoTLS":
      await wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])

    check:
      not wstransport.running
      wstransport.addrs.len == 0

  asyncTest "plain WebSocket start does not wait for autotls":
    let startTimeout = 15.seconds # must be less then `certTimeout`
    let certTimeout = 30.seconds
      # intentionally very large, so loading certifacte is not stopped early by this timeout
    let autotls = AutotlsService(
      certReady: newAsyncEvent(),
      running: newAsyncEvent(),
      config: AutotlsConfig.new(initialCertTimeout = certTimeout),
    )
    let wstransport = WsTransport.new(
      Upgrade(),
      nil, # TLSPrivateKey
      nil, # TLSCertificate
      Opt.some(autotls),
      rng(),
    )

    let startFut = wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/ws")])
    defer:
      if not startFut.finished:
        startFut.cancelSoon()
      await wstransport.stop()

    # A plain /ws listener must start well before AutoTLS gives up on its certificate.
    await startFut.wait(startTimeout)

    check:
      not wstransport.secure
      wstransport.running
      wstransport.addrs.len == 1

  asyncTest "start fails when the autotls service never runs":
    let autotls = AutotlsService(
      certReady: newAsyncEvent(),
      running: newAsyncEvent(),
      config: AutotlsConfig.new(initialCertTimeout = 100.milliseconds),
    )
    let wstransport = WsTransport.new(
      Upgrade(),
      nil, # TLSPrivateKey
      nil, # TLSCertificate
      Opt.some(autotls),
      rng(),
    )

    expectMsgContains TransportStartError,
      "autotls service did not start before the certificate deadline":
      await wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])

    check:
      not wstransport.running
      wstransport.addrs.len == 0

  asyncTest "start fails when the autotls certificate never arrives":
    let autotls = AutotlsService(
      certReady: newAsyncEvent(),
      running: newAsyncEvent(),
      config: AutotlsConfig.new(initialCertTimeout = 100.milliseconds),
    )
    autotls.running.fire()
    let wstransport = WsTransport.new(
      Upgrade(),
      nil, # TLSPrivateKey
      nil, # TLSCertificate
      Opt.some(autotls),
      rng(),
    )

    expectMsgContains TransportStartError,
      "autotls certificate was not available before the certificate deadline":
      await wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])

    check:
      not wstransport.running
      wstransport.addrs.len == 0

  asyncTest "a renewed certificate reaches a running transport":
    let autotls = AutotlsService(
      cert: Opt.some(AutotlsCert.new(secureCert, secureKey, now())),
      certReady: newAsyncEvent(),
      running: newAsyncEvent(),
      config: AutotlsConfig.new(),
    )
    autotls.running.fire()
    autotls.certReady.fire()

    let wstransport = WsTransport.new(
      Upgrade(),
      nil, # TLSPrivateKey
      nil, # TLSCertificate
      Opt.some(autotls),
      rng(),
    )
    await wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])
    defer:
      await wstransport.stop()

    check wstransport.tlsCertificate == secureCert

    # autotls should still reach even after transport restarts 
    await wstransport.stop()
    await wstransport.start(@[ma("/ip4/0.0.0.0/tcp/0/tls/ws")])

    # what issueCertificate does once a renewal completes
    let renewedKeyPair = KeyPair.random(PKScheme.RSA, rng()).get()
    let renewedPeerId = PeerId.init(renewedKeyPair.pubkey).tryGet()
    let (renewedKey, renewedCert) = tlsCertGenerator(Opt.some(renewedKeyPair))
    autotls.installCertificate(AutotlsCert.new(renewedCert, renewedKey, now()))

    checkUntilTimeout:
      wstransport.tlsCertificate == renewedCert
      wstransport.tlsPrivateKey == renewedKey

    # A fresh handshake verifies that the HttpServer, not just the transport
    # fields above, now presents the renewed certificate.
    let client = WsTransport.new(
      Upgrade(),
      nil,
      nil,
      Opt.none(AutotlsService),
      rng(),
      tlsFlags = {TLSFlags.NoVerifyHost},
    )
    let inboundFut = wstransport.accept()
    let outbound = await client.dial($renewedPeerId, wstransport.addrs[0])
    let inbound = await inboundFut
    let closing = outbound.close()
    await inbound.close()
    await closing
