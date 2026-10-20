# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/[byteutils, endians2]
import
  ../../../libp2p/[
    transports/quictransport,
    transports/transport,
    transports/tls/certificate,
    upgrademngrs/upgrade,
    multiaddress,
    multicodec,
    muxers/muxer,
  ]
import ../../tools/[unittest, crypto as cryptoTools, multiaddress]

# TCP

proc isTcpTransport*(ma: MultiAddress): bool =
  # Check if this is a pure TCP transport (not WebSocket or Tor)
  TCP.match(ma)

# TOR

proc isTorTransport*(ma: MultiAddress): bool =
  # Tor transport handles both pure Onion3 addresses and TcpOnion3 addresses
  Onion3.match(ma) or TcpOnion3.match(ma)

# WS

proc isWsTransport*(ma: MultiAddress): bool =
  WebSockets.match(ma)

# QUIC

proc isQuicTransport*(ma: MultiAddress): bool =
  QUIC_V1.match(ma)

proc createServerAcceptConn*(
    server: QuicTransport
): proc(): Future[void] {.
  async: (raises: [transport.TransportError, LPError, LPStreamError, CancelledError])
.} =
  proc handler() {.
      async:
        (raises: [transport.TransportError, LPError, LPStreamError, CancelledError])
  .} =
    let conn = await server.accept()
    let muxer = QuicMuxer.new(conn)
    let stream = await muxer.newStream()
    defer:
      await stream.close()
      await muxer.close()

    var resp: array[6, byte]
    await stream.readExactly(addr resp, 6)
    check string.fromBytes(resp) == "client"
    await stream.write("server")

  return handler

proc invalidCertGenerator*(
    kp: KeyPair
): CertificateX509 {.gcsafe, raises: [TLSCertificateError].} =
  try:
    let keyNew = PrivateKey.random(ECDSA, rng()).get()
    let pubkey = keyNew.getPublicKey().get()
    # invalidKp has pubkey that does not match seckey
    let invalidKp = KeyPair(seckey: kp.seckey, pubkey: pubkey)
    return generateX509(invalidKp, encodingFormat = EncodingFormat.PEM)
  except ResultError[crypto.CryptoError]:
    raiseAssert "private key should be set"

proc createQuicTransport*(
    isServer: bool = false,
    withInvalidCert: bool = false,
    privateKey: Opt[PrivateKey] = Opt.none(PrivateKey),
    addresses: seq[MultiAddress] = @[QuicAutoAddress],
    inTimeout: Duration = DefaultChanTimeout,
    outTimeout: Duration = DefaultChanTimeout,
): Future[QuicTransport] {.async.} =
  let key =
    if privateKey.isNone:
      PrivateKey.random(ECDSA, rng()).tryGet()
    else:
      privateKey.get()

  let trans =
    if withInvalidCert:
      QuicTransport.new(
        Upgrade(),
        key,
        rng(),
        invalidCertGenerator,
        inTimeout = inTimeout,
        outTimeout = outTimeout,
      )
    else:
      QuicTransport.new(
        Upgrade(), key, rng(), inTimeout = inTimeout, outTimeout = outTimeout
      )

  if isServer: # servers are started because they need to listen
    await trans.start(addresses)

  return trans

# Common 

type TransportProvider* = proc(): Transport {.gcsafe, raises: [].}

type StreamProvider* =
  proc(conn: RawConn, handle: bool = true): Muxer {.gcsafe, raises: [].}

type StreamHandler* = proc(stream: MuxedStream) {.async: (raises: []).}

proc addrByFamily*(addrs: seq[MultiAddress], family: MaPattern): MultiAddress =
  ## First address whose leading ip component matches `family` (IP4 or IP6).
  for a in addrs:
    if family.matchPartial(a):
      return a
  raiseAssert "no address for the requested family"

proc extractPort*(ma: MultiAddress): int =
  var codec =
    if isTcpTransport(ma) or isWsTransport(ma):
      multiCodec("tcp")
    elif isQuicTransport(ma):
      multiCodec("udp")
    else:
      raiseAssert "not supported"

  # Extract port number
  let portBytes = ma[codec].tryGet().protoArgument().tryGet()
  let port = int(fromBytesBE(uint16, portBytes))
  port

template noExceptionWithStreamClose*(stream: Stream, body) =
  try:
    body
  except CancelledError:
    discard # handler torn down during muxer close; stream is closed below
  except CatchableError as exc:
    raiseAssert "should not fail: " & exc.msg
  finally:
    await noCancel stream.close()

template noExceptionWithStreamClose*(stream: Stream, handlerDone: Future[void], body) =
  ## Variant for a handler whose peer must wait for it. The scenarios tear the
  ## connection down as soon as the client handler returns, which cancels a
  ## server handler that still runs, so the peer awaits `handlerDone` before it
  ## returns. The signal fires on every exit path, also on a failed check, so
  ## the peer cannot hang and turn a failure into a timeout.
  try:
    noExceptionWithStreamClose(stream, body)
  finally:
    handlerDone.complete()

proc serverHandlerSingleStream*(
    server: Transport, streamProvider: StreamProvider, handler: StreamHandler
) {.async: (raises: []).} =
  try:
    let conn = await server.accept()
    let muxer = streamProvider(conn, false)
    muxer.streamHandler = handler

    await muxer.handle()

    await muxer.close()
    await conn.close()
  except CatchableError as exc:
    raiseAssert "should not fail: " & exc.msg

proc clientRunSingleStreamTo*(
    address: MultiAddress,
    transportProvider: TransportProvider,
    streamProvider: StreamProvider,
    handler: StreamHandler,
) {.async: (raises: []).} =
  try:
    let client = transportProvider()
    let conn = await client.dial("", address)
    let muxer = streamProvider(conn)

    let stream = await muxer.newStream()
    await handler(stream)

    await muxer.close()
    await conn.close()
    await client.stop()
  except CatchableError as exc:
    raiseAssert "should not fail: " & exc.msg

proc clientRunSingleStream*(
    server: Transport,
    transportProvider: TransportProvider,
    streamProvider: StreamProvider,
    handler: StreamHandler,
) {.async: (raises: []).} =
  await clientRunSingleStreamTo(
    server.addrs[0], transportProvider, streamProvider, handler
  )

proc runStreamHandler*(muxer: Muxer, handler: StreamHandler) {.async: (raises: []).} =
  ## Open a new stream on an already-established muxer and run `handler` on it.
  try:
    let stream = await muxer.newStream()
    await handler(stream)
  except CatchableError as exc:
    raiseAssert "should not fail: " & exc.msg

proc runSingleStreamScenario*(
    multiAddress: seq[MultiAddress],
    transportProvider: TransportProvider,
    streamProvider: StreamProvider,
    serverStreamHandler: StreamHandler,
    clientStreamHandler: StreamHandler,
) {.async: (raises: [CancelledError, LPError]).} =
  let server = transportProvider()
  await server.start(multiAddress)
  let serverTask =
    serverHandlerSingleStream(server, streamProvider, serverStreamHandler)

  let clientTask = clientRunSingleStream(
    server, transportProvider, streamProvider, clientStreamHandler
  )
  await clientTask
  await server.stop()
  await serverTask

proc dualStackStreamScenario*(
    listenAddrs: seq[MultiAddress],
    transportProvider: TransportProvider,
    streamProvider: StreamProvider,
    serverStreamHandler: StreamHandler,
    clientStreamHandler: StreamHandler,
) {.async: (raises: [CancelledError, LPError]).} =
  ## Start one server on `listenAddrs`, then dial it once per address family from
  ## a fresh client, serving each accepted connection with `serverStreamHandler`.
  let server = transportProvider()
  await server.start(listenAddrs)
  defer:
    await server.stop()

  # dial the server's resolved address of each family, not the wildcard input
  let targets = @[server.addrs.addrByFamily(IP4), server.addrs.addrByFamily(IP6)]

  # accept() is single-consumer, so serve the clients one after another
  proc serveAll() {.async: (raises: []).} =
    for _ in targets:
      await serverHandlerSingleStream(server, streamProvider, serverStreamHandler)

  let serverTask = serveAll()
  var clientTasks: seq[Future[void]]
  for target in targets:
    clientTasks.add(
      clientRunSingleStreamTo(
        target, transportProvider, streamProvider, clientStreamHandler
      )
    )
  await allFutures(clientTasks)
  await serverTask

proc countTransitions*(readOrder: seq[byte]): int =
  var transitions = 0
  for i in 1 ..< readOrder.len:
    if readOrder[i] != readOrder[i - 1]:
      transitions += 1
  transitions
