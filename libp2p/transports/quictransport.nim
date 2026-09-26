# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[hashes, sets, sequtils]
import chronos, chronicles, metrics, results
import lsquic
import
  ../crypto/rng,
  ../wire,
  ../connmanager,
  ../multiaddress,
  ../multicodec,
  ../muxers/muxer,
  ../stream/connection,
  ../upgrademngrs/upgrade,
  ../utils/opt,
  ../utils/future
import ./transport
import tls/certificate

export multiaddress
export multicodec
export connection
export transport

logScope:
  topics = "libp2p quic"

const QuicHolePunchPacketSize* = 64

type
  P2PConnection = connection.Connection
  QuicConnection = lsquic.Connection
  LsquicStream = lsquic.Stream
  QuicTransportError* = object of transport.TransportError
  QuicTransportDialError* = object of transport.TransportDialError
  QuicTransportAcceptStopped* = object of QuicTransportError

  QuicStream* = ref object of P2PConnection
    session: QuicSession
    stream: LsquicStream

  QuicSession* = ref object of P2PConnection
    connection: QuicConnection
    streams: HashSet[QuicStream]
    inTimeout: Duration
    outTimeout: Duration
    when defined(libp2p_agents_metrics):
      tracked: bool

func hash*(s: QuicStream): Hash =
  cast[pointer](s).hash

const alpn = "libp2p"

initializeLsquic()

proc new(
    _: type QuicStream,
    stream: LsquicStream,
    dir: Direction,
    session: QuicSession,
    timeout: Duration,
    oaddr: Opt[MultiAddress],
    laddr: Opt[MultiAddress],
    peerId: PeerId,
): QuicStream =
  let quicstream = QuicStream(
    session: session,
    stream: stream,
    timeout: timeout,
    observedAddr: oaddr,
    localAddr: laddr,
    peerId: peerId,
  )
  quicstream.objName = "QuicStream"
  quicstream.dir = dir
  quicstream.timeoutHandler = proc(): Future[void] {.async: (raises: [], raw: true).} =
    trace "Idle timeout expired, resetting QuicStream"
    quicstream.reset()
  procCall P2PConnection(quicstream).initStream()
  quicstream

method getWrapped*(self: QuicStream): P2PConnection =
  self.session

when defined(libp2p_agents_metrics):
  proc trackPeerIdentity(s: QuicSession) =
    if not s.tracked and s.shortAgent.len > 0:
      libp2p_peers_identity.inc(labelValues = [s.shortAgent])
      s.tracked = true

  proc untrackPeerIdentity(s: QuicSession) =
    if s.tracked:
      libp2p_peers_identity.dec(labelValues = [s.shortAgent])
      s.tracked = false

method readOnce*(
    stream: QuicStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  if stream.wasResetLocally:
    raise newLPStreamClosedError()

  if stream.atEof:
    raise newLPStreamRemoteClosedError()

  var readLen: int
  try:
    readLen = await stream.stream.readOnce(cast[ptr byte](pbytes), nbytes)
  except StreamError as e:
    raise newLPStreamResetError()

  if readLen == 0:
    stream.isEof = true
    return 0

  stream.activity = true
  libp2p_network_bytes.inc(readLen.int64, labelValues = ["in"])
  when defined(libp2p_agents_metrics):
    stream.session.trackPeerIdentity()
    if stream.session.tracked:
      libp2p_peers_traffic_read.inc(readLen.int64, labelValues = [stream.shortAgent])
  return readLen

method write*(
    stream: QuicStream, bytes: sink seq[byte]
) {.async: (raises: [CancelledError, LPStreamError]).} =
  if stream.wasResetLocally:
    raise newLPStreamClosedError()

  let bytesLen = bytes.len
  try:
    await stream.stream.write(bytes)
    libp2p_network_bytes.inc(bytesLen.int64, labelValues = ["out"])
    stream.activity = true
    when defined(libp2p_agents_metrics):
      stream.session.trackPeerIdentity()
      if stream.session.tracked:
        libp2p_peers_traffic_write.inc(
          bytesLen.int64, labelValues = [stream.shortAgent]
        )
  except StreamError:
    raise newLPStreamResetError()

method closeWrite*(stream: QuicStream) {.async: (raises: []).} =
  ## Close the write side of the QUIC stream
  try:
    await stream.stream.close()
  except CancelledError, StreamError:
    discard

method resetImpl*(stream: QuicStream) {.async: (raises: []).} =
  stream.stream.abort()
  stream.isEof = true
  stream.session.streams.excl(stream)
  await procCall P2PConnection(stream).closeImpl()

method closeImpl*(stream: QuicStream) {.async: (raises: []).} =
  try:
    await stream.stream.close()
  except CancelledError, StreamError:
    discard
  stream.session.streams.excl(stream)
  await procCall P2PConnection(stream).closeImpl()

# Session
method closed*(session: QuicSession): bool {.raises: [].} =
  procCall P2PConnection(session).isClosed or session.connection.isClosed

method close*(session: QuicSession) {.async: (raises: []).} =
  if session.isClosed:
    await noCancel session.join()
    return

  session.isClosed = true

  let streams = session.streams
  session.streams.clear()
  await noCancel allFutures(streams.mapIt(it.close()))
  session.connection.close()
  when defined(libp2p_agents_metrics):
    session.untrackPeerIdentity()
  await procCall P2PConnection(session).closeImpl()

proc getStream(
    session: QuicSession, direction = Direction.In
): Future[QuicStream] {.async: (raises: [CancelledError, ConnectionError]).} =
  if session.closed:
    raise newException(ConnectionClosedError, "session is closed")

  var stream: LsquicStream
  case direction
  of Direction.In:
    stream = await session.connection.incomingStream()
  of Direction.Out:
    stream = await session.connection.openStream()

  let timeout = if direction == Direction.In: session.inTimeout else: session.outTimeout
  let qs = QuicStream.new(
    stream, direction, session, timeout, session.observedAddr, session.localAddr,
    session.peerId,
  )
  when defined(libp2p_agents_metrics):
    qs.shortAgent = session.shortAgent

  # Inherit transportDir from parent session for GossipSub outbound peer tracking
  qs.transportDir = session.transportDir

  session.streams.incl(qs)
  return qs

method getWrapped*(self: QuicSession): P2PConnection =
  # QuicSession is the underlying transport connection; returning nil ends
  # wrapper traversal for callers that walk through layered connections.
  nil

# Muxer
type QuicMuxer* = ref object of Muxer
  session: QuicSession
  handleFut: Future[void]
  handleStreamFuts: seq[Future[void]]

proc parseCertificate(certificatesDer: seq[seq[byte]]): LPResult[P2pCertificate] =
  if certificatesDer.len != 1:
    return err("expected one certificate, got " & $certificatesDer.len)

  try:
    ok(parse(certificatesDer[0]))
  except CertificateParsingError as e:
    err("cannot parse certificate. " & e.msg)

proc certificatePeerId(certificatesDer: seq[seq[byte]]): LPResult[PeerId] =
  let cert = ?parseCertificate(certificatesDer)
  let peerId = PeerId.init(cert.publicKey()).valueOr:
    return err("cannot derive peer ID from certificate. " & $error)
  ok(peerId)

proc tryNew*(
    _: type QuicMuxer, conn: P2PConnection, peerId: Opt[PeerId] = Opt.none(PeerId)
): LPResult[QuicMuxer] =
  if conn.isNil:
    return err("QuicMuxer.new called with nil connection")

  let session = QuicSession(conn)
  session.peerId = peerId.valueOr:
    certificatePeerId(session.connection.certificates()).valueOr:
      return err("QuicMuxer.new called with invalid peer certificate. " & error)
  ok(QuicMuxer(session: session, connection: conn))

proc new*(
    _: type QuicMuxer, conn: P2PConnection, peerId: Opt[PeerId] = Opt.none(PeerId)
): QuicMuxer {.raises: [LPError].} =
  QuicMuxer.tryNew(conn, peerId).valueOrRaise(QuicTransportError)

when defined(libp2p_agents_metrics):
  method setShortAgent*(m: QuicMuxer, shortAgent: string) =
    m.session.shortAgent = shortAgent
    for s in m.session.streams:
      s.shortAgent = shortAgent
    m.connection.shortAgent = shortAgent

method newStream*(
    m: QuicMuxer, name: string = "", lazy: bool = false
): Future[MuxedStream] {.async: (raises: [CancelledError, LPStreamError, MuxerError]).} =
  try:
    return await m.session.getStream(Direction.Out)
  except ConnectionError as e:
    raise newException(MuxerError, "error in newStream: " & e.msg, e)

method getStreams*(m: QuicMuxer): seq[MuxedStream] {.gcsafe.} =
  var streams = newSeqOfCap[MuxedStream](m.session.streams.len)
  for s in m.session.streams:
    streams.add(s)
  return streams

method handle*(m: QuicMuxer): Future[void] {.async: (raises: []).} =
  proc handleStream(stream: QuicStream) {.async: (raises: []).} =
    ## call the muxer stream handler for this channel
    ##
    await m.streamHandler(stream)
    trace "Finished handling stream"
    doAssert(stream.closed, "connection not closed by handler!")

  while not (m.session.atEof or m.session.closed):
    try:
      let stream = await m.session.getStream(Direction.In)
      m.handleStreamFuts.trackFut(handleStream(stream))
    except ConnectionClosedError:
      break # stop handling, connection was closed
    except CancelledError:
      continue # keep handling, until connection is closed
    except ConnectionError as e:
      # keep handling, until connection is closed. 
      # this stream failed but we need to keep handling for other streams.
      trace "QuicMuxer.handler got error while opening stream", err = e.msg

  if not m.session.isClosed:
    await m.session.close()

method close*(m: QuicMuxer) {.async: (raises: []).} =
  if m.isNil:
    return

  ## Closes the session and joins the accept loop. The session must be closed
  ## first or the loop won't exit and `cancelAndWait` would hang.
  if not m.session.isNil:
    await noCancel m.session.close()

  if not m.handleFut.isNil:
    await noCancel m.handleFut.cancelAndWait()

  ## Cancels in-flight stream handlers so each stream is torn down here
  ## (handlers run closeWithEOF on cancel) instead of being aborted during GC.
  let handleStreamFuts = move m.handleStreamFuts
  await noCancel handleStreamFuts.cancelAndWait()

# Transport
type QuicUpgrade = ref object of Upgrade
  connManager: Opt[ConnManager]

type CertGenerator =
  proc(kp: KeyPair): CertificateX509 {.gcsafe, raises: [TLSCertificateError].}

type QuicAcceptType = typeof(default(QuicEndpoint).accept())

type QuicTransport* = ref object of Transport
  listeners: seq[QuicEndpoint]
  acceptFuts: seq[QuicAcceptType]
  dialEndpoint4: Opt[QuicEndpoint]
  dialEndpoint6: Opt[QuicEndpoint]
  privateKey: PrivateKey
  connections: HashSet[P2PConnection]
  rng: Rng
  certGenerator: CertGenerator
  closeFuts: seq[Future[void]]
  inTimeout: Duration
  outTimeout: Duration

type PeerIdCertificateVerifier = ref object of CertificateVerifier
  expectedPeerId: PeerId

proc verifyCertificates(certificatesDer: seq[seq[byte]]): bool =
  let cert = parseCertificate(certificatesDer).valueOr:
    trace "QUIC certificate rejected", err = error
    return false

  if cert.verifiedIdentityKey().isNone:
    trace "QUIC certificate verification failed"
    return false
  true

proc verifyCertificatesForPeer(
    certificatesDer: seq[seq[byte]], expectedPeerId: PeerId
): bool =
  let cert = parseCertificate(certificatesDer).valueOr:
    trace "QUIC certificate rejected", err = error
    return false

  if not cert.verify(expectedPeerId):
    trace "QUIC certificate peer identity rejected", expectedPeerId = expectedPeerId
    return false
  true

method verify(
    self: PeerIdCertificateVerifier, _: string, certificatesDer: seq[seq[byte]]
): bool =
  verifyCertificatesForPeer(certificatesDer, self.expectedPeerId)

proc certificateVerifier(_: string, certificatesDer: seq[seq[byte]]): bool {.gcsafe.} =
  verifyCertificates(certificatesDer)

proc defaultCertGenerator(
    kp: KeyPair
): CertificateX509 {.gcsafe, raises: [TLSCertificateError].} =
  return generateX509(kp, encodingFormat = EncodingFormat.PEM)

proc new*(
    _: type QuicTransport,
    u: Upgrade,
    privateKey: PrivateKey,
    rng: Rng,
    connManager: ConnManager = nil,
    inTimeout: Duration = DefaultChanTimeout,
    outTimeout: Duration = DefaultChanTimeout,
): QuicTransport =
  doAssert not rng.isNil, "Rng is nil"

  let self = QuicTransport(
    upgrader: QuicUpgrade(ms: u.ms, connManager: connManager.toOpt()),
    privateKey: privateKey,
    rng: rng,
    certGenerator: defaultCertGenerator,
    inTimeout: inTimeout,
    outTimeout: outTimeout,
  )
  procCall Transport(self).initialize()
  self

proc new*(
    _: type QuicTransport,
    u: Upgrade,
    privateKey: PrivateKey,
    rng: Rng,
    certGenerator: CertGenerator,
    connManager: ConnManager = nil,
    inTimeout: Duration = DefaultChanTimeout,
    outTimeout: Duration = DefaultChanTimeout,
): QuicTransport =
  doAssert not rng.isNil, "Rng is nil"

  let self = QuicTransport(
    upgrader: QuicUpgrade(ms: u.ms, connManager: connManager.toOpt()),
    privateKey: privateKey,
    rng: rng,
    certGenerator: certGenerator,
    inTimeout: inTimeout,
    outTimeout: outTimeout,
  )
  procCall Transport(self).initialize()
  self

method handles*(transport: QuicTransport, address: MultiAddress): bool {.raises: [].} =
  if not procCall Transport(transport).handles(address):
    return false
  QUIC_V1.match(address)

proc makeConfig(self: QuicTransport): LPResult[TLSConfig] =
  let pubkey = self.privateKey.getPublicKey().valueOr:
    return err("cannot obtain public key. " & $error)

  let cert =
    try:
      self.certGenerator(KeyPair(seckey: self.privateKey, pubkey: pubkey))
    except TLSCertificateError as e:
      return err("cannot generate certificate. " & e.msg)

  let certVerifier = CustomCertificateVerifier.init(certificateVerifier)
  try:
    ok(
      TLSConfig.new(
        cert.certificate,
        cert.privateKey,
        @[alpn],
        Opt.some(CertificateVerifier(certVerifier)),
      )
    )
  except QuicConfigError as e:
    err("invalid TLS config. " & e.msg)

proc toMultiAddress(ta: TransportAddress): MaResult[MultiAddress] =
  concat(?MultiAddress.init(ta, IPPROTO_UDP), ?MultiAddress.init("/quic-v1"))

proc listen(
    self: QuicTransport, addrs: openArray[TransportAddress]
): LPResult[seq[MultiAddress]] =
  ## Endpoints created before a failure stay in `self.listeners` for the caller to stop.
  let tlsConfig = ?self.makeConfig()
  var listenMAs: seq[MultiAddress]
  for ta in addrs:
    let endpoint =
      try:
        QuicEndpoint.new(tlsConfig, ta)
      except QuicError as e:
        return err("cannot listen on " & $ta & ". " & e.msg)
      except TransportOsError as e:
        return err("cannot listen on " & $ta & ". " & e.msg)
    self.listeners.add(endpoint)

    let local =
      try:
        endpoint.localAddress()
      except TransportOsError as e:
        return err("cannot read local address. " & e.msg)
    listenMAs.add(?toMultiAddress(local))

  ok(listenMAs)

method start*(
    self: QuicTransport, addrs: seq[MultiAddress]
) {.async: (raises: [LPError, transport.TransportError, CancelledError]).} =
  if self.running:
    warn "QUIC transport already started"
    return

  doAssert self.listeners.len == 0, "start() already called"

  let addrsTa = self.toTransportAddress(addrs).valueOrRaise(TransportStartError)
  let listenMAs = self.listen(addrsTa).valueOr:
    await noCancel allFutures(self.listeners.mapIt(it.stop()))
    self.listeners = @[]
    raise (ref QuicTransportError)(msg: "QuicTransport.start failed. " & error)

  await procCall Transport(self).start(listenMAs)
  info "QUIC transport started", addresses = self.addrs

method stop*(transport: QuicTransport) {.async: (raises: []).} =
  let wasRunning = transport.running
  if wasRunning:
    await noCancel procCall Transport(transport).stop()
  else:
    warn "QUIC transport already stopped"

  let futs = transport.connections.mapIt(it.close())
  await noCancel allFutures(futs)

  await noCancel allFutures(transport.closeFuts)
  transport.closeFuts = @[]

  var endpointStops: seq[Future[void]]
  transport.dialEndpoint4.ifValue(endpoint):
    endpointStops.add(endpoint.stop())
  transport.dialEndpoint6.ifValue(endpoint):
    endpointStops.add(endpoint.stop())
  await noCancel allFutures(endpointStops)

  transport.dialEndpoint4 = Opt.none(QuicEndpoint)
  transport.dialEndpoint6 = Opt.none(QuicEndpoint)

  await noCancel allFutures(transport.listeners.mapIt(it.stop()))
  transport.listeners = @[]
  transport.acceptFuts = @[]

  if wasRunning:
    info "QUIC transport stopped", addresses = transport.addrs

proc wrapConnection(
    transport: QuicTransport, connection: QuicConnection, transportDir: Direction
): LPResult[QuicSession] =
  let observedAddr = ?toMultiAddress(connection.remoteAddress())
  let localAddr = ?toMultiAddress(connection.localAddress())

  let session = QuicSession(
    dir: transportDir,
    objName: "QuicSession",
    connection: connection,
    observedAddr: Opt.some(observedAddr),
    localAddr: Opt.some(localAddr),
    inTimeout: transport.inTimeout,
    outTimeout: transport.outTimeout,
  )
  session.initStream()

  # Set the transport direction for outbound peer tracking in GossipSub 1.1
  session.transportDir = transportDir

  transport.connections.incl(session)

  proc onClose() {.async: (raises: []).} =
    await noCancel session.join()
    transport.connections.excl(session)
    trace "Cleaned up client"

  transport.closeFuts.trackFut(onClose())

  ok(session)

method accept*(
    self: QuicTransport
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  if not self.running:
    # stop accept only when transport is stopped (not when error occurs)
    raise newException(QuicTransportAcceptStopped, "Quic transport stopped")

  doAssert self.listeners.len > 0, "call start() before calling accept()"

  if self.acceptFuts.len == 0:
    # initially start accept from all listeners
    self.acceptFuts = self.listeners.mapIt(it.accept())

  let finished =
    try:
      let acceptFutsCopy = self.acceptFuts
      await one(acceptFutsCopy)
    except ValueError:
      raiseAssert "acceptFuts should never be empty"
    except CancelledError as exc:
      self.acceptFuts.cancelSoon()
      raise exc

  if not self.running or self.listeners.len == 0: # Stopped while waiting
    raise newTransportClosedError()

  # Replace the completed accept before awaiting its result so that every
  # listener remains ready for future connections.
  let index = self.acceptFuts.find(finished)
  self.acceptFuts[index] = self.listeners[index].accept()

  let conn =
    try:
      await finished
    except common.TransportError as exc:
      debug "QUIC transport stopped during acceptance", err = exc.msg
      raise newTransportClosedError(exc)

  self.wrapConnection(conn, Direction.In).valueOr:
    conn.close()
    raise (ref QuicTransportError)(msg: "QuicTransport.accept failed. " & error)

proc listenerEndpointFor(
    self: QuicTransport, address: TransportAddress
): LPResult[Opt[QuicEndpoint]] =
  var matchedEndpoint = Opt.none(QuicEndpoint)
  for endpoint in self.listeners:
    let local =
      try:
        endpoint.localAddress()
      except TransportOsError as e:
        return err("cannot read listener address. " & e.msg)
    if local.family == address.family:
      if matchedEndpoint.isSome():
        return ok(Opt.none(QuicEndpoint))
      matchedEndpoint = Opt.some(endpoint)

  ok(matchedEndpoint)

proc newDialEndpoint(
    self: QuicTransport, family: AddressFamily
): LPResult[QuicEndpoint] =
  let tlsConfig = ?self.makeConfig()
  try:
    ok(QuicEndpoint.new(tlsConfig, family))
  except QuicError as e:
    err("cannot create dial endpoint. " & e.msg)
  except TransportOsError as e:
    err("cannot create dial endpoint. " & e.msg)

proc dialOnlyEndpointFor(
    self: QuicTransport, family: AddressFamily
): LPResult[QuicEndpoint] =
  case family
  of AddressFamily.IPv4:
    if self.dialEndpoint4.isNone():
      let endpoint = ?self.newDialEndpoint(family)
      self.dialEndpoint4 = Opt.some(endpoint)
    ok(self.dialEndpoint4.get())
  of AddressFamily.IPv6:
    if self.dialEndpoint6.isNone():
      let endpoint = ?self.newDialEndpoint(family)
      self.dialEndpoint6 = Opt.some(endpoint)
    ok(self.dialEndpoint6.get())
  else:
    err("client supports only IPv4/IPv6 address")

proc dialEndpointFor(
    self: QuicTransport, address: TransportAddress
): LPResult[QuicEndpoint] =
  let listenerEndpoint = ?self.listenerEndpointFor(address)
  listenerEndpoint.ifValue(endpoint):
    return ok(endpoint)

  self.dialOnlyEndpointFor(address.family)

proc holePunch(
    self: QuicTransport, endpoint: QuicEndpoint, address: TransportAddress
) {.async: (raises: [CancelledError, QuicTransportDialError]).} =
  # Random UDP packets open the NAT mapping of the Sync sender, which is the QUIC server.
  while true:
    let payload = self.rng.generateBytes(QuicHolePunchPacketSize)
    try:
      await endpoint.datagramTransport().sendTo(address, payload)
    except chronos.TransportError as e:
      raise newException(
        QuicTransportDialError, "QUIC hole punch cannot send packet. " & e.msg, e
      )
    let delay = self.rng.rand(10, 200)
    await sleepAsync(delay.milliseconds)

method dial*(
    self: QuicTransport,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  let taAddress = initTAddress(address).valueOr:
    raise newException(
      QuicTransportDialError,
      "QuicTransport.dial called with invalid address " & $address & ". " & error,
    )

  if dir == Direction.In:
    let listenerEndpoint = self.listenerEndpointFor(taAddress).valueOr:
      raise newException(QuicTransportDialError, "QuicTransport.dial failed. " & error)
    let endpoint = listenerEndpoint.valueOr:
      raise newException(
        QuicTransportDialError,
        "QuicTransport.dial found no unique listener for the address family",
      )
    await self.holePunch(endpoint, taAddress)

  let endpoint = self.dialEndpointFor(taAddress).valueOr:
    raise newException(QuicTransportDialError, "QuicTransport.dial failed. " & error)

  let quicConnection =
    try:
      if peerId.isSome():
        await endpoint.dial(
          taAddress, PeerIdCertificateVerifier(expectedPeerId: peerId.get())
        )
      else:
        await endpoint.dial(taAddress)
    except QuicError as e:
      raise
        newException(QuicTransportDialError, "QuicTransport.dial failed. " & e.msg, e)
    except DialError as e:
      raise
        newException(QuicTransportDialError, "QuicTransport.dial failed. " & e.msg, e)
    except TransportOsError as e:
      raise
        newException(QuicTransportDialError, "QuicTransport.dial failed. " & e.msg, e)

  self.wrapConnection(quicConnection, Direction.Out).valueOr:
    quicConnection.close()
    raise newException(QuicTransportDialError, "QuicTransport.dial failed. " & error)

method upgrade*(
    self: QuicTransport, conn: RawConn, peerId: Opt[PeerId]
): Future[Muxer] {.async: (raises: [CancelledError, LPError]).} =
  let muxer = QuicMuxer.new(conn, peerId)
  muxer.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
    trace "QUIC stream handler started", stream
    try:
      let quicUpgrader = QuicUpgrade(self.upgrader)
      quicUpgrader.connManager.ifValue(connManager):
        let ready = await connManager.waitForPeerReady(stream.peerId)
        if not ready:
          debug "Timed out waiting for peer ready before handling stream", stream
          return
      await self.upgrader.ms.handle(stream) # handle incoming stream
    except CancelledError:
      return
    except CatchableError as exc:
      trace "QUIC stream handler failed", err = exc.msg, stream
    finally:
      await stream.closeWithEOF()
      trace "QUIC stream handler completed", stream
  muxer.handleFut = muxer.handle()
  return muxer
