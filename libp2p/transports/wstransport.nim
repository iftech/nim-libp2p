# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## WebSocket & WebSocket Secure transport implementation

{.push raises: [].}

import ../logging
import std/[sequtils]
import chronos, chronicles, results, metrics, stew/byteutils
import
  transport,
  ../autotls/service,
  ../errors,
  ../wire,
  ../multicodec,
  ../multistream,
  ../multiaddress,
  ../utils/opt,
  ../utils/tlsredact,
  ../crypto/rng,
  ../stream/connection,
  ../upgrademngrs/upgrade,
  websock/websock

logScope:
  topics = "libp2p websocket"

export transport, websock, results

const
  DefaultHeadersTimeout = 3.seconds
  DefaultConcurrentAccepts = 200
  DefaultAcceptFailureBackoff = 100.millis
  DefaultAutotlsWaitTimeout = 3.seconds

type
  WsStream = ref object of Connection
    session: WSSession
    when defined(libp2p_agents_metrics):
      tracked: bool

  WsTransportError* = object of transport.TransportError

method initStream*(s: WsStream) =
  if s.objName.len == 0:
    s.objName = "WsStream"

  procCall Connection(s).initStream()

proc new*(
    T: type WsStream,
    session: WSSession,
    dir: Direction,
    observedAddr: Opt[MultiAddress],
    localAddr: Opt[MultiAddress],
    timeout = 10.minutes,
): T {.raises: [].} =
  let stream = T(
    session: session,
    timeout: timeout,
    dir: dir,
    observedAddr: observedAddr,
    localAddr: localAddr,
  )

  stream.initStream()
  return stream

template mapExceptions(body: untyped): untyped =
  try:
    body
  except AsyncStreamIncompleteError:
    raise newLPStreamIncompleteError()
  except AsyncStreamLimitError:
    raise newLPStreamLimitError()
  except AsyncStreamUseClosedError:
    raise newLPStreamEOFError()
  except WSClosedError:
    raise newLPStreamEOFError()
  except WebSocketError:
    raise newLPStreamEOFError()
  except CancelledError as exc:
    raise exc
  except CatchableError:
    raise newLPStreamEOFError()

when defined(libp2p_agents_metrics):
  proc trackPeerIdentity(s: WsStream) =
    if not s.tracked and s.shortAgent.len > 0:
      libp2p_peers_identity.inc(labelValues = [s.shortAgent])
      s.tracked = true

  proc untrackPeerIdentity(s: WsStream) =
    if s.tracked:
      libp2p_peers_identity.dec(labelValues = [s.shortAgent])
      s.tracked = false

method readOnce*(
    s: WsStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  let res = mapExceptions(await s.session.recv(pbytes, nbytes))

  if res == 0 and s.session.readyState == ReadyState.Closed:
    raise newLPStreamEOFError()
  s.activity = true # reset activity flag
  libp2p_network_bytes.inc(res.int64, labelValues = ["in"])
  when defined(libp2p_agents_metrics):
    s.trackPeerIdentity()
    if s.tracked:
      libp2p_peers_traffic_read.inc(res.int64, labelValues = [s.shortAgent])
  return res

method write*(
    s: WsStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  let msgLen = msg.len
  mapExceptions(await s.session.send(msg, Opcode.Binary))
  s.activity = true # reset activity flag
  libp2p_network_bytes.inc(msgLen.int64, labelValues = ["out"])
  when defined(libp2p_agents_metrics):
    s.trackPeerIdentity()
    if s.tracked:
      libp2p_peers_traffic_write.inc(msgLen.int64, labelValues = [s.shortAgent])

method closeImpl*(s: WsStream): Future[void] {.async: (raises: []).} =
  try:
    await s.session.close()
  except CatchableError:
    discard
  when defined(libp2p_agents_metrics):
    s.untrackPeerIdentity()
  await procCall Connection(s).closeImpl()

method getWrapped*(s: WsStream): Connection =
  nil

type WsTransport* = ref object of Transport
  descriptorWarnings: LogRateLimit
  httpservers: seq[HttpServer]
  wsserver: WSServer
  connections: array[Direction, seq[WsStream]]
  connectionCleanupFuts: seq[Future[void]]
  acceptLoop: Future[void]
  handshakeFuts: seq[Future[void]]
  acceptResults: AsyncQueue[RawConn]
  acceptSem: AsyncSemaphore

  tlsPrivateKey*: TLSPrivateKey
  tlsCertificate*: TLSCertificate
  autotls: Opt[AutotlsService]
  tlsFlags: set[TLSFlags]
  flags: set[ServerFlags]
  headersTimeout: Duration
  concurrentAccepts: int
  factories: seq[ExtFactory]
  rng: Rng

type HostHeaderHook = ref object of Hook
  host: string

proc hostHeaderHook(host: string): Hook =
  let hook = HostHeaderHook(host: host)
  hook.append = proc(ctx: Hook, headers: var HttpTable): LPResult[void] =
    headers.set("Host", HostHeaderHook(ctx).host)
    ok()
  hook

func websockRng(rng: Rng): RandomBytesRng =
  doAssert not rng.isNil(), "Rng is nil"
  proc(dst: var openArray[byte]): bool {.closure, gcsafe, raises: [].} =
    rng.generate(dst)
    true

proc getSni(address: MultiAddress): string =
  let value = address.getProtocolArgument(multiCodec("sni")).valueOr:
    return ""
  string.fromBytes(value)

proc secure*(self: WsTransport): bool =
  not (isNil(self.tlsPrivateKey) or isNil(self.tlsCertificate))

proc notifyAcceptClosed(self: WsTransport) {.raises: [].} =
  if self.acceptResults.isNil:
    return

  try:
    self.acceptResults.addLastNoWait(nil)
  except AsyncQueueFullError:
    trace "Queue is full"

proc releaseAcceptSlot(self: WsTransport) {.raises: [].} =
  try:
    self.acceptSem.release()
  except AsyncSemaphoreError as e:
    trace "WebSocket accept slot release failed", err = e.msg

proc closeHttpStream(stream: AsyncStream) {.async: (raises: []).} =
  try:
    await noCancel stream.closeWait()
  except CatchableError as e:
    trace "HTTP stream close failed", err = e.msg

proc connHandler(
  self: WsTransport, stream: WSSession, secure: bool, dir: Direction
): LPResult[WsStream] {.gcsafe.}

proc wsHandshakeWorker(
    self: WsTransport, server: HttpServer, stream: AsyncStream
) {.async: (raises: [CancelledError]).} =
  var accepted = false
  defer:
    self.releaseAcceptSlot()

  try:
    let conn = await (
      proc(): Future[RawConn] {.async: (raises: [CatchableError]).} =
        let req = await readHttpRequest(stream, server.headersTimeout)
        let session = await self.wsserver.handleRequest(req)
        let conn = self.connHandler(session, server.secure, Direction.In).valueOr:
          safeClose(session)
          raise error.toException(WsTransportError)
        conn
    )()
      .wait(self.headersTimeout)

    await self.acceptResults.addLast(conn)
    accepted = true
  except WebSocketError as e:
    debug "WebSocket handshake failed", err = e.msg
  except HttpError as e:
    debug "WebSocket HTTP handshake failed", err = e.msg
  except AsyncStreamError as e:
    debug "WebSocket transport stream failed", err = e.msg
  except AsyncTimeoutError as e:
    debug "WebSocket handshake timed out", err = e.msg
  except CancelledError as e:
    if not accepted:
      await noCancel closeHttpStream(stream)
    raise e
  except CatchableError as e:
    debug "WebSocket connection acceptance failed", err = e.msg

  if not accepted:
    await closeHttpStream(stream)

proc wsAcceptDispatcher(self: WsTransport) {.async: (raises: []).} =
  var acceptServers = self.httpservers
  var acceptFuts = acceptServers.mapIt(it.acceptStream())
  var notifyOnClose = false

  if acceptFuts.len == 0:
    self.notifyAcceptClosed()
    return

  try:
    while self.running:
      self.handshakeFuts.keepItIf(not it.finished)

      var acquired = false
      try:
        await self.acceptSem.acquire()
        acquired = true

        let finished =
          try:
            await one(acceptFuts)
          except ValueError:
            raiseAssert("accept futures should not be empty")

        let index = acceptFuts.find(finished)
        let server = acceptServers[index]

        if finished.completed():
          let stream = finished.read()
          acceptFuts[index] = server.acceptStream()
          self.handshakeFuts.add(self.wsHandshakeWorker(server, stream))
          acquired = false
        elif finished.failed():
          let exc = finished.error()
          if exc of TransportUseClosedError:
            debug "Server was closed", err = exc.msg
          elif exc of TransportTooManyError:
            if self.descriptorWarnings.allowLog():
              warn "Connection acceptance limited by file descriptor exhaustion",
                err = exc.msg, errType = exc.name, transport = "websocket"
          elif exc of TransportAbortedError:
            debug "Transport connection aborted", err = exc.msg
          elif exc of TransportOsError:
            debug "WebSocket socket acceptance failed", err = exc.msg
          else:
            debug "WebSocket stream acceptance failed", err = exc.msg

          if acquired:
            self.releaseAcceptSlot()
            acquired = false

          if exc of TransportUseClosedError:
            acceptFuts.delete(index)
            acceptServers.delete(index)
            if acceptFuts.len == 0:
              self.running = false
              notifyOnClose = true
              break
          elif self.running:
            await sleepAsync(DefaultAcceptFailureBackoff)
            if self.running:
              acceptFuts[index] = server.acceptStream()
      except CancelledError:
        if acquired:
          self.releaseAcceptSlot()
        break
      except CatchableError as e:
        if acquired:
          self.releaseAcceptSlot()
        if self.running:
          debug "WebSocket accept dispatcher failed", err = e.msg
        else:
          break
  finally:
    for fut in acceptFuts:
      if not fut.finished:
        await noCancel fut.cancelAndWait()
      elif fut.completed():
        try:
          await closeHttpStream(fut.read())
        except CatchableError as e:
          trace "WebSocket accepted stream read failed", err = e.msg

    if notifyOnClose:
      var toWait: seq[Future[void]]
      for fut in self.handshakeFuts:
        if not fut.finished:
          toWait.add(fut.cancelAndWait())

      if toWait.len > 0:
        try:
          await noCancel allFutures(toWait)
        except CatchableError as e:
          trace "WebSocket handshake worker shutdown failed", err = e.msg

      self.notifyAcceptClosed()

proc listen(
    self: WsTransport,
    addrs: openArray[MultiAddress],
    addrsTa: openArray[TransportAddress],
): LPResult[seq[MultiAddress]] =
  ## Servers created before a failure stay in `self.httpservers` for the caller to close.
  var resolved: seq[MultiAddress]
  for i, ma in addrs:
    let isWss = WSS.match(ma)
    if isWss and not self.secure:
      warn "Trying to listen on a WSS address without setting certificate or autotls"
    let secure = isWss and self.secure

    let httpserver =
      try:
        if secure:
          HttpServer.create(
            address = addrsTa[i],
            tlsPrivateKey = self.tlsPrivateKey,
            tlsCertificate = self.tlsCertificate,
            flags = self.flags,
            headersTimeout = self.headersTimeout,
          )
        else:
          HttpServer.create(addrsTa[i], headersTimeout = self.headersTimeout)
      except TransportOsError as e:
        return
          err("WsTransport.start failed to listen on " & $addrsTa[i] & ". " & e.msg)
    self.httpservers &= httpserver

    let codec =
      if secure:
        ?ma[2 .. ^1]
      else:
        ?MultiAddress.init("/ws")
    # read the real address, because the listen address can be 0.0.0.0:0
    resolved.add(?concat(?MultiAddress.init(httpserver.localAddress()), codec))

  ok(resolved)

method start*(
    self: WsTransport, addrs: seq[MultiAddress]
) {.async: (raises: [LPError, transport.TransportError, CancelledError]).} =
  ## listen on the transport
  if self.running:
    warn "WebSocket transport already started"
    return

  let addrsTa = self.toTransportAddress(addrs).valueOrRaise(TransportStartError)

  if not self.secure and self.autotls.isSome():
    self.autotls.ifValue(autotls):
      if not await autotls.running.wait().withTimeout(DefaultAutotlsWaitTimeout):
        error "Unable to upgrade, autotls not running"
        await self.stop()
        return

      trace "Waiting for autotls certificate"
      let autotlsCert =
        try:
          await autotls.getCertWhenReady()
        except AutoTLSError as e:
          raise newException(LPError, e.msg, e)
      self.tlsCertificate = autotlsCert.cert
      self.tlsPrivateKey = autotlsCert.privkey

  self.wsserver = WSServer.new(factories = self.factories, rng = websockRng(self.rng))

  let resolvedAddrs = self.listen(addrs, addrsTa).valueOr:
    await noCancel allFutures(self.httpservers.mapIt(it.closeWait()))
    reset(self.httpservers)
    raise error.toException(WsTransportError)

  self.acceptSem = newAsyncSemaphore(self.concurrentAccepts)
  self.acceptResults = newAsyncQueue[RawConn](self.concurrentAccepts)
  self.handshakeFuts = @[]

  await procCall Transport(self).start(resolvedAddrs)
  self.acceptLoop = self.wsAcceptDispatcher()

  info "WebSocket transport started", addresses = self.addrs

method stop*(self: WsTransport) {.async: (raises: []).} =
  ## stop the transport
  ##

  let wasRunning = self.running
  self.running = false # mark stopped as soon as possible
  if not wasRunning:
    warn "WebSocket transport already stopped"

  try:
    await procCall Transport(self).stop() # call base

    var toWait: seq[Future[void]]
    if not self.acceptLoop.isNil:
      toWait.add(self.acceptLoop.cancelAndWait())

    for fut in self.handshakeFuts:
      toWait.add(fut.cancelAndWait())

    for server in self.httpservers:
      server.stop()
      toWait.add(server.closeWait())

    await allFutures(toWait)

    # stop connections and wait for them to be closed
    discard await allFinished(
      self.connections[Direction.In].mapIt(it.close()) &
        self.connections[Direction.Out].mapIt(it.close())
    )
    self.connectionCleanupFuts.keepItIf(not it.finished)
    discard await allFinished(self.connectionCleanupFuts)

    self.httpservers = @[]
    self.handshakeFuts = @[]
    self.connectionCleanupFuts = @[]
    self.acceptLoop = nil
    if wasRunning:
      info "WebSocket transport stopped", addresses = self.addrs
  except CatchableError as e:
    trace "WebSocket transport shutdown failed", err = e.msg
  finally:
    self.notifyAcceptClosed()

proc connHandler(
    self: WsTransport, stream: WSSession, secure: bool, dir: Direction
): LPResult[WsStream] =
  let codec = ?MultiAddress.init(if secure: "/wss" else: "/ws")
  let addrs = ?stream.stream.reader.tsource.connAddrs()
  let conn = WsStream.new(
    stream,
    dir,
    Opt.some(?concat(addrs.observed, codec)),
    Opt.some(?concat(addrs.local, codec)),
  )

  self.connections[dir].add(conn)
  proc onClose() {.async: (raises: []).} =
    await noCancel conn.session.stream.reader.join()
    self.connections[dir].keepItIf(it != conn)

  self.connectionCleanupFuts.keepItIf(not it.finished)
  self.connectionCleanupFuts.add(onClose())

  ok(conn)

method accept*(
    self: WsTransport
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  if not self.running:
    raise newTransportClosedError()

  let conn = await self.acceptResults.popFirst()
  if not conn.isNil:
    return conn

  raise newTransportClosedError()

method dial*(
    self: WsTransport,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  ## dial a peer
  ##

  trace "Transport connection started", peerId, address = $address

  let secure = WSS.match(address)
  let initAddress = address.initTAddress().valueOr:
    raise newException(
      transport.TransportDialError,
      "WsTransport.dial called with unsupported address " & $address & ". " & error,
    )
  let
    sni = address.getSni()
    httpHostname =
      if hostname.len > 0:
        hostname
      else:
        $initAddress
    serverName = if sni.len > 0: sni else: httpHostname
    hooks =
      if serverName != httpHostname:
        @[hostHeaderHook(httpHostname)]
      else:
        @[]
  trace "Creating websocket",
    address = initAddress,
    secure = secure,
    hostName = httpHostname,
    serverName = serverName

  let session =
    try:
      await WebSocket.connect(
        initAddress,
        "",
        secure = secure,
        hostName = serverName,
        hooks = hooks,
        flags = self.tlsFlags,
        rng = websockRng(self.rng),
      )
    except CancelledError as e:
      raise e
    except CatchableError as e:
      raise newException(
        transport.TransportDialError,
        "WsTransport.dial failed to connect to " & $address & ". " & e.msg,
        e,
      )

  let conn = self.connHandler(session, secure, Direction.Out).valueOr:
    safeClose(session)
    raise newException(
      transport.TransportDialError,
      "WsTransport.dial failed to read connection addresses. " & error,
    )
  conn

method handles*(t: WsTransport, address: MultiAddress): bool {.gcsafe, raises: [].} =
  if procCall Transport(t).handles(address):
    if address.protocols.isOk:
      return WebSockets.match(address)

proc new*(
    T: typedesc[WsTransport],
    upgrade: Upgrade,
    tlsPrivateKey: TLSPrivateKey,
    tlsCertificate: TLSCertificate,
    autotls: Opt[AutotlsService],
    rng: Rng,
    tlsFlags: set[TLSFlags] = {},
    flags: set[ServerFlags] = {},
    factories: openArray[ExtFactory] = [],
    headersTimeout = DefaultHeadersTimeout,
    concurrentAccepts = DefaultConcurrentAccepts,
): T {.raises: [].} =
  ## Creates a secure WebSocket transport
  doAssert concurrentAccepts > 0, "concurrentAccepts must be positive"

  doAssert not rng.isNil, "Rng is nil"

  let self = T(
    upgrader: upgrade,
    tlsPrivateKey: tlsPrivateKey,
    tlsCertificate: tlsCertificate,
    autotls: autotls,
    tlsFlags: tlsFlags,
    flags: flags,
    factories: @factories,
    rng: rng,
    headersTimeout: headersTimeout,
    concurrentAccepts: concurrentAccepts,
  )
  procCall Transport(self).initialize()
  self

proc new*(
    T: typedesc[WsTransport],
    upgrade: Upgrade,
    rng: Rng,
    flags: set[ServerFlags] = {},
    factories: openArray[ExtFactory] = [],
    headersTimeout = DefaultHeadersTimeout,
    concurrentAccepts = DefaultConcurrentAccepts,
): T {.raises: [].} =
  ## Creates a clear-text WebSocket transport

  T.new(
    upgrade = upgrade,
    tlsPrivateKey = nil,
    tlsCertificate = nil,
    autotls = Opt.none(AutotlsService),
    flags = flags,
    factories = @factories,
    rng = rng,
    headersTimeout = headersTimeout,
    concurrentAccepts = concurrentAccepts,
  )
