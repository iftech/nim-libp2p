# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import results
import chronos, chronicles, metrics
import
  ../../../../libp2p/[
    switch,
    muxers/muxer,
    dialer,
    multiaddress,
    transports/transport,
    multicodec,
    peerid,
    wire,
    utils/ipaddr,
  ],
  ../../protocol,
  ./types

logScope:
  topics = "libp2p autonat"

declareCounter(
  libp2p_autonatv2_dial_back_refusals_total,
  "dial requests refused because no dial back permit was free",
)

type AutonatV2Config* = object
  dialTimeout: Duration
  dialDataSize: uint64
  amplificationAttackTimeout: Duration
  allowPrivateAddresses: bool
  maxConcurrentDialBacks: int
  maxConcurrentRequestsPerPeer: int
  maxConcurrentRequestsTotal: int

type AutonatV2* = ref object of LPProtocol
  switch*: Switch
  config: AutonatV2Config
  dialBackSem: AsyncSemaphore

type DialBackConn = object
  mux: Muxer
  stream: Stream

proc new*(
    T: typedesc[AutonatV2Config],
    dialTimeout: Duration = DefaultDialTimeout,
    dialDataSize: uint64 = DefaultDialDataSize,
    amplificationAttackTimeout: Duration = DefaultAmplificationAttackDialTimeout,
    allowPrivateAddresses: bool = false,
    maxConcurrentDialBacks: int = DefaultMaxConcurrentDialBacks,
    maxConcurrentRequestsPerPeer: int = DefaultMaxConcurrentRequestsPerPeer,
    maxConcurrentRequestsTotal: int = DefaultMaxConcurrentRequestsTotal,
): T =
  T(
    dialTimeout: dialTimeout,
    dialDataSize: dialDataSize,
    amplificationAttackTimeout: amplificationAttackTimeout,
    allowPrivateAddresses: allowPrivateAddresses,
    maxConcurrentDialBacks: maxConcurrentDialBacks,
    maxConcurrentRequestsPerPeer: maxConcurrentRequestsPerPeer,
    maxConcurrentRequestsTotal: maxConcurrentRequestsTotal,
  )

proc sendDialResponse(
    stream: Stream,
    status: ResponseStatus,
    addrIdx: Opt[AddrIdx] = Opt.none(AddrIdx),
    dialStatus: Opt[DialStatus] = Opt.none(DialStatus),
) {.async: (raises: [CancelledError, LPStreamError]).} =
  await stream.writeLp(
    AutonatV2Msg(
      oneof: AutonatV2MsgOneof(
        kind: MsgKind.DialResponse,
        dialResponse:
          DialResponse(status: status, addrIdx: addrIdx, dialStatus: dialStatus),
      )
    ).encode()
  )

proc findObservedIPAddr*(
    stream: Stream, req: DialRequest
): Future[Opt[MultiAddress]] {.async: (raises: [CancelledError, LPStreamError]).} =
  let observedAddr = stream.observedAddr.valueOr:
    await stream.sendDialResponse(ResponseStatus.EInternalError)
    return Opt.none(MultiAddress)

  let isRelayed = observedAddr.contains(multiCodec("p2p-circuit")).valueOr:
    trace "Invalid observed address"
    await stream.sendDialResponse(ResponseStatus.EDialRefused)
    return Opt.none(MultiAddress)

  if isRelayed:
    trace "Invalid observed address: relayed address"
    await stream.sendDialResponse(ResponseStatus.EDialRefused)
    return Opt.none(MultiAddress)

  let hostIp = observedAddr[0].valueOr:
    trace "Invalid observed address"
    await stream.sendDialResponse(ResponseStatus.EInternalError)
    return Opt.none(MultiAddress)

  return Opt.some(hostIp)

proc dialBack(
    stream: Stream, nonce: Nonce
): Future[DialStatus] {.
    async: (raises: [CancelledError, DialFailedError, LPStreamError])
.} =
  try:
    # send dial back
    await stream.writeLp(DialBack(nonce: nonce).encode())

    # receive DialBackResponse
    discard DialBackResponse.decode(await stream.readLp(AutonatV2MsgLpSize)).valueOr:
      trace "DialBack failed, could not decode DialBackResponse", err = error
      return DialStatus.EDialBackError
  except LPStreamRemoteClosedError as exc:
    # failed because of nonce error (remote reset the stream): EDialBackError
    trace "DialBack failed, remote closed the connection", err = exc.msg
    return DialStatus.EDialBackError

  # TODO: failed because of client or server resources: EDialError

  trace "DialBack successful"
  return DialStatus.Ok

proc handleDialDataResponses(
    self: AutonatV2, stream: Stream
) {.async: (raises: [CancelledError, AutonatV2Error, LPStreamError]).} =
  var dataReceived: uint64 = 0

  while dataReceived < self.config.dialDataSize:
    let msg = AutonatV2Msg
      .decode(await stream.readLp(DialDataResponseLpSize))
      .valueOrRaise(AutonatV2Error)
    trace "Received message"

    if msg.oneof.kind != MsgKind.DialDataResponse:
      raise newException(
        AutonatV2Error, "Expecting DialDataResponse, got " & $msg.oneof.kind
      )

    let resp = msg.oneof.dialDataResponse
    dataReceived += resp.data.len.uint64
    trace "received data",
      dataReceived = resp.data.len.uint64, totalDataReceived = dataReceived

proc amplificationAttackPrevention(
    self: AutonatV2, stream: Stream, addrIdx: AddrIdx
) {.async: (raises: [CancelledError, AutonatV2Error, LPStreamError]).} =
  # send DialDataRequest
  await stream.writeLp(
    AutonatV2Msg(
      oneof: AutonatV2MsgOneof(
        kind: MsgKind.DialDataRequest,
        dialDataRequest:
          DialDataRequest(addrIdx: addrIdx, numBytes: self.config.dialDataSize),
      )
    ).encode()
  )

  await self.handleDialDataResponses(stream)

proc canDial(self: AutonatV2, addrs: MultiAddress): bool =
  let (ipv4Support, ipv6Support) = self.switch.peerInfo.listenAddrs.ipSupport()
  addrs[0].ifValue(addrIp):
    if IP4.match(addrIp) and not ipv4Support:
      return false
    if IP6.match(addrIp) and not ipv6Support:
      return false

  # A name and a relayed address have no global IP, so both are refused here too.
  if not self.config.allowPrivateAddresses and not addrs.isGlobalMA():
    trace "Refusing to dial back a non-global address", address = addrs
    return false

  for t in self.switch.transports:
    if t.handles(addrs):
      return true
  return false

proc forceNewConnection(
    self: AutonatV2, pid: PeerId, addrs: seq[MultiAddress]
): Future[Opt[DialBackConn]] {.async: (raises: [CancelledError]).} =
  ## Bypasses connManager to force a new connection to ``pid``
  ## instead of reusing a preexistent one
  var mux: Muxer
  try:
    mux = await self.switch.dialer.dialAndUpgrade(Opt.some(pid), addrs)
    if mux.isNil():
      return Opt.none(DialBackConn)
    return Opt.some(
      DialBackConn(
        mux: mux,
        stream: await self.switch.dialer.negotiateStream(
          await mux.newStream(), @[$AutonatV2Codec.DialBack]
        ),
      )
    )
  except CancelledError as exc:
    if mux != nil:
      await mux.close()
    raise exc
  except LPError:
    if mux != nil:
      await mux.close()
    return Opt.none(DialBackConn)

proc selectDialAddr(self: AutonatV2, addrs: seq[MultiAddress]): Opt[AddrIdx] =
  for i, ma in addrs:
    if self.canDial(ma):
      return Opt.some(i.AddrIdx)
  Opt.none(AddrIdx)

proc dialBackConnection(
    self: AutonatV2, pid: PeerId, ma: MultiAddress
): Future[Opt[DialBackConn]] {.async: (raises: [CancelledError]).} =
  trace "Trying to dial", address = ma
  try:
    await self.forceNewConnection(pid, @[ma]).wait(self.config.dialTimeout)
  except AsyncTimeoutError:
    trace "Dial timed out", timeout = self.config.dialTimeout
    Opt.none(DialBackConn)

proc handleDialRequest(
    self: AutonatV2, stream: Stream, req: DialRequest
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let observedIPAddr = (await stream.findObservedIPAddr(req)).valueOr:
    trace "Could not find observed IP address"
    await stream.sendDialResponse(ResponseStatus.ERequestRejected)
    return

  let addrIdx = self.selectDialAddr(req.addrs).valueOr:
    trace "No dialable addresses found"
    await stream.sendDialResponse(ResponseStatus.EDialRefused)
    return

  if not self.dialBackSem.tryAcquire():
    libp2p_autonatv2_dial_back_refusals_total.inc()
    debug "Too many concurrent dial backs, refusing request", peerId = stream.peerId
    await stream.sendDialResponse(ResponseStatus.EDialRefused)
    return
  defer:
    try:
      self.dialBackSem.release()
    except AsyncSemaphoreError:
      raiseAssert "semaphore released without acquire"

  # the spec exempts only a selected addr whose IP equals the observed IP
  if not ipAddrMatches(observedIPAddr, [req.addrs[addrIdx]]):
    trace "Starting amplification attack prevention",
      observedIPAddr = observedIPAddr, testAddr = req.addrs[addrIdx]
    try:
      await self.amplificationAttackPrevention(stream, addrIdx).wait(
        self.config.amplificationAttackTimeout
      )
    except AsyncTimeoutError:
      warn "Amplification attack prevention timed out",
        peer = stream.peerId, timeout = self.config.amplificationAttackTimeout
      await stream.sendDialResponse(ResponseStatus.EDialRefused)
      return
    except AutonatV2Error as exc:
      debug "Amplification attack prevention failed",
        peer = stream.peerId, err = exc.msg
      await stream.sendDialResponse(ResponseStatus.EDialRefused)
      return

  let dialBack = (await self.dialBackConnection(stream.peerId, req.addrs[addrIdx])).valueOr:
    trace "Dial failed"
    await stream.sendDialResponse(
      ResponseStatus.Ok,
      addrIdx = Opt.some(addrIdx),
      dialStatus = Opt.some(DialStatus.EDialError),
    )
    return
  defer:
    await dialBack.stream.close()
    await dialBack.mux.close()

  trace "Sending DialBack",
    nonce = req.nonce, addrIdx = addrIdx, addr = req.addrs[addrIdx]

  try:
    let dialStatus =
      await dialBack.stream.dialBack(req.nonce).wait(self.config.dialTimeout)
    await stream.sendDialResponse(
      ResponseStatus.Ok, addrIdx = Opt.some(addrIdx), dialStatus = Opt.some(dialStatus)
    )
  except DialFailedError as exc:
    trace "DialBack failed", err = exc.msg
    await stream.sendDialResponse(
      ResponseStatus.Ok,
      addrIdx = Opt.some(addrIdx),
      dialStatus = Opt.some(DialStatus.EDialBackError),
    )
  except AsyncTimeoutError:
    trace "DialBack timeout", timeout = self.config.dialTimeout
    await stream.sendDialResponse(
      ResponseStatus.Ok,
      addrIdx = Opt.some(addrIdx),
      dialStatus = Opt.some(DialStatus.EDialBackError),
    )

proc new*(
    Self: typedesc[AutonatV2],
    switch: Switch,
    config: AutonatV2Config = AutonatV2Config.new(),
): Self =
  # Self instead of T to avoid clashing with ifValue[T]'s type param under --lineDir:on
  let autonatV2 = Self(
    switch: switch,
    config: config,
    dialBackSem: newAsyncSemaphore(config.maxConcurrentDialBacks),
  )
  autonatV2.setStreamLimits(
    maxIncomingStreamsTotal = config.maxConcurrentRequestsTotal,
    maxIncomingStreamsPerPeer = config.maxConcurrentRequestsPerPeer,
  )

  proc handleStream(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    defer:
      await stream.close()

    let msg =
      try:
        AutonatV2Msg.decode(await stream.readLp(AutonatV2MsgLpSize)).valueOr:
          trace "Unable to decode AutonatV2Msg", err = error
          return
      except LPStreamError as exc:
        trace "Could not receive AutonatV2Msg", err = exc.msg
        return

    trace "Received message", kind = $msg.oneof.kind
    if msg.oneof.kind != MsgKind.DialRequest:
      trace "Expecting DialRequest", receivedMsgType = msg.oneof.kind
      return

    try:
      await autonatV2.handleDialRequest(stream, msg.oneof.dialRequest)
    except CancelledError as exc:
      raise exc
    except LPStreamRemoteClosedError as exc:
      trace "Stream closed by peer", err = exc.msg, peerId = stream.peerId
    except LPStreamError as exc:
      trace "Stream Error", err = exc.msg

  autonatV2.handler = handleStream
  autonatV2.codec = $AutonatV2Codec.DialRequest
  autonatV2
