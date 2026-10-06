# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import sequtils, tables

import chronos, chronicles

import
  ./messages,
  ./rconn,
  ./utils,
  ./relay_metrics,
  ../../../peerinfo,
  ../../../switch,
  ../../../multiaddress,
  ../../../multicodec,
  ../../../stream/connection,
  ../../../protocols/protocol,
  ../../../errors,
  ../../../utils/heartbeat,
  ../../../utils/future,
  ../../../signed_envelope

# TODO:
# * Eventually replace std/times by chronos/timer. Currently chronos/timer
#   doesn't offer the possibility to get a datetime in UNIX UTC
# * Eventually add an access control list in the handleReserve, handleConnect
#   and handleHop
# * Better reservation management ie find a way to re-reserve when the end is nigh

import std/times
export chronicles

const
  RelayMsgSize* = 4096
  DefaultReservationTTL* = initDuration(hours = 1)
  DefaultLimitDuration* = 120
  DefaultLimitData* = 1 shl 17
  DefaultHeartbeatSleepTime* = 1
  MaxCircuit* = 128
  MaxCircuitPerPeer* = 16

logScope:
  topics = "libp2p relay"

type
  RelayV2Error* = object of LPError
  SendStopError = object of RelayV2Error

# Relay Side

type Relay* = ref object of LPProtocol
  switch*: Switch
  peerCount: CountTable[PeerId]

  # number of reservation (relayv2) + number of connection (relayv1)
  maxCircuit*: int

  maxCircuitPerPeer*: int
  msgSize*: int
  # RelayV1
  isCircuitRelayV1*: bool
  streamCount: int
  # RelayV2
  rsvp: Table[PeerId, DateTime]
  reservationLoop: Future[void]
  reservationTTL*: times.Duration
  heartbeatSleepTime*: uint32
  limit*: Limit

# Relay V2

proc createReserveResponse(
    r: Relay, pid: PeerId, expire: DateTime
): Result[HopMessage, CryptoError] =
  let
    expireUnix = expire.toTime.toUnix.uint64
    v = Voucher.init(r.switch.peerInfo.peerId, pid, expireUnix)
    sv = ?SignedVoucher.init(r.switch.peerInfo.privateKey, v)
    ma = ?MultiAddress.init("/p2p/" & $r.switch.peerInfo.peerId).orErr(
      CryptoError.KeyError
    )
    rsrv = Reservation(
      expire: Opt.some(expireUnix),
      addrs: r.switch.peerInfo.addrs.mapIt(?it.concat(ma).orErr(CryptoError.KeyError)),
      svoucher: Opt.some(sv.encode),
    )
    msg = HopMessage(
      msgType: Opt.some(HopMessageType.Status),
      reservation: Opt.some(rsrv),
      limit: Opt.some(r.limit),
      status: Opt.some(Ok),
    )
  return ok(msg)

proc isRelayed*(stream: Stream): bool =
  var wrappedConn = stream
  while not isNil(wrappedConn):
    if wrappedConn of RelayConnection:
      return true
    wrappedConn = wrappedConn.getWrapped()
  return false

proc handleReserve(
    r: Relay, stream: Stream
) {.async: (raises: [CancelledError, LPStreamError]).} =
  if stream.isRelayed():
    libp2p_relay_reservation_attempts.inc(labelValues = ["permission_denied"])
    trace "reservation attempt over relay connection", pid = stream.peerId
    await sendHopStatus(stream, PermissionDenied)
    return

  if r.peerCount[stream.peerId] + r.rsvp.len() >= r.maxCircuit:
    libp2p_relay_reservation_attempts.inc(labelValues = ["limit"])
    trace "Too many reservations", pid = stream.peerId
    await sendHopStatus(stream, ReservationRefused)
    return
  trace "reserving relay slot for", pid = stream.peerId
  let
    pid = stream.peerId
    expire = getTime().utc + r.reservationTTL
    msg = r.createReserveResponse(pid, expire).valueOr:
      libp2p_relay_reservation_attempts.inc(labelValues = ["signing_error"])
      trace "error signing the voucher", pid
      return

  r.rsvp[pid] = expire
  libp2p_relay_reservations_active.set(r.rsvp.len.int64)
  libp2p_relay_reservation_attempts.inc(labelValues = ["success"])
  await stream.writeLp(encode(msg))

proc handleConnect(
    r: Relay, srcStream: Stream, msg: HopMessage
) {.async: (raises: [CancelledError, LPStreamError]).} =
  if srcStream.isRelayed():
    libp2p_relay_connections.inc(labelValues = ["permission_denied"])
    trace "connection attempt over relay connection"
    await sendHopStatus(srcStream, PermissionDenied)
    return
  let
    msgPeer = msg.peer.valueOr:
      await sendHopStatus(srcStream, MalformedMessage)
      return
    dst = msgPeer.peerId.valueOr:
      await sendHopStatus(srcStream, MalformedMessage)
      return
    src = srcStream.peerId
  if dst notin r.rsvp:
    libp2p_relay_connections.inc(labelValues = ["no_reservation"])
    trace "refusing connection, no reservation", src, dst
    await sendHopStatus(srcStream, NoReservation)
    return

  r.peerCount.inc(src)
  r.peerCount.inc(dst)
  defer:
    r.peerCount.inc(src, -1)
    r.peerCount.inc(dst, -1)

  if r.peerCount[src] > r.maxCircuitPerPeer or r.peerCount[dst] > r.maxCircuitPerPeer:
    libp2p_relay_connections.inc(labelValues = ["limit"])
    trace "too many connections",
      src = r.peerCount[src], dst = r.peerCount[dst], max = r.maxCircuitPerPeer
    await sendHopStatus(srcStream, ResourceLimitExceeded)
    return

  let dstStream =
    try:
      await r.switch.dial(dst, RelayV2StopCodec)
    except CancelledError as exc:
      raise exc
    except DialFailedError as exc:
      libp2p_relay_connections.inc(labelValues = ["dial_failed"])
      trace "error opening relay stream", err = exc.msg, dst
      await sendHopStatus(srcStream, ConnectionFailed)
      return
  defer:
    await dstStream.close()

  proc sendStopMsg() {.async: (raises: [SendStopError, CancelledError, LPStreamError]).} =
    let stopMsg = StopMessage(
      msgType: Opt.some(StopMessageType.Connect),
      peer: Opt.some(Peer(peerId: Opt.some(src), addrs: @[])),
      limit: Opt.some(r.limit),
    )
    await dstStream.writeLp(encode(stopMsg))
    let msg = StopMessage.decode(await dstStream.readLp(r.msgSize)).valueOr:
      raise newException(SendStopError, "Malformed message")
    if msg.msgType != Opt.some(StopMessageType.Status):
      raise
        newException(SendStopError, "Unexpected stop response, not a status message")
    if msg.status.get(UnexpectedMessage) != Ok:
      raise newException(SendStopError, "Relay stop failure")
    await srcStream.writeLp(
      encode(HopMessage(msgType: Opt.some(HopMessageType.Status), status: Opt.some(Ok)))
    )

  try:
    await sendStopMsg()
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    libp2p_relay_connections.inc(labelValues = ["stop_failed"])
    trace "error sending stop message", err = exc.msg
    await sendHopStatus(srcStream, ConnectionFailed)
    return

  trace "relaying connection", src, dst
  libp2p_relay_connections.inc(labelValues = ["success"])
  libp2p_relay_circuits_active.inc()
  defer:
    libp2p_relay_circuits_active.dec()
  let
    srcRelayConn = RelayConnection.new(srcStream, r.limit.duration, r.limit.data)
    dstRelayConn = RelayConnection.new(dstStream, r.limit.duration, r.limit.data)
  defer:
    await srcRelayConn.close()
    await dstRelayConn.close()
  await bridge(srcRelayConn, dstRelayConn)

proc handleHopStreamV2*(
    r: Relay, stream: Stream
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let msg = HopMessage.decode(await stream.readLp(r.msgSize)).valueOr:
    await sendHopStatus(stream, MalformedMessage)
    return
  trace "relayv2 handle stream", hopMsg = msg

  if msg.msgType.isNone:
    trace "relayv2 mesage type not set"
    await sendHopStatus(stream, MalformedMessage)
    return

  case msg.msgType.get()
  of HopMessageType.Reserve:
    await r.handleReserve(stream)
  of HopMessageType.Connect:
    await r.handleConnect(stream, msg)
  else:
    trace "Unexpected relayv2 handshake", msgType = msg.msgType
    await sendHopStatus(stream, MalformedMessage)

# Relay V1

proc handleHop*(
    r: Relay, srcStream: Stream, msg: RelayMessage
) {.async: (raises: [CancelledError]).} =
  r.streamCount.inc()
  defer:
    r.streamCount.dec()
  if r.streamCount + r.rsvp.len() >= r.maxCircuit:
    trace "refusing connection; too many active circuit",
      streamCount = r.streamCount, rsvp = r.rsvp.len()
    await sendStatus(srcStream, StatusV1.HopCantSpeakRelay)
    return

  var src, dst: RelayPeer
  proc checkMsg(): Result[RelayMessage, StatusV1] =
    src = msg.srcPeer.valueOr:
      return err(StatusV1.HopSrcMultiaddrInvalid)
    if src.peerId != srcStream.peerId:
      return err(StatusV1.HopSrcMultiaddrInvalid)
    dst = msg.dstPeer.valueOr:
      return err(StatusV1.HopDstMultiaddrInvalid)
    if dst.peerId == r.switch.peerInfo.peerId:
      return err(StatusV1.HopCantRelayToSelf)
    if not r.switch.isConnected(dst.peerId):
      trace "relay not connected to dst", dst
      return err(StatusV1.HopNoConnToDst)
    ok(msg)

  checkMsg().isOkOr:
    await sendStatus(srcStream, error)
    return

  if r.peerCount[src.peerId] >= r.maxCircuitPerPeer or
      r.peerCount[dst.peerId] >= r.maxCircuitPerPeer:
    trace "refusing connection; too many connection from src or to dst", src, dst
    await sendStatus(srcStream, StatusV1.HopCantSpeakRelay)
    return
  r.peerCount.inc(src.peerId)
  r.peerCount.inc(dst.peerId)
  defer:
    r.peerCount.inc(src.peerId, -1)
    r.peerCount.inc(dst.peerId, -1)

  let dstStream =
    try:
      await r.switch.dial(dst.peerId, RelayV1Codec)
    except CancelledError as exc:
      raise exc
    except DialFailedError as exc:
      trace "error opening relay stream", err = exc.msg, dst
      await sendStatus(srcStream, StatusV1.HopCantDialDst)
      return
  defer:
    await dstStream.close()

  let msgToSend = RelayMessage(
    msgType: Opt.some(RelayType.Stop), srcPeer: Opt.some(src), dstPeer: Opt.some(dst)
  )

  let msgRcvFromDstOpt =
    try:
      await dstStream.writeLp(encode(msgToSend))
      RelayMessage.decode(await dstStream.readLp(r.msgSize))
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      trace "error writing stop handshake or reading stop response", err = exc.msg
      await sendStatus(srcStream, StatusV1.HopCantOpenDstStream)
      return

  let msgRcvFromDst: RelayMessage = msgRcvFromDstOpt.valueOr:
    trace "error reading stop response", responsePresent = msgRcvFromDstOpt.isOk
    await sendStatus(srcStream, StatusV1.HopCantOpenDstStream)
    return

  if msgRcvFromDst.msgType.get(RelayType.Stop) != RelayType.Status or
      msgRcvFromDst.status.get(StatusV1.StopRelayRefused) != StatusV1.Success:
    trace "Unexpected relay stop response", response = msgRcvFromDst
    await sendStatus(srcStream, StatusV1.HopCantOpenDstStream)
    return

  await sendStatus(srcStream, StatusV1.Success)
  trace "relaying connection", src, dst
  await bridge(srcStream, dstStream)

proc handleStreamV1(
    r: Relay, stream: Stream
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let msg = RelayMessage.decode(await stream.readLp(r.msgSize)).valueOr:
    await sendStatus(stream, StatusV1.MalformedMessage)
    return
  trace "relay handle stream", msg

  let typ = msg.msgType.valueOr:
    trace "Message type not set"
    await sendStatus(stream, StatusV1.MalformedMessage)
    return
  case typ
  of RelayType.Hop:
    await r.handleHop(stream, msg)
  of RelayType.Stop:
    await sendStatus(stream, StatusV1.StopRelayRefused)
  of RelayType.CanHop:
    await sendStatus(stream, StatusV1.Success)
  else:
    trace "Unexpected relay handshake", msgType = msg.msgType
    await sendStatus(stream, StatusV1.MalformedMessage)

proc setup*(r: Relay, switch: Switch) =
  r.switch = switch
  r.switch.addPeerEventHandler(
    proc(peerId: PeerId, event: PeerEvent) {.async: (raises: [CancelledError]).} =
      r.rsvp.del(peerId)
      libp2p_relay_reservations_active.set(r.rsvp.len.int64),
    Left,
  )

proc new*(
    T: typedesc[Relay],
    reservationTTL: times.Duration = DefaultReservationTTL,
    limitDuration: uint32 = DefaultLimitDuration,
    limitData: uint64 = DefaultLimitData,
    heartbeatSleepTime: uint32 = DefaultHeartbeatSleepTime,
    maxCircuit: int = MaxCircuit,
    maxCircuitPerPeer: int = MaxCircuitPerPeer,
    msgSize: int = RelayMsgSize,
    circuitRelayV1: bool = false,
): T =
  let r = T(
    reservationTTL: reservationTTL,
    limit: Limit(duration: limitDuration, data: limitData),
    heartbeatSleepTime: heartbeatSleepTime,
    maxCircuit: maxCircuit,
    maxCircuitPerPeer: maxCircuitPerPeer,
    msgSize: msgSize,
    isCircuitRelayV1: circuitRelayV1,
  )

  proc handleStream(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    try:
      case proto
      of RelayV2HopCodec:
        await r.handleHopStreamV2(stream)
      of RelayV1Codec:
        await r.handleStreamV1(stream)
    except CancelledError as exc:
      trace "cancelled relayv2 handler"
      raise exc
    except CatchableError as exc:
      debug "exception in relayv2 handler", err = exc.msg, stream
    finally:
      trace "exiting relayv2 handler", stream
      await stream.close()

  r.codecs =
    if r.isCircuitRelayV1:
      @[RelayV1Codec]
    else:
      @[RelayV2HopCodec]
  r.handler = handleStream
  r

proc deletesReservation(r: Relay) {.async: (raises: [CancelledError]).} =
  heartbeat "Reservation timeout", r.heartbeatSleepTime.seconds():
    try:
      let n = getTime().utc
      for k in toSeq(r.rsvp.keys):
        if n > r.rsvp[k]:
          r.rsvp.del(k)
      libp2p_relay_reservations_active.set(r.rsvp.len.int64)
    except KeyError:
      raiseAssert "checked with in"

method start*(r: Relay): Future[void] {.async: (raises: [CancelledError], raw: true).} =
  let fut = newFutureCompleted[void]()
  if not r.reservationLoop.isNil:
    warn "Starting relay twice"
    return fut
  r.reservationLoop = r.deletesReservation()
  r.started = true
  info "Circuit relay service started", protocols = r.codecs
  fut

method stop*(r: Relay): Future[void] {.async: (raises: [], raw: true).} =
  if r.reservationLoop.isNil:
    warn "Stopping relay without starting it"
    return newFutureCompleted[void]()

  r.started = false
  libp2p_relay_reservations_active.set(0)
  r.reservationLoop.cancelSoon()
  r.reservationLoop = nil
  newFutureCompleted[void]()
