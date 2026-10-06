# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import times
import chronos, chronicles
import
  ./relay,
  ./messages,
  ./rconn,
  ./utils,
  ../../../peerinfo,
  ../../../switch,
  ../../../multiaddress,
  ../../../stream/connection,
  ../../../signed_envelope

logScope:
  topics = "libp2p relay"

const RelayClientMsgSize = 4096

type
  RelayClientError* = object of LPError
  ReservationError* = object of RelayClientError
  RelayDialError* = object of DialFailedError
  RelayV1DialError* = object of RelayDialError
  RelayV2DialError* = object of RelayDialError
  RelayClientAddConn* = proc(
    conn: RawConn, duration: uint32, data: uint64
  ): Future[void] {.gcsafe, async: (raises: [CancelledError]).}
  RelayClient* = ref object of Relay
    onNewConnection*: RelayClientAddConn
    canHop: bool

  Rsvp* = object
    expire*: uint64 # required, Unix expiration time (UTC)
    addrs*: seq[MultiAddress] # relay address for reserving peer
    voucher*: Opt[Voucher] # optional, reservation voucher
    limitDuration*: uint32 # seconds
    limitData*: uint64 # bytes

proc sendStopError(
    stream: Stream, code: StatusV2
) {.async: (raises: [CancelledError]).} =
  trace "send stop status", status = $code & " (" & $ord(code) & ")"
  try:
    let msg =
      StopMessage(msgType: Opt.some(StopMessageType.Status), status: Opt.some(code))
    await stream.writeLp(encode(msg))
  except CancelledError as e:
    raise e
  except LPStreamError as e:
    trace "failed to send stop status", err = e.msg

proc handleRelayedConnect(
    cl: RelayClient, stream: Stream, msg: StopMessage
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let
    # TODO: check the go version to see in which way this could fail
    # it's unclear in the spec
    srcPeer = msg.peer.valueOr:
      await sendStopError(stream, MalformedMessage)
      return ok()
    src = srcPeer.peerId.valueOr:
      await sendStopError(stream, MalformedMessage)
      return ok()
    limitDuration = msg.limit.get(Limit()).duration
    limitData = msg.limit.get(Limit()).data
    msg = StopMessage(msgType: Opt.some(StopMessageType.Status), status: Opt.some(Ok))

  trace "incoming relay connection", src

  if cl.onNewConnection.isNil():
    await sendStopError(stream, StatusV2.ConnectionFailed)
    await stream.close()
    return ok()

  try:
    await stream.writeLp(encode(msg))
  except LPStreamError as e:
    return err("error writing stop status: " & e.msg)

  # This sound redundant but the callback could, in theory, be set to nil during
  # stream.writeLp so it's safer to double check
  if cl.onNewConnection.isNil():
    await stream.close()
  else:
    await cl.onNewConnection(stream, limitDuration, limitData)
  ok()

proc toRsvp(msg: HopMessage, relayPeerId: PeerId): LPResult[Rsvp] =
  if msg.msgType != Opt.some(HopMessageType.Status):
    return err("Unexpected relay response type")
  if msg.status.get(UnexpectedMessage) != Ok:
    return err("Reservation failed")

  let reservation = msg.reservation.valueOr:
    return err("Missing reservation information")
  let expire = reservation.expire.valueOr:
    return err("Missing expire")
  if expire > int64.high().uint64 or getTime().utc > expire.int64.fromUnix.utc:
    return err("Bad expiration date")

  var rsvp = Rsvp(
    expire: expire,
    addrs: reservation.addrs,
    limitDuration: msg.limit.get(Limit()).duration,
    limitData: msg.limit.get(Limit()).data,
  )
  reservation.svoucher.ifValue(sv):
    let svoucher = SignedVoucher.decode(sv).valueOr:
      if error == EnvelopeFieldMissing:
        return err("Missing voucher field")
      return err("Invalid voucher")
    let voucherRelayPeerId = svoucher.data.relayPeerId.valueOr:
      return err("Missing voucher relay PeerId")
    if voucherRelayPeerId != relayPeerId:
      return err("Voucher relay PeerId mismatch")
    rsvp.voucher = Opt.some(svoucher.data)

  ok(rsvp)

proc tryReserve*(
    cl: RelayClient, peerId: PeerId, addrs: seq[MultiAddress] = @[]
): Future[LPResult[Rsvp]] {.async: (raises: [CancelledError]).} =
  let stream =
    try:
      await cl.switch.dial(peerId, addrs, RelayV2HopCodec)
    except DialFailedError as e:
      return err("dial relay peer failed: " & e.msg)
  defer:
    await stream.close()

  let msg =
    try:
      await stream.writeLp(
        encode(HopMessage(msgType: Opt.some(HopMessageType.Reserve)))
      )
      HopMessage.decode(await stream.readLp(RelayClientMsgSize)).valueOr:
        return err("Invalid reservation response: " & error)
    except LPStreamError as e:
      trace "error writing or reading reservation message", err = e.msg
      return err(e.msg)

  msg.toRsvp(peerId)

proc reserve*(
    cl: RelayClient, peerId: PeerId, addrs: seq[MultiAddress] = @[]
): Future[Rsvp] {.async: (raises: [ReservationError, CancelledError]).} =
  (await cl.tryReserve(peerId, addrs)).valueOrRaise(ReservationError)

func checkHopResponse(msg: LPResult[RelayMessage]): LPResult[void] =
  let response = msg.valueOr:
    return err("Hop can't open destination stream: " & error)
  if response.msgType != Opt.some(RelayType.Status):
    return err("Hop can't open destination stream: wrong message type")
  if response.status != Opt.some(StatusV1.Success):
    return err("Hop can't open destination stream: status failed")
  ok()

proc tryDialPeerV1*(
    cl: RelayClient, stream: Stream, dstPeerId: PeerId, dstAddrs: seq[MultiAddress]
): Future[LPResult[RawConn]] {.async: (raises: [CancelledError]).} =
  let msg = RelayMessage(
    msgType: Opt.some(RelayType.Hop),
    srcPeer: Opt.some(
      RelayPeer(peerId: cl.switch.peerInfo.peerId, addrs: cl.switch.peerInfo.addrs)
    ),
    dstPeer: Opt.some(RelayPeer(peerId: dstPeerId, addrs: dstAddrs)),
  )

  trace "Dial peer", msgSend = msg

  try:
    await stream.writeLp(encode(msg))
  except LPStreamError as e:
    trace "error writing hop request", err = e.msg
    return err("error writing hop request: " & e.msg)

  let response =
    try:
      RelayMessage.decode(await stream.readLp(RelayClientMsgSize))
    except LPStreamError as e:
      trace "error reading stop response", err = e.msg
      await sendStatus(stream, StatusV1.HopCantOpenDstStream)
      return err("error reading stop response: " & e.msg)

  checkHopResponse(response).isOkOr:
    await sendStatus(stream, StatusV1.HopCantOpenDstStream)
    return err(error)

  ok(stream)

proc dialPeerV1*(
    cl: RelayClient, stream: Stream, dstPeerId: PeerId, dstAddrs: seq[MultiAddress]
): Future[RawConn] {.async: (raises: [CancelledError, RelayV1DialError]).} =
  (await cl.tryDialPeerV1(stream, dstPeerId, dstAddrs)).valueOrRaise(RelayV1DialError)

func checkStopResponse(msg: HopMessage): LPResult[void] =
  if msg.msgType != Opt.some(HopMessageType.Status):
    return err("Unexpected stop response")
  if msg.status.get(UnexpectedMessage) != Ok:
    return err("Relay stop failure")
  ok()

proc tryDialPeerV2*(
    cl: RelayClient,
    relayConn: RelayConnection,
    dstPeerId: PeerId,
    dstAddrs: seq[MultiAddress],
): Future[LPResult[RawConn]] {.async: (raises: [CancelledError]).} =
  let p = Peer(peerId: Opt.some(dstPeerId), addrs: dstAddrs)

  trace "Dial peer", peer = p

  let response =
    try:
      await relayConn.writeLp(
        encode(HopMessage(msgType: Opt.some(HopMessageType.Connect), peer: Opt.some(p)))
      )
      HopMessage.decode(await relayConn.readLp(RelayClientMsgSize)).valueOr:
        return err("invalid stop response: " & error)
    except LPStreamError as e:
      trace "error exchanging stop messages", err = e.msg
      return err("error exchanging stop messages: " & e.msg)

  checkStopResponse(response).isOkOr:
    trace "Relay stop failed", description = response.status
    return err(error)

  relayConn.limitDuration = response.limit.get(Limit()).duration
  relayConn.limitData = response.limit.get(Limit()).data
  ok(RawConn(relayConn))

proc dialPeerV2*(
    cl: RelayClient,
    relayConn: RelayConnection,
    dstPeerId: PeerId,
    dstAddrs: seq[MultiAddress],
): Future[RawConn] {.async: (raises: [RelayV2DialError, CancelledError]).} =
  (await cl.tryDialPeerV2(relayConn, dstPeerId, dstAddrs)).valueOrRaise(
    RelayV2DialError
  )

proc handleStopStreamV2(
    cl: RelayClient, stream: Stream
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let decoded =
    try:
      StopMessage.decode(await stream.readLp(RelayClientMsgSize))
    except LPStreamError as e:
      return err("error reading stop message: " & e.msg)
  let msg = decoded.valueOr:
    try:
      await sendHopStatus(stream, MalformedMessage)
    except LPStreamError as e:
      return err("error writing hop status: " & e.msg)
    return ok()
  trace "client circuit relay v2 handle stream", msg

  if msg.msgType != Opt.some(StopMessageType.Connect):
    trace "Unexpected client / relayv2 handshake", msgType = msg.msgType
    await sendStopError(stream, MalformedMessage)
    return ok()

  await cl.handleRelayedConnect(stream, msg)

proc handleStop(
    cl: RelayClient, stream: Stream, msg: RelayMessage
) {.async: (raises: [CancelledError]).} =
  let src = msg.srcPeer.valueOr:
    await sendStatus(stream, StatusV1.StopSrcMultiaddrInvalid)
    return

  let dst = msg.dstPeer.valueOr:
    await sendStatus(stream, StatusV1.StopDstMultiaddrInvalid)
    return

  if dst.peerId != cl.switch.peerInfo.peerId:
    await sendStatus(stream, StatusV1.StopDstMultiaddrInvalid)
    return

  trace "get a relay connection", src, stream

  if cl.onNewConnection.isNil():
    await sendStatus(stream, StatusV1.StopRelayRefused)
    await stream.close()
    return
  await sendStatus(stream, StatusV1.Success)
  # This sound redundant but the callback could, in theory, be set to nil during
  # sendStatus(Success) so it's safer to double check
  if cl.onNewConnection.isNil():
    await stream.close()
  else:
    await cl.onNewConnection(stream, 0, 0)

proc handleStreamV1(
    cl: RelayClient, stream: Stream
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let decoded =
    try:
      RelayMessage.decode(await stream.readLp(RelayClientMsgSize))
    except LPStreamError as e:
      return err("error reading relay message: " & e.msg)
  let msg = decoded.valueOr:
    await sendStatus(stream, StatusV1.MalformedMessage)
    return ok()
  trace "client circuit relay v1 handle stream", msg

  let typ = msg.msgType.valueOr:
    trace "Message type not set"
    await sendStatus(stream, StatusV1.MalformedMessage)
    return ok()

  case typ
  of RelayType.Hop:
    if cl.canHop:
      await cl.handleHop(stream, msg)
    else:
      await sendStatus(stream, StatusV1.HopCantSpeakRelay)
  of RelayType.Stop:
    await cl.handleStop(stream, msg)
  of RelayType.CanHop:
    if cl.canHop:
      await sendStatus(stream, StatusV1.Success)
    else:
      await sendStatus(stream, StatusV1.HopCantSpeakRelay)
  else:
    trace "Unexpected relay handshake", msgType = msg.msgType
    await sendStatus(stream, StatusV1.MalformedMessage)
  ok()

proc new*(
    T: typedesc[RelayClient],
    canHop: bool = false,
    reservationTTL: times.Duration = DefaultReservationTTL,
    limitDuration: uint32 = DefaultLimitDuration,
    limitData: uint64 = DefaultLimitData,
    heartbeatSleepTime: uint32 = DefaultHeartbeatSleepTime,
    maxCircuit: int = MaxCircuit,
    maxCircuitPerPeer: int = MaxCircuitPerPeer,
    msgSize: int = RelayClientMsgSize,
    circuitRelayV1: bool = false,
): T =
  let cl = T(
    canHop: canHop,
    reservationTTL: reservationTTL,
    limit: Limit(duration: limitDuration, data: limitData),
    heartbeatSleepTime: heartbeatSleepTime,
    maxCircuit: maxCircuit,
    maxCircuitPerPeer: maxCircuitPerPeer,
    msgSize: msgSize,
    isCircuitRelayV1: circuitRelayV1,
  )
  proc dispatch(
      stream: Stream, proto: string
  ): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
    case proto
    of RelayV1Codec:
      await cl.handleStreamV1(stream)
    of RelayV2StopCodec:
      await cl.handleStopStreamV2(stream)
    of RelayV2HopCodec:
      try:
        await cl.handleHopStreamV2(stream)
        ok()
      except LPStreamError as e:
        err(e.msg)
    else:
      err("unexpected protocol " & proto)

  proc handleStream(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    defer:
      await stream.close()

    (await dispatch(stream, proto)).isOkOr:
      trace "error in client handler", err = error, stream

  cl.handler = handleStream
  cl.codecs =
    if cl.canHop:
      @[RelayV1Codec, RelayV2HopCodec, RelayV2StopCodec]
    else:
      @[RelayV1Codec, RelayV2StopCodec]
  cl
