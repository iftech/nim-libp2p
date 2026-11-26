# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import results
import chronos, chronicles, tables
import
  ../../protocol,
  ../../../switch,
  ../../../multiaddress,
  ../../../multicodec,
  ../../../peerid,
  ./types,
  ./utils

logScope:
  topics = "libp2p autonat"

const
  MaxAcceptedDialDataRequest* = 100 * 1024 # 100 KB
  MaxDialDataResponsePayload* = 1024
  DefaultDialBackTimeout* = 5.seconds

type
  PendingDialBack = object
    startedAt: Moment
    localAddr: Opt[MultiAddress]

  AutonatV2Client* = ref object of LPProtocol
    dialer*: Dial
    dialBackTimeout: Duration
    rng: Rng
    expectedNonces: Table[Nonce, PendingDialBack]

proc handleDialBack(
    self: AutonatV2Client, stream: Stream, dialBack: DialBack
) {.async: (raises: [CancelledError, LPStreamError]).} =
  trace "Handling DialBack",
    stream, localAddr = stream.localAddr, observedAddr = stream.observedAddr

  if not self.expectedNonces.hasKey(dialBack.nonce):
    trace "Not expecting this nonce", nonce = dialBack.nonce
    return

  let pending = self.expectedNonces.getOrDefault(dialBack.nonce)
  if pending.localAddr.isSome:
    trace "Already received DialBack", nonce = dialBack.nonce
    return

  # A new muxed stream is not proof of a new inbound transport connection.
  let transport = stream.getUnderlying()

  if stream.transportDir != Direction.In or transport.dir != Direction.In or
      transport.openedAt <= pending.startedAt:
    trace "DialBack requires a fresh inbound connection", nonce = dialBack.nonce
    return

  stream.localAddr.ifValue(localAddr):
    trace "Setting expectedNonces",
      nonce = dialBack.nonce, localAddr = Opt.some(localAddr)
    self.expectedNonces[dialBack.nonce] =
      PendingDialBack(startedAt: pending.startedAt, localAddr: Opt.some(localAddr))
  else:
    debug "Unable to get localAddr from connection"
    return

  trace "Sending DialBackResponse"
  await stream.writeLp(DialBackResponse(status: DialBackStatus.Ok).encode())

proc new*(
    T: typedesc[AutonatV2Client],
    rng: Rng,
    dialBackTimeout: Duration = DefaultDialBackTimeout,
): T =
  let client = T(rng: rng, dialBackTimeout: dialBackTimeout)

  # handler for DialBack messages
  proc handleStream(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    defer:
      await stream.close()

    try:
      let dialBack = DialBack.decode(await stream.readLp(DialBackLpSize)).valueOr:
        trace "Unable to decode DialBack", err = error
        return
      if not await client.handleDialBack(stream, dialBack).withTimeout(
        client.dialBackTimeout
      ):
        trace "Sending DialBackResponse timed out"
    except CancelledError as exc:
      raise exc
    except LPStreamRemoteClosedError as exc:
      trace "Stream closed by peer", err = exc.msg, peerId = stream.peerId
    except LPStreamError as exc:
      trace "Stream closed by peer", err = exc.msg, peerId = stream.peerId

  client.handler = handleStream
  client.codec = $AutonatV2Codec.DialBack
  client

proc setup*(self: AutonatV2Client, switch: Switch) =
  self.dialer = switch.dialer

proc tryHandleDialDataRequest*(
    stream: Stream, req: DialDataRequest
): Future[LPResult[DialResponse]] {.async: (raises: [CancelledError, LPStreamError]).} =
  trace "Received DialDataRequest",
    numBytes = req.numBytes, maxAcceptedNumBytes = MaxAcceptedDialDataRequest

  if req.numBytes > MaxAcceptedDialDataRequest:
    return err("Rejecting DialDataRequest: numBytes is greater than the maximum")

  # send required data
  let data = AutonatV2Msg(
    oneof: AutonatV2MsgOneof(
      kind: MsgKind.DialDataResponse,
      dialDataResponse: DialDataResponse(data: newSeq[byte](MaxDialDataResponsePayload)),
    )
  ).encode()
  let messagesToSend =
    (req.numBytes + MaxDialDataResponsePayload - 1) div MaxDialDataResponsePayload
  for i in 0 ..< messagesToSend:
    await stream.writeLp(data)
    trace "Sending DialDataResponse", index = i, messagesToSend = messagesToSend

  let msg = AutonatV2Msg.decode(await stream.readLp(AutonatV2MsgLpSize)).valueOr:
    return err(error)

  trace "Received message", kind = msg.oneof.kind
  if msg.oneof.kind != MsgKind.DialResponse:
    return err($msg.oneof.kind, "received message is not a DialResponse")

  ok(msg.oneof.dialResponse)

proc handleDialDataRequest*(
    stream: Stream, req: DialDataRequest
): Future[DialResponse] {.
    async: (raises: [CancelledError, AutonatV2Error, LPStreamError])
.} =
  let handled = await stream.tryHandleDialDataRequest(req)
  handled.valueOrRaise(AutonatV2Error)

proc checkAddrIdx(
    self: AutonatV2Client, addrIdx: AddrIdx, testAddrs: seq[MultiAddress], nonce: Nonce
): bool {.raises: [].} =
  trace "checking addrs", addrIdx = addrIdx, testAddrs = testAddrs, nonce = nonce
  let dialBackAddrs = self.expectedNonces.getOrDefault(nonce).localAddr.valueOr:
    trace "Not expecting this nonce",
      nonce = nonce, expectedNonces = self.expectedNonces
    return false

  if addrIdx.int >= testAddrs.len:
    trace "addrIdx outside of testAddrs range",
      addrIdx = addrIdx, testAddrs = testAddrs, testAddrsLen = testAddrs.len
    return false

  let dialRespAddrs = testAddrs[addrIdx]
  if not areAddrsConsistent(dialRespAddrs, dialBackAddrs):
    trace "Invalid addrIdx: got DialBack in another address",
      addrIdx = addrIdx, dialBackAddrs = dialBackAddrs, dialRespAddrs = dialRespAddrs
    return false
  true

proc trySendDialRequest*(
    self: AutonatV2Client, pid: PeerId, testAddrs: seq[MultiAddress]
): Future[LPResult[AutonatV2Response]] {.
    async: (raises: [CancelledError, DialFailedError, LPStreamError])
.} =
  ## Dials peer with `pid` and requests that it tries connecting to `testAddrs`

  let nonce = self.rng.generate(Nonce)

  var dialResp: DialResponse
  try:
    let stream = await self.dialer.dial(pid, @[$AutonatV2Codec.DialRequest])
    defer:
      await stream.close()

    # Dialback identities may differ from pid, and NAT may rewrite IPs and ports.
    self.expectedNonces[nonce] = PendingDialBack(startedAt: Moment.now())

    # send dialRequest
    await stream.writeLp(
      AutonatV2Msg(
        oneof: AutonatV2MsgOneof(
          kind: MsgKind.DialRequest,
          dialRequest: DialRequest(addrs: testAddrs, nonce: nonce),
        )
      ).encode()
    )
    let msg = AutonatV2Msg.decode(await stream.readLp(AutonatV2MsgLpSize)).valueOr:
      return err(error)

    dialResp =
      case msg.oneof.kind
      of MsgKind.DialResponse:
        msg.oneof.dialResponse
      of MsgKind.DialDataRequest:
        let handled = await stream.tryHandleDialDataRequest(msg.oneof.dialDataRequest)
        ?handled
      else:
        return err(
          $msg.oneof.kind, "received message is not a DialResponse or DialDataRequest"
        )

    trace "Received DialResponse", dialResp = dialResp

    dialResp.dialStatus.ifValue(dialStatus):
      if dialStatus == DialStatus.Ok:
        let addrIdx = dialResp.addrIdx.valueOr(0.AddrIdx)
        if not self.checkAddrIdx(addrIdx, testAddrs, nonce):
          return err("Invalid addrIdx in DialResponse")
  except LPStreamRemoteClosedError as exc:
    trace "Stream reset by server", err = exc.msg, peerId = pid
  finally:
    # rollback any changes
    self.expectedNonces.del(nonce)

  ok(dialResp.asAutonatV2Response(testAddrs))

method sendDialRequest*(
    self: AutonatV2Client, pid: PeerId, testAddrs: seq[MultiAddress]
): Future[AutonatV2Response] {.
    base,
    async: (raises: [AutonatV2Error, CancelledError, DialFailedError, LPStreamError])
.} =
  let sent = await self.trySendDialRequest(pid, testAddrs)
  sent.valueOrRaise(AutonatV2Error)
