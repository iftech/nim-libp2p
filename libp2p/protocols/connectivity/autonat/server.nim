# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils]
import results
import chronos, chronicles
import
  ../../protocol,
  ../../../switch,
  ../../../multiaddress,
  ../../../multicodec,
  ../../../peerid,
  ../../../utils/[future],
  ../../../errors
import types

export types

logScope:
  topics = "libp2p autonat"

type Autonat* = ref object of LPProtocol
  sem: AsyncSemaphore
  switch*: Switch
  dialTimeout: Duration

proc sendResponseError(
    stream: Stream, status: ResponseStatus, text: string = ""
) {.async: (raises: [CancelledError]).} =
  let pb = AutonatMsg(
    msgType: Opt.some(MsgType.DialResponse),
    response: Opt.some(
      AutonatDialResponse(
        status: Opt.some(status),
        text:
          if text == "":
            Opt.none(string)
          else:
            Opt.some(text),
        ma: Opt.none(MultiAddress),
      )
    ),
  ).encode()
  try:
    await stream.writeLp(pb)
  except LPStreamError as exc:
    trace "autonat failed to send response error", err = exc.msg, stream

proc sendResponseOk(
    stream: Stream, ma: MultiAddress
) {.async: (raises: [CancelledError]).} =
  let pb = AutonatMsg(
    msgType: Opt.some(MsgType.DialResponse),
    response: Opt.some(
      AutonatDialResponse(
        status: Opt.some(ResponseStatus.Ok), text: Opt.some("Ok"), ma: Opt.some(ma)
      )
    ),
  ).encode()
  try:
    await stream.writeLp(pb)
  except LPStreamError as exc:
    trace "autonat failed to send response ok", err = exc.msg, stream

proc tryDial(
    autonat: Autonat, stream: Stream, addrs: seq[MultiAddress]
) {.async: (raises: [DialFailedError, CancelledError]).} =
  if not autonat.sem.tryAcquire():
    debug "Too many concurrent dials, refusing request", peerId = stream.peerId
    await stream.sendResponseError(DialRefused, "Too many concurrent dials")
    return
  var futs: seq[Future[Opt[MultiAddress]].Raising([DialFailedError, CancelledError])]
  try:
    # This is to bypass the per peer max connections limit
    let outgoingConnection =
      autonat.switch.connManager.expectConnection(stream.peerId, Out)
    if outgoingConnection.failed() and
        outgoingConnection.error of AlreadyExpectingConnectionError:
      await stream.sendResponseError(DialRefused, outgoingConnection.error.msg)
      return
    # Safer to always try to cancel cause we aren't sure if the connection was established
    defer:
      outgoingConnection.cancelSoon()

    # tryDial is to bypass the global max connections limit
    futs = addrs.mapIt(autonat.switch.dialer.tryDial(stream.peerId, @[it]))
    let fut = await anyCompleted(futs).wait(autonat.dialTimeout)
    let ma = await fut
    ma.ifValue(maddr):
      await stream.sendResponseOk(maddr)
    else:
      await stream.sendResponseError(DialError, "Missing observed address")
  except CancelledError as exc:
    raise exc
  except AllFuturesFailedError as exc:
    debug "All dial attempts failed", err = exc.msg, addresses = addrs
    await stream.sendResponseError(DialError, "All dial attempts failed")
  except AsyncTimeoutError as exc:
    debug "Dial timeout", err = exc.msg, addresses = addrs
    await stream.sendResponseError(DialError, "Dial timeout")
  finally:
    try:
      autonat.sem.release()
    except AsyncSemaphoreError:
      raiseAssert "semaphore released without acquire"
    futs.cancelSoon()

proc handleDial(autonat: Autonat, stream: Stream, msg: AutonatMsg): Future[void] =
  let dial = msg.dial.valueOr:
    return stream.sendResponseError(BadRequest, "Missing Dial")
  let peerInfo = dial.peerInfo.valueOr:
    return stream.sendResponseError(BadRequest, "Missing Peer Info")
  peerInfo.id.ifValue(id):
    if id != stream.peerId:
      return stream.sendResponseError(BadRequest, "PeerId mismatch")

  let observedAddr = stream.observedAddr.valueOr:
    return stream.sendResponseError(BadRequest, "Missing observed address")

  var isRelayed = observedAddr.contains(multiCodec("p2p-circuit")).valueOr:
    return stream.sendResponseError(DialRefused, "Invalid observed address")
  if isRelayed:
    return stream.sendResponseError(
      DialRefused, "Refused to dial a relayed observed address"
    )
  let hostIp = observedAddr[0].valueOr:
    return stream.sendResponseError(InternalError, "Wrong observed address")
  if not IP.match(hostIp):
    return stream.sendResponseError(InternalError, "Expected an IP address")
  var addrs = initHashSet[MultiAddress]()
  addrs.incl(observedAddr)
  trace "addrs received", addresses = peerInfo.addrs
  for ma in peerInfo.addrs:
    isRelayed = ma.contains(multiCodec("p2p-circuit")).valueOr:
      continue
    let maFirst = ma[0].valueOr:
      continue
    if not DNS_OR_IP.match(maFirst):
      continue

    try:
      addrs.incl(
        if maFirst == hostIp:
          ma
        else:
          let maEnd = ma[1 ..^ 1].valueOr:
            continue
          hostIp & maEnd
      )
    except LPError:
      continue
    if len(addrs) >= AddressLimit:
      break

  if len(addrs) == 0:
    return stream.sendResponseError(DialRefused, "No dialable address")
  let addrsSeq = toSeq(addrs)
  trace "trying to dial", addresses = addrsSeq
  return autonat.tryDial(stream, addrsSeq)

proc new*(
    T: typedesc[Autonat],
    switch: Switch,
    semSize: int = 1,
    dialTimeout = 15.seconds,
    maxIncomingStreamsTotal = max(DefaultMaxIncomingStreamsTotal, semSize),
    maxIncomingStreamsPerPeer = DefaultMaxIncomingStreamsPerPeer,
): T =
  let autonat =
    T(switch: switch, sem: newAsyncSemaphore(semSize), dialTimeout: dialTimeout)
  autonat.setStreamLimits(
    maxIncomingStreamsTotal = maxIncomingStreamsTotal,
    maxIncomingStreamsPerPeer = maxIncomingStreamsPerPeer,
  )

  proc handleStream(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    try:
      let msg = AutonatMsg.decode(await stream.readLp(1024)).valueOrRaise(AutonatError)
      if msg.msgType.get(MsgType.Dial) != MsgType.Dial:
        raise newException(AutonatError, "Message type should be dial")
      await autonat.handleDial(stream, msg)
    except CancelledError as exc:
      trace "cancelled autonat handler"
      raise exc
    except CatchableError as exc:
      debug "exception in autonat handler", err = exc.msg, stream
    finally:
      trace "exiting autonat handler", stream
      await stream.close()

  autonat.handler = handleStream
  autonat.codec = AutonatCodec
  autonat
