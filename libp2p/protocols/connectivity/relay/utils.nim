# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import ../../../protocodec
import chronos, chronicles
import ./messages, ./relay_metrics, ../../../stream/connection

logScope:
  topics = "libp2p relay"

const
  RelayV1Codec* = ProtoCodec("/libp2p/circuit/relay/0.1.0")
  RelayV2HopCodec* = ProtoCodec("/libp2p/circuit/relay/0.2.0/hop")
  RelayV2StopCodec* = ProtoCodec("/libp2p/circuit/relay/0.2.0/stop")

proc sendStatus*(stream: Stream, code: StatusV1) {.async: (raises: [CancelledError]).} =
  trace "send relay/v1 status", status = $code & "(" & $ord(code) & ")"
  try:
    let msg = RelayMessage(msgType: Opt.some(RelayType.Status), status: Opt.some(code))
    await stream.writeLp(encode(msg))
  except CancelledError as e:
    raise e
  except LPStreamError as e:
    trace "error sending relay status", err = e.msg

proc sendHopStatus*(
    stream: Stream, code: StatusV2
) {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  trace "send hop relay/v2 status", status = $code & "(" & $ord(code) & ")"
  let msg = HopMessage(msgType: Opt.some(HopMessageType.Status), status: Opt.some(code))
  stream.writeLp(encode(msg))

proc sendStopStatus*(
    stream: Stream, code: StatusV2
) {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  trace "send stop relay/v2 status", status = $code & " (" & $ord(code) & ")"
  let msg =
    StopMessage(msgType: Opt.some(StopMessageType.Status), status: Opt.some(code))
  stream.writeLp(encode(msg))

proc bridge*(
    srcStream: Stream, dstStream: Stream
) {.async: (raises: [CancelledError]).} =
  const bufferSize = 4096
  var
    bufSrcToDst: array[bufferSize, byte]
    bufDstToSrc: array[bufferSize, byte]
    futSrc = srcStream.readOnce(addr bufSrcToDst[0], bufSrcToDst.len)
    futDst = dstStream.readOnce(addr bufDstToSrc[0], bufDstToSrc.len)
    bytesSentFromSrcToDst = 0
    bytesSentFromDstToSrc = 0
    eof = false # a flag, not a break: the other direction still drains this pass

  defer:
    # both reads write into this frame's buffers, so none of them may outlive it
    await noCancel allFutures(futSrc.cancelAndWait(), futDst.cancelAndWait())

  try:
    while not eof and not srcStream.closed() and not dstStream.closed():
      try: # https://github.com/status-im/nim-chronos/issues/516
        discard await race(futSrc, futDst)
      except ValueError as e:
        raiseAssert("Futures list is not empty: " & e.msg)
      if futSrc.finished():
        let bufRead = await futSrc
        if bufRead == 0:
          eof = true
        else:
          bytesSentFromSrcToDst.inc(bufRead)
          await dstStream.write(@bufSrcToDst[0 ..< bufRead])
          zeroMem(addr bufSrcToDst[0], bufSrcToDst.len)
          futSrc = srcStream.readOnce(addr bufSrcToDst[0], bufSrcToDst.len)
      if futDst.finished():
        let bufRead = await futDst
        if bufRead == 0:
          eof = true
        else:
          bytesSentFromDstToSrc += bufRead
          await srcStream.write(bufDstToSrc[0 ..< bufRead])
          zeroMem(addr bufDstToSrc[0], bufDstToSrc.len)
          futDst = dstStream.readOnce(addr bufDstToSrc[0], bufDstToSrc.len)
  except CancelledError as exc:
    raise exc
  except LPStreamError as exc:
    if srcStream.closed() or srcStream.atEof():
      trace "relay src closed connection", src = srcStream.peerId
    if dstStream.closed() or dstStream.atEof():
      trace "relay dst closed connection", dst = dstStream.peerId
    trace "relay error", err = exc.msg
  trace "end relaying", bytesSentFromSrcToDst, bytesSentFromDstToSrc
  libp2p_relay_bytes.inc(bytesSentFromSrcToDst.int64, labelValues = ["in"])
  libp2p_relay_bytes.inc(bytesSentFromDstToSrc.int64, labelValues = ["out"])
