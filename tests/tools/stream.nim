# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, stew/byteutils
import ../../libp2p/stream/connection

proc newData*(size: int, val: byte = byte(0xFF)): seq[byte] =
  var data = newSeq[byte](size)
  for i in 0 ..< size:
    data[i] = val
  data

proc readStreamByChunkTillEOF*(
    stream: Stream, chunkSize: int, maxBytes: int = int.high
): Future[seq[byte]] {.async.} =
  ## Reads from stream until EOF is reached or the received data size meets/exceeds maxBytes
  var receivedData: seq[byte] = @[]

  while receivedData.len < maxBytes:
    var chunk = newSeq[byte](chunkSize)
    let bytesRead = await stream.readOnce(addr chunk[0], chunkSize)
    if bytesRead == 0:
      break
    receivedData.add(chunk[0 ..< bytesRead])

  receivedData

proc readExactlyAsStr*(stream: Stream, nbytes: int): Future[string] {.async.} =
  ## Reads exactly `nbytes` from the stream and returns them decoded as a string
  doAssert nbytes > 0, "readExactlyAsStr requires nbytes > 0"
  var buffer = newSeq[byte](nbytes)
  await stream.readExactly(addr buffer[0], nbytes)
  string.fromBytes(buffer)

type HalfCloseStream* = ref object of Connection
  ## Close ends only the wrapper, so reads reach the open inner stream
  inner: Connection

method readOnce*(
    s: HalfCloseStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  s.inner.readOnce(pbytes, nbytes)

method write*(
    s: HalfCloseStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  s.inner.write(move(msg))

proc newHalfCloseStream*(inner: Connection): HalfCloseStream =
  let stream = HalfCloseStream(inner: inner)
  stream.initStream()
  stream
