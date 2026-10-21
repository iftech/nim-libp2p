# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Length Prefixed stream implementation

{.push gcsafe.}
{.push raises: [].}

import std/[oids, strutils]
import stew/byteutils
import chronicles, chronos, metrics
import ../varint, ../peerinfo, ../multiaddress, ../utils/shortlog, ../errors
import ../utils/future

export errors

declareGauge libp2p_open_streams, "open stream instances", labels = ["type", "dir"]
declarePublicCounter libp2p_stream_resets,
  "streams reset locally", labels = ["type", "direction"]

export oids

logScope:
  topics = "libp2p stream"

const
  LPStreamTrackerName* = "LPStream"
  Eof* = @[]

type
  Direction* {.pure.} = enum
    In
    Out

  LPStream* = ref object of RootObj
    closeEvent*: AsyncEvent
    isClosed*: bool
    isEof*: bool
    objName*: string
    oid*: Oid
    dir*: Direction
    closedWithEOF: bool # prevent concurrent calls
    isResetLocally: bool
    isClosedRemotely*: bool

  LPStreamError* = object of LPError
  LPStreamIncompleteError* = object of LPStreamError
  LPStreamLimitError* = object of LPStreamError
  LPStreamEOFError* = object of LPStreamError

  #        X        |           Read            |         Write
  #   Local close   |           Works           |  LPStreamClosedError
  #   Remote close  | LPStreamRemoteClosedError |         Works
  #   Local reset   |    LPStreamClosedError    |  LPStreamClosedError
  #   Remote reset  |    LPStreamResetError     |  LPStreamResetError
  # Connection down |     LPStreamConnDown      | LPStreamConnDownError
  LPStreamResetError* = object of LPStreamEOFError
  LPStreamClosedError* = object of LPStreamEOFError
  LPStreamRemoteClosedError* = object of LPStreamEOFError
  LPStreamConnDownError* = object of LPStreamEOFError

  InvalidVarintError* = object of LPStreamError
  MaxSizeError* = object of LPStreamError
    msgLen*: uint64 ## length of the incoming message, as declared by its prefix
    maxLen*: uint64 ## the limit that `msgLen` exceeded

  StreamTracker* = ref object of TrackerBase
    opened*: uint64
    closed*: uint64

func metricLabel*(dir: Direction): string =
  ($dir).toLowerAscii()

proc newLPStreamIncompleteError*(): ref LPStreamIncompleteError =
  newException(LPStreamIncompleteError, "Incomplete data received")

proc newLPStreamLimitError*(): ref LPStreamLimitError =
  newException(LPStreamLimitError, "Buffer limit reached")

proc newLPStreamEOFError*(): ref LPStreamEOFError =
  newException(LPStreamEOFError, "Stream EOF!")

proc newLPStreamResetError*(): ref LPStreamResetError =
  newException(LPStreamResetError, "Stream Reset!")

proc newLPStreamClosedError*(): ref LPStreamClosedError =
  newException(LPStreamClosedError, "Stream Closed!")

proc newLPStreamRemoteClosedError*(): ref LPStreamRemoteClosedError =
  newException(LPStreamRemoteClosedError, "Stream Remotely Closed!")

proc newLPStreamConnDownError*(
    parentException: ref Exception = nil
): ref LPStreamConnDownError =
  newException(
    LPStreamConnDownError, "Stream Underlying Connection Closed!", parentException
  )

func shortLog*(s: LPStream): auto =
  if s == nil:
    "LPStream(nil)"
  else:
    $s.oid

chronicles.formatIt(LPStream):
  shortLog(it)

method initStream*(s: LPStream) {.base.} =
  if s.objName.len == 0:
    s.objName = LPStreamTrackerName

  s.closeEvent = newAsyncEvent()
  s.oid = genOid()

  libp2p_open_streams.inc(labelValues = [s.objName, metricLabel(s.dir)])
  trackCounter(s.objName)
  trace "Stream created", stream = s, objName = s.objName, dir = $s.dir

method join*(
    s: LPStream
): Future[void] {.base, async: (raises: [CancelledError], raw: true).} =
  ## Wait for the stream to be closed
  s.closeEvent.wait()

method closed*(s: LPStream): bool {.base.} =
  s.isClosed

method atEof*(s: LPStream): bool {.base.} =
  s.isEof

func wasResetLocally*(s: LPStream): bool =
  s.isResetLocally

method readOnce*(
    s: LPStream, pbytes: pointer, nbytes: int
): Future[int] {.base, async: (raises: [CancelledError, LPStreamError], raw: true).} =
  ## Reads whatever is available in the stream,
  ## up to `nbytes`. Will block if nothing is
  ## available
  raiseAssert("[LPStream.readOnce] abstract method not implemented!")

method readExactly*(
    s: LPStream, pbytes: pointer, nbytes: int
): Future[void] {.base, async: (raises: [CancelledError, LPStreamError]).} =
  ## Waits for `nbytes` to be available, then read
  ## them and return them
  if s.atEof:
    var ch: char
    discard await s.readOnce(addr ch, 1)
    raise newLPStreamEOFError()

  if nbytes == 0:
    return

  logScope:
    s
    nbytes = nbytes
    objName = s.objName

  var pbuffer = cast[ptr UncheckedArray[byte]](pbytes)
  var read = 0
  while read < nbytes and not (s.atEof()):
    read += await s.readOnce(addr pbuffer[read], nbytes - read)

  if read == 0:
    doAssert s.atEof()
    trace "Couldn't read all bytes, stream EOF", stream = s, nbytes, read
    # Re-readOnce to raise a more specific error than EOF
    # Raise EOF if it doesn't raise anything(shouldn't happen)
    discard await s.readOnce(addr pbuffer[read], nbytes - read)
    trace "Read twice while at EOF"
    raise newLPStreamEOFError()

  if read < nbytes:
    trace "Couldn't read all bytes, incomplete data", stream = s, nbytes, read
    raise newLPStreamIncompleteError()

method readLine*(
    s: LPStream, limit = 0, sep = "\r\n"
): Future[string] {.base, async: (raises: [CancelledError, LPStreamError]).} =
  ## Reads up to `limit` bytes are read, or a `sep` is found
  # TODO replace with something that exploits buffering better
  var lim = if limit <= 0: -1 else: limit
  var state = 0
  var line: string

  while true:
    var ch: char
    await readExactly(s, addr ch, 1)

    if sep[state] == ch:
      inc(state)
      if state == len(sep):
        break
    else:
      state = 0
      if limit > 0:
        let missing = min(state, lim - len(line) - 1)
        line.add(sep[0 ..< missing])
      else:
        line.add(sep[0 ..< state])

      line.add(ch)
      if len(line) == lim:
        break
  line

method readVarint*(
    conn: LPStream
): Future[uint64] {.base, async: (raises: [CancelledError, LPStreamError]).} =
  var buffer: array[10, byte]

  for i in 0 ..< len(buffer):
    await conn.readExactly(addr buffer[i], 1)

    var
      varint: uint64
      length: int
    let res = PB.getUVarint(buffer.toOpenArray(0, i), length, varint)
    if res.isOk():
      return varint
    if res.error() != VarintError.Incomplete:
      break
  if true: # can't end with a raise apparently
    raise (ref InvalidVarintError)(msg: "Cannot parse varint")

method readLp*(
    s: LPStream, maxSize: int
): Future[seq[byte]] {.base, async: (raises: [CancelledError, LPStreamError]).} =
  ## read length prefixed msg, with the length encoded as a varint
  let
    length = await s.readVarint()
    maxLen = uint64(if maxSize < 0: int.high else: maxSize)

  if length > maxLen:
    raise (ref MaxSizeError)(
      msg: "Message length " & $length & " exceeds maximum " & $maxLen,
      msgLen: length,
      maxLen: maxLen,
    )

  if length == 0:
    return

  var res = newSeqUninit[byte](length)
  await s.readExactly(addr res[0], res.len)
  res

method write*(
    s: LPStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true), base.} =
  # Write `msg` to stream, waiting for the write to be finished
  raiseAssert("[LPStream.write] abstract method not implemented!")

method writeLp*(
    s: LPStream, msg: openArray[byte]
): Future[void] {.base, async: (raises: [CancelledError, LPStreamError], raw: true).} =
  ## Write `msg` with a varint-encoded length prefix
  let vbytes = PB.toBytes(msg.len().uint64)
  var buf = newSeqUninit[byte](msg.len() + vbytes.len)
  buf[0 ..< vbytes.len] = vbytes.toOpenArray()
  buf[vbytes.len ..< buf.len] = msg
  s.write(move(buf))

method writeLp*(
    s: LPStream, msg: string
): Future[void] {.base, async: (raises: [CancelledError, LPStreamError], raw: true).} =
  writeLp(s, msg.toOpenArrayByte(0, msg.high))

proc write*(
    s: LPStream, msg: string
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  s.write(msg.toBytes())

method closeImpl*(s: LPStream): Future[void] {.async: (raises: [], raw: true), base.} =
  ## Implementation of close - called only once
  trace "Closing stream", stream = s, objName = s.objName, dir = $s.dir
  libp2p_open_streams.dec(labelValues = [s.objName, metricLabel(s.dir)])
  untrackCounter(s.objName)
  s.closeEvent.fire()
  trace "Closed stream", stream = s, objName = s.objName, dir = $s.dir
  newFutureCompleted[void]()

method resetImpl*(s: LPStream): Future[void] {.async: (raises: [], raw: true), base.} =
  ## Default reset fallback for transports without an abort primitive.
  closeImpl(s)

method close*(s: LPStream): Future[void] {.async: (raises: [], raw: true), base.} =
  ## close the stream - this may block, but will not raise exceptions
  ##
  if s.isClosed:
    trace "Already closed", stream = s
    return newFutureCompleted[void]()

  s.isClosed = true # Set flag before performing virtual close

  # A separate implementation method is used so that even when derived types
  # override `closeImpl`, it is called only once - anyone overriding `close`
  # itself must implement this - once-only check as well, with their own field
  closeImpl(s)

proc resetStream(s: LPStream): Future[void] {.async: (raises: [], raw: true).} =
  ## Abort the stream and best-effort notify the remote peer, if supported.
  if s.isClosed:
    trace "Already closed", stream = s
    return newFutureCompleted[void]()

  s.isClosed = true
  s.isResetLocally = true
  libp2p_stream_resets.inc(labelValues = [s.objName, metricLabel(s.dir)])
  resetImpl(s)

template reset*[T: LPStream](s: T): untyped =
  resetStream(s)

proc closeWithEOF*(s: LPStream): Future[void] {.async: (raises: []).} =
  ## Close the stream and wait for EOF - use this with half-closed streams where
  ## an EOF is expected to arrive from the other end.
  ##
  ## Note - this should only be used when there has been an in-protocol
  ## notification that no more data will arrive and that the only thing left
  ## for the other end to do is to close the stream gracefully.
  ##
  ## In particular, it must not be used when there is another concurrent read
  ## ongoing (which may be the case during cancellations)!
  ##

  trace "Closing with EOF", stream = s
  if s.closedWithEOF:
    trace "Already closed"
    return

  # prevent any further calls to avoid triggering
  # reading the stream twice (which should assert)
  s.closedWithEOF = true
  await s.close()

  if s.isResetLocally or s.atEof():
    return

  try:
    var buf: array[8, byte]
    if (await readOnce(s, addr buf[0], buf.len)) != 0:
      debug "Unexpected bytes while waiting for EOF", stream = s
  except CancelledError:
    discard
  except LPStreamEOFError as e:
    trace "Expected EOF came", err = e.msg, stream = s
  except LPStreamError as exc:
    debug "Unexpected error while waiting for EOF", err = exc.msg, stream = s
