# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push gcsafe.}
{.push raises: [].}

import std/[strformat]
import results
import chronos, chronicles
import
  ../protocol,
  ../../utils/zeroqueue,
  ../../stream/connection,
  ../../multiaddress,
  ../../peerinfo

export protocol, results

logScope:
  topics = "libp2p secure-channel"

const SecureConnTrackerName* = "SecureConn"

type
  Secure* = ref object of LPProtocol # base type for secure managers

  SecureConn* = ref object of Connection
    stream*: RawConn
    earlyMuxer*: string
    buf: ZeroQueue
    cleanupFut: Future[void]

func shortLog*(conn: SecureConn): auto =
  try:
    if conn == nil:
      "SecureConn(nil)"
    else:
      &"{shortLog(conn.peerId)}:{conn.oid}"
  except ValueError as exc:
    raiseAssert(exc.msg)

chronicles.formatIt(SecureConn):
  shortLog(it)

proc new*(
    T: type SecureConn,
    conn: RawConn,
    peerId: PeerId,
    observedAddr: Opt[MultiAddress],
    localAddr: Opt[MultiAddress],
    timeout: Duration = DefaultConnectionTimeout,
): T =
  let sconn = T(
    stream: conn,
    peerId: peerId,
    observedAddr: observedAddr,
    localAddr: localAddr,
    closeEvent: conn.closeEvent,
    timeout: timeout,
    dir: conn.dir,
  )
  sconn.initStream()
  sconn

method initStream*(s: SecureConn) =
  if s.objName.len == 0:
    s.objName = SecureConnTrackerName

  procCall Connection(s).initStream()

method closeImpl*(s: SecureConn) {.async: (raises: []).} =
  trace "Closing secure conn", conn = s, dir = s.dir
  if not s.cleanupFut.isNil():
    s.cleanupFut.cancelSoon()
  if s.stream != nil:
    await s.stream.close()

  await procCall Connection(s).closeImpl()

method resetImpl*(s: SecureConn) {.async: (raises: []).} =
  trace "Resetting secure conn", conn = s, dir = s.dir
  if not s.cleanupFut.isNil():
    s.cleanupFut.cancelSoon()
  if s.stream != nil:
    await s.stream.reset()

  await procCall Connection(s).closeImpl()

method readMessage*(
    c: SecureConn
): Future[seq[byte]] {.
    async: (raises: [CancelledError, LPStreamError], raw: true), base
.} =
  raiseAssert("[SecureConn.readMessage] abstract method not implemented!")

method getWrapped*(s: SecureConn): Connection =
  s.stream

method handshake*(
    s: Secure, conn: RawConn, initiator: bool, peerId: Opt[PeerId]
): Future[SecureConn] {.
    async: (raises: [CancelledError, LPStreamError], raw: true), base
.} =
  raiseAssert("[Secure.handshake] abstract method not implemented!")

proc handleConn(
    s: Secure, conn: RawConn, initiator: bool, peerId: Opt[PeerId]
): Future[SecureConn] {.async: (raises: [CancelledError, LPStreamError]).} =
  var sconn = await s.handshake(conn, initiator, peerId)
  # mark connection bottom level transport direction
  # this is the safest place to do this
  # we require this information in for example gossipsub
  sconn.transportDir = if initiator: Direction.Out else: Direction.In

  proc cleanup() {.async: (raises: []).} =
    try:
      block:
        let
          fut1 = conn.join()
          fut2 = sconn.join()
        try: # https://github.com/status-im/nim-chronos/issues/516
          discard await race(fut1, fut2)
        except ValueError as e:
          raiseAssert("Futures list is not empty: " & e.msg)
        # at least one join() completed, cancel pending one, if any
        if not fut1.finished:
          await fut1.cancelAndWait()
        if not fut2.finished:
          await fut2.cancelAndWait()
      block:
        let
          fut1 = sconn.close()
          fut2 = conn.close()
        await allFutures(fut1, fut2)
        static:
          doAssert typeof(fut1).E is void
          # Cannot fail
        static:
          doAssert typeof(fut2).E is void
          # Cannot fail
    except CancelledError:
      # This is top-level procedure which will work as separate task, so it
      # do not need to propagate CancelledError.
      discard

  if sconn != nil:
    # All the errors are handled inside `cleanup()` procedure.
    sconn.cleanupFut = cleanup()

  sconn

method init*(s: Secure) =
  procCall LPProtocol(s).init()

  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    trace "Secure upgrade started", protocol = proto, stream
    try:
      # We don't need the result but we
      # definitely need to await the handshake
      discard await s.handleConn(stream, false, Opt.none(PeerId))
      trace "Secure upgrade completed", protocol = proto, stream
    except CancelledError as exc:
      trace "Secure upgrade canceled", protocol = proto, stream
      raise exc
    except LPStreamError as exc:
      trace "Secure upgrade failed", err = exc.msg, protocol = proto, stream
    finally:
      await stream.close()

  s.handler = handle

method secure*(
    s: Secure, conn: RawConn, peerId: Opt[PeerId]
): Future[SecureConn] {.
    async: (raises: [CancelledError, LPStreamError], raw: true), base
.} =
  s.handleConn(conn, conn.dir == Direction.Out, peerId)

method readOnce*(
    s: SecureConn, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  doAssert(nbytes > 0, "nbytes must be positive integer")

  if s.isEof:
    raise newLPStreamEOFError()

  if s.buf.isEmpty:
    try:
      let buf = await s.readMessage() # Always returns >0 bytes or raises
      s.activity = true
      s.buf.push(buf)
    except LPStreamEOFError as err:
      s.isEof = true
      await s.close()
      raise newException(LPStreamEOFError, "Secure connection EOF: " & err.msg, err)
    except CancelledError as exc:
      raise exc
    except LPStreamError as err:
      debug "Secure connection message read failed",
        err = err.msg, errType = err.name, connection = s
      await s.close()
      raise newException(LPStreamError, "Secure connection read error: " & err.msg, err)

  return s.buf.consumeTo(pbytes, nbytes)
