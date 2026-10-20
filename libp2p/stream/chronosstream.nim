# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[strformat]
import results
import chronos, chronicles, metrics
import connection
import ../utils/shortlog

export results

logScope:
  topics = "libp2p chronos-stream"

const
  DefaultChronosStreamTimeout = 10.minutes
  ChronosStreamTrackerName* = "ChronosStream"

type ChronosStream* = ref object of Connection
  client: StreamTransport
  when defined(libp2p_agents_metrics):
    tracked: bool

func shortLog*(conn: ChronosStream): auto =
  try:
    if conn == nil:
      "ChronosStream(nil)"
    else:
      &"{shortLog(conn.peerId)}:{conn.oid}"
  except ValueError as exc:
    raiseAssert(exc.msg)

chronicles.formatIt(ChronosStream):
  shortLog(it)

method initStream*(s: ChronosStream) =
  if s.objName.len == 0:
    s.objName = ChronosStreamTrackerName

  s.timeoutHandler = proc(): Future[void] {.async: (raises: [], raw: true).} =
    trace "Idle timeout expired, closing ChronosStream", conn = s
    s.close()

  procCall Connection(s).initStream()

proc init*(
    C: type ChronosStream,
    client: StreamTransport,
    dir: Direction,
    timeout = DefaultChronosStreamTimeout,
    observedAddr: Opt[MultiAddress],
    localAddr: Opt[MultiAddress],
): ChronosStream =
  let s = C(
    client: client,
    timeout: timeout,
    dir: dir,
    observedAddr: observedAddr,
    localAddr: localAddr,
  )
  s.initStream()
  s

template withExceptions(body: untyped) =
  try:
    body
  except CancelledError as exc:
    raise exc
  except TransportIncompleteError:
    # for all intents and purposes this is an EOF
    raise newLPStreamIncompleteError()
  except TransportLimitError:
    raise newLPStreamLimitError()
  except TransportUseClosedError:
    raise newLPStreamEOFError()
  except TransportError as exc:
    # TODO https://github.com/status-im/nim-chronos/pull/99
    raise (ref LPStreamEOFError)(msg: "Stream EOF: " & exc.msg, parent: exc)

when defined(libp2p_agents_metrics):
  proc trackPeerIdentity(s: ChronosStream) =
    if not s.tracked and s.shortAgent.len > 0:
      libp2p_peers_identity.inc(labelValues = [s.shortAgent])
      s.tracked = true

  proc untrackPeerIdentity(s: ChronosStream) =
    if s.tracked:
      libp2p_peers_identity.dec(labelValues = [s.shortAgent])
      s.tracked = false

method readOnce*(
    s: ChronosStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  if s.atEof:
    raise newLPStreamEOFError()
  withExceptions:
    let bytesRead = await s.client.readOnce(pbytes, nbytes)
    s.activity = true # reset activity flag
    libp2p_network_bytes.inc(bytesRead.int64, labelValues = ["in"])
    when defined(libp2p_agents_metrics):
      s.trackPeerIdentity()
      if s.tracked:
        libp2p_peers_traffic_read.inc(bytesRead.int64, labelValues = [s.shortAgent])
    return bytesRead

proc completeWrite(
    s: ChronosStream,
    fut: Future[int].Raising([TransportError, CancelledError]),
    msgLen: int,
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  withExceptions:
    # StreamTransport will only return written < msg.len on fatal failures where
    # further writing is not possible - in such cases, we'll raise here,
    # since we don't return partial writes lengths
    await fut.join() # chronos frees a cancelled write's buffer while it stays queued
    let written = await fut

    if written < msgLen:
      raise (ref LPStreamClosedError)(
        msg: "Write failed: connection reset or closed by remote peer"
      )

    s.activity = true # reset activity flag
    libp2p_network_bytes.inc(msgLen.int64, labelValues = ["out"])
    when defined(libp2p_agents_metrics):
      s.trackPeerIdentity()
      if s.tracked:
        libp2p_peers_traffic_write.inc(msgLen.int64, labelValues = [s.shortAgent])

method write*(
    s: ChronosStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  # Avoid a copy of msg being kept in the closure created by `{.async.}` as this
  # drives up memory usage
  let msgLen = msg.len
  if msg.len == 0:
    trace "Empty byte seq, nothing to write"
    let fut = newFuture[void]("chronosstream.write.empty")
    fut.complete()
    return fut
  if s.closed:
    let fut = newFuture[void]("chronosstream.write.closed")
    fut.fail(newLPStreamClosedError())
    return fut

  s.completeWrite(s.client.write(msg), msgLen)

method closed*(s: ChronosStream): bool =
  s.client.closed

method atEof*(s: ChronosStream): bool =
  s.client.atEof()

method closeWrite*(s: ChronosStream) {.async: (raises: []).} =
  ## Close the write side of the TCP connection using half-close
  if not s.client.closed():
    try:
      await s.client.shutdownWait()
      trace "Write side closed", address = $s.client.remoteAddress(), conn = s
    except TransportError:
      # Ignore transport errors during shutdown
      discard
    except CatchableError:
      # Ignore other errors during shutdown
      discard

method closeImpl*(s: ChronosStream) {.async: (raises: []).} =
  trace "Shutting down chronos stream", address = $s.client.remoteAddress(), conn = s

  if not s.client.closed():
    await s.client.closeWait()
  trace "Shutdown chronos stream", address = $s.client.remoteAddress(), conn = s

  when defined(libp2p_agents_metrics):
    # do this after closing!
    s.untrackPeerIdentity()

  await procCall Connection(s).closeImpl()

method getWrapped*(s: ChronosStream): Connection =
  nil
