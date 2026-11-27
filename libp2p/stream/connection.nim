# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[hashes, oids, strformat]
import results
import chronicles, chronos, metrics
import lpstream, ../multiaddress, ../peerinfo, ../errors

export lpstream, peerinfo, errors, results

logScope:
  topics = "libp2p connection"

const
  ConnectionTrackerName* = "Connection"
  DefaultConnectionTimeout* = 5.minutes

type
  TimeoutHandler* = proc(): Future[void] {.async: (raises: []).}

  Connection* = ref object of LPStream
    activity*: bool # reset every time data is sent or received
    timeout*: Duration # channel timeout if no activity
    timerTaskFut: Future[void].Raising([]) # the current timer instance
    timeoutHandler*: TimeoutHandler # timeout handler
    peerId*: PeerId
    observedAddr*: Opt[MultiAddress]
    localAddr*: Opt[MultiAddress]
    protocol*: string # protocol used by the connection, used as metrics tag
    transportDir*: Direction # underlying transport (usually socket) direction
    openedAt*: Moment # initialization time of this layer; unwrap for transport age
    when defined(libp2p_agents_metrics):
      shortAgent*: string

  ## Semantic aliases for stream endpoints at different stages of the stack.
  ## These are aliases, not distinct types.
  Stream* = Connection
  RawConn* = Stream
  MuxedStream* = Stream

proc timeoutMonitor(s: Connection) {.async: (raises: []).}

method closeWrite*(s: Connection): Future[void] {.base, async: (raises: []).} =
  ## Close the write side of the connection
  ## Subclasses should implement this for their specific transport
  ## Default implementation just closes the entire connection
  await s.close()

func shortLog*(conn: Connection): string =
  try:
    if conn == nil:
      "Connection(nil)"
    else:
      &"{shortLog(conn.peerId)}:{conn.oid}"
  except ValueError as exc:
    raiseAssert(exc.msg)

chronicles.formatIt(Connection):
  shortLog(it)

declarePublicCounter libp2p_network_bytes, "total traffic", labels = ["direction"]
declarePublicCounter libp2p_stream_timeouts,
  "stream inactivity timeouts", labels = ["type", "direction"]

when defined(libp2p_agents_metrics):
  declarePublicGauge libp2p_peers_identity, "peers identities", labels = ["agent"]
  declarePublicCounter libp2p_peers_traffic_read, "incoming traffic", labels = ["agent"]
  declarePublicCounter libp2p_peers_traffic_write,
    "outgoing traffic", labels = ["agent"]

method initStream*(s: Connection) =
  if s.objName.len == 0:
    s.objName = ConnectionTrackerName

  s.openedAt = Moment.now()
  procCall LPStream(s).initStream()

  doAssert(s.timerTaskFut == nil)

  if s.timeout > 0.millis:
    trace "Monitoring for timeout", conn = s, timeout = s.timeout

    s.timerTaskFut = s.timeoutMonitor()
    if s.timeoutHandler == nil:
      s.timeoutHandler = proc(): Future[void] {.async: (raises: [], raw: true).} =
        trace "Idle timeout expired, closing connection", conn = s
        s.close()

method closeImpl*(s: Connection): Future[void] {.async: (raises: []).} =
  # Cleanup timeout timer
  trace "Closing connection", conn = s

  if s.timerTaskFut != nil and not s.timerTaskFut.finished:
    # Don't `cancelAndWait` here to avoid risking deadlock in this scenario:
    # - `pollActivity` is waiting for `s.timeoutHandler` to complete.
    # - `s.timeoutHandler` may have triggered `closeImpl` and we are now here.
    # In this situation, we have to return for `s.timerTaskFut` to complete.
    s.timerTaskFut.cancelSoon()
    s.timerTaskFut = nil

  trace "Closed connection", conn = s

  procCall LPStream(s).closeImpl()

func hash*(p: Connection): Hash =
  cast[pointer](p).hash

proc pollActivity(s: Connection): Future[bool] {.async: (raises: []).} =
  if s.closed and s.atEof:
    return false # Done, no more monitoring

  if s.activity:
    s.activity = false
    return true

  # Inactivity timeout happened, call timeout monitor

  trace "Connection timed out", conn = s
  libp2p_stream_timeouts.inc(labelValues = [s.objName, metricLabel(s.dir)])
  if s.timeoutHandler != nil:
    trace "Calling timeout handler", conn = s
    await s.timeoutHandler()

  return false

proc timeoutMonitor(s: Connection) {.async: (raises: []).} =
  ## monitor the channel for inactivity
  ##
  ## if the timeout was hit, it means that
  ## neither incoming nor outgoing activity
  ## has been detected and the channel will
  ## be reset
  ##

  while true:
    try: # Sleep at least once!
      await sleepAsync(s.timeout)
    except CancelledError:
      return

    if not await s.pollActivity():
      return

method getWrapped*(s: Connection): Connection {.base, gcsafe.} =
  raiseAssert("[Connection.getWrapped] abstract method not implemented!")

proc getUnderlying*(s: Connection): Connection =
  ## Returns the innermost connection, stopping at a nil or self wrapper.
  var conn = s
  while conn != nil:
    let wrapped = conn.getWrapped()
    if wrapped == nil or wrapped == conn:
      break
    conn = wrapped
  conn

when defined(libp2p_agents_metrics):
  proc setShortAgent*(s: Connection, shortAgent: string) =
    var conn = s
    while conn != nil:
      conn.shortAgent = shortAgent
      let wrapped = conn.getWrapped()
      if wrapped == conn:
        break
      conn = wrapped

proc new*(
    C: type Connection,
    peerId: PeerId,
    dir: Direction,
    observedAddr: Opt[MultiAddress] = Opt.none(MultiAddress),
    localAddr: Opt[MultiAddress] = Opt.none(MultiAddress),
    timeout: Duration = DefaultConnectionTimeout,
    timeoutHandler: TimeoutHandler = nil,
): Connection =
  let conn = C(
    peerId: peerId,
    dir: dir,
    timeout: timeout,
    timeoutHandler: timeoutHandler,
    observedAddr: observedAddr,
    localAddr: localAddr,
  )

  conn.initStream()
  conn
