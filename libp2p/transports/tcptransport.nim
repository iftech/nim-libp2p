# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## TCP transport implementation

{.push raises: [].}

import ../logging
import std/[sequtils, oserrors]
import chronos, chronicles, results
import
  ./transport,
  ../wire,
  ../multiaddress,
  ../stream/connection,
  ../stream/chronosstream,
  ../upgrademngrs/upgrade,
  ../utils/future

logScope:
  topics = "libp2p tcp"

export transport, connection, upgrade

const TcpTransportTrackerName* = "libp2p.tcptransport"

type
  AcceptFuture = typeof(default(StreamServer).accept())

  TcpTransport* = ref object of Transport
    servers*: seq[StreamServer]
    clients: array[Direction, seq[StreamTransport]]
    flags: set[ServerFlags]
    clientFlags: set[SocketFlags]
    acceptFuts: seq[AcceptFuture]
    connectionsTimeout: Duration
    stopping: bool
    descriptorWarnings: LogRateLimit
    closeFuts: seq[Future[void]]

  TcpTransportError* = object of transport.TransportError

  ConnAddrs = object
    observed: MultiAddress
    local: MultiAddress

proc connHandler*(
    self: TcpTransport,
    client: StreamTransport,
    observedAddr: Opt[MultiAddress],
    localAddr: Opt[MultiAddress],
    dir: Direction,
): RawConn =
  trace "Handling tcp connection",
    address = $observedAddr,
    dir = $dir,
    clients = self.clients[Direction.In].len + self.clients[Direction.Out].len

  let conn = Connection(
    ChronosStream.init(
      client = client,
      dir = dir,
      observedAddr = observedAddr,
      localAddr = localAddr,
      timeout = self.connectionsTimeout,
    )
  )

  proc onClose() {.async: (raises: []).} =
    await noCancel client.join()

    trace "Cleaning up client", addresses = ($client.remoteAddress).shortLog, conn

    self.clients[dir].keepItIf(it != client)

    # Propagate the chronos client being closed to the connection
    # TODO This is somewhat dubious since it's the connection that owns the
    #      client, but it allows the transport to close all connections when
    #      shutting down (also dubious! it would make more sense that the owner
    #      of all connections closes them, or the next read detects the closed
    #      socket and does the right thing..)

    await conn.close()

    trace "Cleaned up client", addresses = ($client.remoteAddress).shortLog, conn

  self.clients[dir].add(client)

  self.closeFuts.trackFut(onClose())

  return conn

proc new*(
    T: typedesc[TcpTransport],
    flags: set[ServerFlags] = {},
    upgrade: Upgrade,
    connectionsTimeout = 10.minutes,
): T =
  let self = T(
    flags: flags,
    clientFlags:
      if ServerFlags.TcpNoDelay in flags:
        {SocketFlags.TcpNoDelay}
      else:
        default(set[SocketFlags]),
    upgrader: upgrade,
    networkReachability: NetworkReachability.Unknown,
    connectionsTimeout: connectionsTimeout,
  )
  procCall Transport(self).initialize()
  self

proc listen(
    self: TcpTransport, addrs: openArray[TransportAddress]
): LPResult[seq[MultiAddress]] =
  ## Servers created before a failure stay in `self.servers` for the caller to close.
  var supported: seq[MultiAddress]
  for ta in addrs:
    let server =
      try:
        createStreamServer(ta, flags = self.flags)
      except common.TransportError as e:
        return err("TcpTransport.start failed to listen on " & $ta & ". " & e.msg)
    self.servers &= server

    let localAddr = MultiAddress.init(server.sock.getLocalAddress()).valueOr:
      return err("TcpTransport.start got invalid local address. " & error)
    trace "Listening on", address = localAddr
    supported.add(localAddr)

  ok(supported)

proc connAddrs(transp: StreamTransport): LPResult[ConnAddrs] =
  let remote = transp.remoteAddress2().valueOr:
    return err("cannot read remote address. " & osErrorMsg(error))
  let local = transp.localAddress2().valueOr:
    return err("cannot read local address. " & osErrorMsg(error))

  ok ConnAddrs(observed: ?MultiAddress.init(remote), local: ?MultiAddress.init(local))

method start*(
    self: TcpTransport, addrs: seq[MultiAddress]
): Future[void] {.async: (raises: [LPError, transport.TransportError, CancelledError]).} =
  ## Start transport listening to the given addresses - for dial-only transports,
  ## start with an empty list

  if self.running:
    warn "TCP transport already started"
    return

  self.flags.incl(ServerFlags.ReusePort)

  let addrsTa = self.toTransportAddress(addrs).valueOrRaise(TransportStartError)
  let supported = self.listen(addrsTa).valueOr:
    await noCancel allFutures(self.servers.mapIt(it.closeWait()))
    reset(self.servers)
    raise error.toException(TcpTransportError)

  await procCall Transport(self).start(supported)

  trackCounter(TcpTransportTrackerName)
  info "TCP transport started", addresses = self.addrs

method stop*(self: TcpTransport): Future[void] {.async: (raises: []).} =
  self.stopping = true
  defer:
    self.stopping = false

  if self.running:
    # Reset the running flag
    await noCancel procCall Transport(self).stop()
    # Stop each server by closing the socket - this will cause all accept loops
    # to fail - since the running flag has been reset, it's also safe to close
    # all known clients since no more of them will be added
    await noCancel allFutures(
      self.servers.mapIt(it.closeWait()) &
        self.clients[Direction.In].mapIt(it.closeWait()) &
        self.clients[Direction.Out].mapIt(it.closeWait())
    )

    self.servers = @[]

    for acceptFut in self.acceptFuts:
      if acceptFut.completed():
        await acceptFut.value().closeWait()
    self.acceptFuts = @[]

    await noCancel allFutures(self.closeFuts)
    self.closeFuts = @[]

    if self.clients[Direction.In].len != 0 or self.clients[Direction.Out].len != 0:
      # Future updates could consider turning this warn into an assert since
      # it should never happen if the shutdown code is correct
      warn "Couldn't clean up clients",
        len = self.clients[Direction.In].len + self.clients[Direction.Out].len

    info "TCP transport stopped", addresses = self.addrs
    untrackCounter(TcpTransportTrackerName)
  else:
    # For legacy reasons, `stop` on a transpart that wasn't started is
    # expected to close outgoing connections created by the transport
    warn "TCP transport already stopped"

    doAssert self.clients[Direction.In].len == 0,
      "No incoming connections possible without start"
    await noCancel allFutures(self.clients[Direction.Out].mapIt(it.closeWait()))

    await noCancel allFutures(self.closeFuts)
    self.closeFuts = @[]

method accept*(
    self: TcpTransport
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  ## accept a new TCP connection, returning nil on non-fatal errors
  ##
  ## Raises an exception when the transport is broken and cannot be used for
  ## accepting further connections
  # TODO returning nil for non-fatal errors is problematic in that error
  #      information is lost and must be logged here instead of being
  #      available to the caller - further refactoring should propagate errors
  #      to the caller instead

  if not self.running:
    raise newTransportClosedError()

  if self.servers.len == 0:
    raise (ref TcpTransportError)(msg: "No listeners configured")
  elif self.acceptFuts.len == 0:
    # Holds futures representing ongoing accept calls on multiple servers.
    self.acceptFuts = self.servers.mapIt(it.accept())

  let
    finished =
      try:
        # Waits for any one of these futures to complete, indicating that a new connection has been accepted on one of the servers.
        await one(self.acceptFuts)
      except ValueError:
        raiseAssert "Accept futures should not be empty"
      except CancelledError as exc:
        self.acceptFuts.cancelSoon()
        raise exc
    index = self.acceptFuts.find(finished)

  # A new connection has been accepted. The corresponding server should immediately start accepting another connection.
  # Thus we replace the completed future with a new one by calling accept on the same server again.
  self.acceptFuts[index] = self.servers[index].accept()
  let transp =
    try:
      await finished
    except TransportTooManyError as exc:
      if self.descriptorWarnings.allowLog():
        warn "Connection acceptance limited by file descriptor exhaustion",
          err = exc.msg, errType = exc.name, transport = "tcp"
      return nil
    except TransportAbortedError as exc:
      debug "Transport connection aborted", err = exc.msg
      return nil
    except TransportUseClosedError as exc:
      raise newTransportClosedError(exc)
    except TransportOsError as exc:
      raise (ref TcpTransportError)(
        msg: "TransportOs error in accept:" & exc.msg, parent: exc
      )
    except common.TransportError as exc: # Needed for chronos 4.0.0 support
      raise (ref TcpTransportError)(
        msg: "TransportError in accept: " & exc.msg, parent: exc
      )
    except CancelledError as exc:
      self.acceptFuts.cancelSoon()
      raise exc

  if not self.running: # Stopped while waiting
    safeCloseWait(transp)
    raise newTransportClosedError()

  let addrs = transp.connAddrs().valueOr:
    # The connection had errors / was closed before `await` returned control
    safeCloseWait(transp)
    debug "Cannot read address", err = error
    return nil
  self.connHandler(
    transp, Opt.some(addrs.observed), Opt.some(addrs.local), Direction.In
  )

proc findAddressByFamily(
    addrs: openArray[MultiAddress], family: AddressFamily
): Opt[TransportAddress] =
  for addr in addrs:
    let transportAddress = initTAddress(addr).expect("self address is valid")
    if transportAddress.family == family:
      return Opt.some(transportAddress)

  Opt.none(TransportAddress)

method dial*(
    self: TcpTransport,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  ## dial a peer
  if self.stopping:
    raise newTransportClosedError()

  let ta = initTAddress(address).valueOr:
    raise (ref TcpTransportError)(
      msg:
        "TcpTransport.dial called with unsupported address " & $address & ". " & error
    )
  let local =
    if self.networkReachability == NetworkReachability.NotReachable:
      findAddressByFamily(self.addrs, ta.family)
    else:
      Opt.none(TransportAddress)

  trace "Transport connection started", peerId, address = $address
  let transp =
    try:
      await(
        if local.isSome():
          self.clientFlags.incl(SocketFlags.ReusePort)
          connect(ta, flags = self.clientFlags, localAddress = local.get())
        else:
          connect(ta, flags = self.clientFlags)
      )
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raise
        (ref TcpTransportError)(msg: "TcpTransport dial error: " & exc.msg, parent: exc)

  # If `stop` is called after `connect` but before `await` returns, we might
  # end up with a race condition where `stop` returns but not all connections
  # have been closed - we drop connections in this case in order not to leak
  # them
  if self.stopping:
    # Stopped while waiting for new connection
    safeCloseWait(transp)
    raise newTransportClosedError()

  let addrs = transp.connAddrs().valueOr:
    safeCloseWait(transp)
    raise (ref TcpTransportError)(msg: "TcpTransport.dial failed. " & error)

  self.connHandler(
    transp, Opt.some(addrs.observed), Opt.some(addrs.local), Direction.Out
  )

method handles*(t: TcpTransport, address: MultiAddress): bool {.raises: [].} =
  if procCall Transport(t).handles(address):
    if address.protocols.isOk:
      return TCP.match(address)
