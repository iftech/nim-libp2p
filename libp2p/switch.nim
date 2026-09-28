# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The switch is the core of libp2p, which brings together the
## transports, the connection manager, the upgrader and other
## parts to allow programs to use libp2p

{.push raises: [].}

import std/[options, tables, sequtils, sets]
import chronos, chronicles, metrics

import
  stream/connection,
  transports/transport,
  upgrademngrs/upgrade,
  multistream,
  multiaddress,
  protocols/protocol,
  protocols/identify,
  peerinfo,
  connmanager,
  upgrademngrs/muxedupgrade,
  nameresolving/nameresolver,
  peerid,
  peerstore,
  errors,
  results,
  dialer,
  address_manager,
  observedaddrmanager,
  utils/future,
  crypto/rng

export connmanager, upgrade, dialer, peerstore, address_manager, observedaddrmanager

logScope:
  topics = "libp2p switch"

#TODO: General note - use a finite state machine to manage the different
# steps of connections establishing and upgrading. This makes everything
# more robust and less prone to ordering attacks - i.e. muxing can come if
# and only if the channel has been secured (i.e. if a secure manager has been
# previously provided)

const
  ConcurrentUpgrades* = 32
  MaxRejectedConnectionCloses = ConcurrentUpgrades
  UpgradeTimeout* = 30.seconds
  AcceptRetryDelay* = 100.millis

# a Switch built field by field, as TorSwitch and SwitchStub do, must copy it
const MissingAddressManager = "switch has no AddressManager"

type
  Switch* = ref object of Dial
    peerInfo*: PeerInfo
    connManager*: ConnManager
    transports*: seq[Transport]
    muxedUpgrade*: MuxedUpgrade
    ms*: MultistreamSelect
    acceptFuts: seq[Future[void]]
    upgradeFuts: seq[Future[void]]
    rejectedConnCloseFuts: seq[Future[void]]
    dialer*: Dialer
    peerStore*: PeerStore
    nameResolver*: NameResolver
    addressManager*: AddressManager
    started: bool
    stopping: bool
    services*: seq[Service]
    rng*: Rng

  UpgradeError* = object of LPError

  ServiceSetupError* = object of LPError

  Service* = ref object of RootObj
    ## Service is internal component of Switch. Service is automatically started and stopped
    ## when the Switch starts and stops.

{.push hint[XCannotRaiseY]: off.}
  # Base setup keeps `raises: [ServiceSetupError]` to match overrides.
method setup*(
    self: Service, switch: Switch
) {.base, gcsafe, raises: [ServiceSetupError].} =
  raiseAssert "[Service.setup] abstract method not implemented!"

{.pop.}

method start*(
    self: Service, switch: Switch
) {.base, async: (raises: [CancelledError]).} =
  raiseAssert "[Service.start] abstract method not implemented!"

method stop*(
    self: Service, switch: Switch
) {.base, async: (raises: [CancelledError]).} =
  raiseAssert "[Service.stop] abstract method not implemented!"

proc observedAddrManager*(
    s: Switch
): AddressManager {.deprecated: "use switch.addressManager".} =
  s.addressManager

proc addConnEventHandler*(s: Switch, handler: ConnEventHandler, kind: ConnEventKind) =
  ## Adds a ConnEventHandler, which will be triggered when
  ## a connection to a peer is created or dropped.
  ## There may be multiple connections per peer.
  ##
  ## The handler should not raise.
  s.connManager.addConnEventHandler(handler, kind)

proc removeConnEventHandler*(
    s: Switch, handler: ConnEventHandler, kind: ConnEventKind
) =
  s.connManager.removeConnEventHandler(handler, kind)

proc addPeerEventHandler*(s: Switch, handler: PeerEventHandler, kind: PeerEventKind) =
  ## Adds a PeerEventHandler, which will be triggered when
  ## a peer connects or disconnects from us.
  ##
  ## The handler should not raise.
  s.connManager.addPeerEventHandler(handler, kind)

proc removePeerEventHandler*(
    s: Switch, handler: PeerEventHandler, kind: PeerEventKind
) =
  s.connManager.removePeerEventHandler(handler, kind)

method addTransport*(s: Switch, t: Transport) =
  s.transports &= t
  s.dialer.addTransport(t)

proc connectedPeers*(s: Switch, dir: Direction): seq[PeerId] =
  s.connManager.connectedPeers(dir)

proc connectedPeers*(s: Switch): seq[PeerId] =
  ## Peers with at least one connection, in either direction.
  s.connManager.connectedPeers()

proc isConnected*(s: Switch, peerId: PeerId): bool =
  ## returns true if the peer has one or more
  ## associated connections
  ##

  peerId in s.connManager

proc disconnect*(s: Switch, peerId: PeerId) {.async: (raises: [CancelledError]).} =
  ## Disconnect from a peer, waiting for the connection(s) to be dropped
  await s.connManager.dropPeer(peerId)

method connect*(
    s: Switch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    forceDial = false,
    reuseConnection = true,
    dir = Direction.Out,
): Future[void] {.async: (raises: [DialFailedError, CancelledError], raw: true).} =
  ## Connects to a peer without opening a stream to it

  s.dialer.connect(peerId, addrs, forceDial, reuseConnection, dir)

method connect*(
    s: Switch, address: MultiAddress, allowUnknownPeerId = false
): Future[PeerId] {.async: (raises: [DialFailedError, CancelledError], raw: true).} =
  ## Connects to a peer and retrieve its PeerId
  ##
  ## If the P2P part is missing from the MA and `allowUnknownPeerId` is set
  ## to true, this will discover the PeerId while connecting. This exposes
  ## you to MiTM attacks, so it shouldn't be used without care!

  s.dialer.connect(address, allowUnknownPeerId)

method dial*(
    s: Switch, peerId: PeerId, protos: seq[string]
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError], raw: true).} =
  ## Open a stream to a connected peer with the specified `protos`

  s.dialer.dial(peerId, protos)

proc dial*(
    s: Switch, peerId: PeerId, proto: string
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError], raw: true).} =
  ## Open a stream to a connected peer with the specified `proto`

  dial(s, peerId, @[proto])

method dial*(
    s: Switch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError], raw: true).} =
  ## Connected to a peer and open a stream
  ## with the specified `protos`

  s.dialer.dial(peerId, addrs, protos, forceDial)

proc dial*(
    s: Switch, peerId: PeerId, addrs: seq[MultiAddress], proto: string
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError], raw: true).} =
  ## Connected to a peer and open a stream
  ## with the specified `proto`

  dial(s, peerId, addrs, @[proto])

proc add*(
    s: Switch, service: Service
) {.
    raises: [ServiceSetupError],
    deprecated: "externally created services should not be added to Switch"
.} =
  if service.isNil:
    return

  s.services.add(service)
  service.setup(s)

proc mount*[T: LPProtocol](
    s: Switch, proto: T, matcher: Matcher = nil
) {.gcsafe, raises: [LPError].} =
  ## mount a protocol to the switch

  if proto.handler.isNil:
    raise newException(LPError, "Protocol has to define a handle method or proc")

  if proto.codec.len == 0:
    raise newException(LPError, "Protocol has to define a codec string")

  if s.started and not proto.started:
    raise newException(
      LPError, "Protocol needs to be started when mounting to started Switch"
    )

  s.ms.addHandler(proto, matcher)
  s.peerInfo.protocols.add(proto.codec)
  s.peerInfo.notifyObservers()

proc upgrader(
    switch: Switch, trans: Transport, conn: RawConn
) {.async: (raises: [CancelledError, UpgradeError]).} =
  try:
    let muxed = await trans.upgrade(conn, Opt.none(PeerId))
    (await switch.connManager.storeMuxer(muxed)).onErrorRaise(UpgradeError)
    await switch.peerStore.identify(muxed, conn.transportDir)
    await switch.connManager.triggerPeerEvents(
      muxed.connection.peerId,
      PeerEvent(kind: PeerEventKind.Identified, initiator: false),
    )
  except CancelledError as e:
    raise e
  except CatchableError as e:
    raise newException(UpgradeError, "catchable error upgrader: " & e.msg, e)

proc upgradeMonitor(
    switch: Switch, trans: Transport, conn: RawConn, upgrades: AsyncSemaphore
) {.async: (raises: []).} =
  var semAcquired = false
  var upgradeSuccessful = false
  let deadlineFut = sleepAsync(UpgradeTimeout)
  try:
    await upgrades.acquire().wait(deadlineFut)
    semAcquired = true
    await switch.upgrader(trans, conn).wait(deadlineFut)
    trace "Incoming connection upgrade completed", conn
    upgradeSuccessful = true
  except CancelledError:
    trace "Incoming connection upgrade canceled", conn
  except AsyncTimeoutError:
    trace "Incoming connection upgrade timed out", conn
    libp2p_failed_upgrades_incoming.inc()
  except UpgradeError as e:
    trace "Incoming connection upgrade failed", err = e.msg, conn
    libp2p_failed_upgrades_incoming.inc()
  finally:
    deadlineFut.cancelSoon()
    if (not upgradeSuccessful) and (not isNil(conn)):
      await conn.close()
    if semAcquired:
      try:
        upgrades.release()
      except AsyncSemaphoreError:
        raiseAssert "semaphore released without acquire"

proc accept(s: Switch, transport: Transport) {.async: (raises: []).} =
  ## switch accept loop, ran for every transport
  ##
  let upgrades = newAsyncSemaphore(ConcurrentUpgrades)

  info "Transport connection acceptance started", addresses = transport.addrs

  while transport.running:
    var conn: RawConn
    try:
      conn =
        try:
          await transport.accept()
        except CancelledError as exc:
          raise exc
        except CatchableError as exc:
          raise
            newException(CatchableError, "failed to accept connection: " & exc.msg, exc)
      if isNil(conn):
        # A nil connection means that we might have hit a
        # file-handle limit (or another non-fatal error),
        # we can get one on the next try
        trace "Transport connection acceptance returned no connection",
          addresses = transport.addrs
        await sleepAsync(AcceptRetryDelay)
        continue

      let slot = s.connManager.tryGetIncomingSlot().valueOr:
        debug "Incoming connection limit reached", conn
        s.rejectedConnCloseFuts.trackFut(conn.close())
        s.connManager.triggerTrim()
        if s.rejectedConnCloseFuts.len >= MaxRejectedConnectionCloses:
          discard await one(s.rejectedConnCloseFuts)
        continue

      slot.trackConnection(conn)

      # set the direction of this bottom level transport
      # in order to be able to consume this information in gossipsub if required
      # gossipsub gives priority to connections we make
      conn.transportDir = Direction.In

      trace "Transport connection accepted", conn
      s.upgradeFuts.trackFut(s.upgradeMonitor(transport, conn, upgrades))
    except CancelledError:
      return
    except CatchableError as exc:
      error "Accept loop stopped", err = exc.msg, errType = exc.name
      if not isNil(conn):
        await conn.close()
      return

when defined(libp2p_testing):
  proc acceptFuts*(s: Switch): seq[Future[void]] =
    s.acceptFuts

proc isStopping*(s: Switch): bool =
  ## True from the beginning of shutdown until the next start.
  s.stopping

proc stop*(s: Switch) {.async: (raises: [CancelledError]).} =
  ## Stop listening on every transport, and
  ## close every active connections

  info "Stopping switch"

  s.started = false
  s.stopping = true

  try:
    # Stop accepting incoming connections
    await s.acceptFuts.cancelAndWait().wait(1.seconds)
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    warn "Accept loop cancellation failed",
      err = exc.msg,
      errType = exc.name,
      pendingAccepts = s.acceptFuts.countIt(not it.finished())

  await s.upgradeFuts.cancelAndWait()
  s.upgradeFuts = @[]

  await noCancel allFutures(s.rejectedConnCloseFuts)
  s.rejectedConnCloseFuts = @[]

  for service in s.services:
    await service.stop(s)

  # Drain incoming work and services before protocols, keeping established connections.
  await s.ms.stop()

  # close and cleanup all connections
  await s.connManager.stop()

  for transp in s.transports:
    try:
      await transp.stop()
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      warn "Transport cleanup failed", err = exc.msg

  # stopped last, after every component which can still feed an address
  doAssert not s.addressManager.isNil(), MissingAddressManager
  s.addressManager.stop()

  s.peerStore.close()

  info "Switch stopped"

proc start*(s: Switch) {.async: (raises: [CancelledError, LPError]).} =
  ## Start listening on every transport
  if s.started:
    warn "Switch has already been started"
    return

  info "Starting switch for peer", peerInfo = s.peerInfo
  s.stopping = false

  if not s.connManager.isRunning():
    s.connManager.start()

  # started first, so that it owns the mapper chain before any service adds one
  doAssert not s.addressManager.isNil(), MissingAddressManager
  s.addressManager.setPeerInfo(s.peerInfo)
  s.addressManager.start()

  # start services and transports without await to prevent any
  # issues when one needs another to start first.
  var startFuts: seq[Future[void]]

  for service in s.services:
    startFuts.add(service.start(s))

  for t in s.transports:
    let addrs = s.peerInfo.listenAddrs.filterIt(t.handles(it))
    s.peerInfo.listenAddrs.keepItIf(it notin addrs)
    startFuts.add(t.start(addrs))

  await allFutures(startFuts)

  for fut in startFuts:
    if fut.failed:
      await s.stop()
      raise newException(
        LPError, "starting services and transports failed: " & $fut.error.msg, fut.error
      )

  for t in s.transports:
    s.acceptFuts.add(s.accept(t))
    s.peerInfo.listenAddrs &= t.addrs

  await s.peerInfo.update()
  await s.ms.start()

  s.started = true

  s.peerStore.startAddressPruning()

  info "Libp2p node started",
    peerId = s.peerInfo.peerId,
    listenAddresses = s.peerInfo.listenAddrs,
    announcedAddresses = s.peerInfo.addrs,
    protocols = s.peerInfo.protocols,
    transports = s.transports.len,
    services = s.services.len
