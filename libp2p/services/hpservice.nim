# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[algorithm, tables, sequtils]

import chronos, chronicles

import ../switch, ../wire, ../peerstore
import ../protocols/rendezvous
import ../services/[autorelayservice, reachabilityobservers]
import ../protocols/connectivity/relay/relay
import ../protocols/connectivity/autonat/service
import ../protocols/connectivity/dcutr/[client, server]

export reachabilityobservers

logScope:
  topics = "libp2p hole-punching"

type HPService* = ref object of Service
  newConnectedPeerHandler: PeerEventHandler
  onNewStatusHandler: ReachabilityHandler
  autoRelayService: AutoRelayService
  autonatService: AutonatService
  dcutr: Dcutr

proc new*(
    T: typedesc[HPService],
    autonatService: AutonatService,
    autoRelayService: AutoRelayService,
): T =
  return T(autonatService: autonatService, autoRelayService: autoRelayService)

func natAddrs(switch: Switch): seq[MultiAddress] =
  ## The addresses the peer should punch to, best proof first.
  let manager = switch.addressManager
  let confirmed = manager.confirmedAddrs()
  if confirmed.len > 0:
    return confirmed

  let observed = manager.mostObservedProtosAndPorts()
  if observed.len > 0:
    return observed

  # the announce set honors withAnnouncedAddresses over a per-listen-addr guess
  if switch.peerInfo.addrs.len > 0:
    return switch.peerInfo.addrs
  switch.peerInfo.listenAddrs.mapIt(manager.externalAddrFor(it))

proc directDialAddrs(switch: Switch, peerId: PeerId): seq[MultiAddress] =
  ## Live public addresses, highest confidence first, so a verified address is dialed first.
  let book = switch.peerStore[AddressBook]
  let live = book[peerId]
  book
    .entries(peerId)
    .filterIt(
      it.address in live and not it.address.isCircuitRelayMA() and
        it.address.isPublicMA()
    )
    .sortedByIt(-ord(it.confidence))
    .mapIt(it.address)

proc tryStartingDirectConn(
    self: HPService, switch: Switch, peerId: PeerId, connectTimeout: Duration
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Dials every live public address in one call; the dialer decides how many run at once.
  let addrs = switch.directDialAddrs(peerId)
  if addrs.len == 0:
    return false

  trace "Trying to create direct connection", peerId, addrs
  try:
    await switch.connect(peerId, addrs, forceDial = false, reuseConnection = false).wait(
      connectTimeout
    )
  except DialFailedError as e:
    debug "Failed to create direct connection", err = e.msg, peerId, addrs
    return false
  except AsyncTimeoutError as e:
    debug "Direct connection timed out", err = e.msg, peerId, addrs
    return false

  debug "Direct connection created", peerId
  true

proc closeRelayConn(relayedConn: RawConn) {.async: (raises: [CancelledError]).} =
  await sleepAsync(2000.milliseconds) # grace period before closing relayed connection
  await relayedConn.close()

proc newConnectedPeerHandler(
    self: HPService, switch: Switch, peerId: PeerId, event: PeerEvent
) {.async: (raises: [CancelledError]).} =
  try:
    # Get all connections to the peer. If there is at least one non-relayed connection, return.
    let connections = switch.connManager.getConnections()[peerId].mapIt(it.connection)
    if connections.anyIt(not isRelayed(it)):
      return
    let incomingRelays = connections.filterIt(it.transportDir == Direction.In)
    if incomingRelays.len == 0:
      return

    let relayedConn = incomingRelays[0]

    let dcutrClient = DcutrClient.new()
    if await self.tryStartingDirectConn(switch, peerId, dcutrClient.connectTimeout):
      await closeRelayConn(relayedConn)
      return

    await dcutrClient.startSync(switch, peerId, switch.natAddrs())
    await closeRelayConn(relayedConn)
  except CancelledError as err:
    raise err
  except CatchableError as err:
    debug "Hole punching failed during dcutr", err = err.msg

proc reachabilityObservers*(self: HPService): ReachabilityObservers =
  ## The observers of the AutoNAT v1 service that drives hole punching.
  self.autonatService.reachabilityObservers

proc configure(self: HPService, switch: Switch) {.raises: [LPError].} =
  self.newConnectedPeerHandler = proc(
      peerId: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    await newConnectedPeerHandler(self, switch, peerId, event)

  self.onNewStatusHandler = proc(
      networkReachability: NetworkReachability,
      confidence: Opt[float],
      dialBackAddr: Opt[MultiAddress],
  ) {.async: (raises: [CancelledError]).} =
    if networkReachability == NetworkReachability.NotReachable and
        not self.autoRelayService.isRunning():
      try:
        await self.autoRelayService.start(switch)
      except LPError as e:
        error "Unable to start auto-relay service", err = e.msg
    elif networkReachability == NetworkReachability.Reachable and
        self.autoRelayService.isRunning():
      await self.autoRelayService.stop(switch)

    # We do it here instead of in the AutonatService because this is useful only when hole punching.
    for t in switch.transports:
      t.networkReachability = networkReachability

method start*(
    self: HPService, switch: Switch
) {.async: (raises: [CancelledError, LPError]).} =
  if self.dcutr.isNil:
    let dcutr = Dcutr.new(switch)
    await dcutr.start()
    switch.tryMount(dcutr).onErrorRaise(LPError)
    self.dcutr = dcutr

  self.configure(switch)
  switch.connManager.addPeerEventHandler(
    self.newConnectedPeerHandler, PeerEventKind.Identified
  )

  discard self.reachabilityObservers.add(self.onNewStatusHandler)
  await self.autonatService.start(switch)
  info "Hole-punching service started"

method stop*(self: HPService, switch: Switch) {.async: (raises: [CancelledError]).} =
  info "Stopping hole-punching service"

  switch.connManager.removePeerEventHandler(
    self.newConnectedPeerHandler, PeerEventKind.Identified
  )
  discard self.reachabilityObservers.remove(self.onNewStatusHandler)
  await self.autonatService.stop(switch)
  if self.autoRelayService.isRunning():
    await self.autoRelayService.stop(switch)

  if not self.dcutr.isNil:
    await self.dcutr.stop()
    discard switch.unmount(self.dcutr)
    self.dcutr = nil
