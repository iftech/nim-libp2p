# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[tables, sequtils]

import chronos, chronicles

import ../switch, ../wire
import ../protocols/rendezvous
import ../services/[autorelayservice, reachabilityobservers]
import ../protocols/connectivity/relay/relay
import ../protocols/connectivity/autonat/service
import ../protocols/connectivity/dcutr/[client, server]
import ../multicodec

export reachabilityobservers

logScope:
  topics = "libp2p hole-punching"

type HPService* = ref object of Service
  newConnectedPeerHandler: PeerEventHandler
  onNewStatusHandler: ReachabilityHandler
  autoRelayService: AutoRelayService
  autonatService: AutonatService

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

proc tryStartingDirectConn(
    self: HPService, switch: Switch, peerId: PeerId
): Future[bool] {.async: (raises: [CancelledError]).} =
  proc tryConnect(
      address: MultiAddress
  ): Future[bool] {.async: (raises: [DialFailedError, CancelledError]).} =
    trace "Trying to create direct connection", peerId, address
    await switch.connect(peerId, @[address], true, false)
    debug "Direct connection created", peerId, address
    return true

  for address in switch.peerStore[AddressBook][peerId]:
    try:
      let isRelayed = address.contains(multiCodec("p2p-circuit"))
      if not isRelayed.get(false) and address.isPublicMA():
        return await tryConnect(address)
    except CancelledError as err:
      raise err
    except CatchableError as err:
      debug "Failed to create direct connection", err = err.msg, peerId, address
      continue
  return false

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

    if await self.tryStartingDirectConn(switch, peerId):
      await closeRelayConn(relayedConn)
      return

    let dcutrClient = DcutrClient.new()
    await dcutrClient.startSync(switch, peerId, switch.natAddrs())
    await closeRelayConn(relayedConn)
  except CancelledError as err:
    raise err
  except CatchableError as err:
    debug "Hole punching failed during dcutr", err = err.msg

proc reachabilityObservers*(self: HPService): ReachabilityObservers =
  ## The observers of the AutoNAT v1 service that drives hole punching.
  self.autonatService.reachabilityObservers

method setup*(self: HPService, switch: Switch) {.raises: [ServiceSetupError].} =
  self.autonatService.setup(switch)
  self.autoRelayService.setup(switch)

  switch.tryMount(Dcutr.new(switch)).isOkOr:
    raise newException(
      ServiceSetupError, "HPService Failed to mount Dcutr. Reason: " & error
    )

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
      await self.autoRelayService.start(switch)
    elif networkReachability == NetworkReachability.Reachable and
        self.autoRelayService.isRunning():
      await self.autoRelayService.stop(switch)

    # We do it here instead of in the AutonatService because this is useful only when hole punching.
    for t in switch.transports:
      t.networkReachability = networkReachability

method start*(self: HPService, switch: Switch) {.async: (raises: [CancelledError]).} =
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
