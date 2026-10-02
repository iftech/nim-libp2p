# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, chronicles, times, tables, sequtils
import ../logging
import ../switch, ../protocols/connectivity/relay/[client, utils]

logScope:
  topics = "libp2p auto-relay"

type
  OnReservationHandler* = proc(addresses: seq[MultiAddress]) {.gcsafe, raises: [].}

  AutoRelayService* = ref object of Service
    running: bool
    runner: Future[void]
    client: RelayClient
    maxNumRelays: int # maximum number of relays we can reserve at the same time
    relayPeers: Table[PeerId, Future[void]]
    relayAddresses: Table[PeerId, seq[MultiAddress]]
    backingOff: Table[PeerId, Future[void]]
    peerAvailable: AsyncEvent
    onReservation: OnReservationHandler
    addressMapper: AddressMapper
    rng: Rng
    reservationWarnings: LogRateLimit
    lifetimeWarnings: LogRateLimit
    availabilityWarnings: LogRateLimit
    onIdentifiedHandler: PeerEventHandler
    onLeftHandler: PeerEventHandler

proc isRunning*(self: AutoRelayService): bool =
  return self.running

proc addressMapper(
    self: AutoRelayService, listenAddrs: seq[MultiAddress]
): Future[seq[MultiAddress]] {.async: (raises: []).} =
  ## The manager drops a relay address which a confirmed direct address replaces.
  return concat(toSeq(self.relayAddresses.values)) & listenAddrs

proc reserveAndUpdate(
    self: AutoRelayService, relayPid: PeerId, switch: Switch
) {.async: (raises: [CatchableError]).} =
  # CatchableError used to simplify raised errors here, as there could be 
  # many different errors raised but caller don't really care what is cause of error
  while self.running:
    let
      rsvp = await self.client.reserve(relayPid).wait(chronos.seconds(5))
      relayedAddr = rsvp.addrs.mapIt(MultiAddress.init($it & "/p2p-circuit").tryGet())
      ttl = rsvp.expire.int64 - times.getTime().toUnix
    if ttl <= 60:
      if self.lifetimeWarnings.allowLog():
        warn "Relay reservation lifetime too short", relayPid, ttl, minimumTtl = 61
      # A reservation under a minute is basically useless
      break
    if relayPid notin self.relayAddresses or self.relayAddresses[relayPid] != relayedAddr:
      let hadAddresses = self.relayAddresses.values.toSeq().anyIt(it.len > 0)
      self.relayAddresses[relayPid] = relayedAddr
      await switch.peerInfo.update()
      debug "Updated relay addresses", relayPid, relayedAddr
      if not hadAddresses and relayedAddr.len > 0:
        info "Relay connectivity established", relayPid, addresses = relayedAddr.len
      if self.running and not self.onReservation.isNil():
        self.onReservation(concat(toSeq(self.relayAddresses.values)))
    await sleepAsync chronos.seconds(ttl - 30)

proc configure(self: AutoRelayService, switch: Switch) =
  self.addressMapper = proc(
      listenAddrs: seq[MultiAddress]
  ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    return await addressMapper(self, listenAddrs)

  proc handlePeerIdentified(
      peerId: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    trace "Peer Identified", peerId
    if self.relayPeers.len < self.maxNumRelays:
      self.peerAvailable.fire()

  proc handlePeerLeft(
      peerId: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    trace "Peer Left", peerId
    self.relayPeers.withValue(peerId, future):
      future[].cancelSoon()

  self.onIdentifiedHandler = handlePeerIdentified
  self.onLeftHandler = handlePeerLeft

proc manageBackedOff(
    self: AutoRelayService, pid: PeerId
) {.async: (raises: [CancelledError]).} =
  await sleepAsync(chronos.seconds(5))
  self.backingOff.del(pid)
  self.peerAvailable.fire()

proc innerRun(
    self: AutoRelayService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  while self.running:
    let addressCount = self.relayAddresses.len
    for (k, future) in toSeq(self.relayPeers.pairs()):
      if future.finished():
        let
          hadReservation = self.relayAddresses.hasKey(k)
          hadAddresses = self.relayAddresses.values.toSeq().anyIt(it.len > 0)
        self.relayPeers.del(k)
        self.relayAddresses.del(k)
        let remainingRelays = self.relayAddresses.len
        if future.failed() and self.reservationWarnings.allowLog():
          let exc = future.error()
          warn "Relay reservation task failed",
            err = exc.msg,
            errType = exc.name,
            relayPid = k,
            hadReservation,
            remainingRelays
        if self.running and hadAddresses and
            not self.relayAddresses.values.toSeq().anyIt(it.len > 0) and
            self.availabilityWarnings.allowLog():
          warn "Last usable relay reservation lost", relayPid = k, remainingRelays
        if self.running and not self.onReservation.isNil():
          self.onReservation(concat(toSeq(self.relayAddresses.values)))
        # Avoid immediately retrying a failed reservation.
        self.backingOff[k] = self.manageBackedOff(k)
    if self.relayAddresses.len != addressCount:
      await switch.peerInfo.update()

    # Get all connected relayPeers
    self.peerAvailable.clear()
    var connectedPeers = switch.connectedPeers(Direction.Out)
    connectedPeers.keepItIf(
      RelayV2HopCodec in switch.peerStore[ProtoBook][it] and it notin self.relayPeers and
        it notin self.backingOff
    )
    self.rng.shuffle(connectedPeers)

    for relayPid in connectedPeers:
      if self.relayPeers.len() >= self.maxNumRelays:
        break
      self.relayPeers[relayPid] = self.reserveAndUpdate(relayPid, switch)

    if self.relayPeers.len() > 0:
      try:
        await one(toSeq(self.relayPeers.values())) or self.peerAvailable.wait()
      except ValueError:
        raiseAssert "checked with relayPeers.len()"
    else:
      await self.peerAvailable.wait()

method start*(
    self: AutoRelayService, switch: Switch
) {.async: (raises: [CancelledError, LPError]).} =
  if self.running:
    return
  self.configure(switch)
  switch.addPeerEventHandler(self.onIdentifiedHandler, Identified)
  switch.addPeerEventHandler(self.onLeftHandler, Left)
  self.running = true
  switch.addressManager.addMapper(self.addressMapper, AddrSource.Circuit)
  await switch.peerInfo.update()
  self.runner = self.innerRun(switch)
  info "Auto-relay service started", maxRelays = self.maxNumRelays

method stop*(
    self: AutoRelayService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  if not self.running:
    return

  info "Stopping auto-relay service"

  self.running = false
  await noCancel self.runner.cancelAndWait()
  await noCancel (toSeq(self.relayPeers.values) & toSeq(self.backingOff.values)).cancelAndWait()
  self.relayPeers.clear()
  self.relayAddresses.clear()
  self.backingOff.clear()
  switch.removePeerEventHandler(self.onIdentifiedHandler, Identified)
  switch.removePeerEventHandler(self.onLeftHandler, Left)
  self.onIdentifiedHandler = nil
  self.onLeftHandler = nil
  switch.addressManager.removeMapper(self.addressMapper)
  await switch.peerInfo.update()

proc getAddresses*(self: AutoRelayService): seq[MultiAddress] =
  concat(toSeq(self.relayAddresses.values))

proc new*(
    T: typedesc[AutoRelayService],
    maxNumRelays: int,
    client: RelayClient,
    onReservation: OnReservationHandler,
    rng: Rng,
): T =
  T(
    maxNumRelays: maxNumRelays,
    client: client,
    onReservation: onReservation,
    peerAvailable: newAsyncEvent(),
    rng: rng,
  )
