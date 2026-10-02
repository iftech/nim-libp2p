# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, chronicles, results
import
  ../../../switch,
  ../../../multiaddress,
  ../../../wire,
  ../../../services/reachabilityobservers,
  ../../../crypto/crypto,
  ../autonat/types,
  ./client,
  ./verifier

export reachabilityobservers

logScope:
  topics = "libp2p autonat"

# needed because nim 2.0 can't do proper type assertions
const noneDuration: Opt[Duration] = Opt.none(Duration)

type
  AutonatV2ServiceConfig* = object
    scheduleInterval: Opt[Duration]
    enableAddressMapper: bool
    enableDialableCandidates: bool

  AutonatV2Service* = ref object of Service
    reachabilityObservers*: ReachabilityObservers
    config*: AutonatV2ServiceConfig
    addressMapper: AddressMapper
    addressManager: AddressManager
    verifier: AutonatV2Verifier
    peerHandler: PeerEventHandler
    client*: AutonatV2Client
    rng: Rng

  StatusAndConfidenceHandler* = ReachabilityHandler
    ## The name of the replaced single-subscriber API; use `ReachabilityHandler`.

proc new*(
    T: typedesc[AutonatV2ServiceConfig],
    scheduleInterval: Opt[Duration] = noneDuration,
    enableAddressMapper = true,
    enableDialableCandidates = false,
): T =
  T(
    scheduleInterval: scheduleInterval,
    enableAddressMapper: enableAddressMapper,
    enableDialableCandidates: enableDialableCandidates,
  )

proc new*(
    T: typedesc[AutonatV2Service],
    rng: Rng,
    client: AutonatV2Client = AutonatV2Client.new(),
    config: AutonatV2ServiceConfig = AutonatV2ServiceConfig.new(),
): T =
  T(
    reachabilityObservers: ReachabilityObservers.new(),
    config: config,
    client: client,
    rng: rng,
  )

func networkReachability*(self: AutonatV2Service): NetworkReachability =
  ## The address manager's summary; `Unknown` before start.
  if self.addressManager.isNil():
    return NetworkReachability.Unknown
  self.addressManager.reachability()

proc addressMapper(
    self: AutonatV2Service, listenAddrs: seq[MultiAddress]
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  if not self.networkReachability().isReachable():
    return listenAddrs

  var addrs = newSeq[MultiAddress]()
  for listenAddr in listenAddrs:
    if listenAddr.isPublicMA():
      addrs.add(listenAddr)
    else:
      addrs.add(self.addressManager.externalAddrFor(listenAddr))
  addrs

proc configure(self: AutonatV2Service, switch: Switch) =
  self.addressManager = switch.addressManager
  self.verifier = AutonatV2Verifier.new(switch, self.client, self.rng)

  self.addressMapper = proc(
      listenAddrs: seq[MultiAddress]
  ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    return await addressMapper(self, listenAddrs)

method start*(
    self: AutonatV2Service, switch: Switch
) {.async: (raises: [CancelledError, LPError]).} =
  self.configure(switch)
  let manager = switch.addressManager
  self.config.scheduleInterval.ifValue(interval):
    manager.verifyInterval = interval
  manager.deriveIdentifyCandidates = self.config.enableDialableCandidates
  manager.onReachabilityChange = proc(
      reachability: NetworkReachability
  ) {.async: (raises: [CancelledError]).} =
    await self.reachabilityObservers.notify(reachability, Opt.none(float))

  if self.config.enableAddressMapper:
    manager.addMapper(self.addressMapper, AddrSource.Autonat)

  # resolve the candidates first: registering the verifier restarts the heartbeat
  await switch.peerInfo.update()
  manager.verifier = self.verifier

  # the first runs find no peer to ask; a new peer ends the Unknown state now
  self.peerHandler = proc(
      peerId: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    if manager.reachability() == NetworkReachability.Unknown:
      manager.triggerVerification()
  switch.addPeerEventHandler(self.peerHandler, PeerEventKind.Identified)

  info "AutoNAT v2 service started"

method stop*(
    self: AutonatV2Service, switch: Switch
) {.async: (raises: [CancelledError]).} =
  info "Stopping AutonatV2Service"

  let manager = switch.addressManager
  switch.removePeerEventHandler(self.peerHandler, PeerEventKind.Identified)
  manager.verifier = nil
  manager.onReachabilityChange = nil
  manager.deriveIdentifyCandidates = false
  if self.config.enableAddressMapper:
    manager.removeMapper(self.addressMapper)
  await switch.peerInfo.update()

proc setStatusAndConfidenceHandler*(
    self: AutonatV2Service, handler: StatusAndConfidenceHandler
) {.deprecated: "use reachabilityObservers.add; it appends, it does not replace".} =
  discard self.reachabilityObservers.add(handler)
