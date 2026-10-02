# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[deques, sequtils]
import chronos, metrics
import ../../../switch
import ../../../wire
import client
from types import NetworkReachability, AutonatUnreachableError
import ../../../utils/heartbeat
import ../../../services/reachabilityobservers
import ../../../crypto/crypto

export reachabilityobservers

logScope:
  topics = "libp2p autonat"

declarePublicGauge(
  libp2p_autonat_reachability_confidence,
  "autonat reachability confidence",
  labels = ["reachability"],
)

type
  AutonatService* = ref object of Service
    reachabilityObservers*: ReachabilityObservers
    newConnectedPeerHandler: PeerEventHandler
    addressMapper: AddressMapper
    scheduleHandle: Future[void]
    networkReachability*: NetworkReachability
    confidence: Opt[float]
    answers: Deque[NetworkReachability]
    autonatClient: AutonatClient
    rng: Rng
    scheduleInterval: Opt[Duration]
    askNewConnectedPeers: bool
    numPeersToAsk: int
    maxQueueSize: int
    minConfidence: float
    dialTimeout: Duration
    enableAddressMapper: bool

  StatusAndConfidenceHandler* = proc(
    networkReachability: NetworkReachability, confidence: Opt[float]
  ): Future[void] {.gcsafe, async: (raises: [CancelledError]).}
    ## The handler of the replaced single-subscriber API. Use
    ## `ReachabilityHandler` instead.

proc new*(
    T: typedesc[AutonatService],
    autonatClient: AutonatClient,
    rng: Rng,
    scheduleInterval: Opt[Duration] = Opt.none(Duration),
    askNewConnectedPeers = true,
    numPeersToAsk: int = 5,
    maxQueueSize: int = 10,
    minConfidence: float = 0.3,
    dialTimeout = 30.seconds,
    enableAddressMapper = true,
): T =
  return T(
    reachabilityObservers: ReachabilityObservers.new(),
    scheduleInterval: scheduleInterval,
    networkReachability: Unknown,
    confidence: Opt.none(float),
    answers: initDeque[NetworkReachability](),
    autonatClient: autonatClient,
    rng: rng,
    askNewConnectedPeers: askNewConnectedPeers,
    numPeersToAsk: numPeersToAsk,
    maxQueueSize: maxQueueSize,
    minConfidence: minConfidence,
    dialTimeout: dialTimeout,
    enableAddressMapper: enableAddressMapper,
  )

proc hasEnoughIncomingSlots(switch: Switch): bool =
  # we leave some margin instead of comparing to 0 as a peer could connect to us while we are asking for the dial back
  return switch.connManager.availableSlots(In) >= 2

proc doesPeerHaveIncomingConn(switch: Switch, peerId: PeerId): bool =
  return switch.connManager.selectMuxer(peerId, In) != nil

proc handleAnswer(
    self: AutonatService, ans: NetworkReachability
): Future[bool] {.async: (raises: [CancelledError]).} =
  if ans == Unknown:
    return

  let oldNetworkReachability = self.networkReachability
  let oldConfidence = self.confidence

  if self.answers.len == self.maxQueueSize:
    self.answers.popFirst()
  self.answers.addLast(ans)

  self.networkReachability = Unknown
  self.confidence = Opt.none(float)
  const reachabilityPriority = [Reachable, NotReachable]
  for reachability in reachabilityPriority:
    let confidence = self.answers.countIt(it == reachability) / self.maxQueueSize
    libp2p_autonat_reachability_confidence.set(
      value = confidence, labelValues = [$reachability]
    )
    if self.confidence.isNone and confidence >= self.minConfidence:
      self.networkReachability = reachability
      self.confidence = Opt.some(confidence)

  if self.networkReachability != oldNetworkReachability:
    info "Network reachability changed",
      previous = oldNetworkReachability,
      current = self.networkReachability,
      confidence = self.confidence

  trace "Current status",
    currentStats = $self.networkReachability,
    confidence = $self.confidence,
    answers = self.answers

  # Return whether anything has changed
  return
    self.networkReachability != oldNetworkReachability or
    self.confidence != oldConfidence

proc askPeer(
    self: AutonatService, switch: Switch, peerId: PeerId
): Future[NetworkReachability] {.async: (raises: [CancelledError]).} =
  logScope:
    peerId = $peerId

  if doesPeerHaveIncomingConn(switch, peerId):
    return Unknown

  if not hasEnoughIncomingSlots(switch):
    trace "No incoming slots available, not asking peer",
      incomingSlotsAvailable = switch.connManager.availableSlots(In)
    return Unknown

  trace "Asking peer for reachability"
  let ans =
    try:
      discard await self.autonatClient.dialMe(switch, peerId).wait(self.dialTimeout)
      trace "dialMe answer is reachable"
      Reachable
    except AutonatUnreachableError as error:
      trace "dialMe answer is not reachable", err = error.msg
      NotReachable
    except AsyncTimeoutError as error:
      trace "dialMe timed out", err = error.msg
      Unknown
    except CancelledError as error:
      raise error
    except CatchableError as error:
      trace "dialMe unexpected error", err = error.msg
      Unknown
  let hasReachabilityOrConfidenceChanged = await self.handleAnswer(ans)
  if hasReachabilityOrConfidenceChanged:
    await self.reachabilityObservers.notify(self.networkReachability, self.confidence)
  await switch.peerInfo.update()
  return ans

proc askConnectedPeers(
    self: AutonatService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  trace "Asking peers for reachability"
  var peers = switch.connectedPeers(Direction.Out)
  self.rng.shuffle(peers)
  var answersFromPeers = 0
  var attempted, reachable, unreachable, unknown: int
  var outcome = "cancelled"
  defer:
    debug "Reachability check finished",
      outcome,
      peers = peers.len,
      attempted,
      reachable,
      unreachable,
      unknown,
      reachability = self.networkReachability,
      confidence = self.confidence
  for peer in peers:
    if answersFromPeers >= self.numPeersToAsk:
      break
    if not hasEnoughIncomingSlots(switch):
      trace "No incoming slots available, not asking peers",
        incomingSlotsAvailable = switch.connManager.availableSlots(In)
      break
    attempted.inc()
    case await askPeer(self, switch, peer)
    of Reachable:
      reachable.inc()
      answersFromPeers.inc()
    of NotReachable:
      unreachable.inc()
      answersFromPeers.inc()
    of Unknown:
      unknown.inc()
  outcome =
    if answersFromPeers >= self.numPeersToAsk: "completed" else: "insufficientAnswers"

proc schedule(
    service: AutonatService, switch: Switch, interval: Duration
) {.async: (raises: [CancelledError]).} =
  heartbeat "Scheduling AutonatService run", interval:
    await service.askConnectedPeers(switch)

proc addressMapper(
    self: AutonatService, addressManager: AddressManager, listenAddrs: seq[MultiAddress]
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  if self.networkReachability != NetworkReachability.Reachable:
    return listenAddrs

  var addrs = newSeq[MultiAddress]()
  for listenAddr in listenAddrs:
    var processedMA = listenAddr
    try:
      if not listenAddr.isPublicMA() and
          self.networkReachability == NetworkReachability.Reachable:
        processedMA = addressManager.externalAddrFor(listenAddr)
          # handle manual port forwarding
    except CatchableError as exc:
      debug "Error while handling address mapper", err = exc.msg
    addrs.add(processedMA)
  return addrs

proc configure(self: AutonatService, switch: Switch) =
  self.addressMapper = proc(
      listenAddrs: seq[MultiAddress]
  ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    return await addressMapper(self, switch.addressManager, listenAddrs)

  if self.askNewConnectedPeers:
    self.newConnectedPeerHandler = proc(
        peerId: PeerId, event: PeerEvent
    ): Future[void] {.async: (raises: [CancelledError]).} =
      discard askPeer(self, switch, peerId)

method start*(
    self: AutonatService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  self.configure(switch)
  if not self.newConnectedPeerHandler.isNil:
    switch.connManager.addPeerEventHandler(
      self.newConnectedPeerHandler, PeerEventKind.Joined
    )

  if self.enableAddressMapper:
    switch.addressManager.addMapper(self.addressMapper, AddrSource.Autonat)
    await switch.peerInfo.update()

  self.scheduleInterval.ifValue(interval):
    if self.scheduleHandle.isNil:
      self.scheduleHandle = schedule(self, switch, interval)

  info "AutoNAT service started"

method stop*(
    self: AutonatService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  info "Stopping AutonatService"
  if not isNil(self.scheduleHandle):
    self.scheduleHandle.cancelSoon()
    self.scheduleHandle = nil
  if not isNil(self.newConnectedPeerHandler):
    switch.connManager.removePeerEventHandler(
      self.newConnectedPeerHandler, PeerEventKind.Joined
    )
  if self.enableAddressMapper:
    switch.addressManager.removeMapper(self.addressMapper)
  await switch.peerInfo.update()

proc statusAndConfidenceHandler*(
    self: AutonatService, handler: StatusAndConfidenceHandler
) {.deprecated: "use reachabilityObservers.add; it appends, it does not replace".} =
  if handler.isNil():
    return

  discard self.reachabilityObservers.add(
    proc(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      await handler(networkReachability, confidence)
  )
