# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The `AddressManager` owns the addresses a node announces: one candidate per
## address, and the only `AddressMapper` the local `PeerInfo` runs. The wildcard
## resolver, the NAT port mapper, AutoNAT, AutoRelay and the explicit announce
## list all feed it.

{.push raises: [].}

import std/[sequtils, tables]
import chronos, chronos/transports/[osnet, ipnet]
import multiaddress, multicodec, peerid, peerinfo, wire, utils/[future, heartbeat]
import protocols/connectivity/autonat/types

export NetworkReachability

logScope:
  topics = "libp2p address-manager"

const
  DefaultObservedAddrMaxSize* = 10
  DefaultObservedAddrMinCount* = 3
  DefaultVerifyInterval* = 5.minutes
  DefaultVerifyTimeout* = 2.minutes
  RefutedGuessRuns = 12
    ## The runs a refuted guess stays out. A wrong refutation heals after them.

type
  NetworkInterfaceProvider* =
    proc(addrFamily: AddressFamily): seq[InterfaceAddress] {.gcsafe, raises: [].}

  AddrSource* {.pure.} = enum
    Autonat
    Identify ## guessed from the addresses which identify peers observed
    Upnp
    NatPmp
    PortMapped ## a port mapper answered and did not report which protocol it used
    ExplicitIp
    Circuit
    Listen
    Announced

  AddrState* {.pure.} = enum
    Unverified
    Confirmed
    Unreachable

  AddrCandidate* = object
    address*: MultiAddress
    sources*: set[AddrSource]
    state*: AddrState

  Verifier* = ref object of RootObj
    ## Tells the manager whether a remote peer reaches one candidate.

  ReachabilityChangeHandler* = proc(reachability: NetworkReachability): Future[void] {.
    gcsafe, async: (raises: [CancelledError])
  .}

  AddressManagerConfig* = object
    maxSize*: int = DefaultObservedAddrMaxSize
    minCount*: int = DefaultObservedAddrMinCount ## The peers which must agree.
    verifyInterval*: Duration = DefaultVerifyInterval ## The time between two runs.
    verifyTimeout*: Duration = DefaultVerifyTimeout
      ## The time one run gets; it keeps the verdicts it already collected.

  SourcedMapper = object
    mapper: AddressMapper
    source: AddrSource

  RefutedGuess = object
    address: MultiAddress
    runsLeft: int

  Observation = object
    observer: PeerId
    address: MultiAddress

  AddressManager* = ref object of RootObj
    observations: seq[Observation]
    candidates: OrderedTable[MultiAddress, AddrCandidate]
    mappers: seq[SourcedMapper]
    chainAddrs: Table[MultiAddress, set[AddrSource]]
    peerInfo: PeerInfo
    addressMapper: AddressMapper
    networkInterfaceProvider: NetworkInterfaceProvider
    verifier: Verifier
    verifyInterval: Duration
    verifyTimeout: Duration
    verifyFut: Future[void]
    reachabilityNotifyTail: Future[void].Raising([])
    reachabilityNotifyFuts: seq[Future[void].Raising([])]
    onReachabilityChange: ReachabilityChangeHandler
    notifiedReachability: NetworkReachability
    deriveIdentify: bool
    verifying: bool
    refutedGuesses: seq[RefutedGuess]
    maxSize: int
    minCount: int
    started: bool

method verify*(
    self: Verifier, address: MultiAddress
): Future[Opt[AddrState]] {.base, async: (raises: [CancelledError]).} =
  ## The state a remote peer proves; `none` keeps the current one and concludes nothing.
  Opt.none(AddrState)

func isStarted*(self: AddressManager): bool =
  self.started

proc isObservableIp(ip: IpAddress): bool =
  ## Loopback and private stay allowed: a peer on the same host or the same LAN
  ## does reach us there, and `PeerAddressPolicy` decides what is announced.
  case ip.family
  of IpAddressFamily.IPv4:
    # 224.0.0.0/4 is multicast, and everything above it is reserved
    ip.address_v4 != AnyAddress.address_v4 and ip.address_v4[0] < 224'u8
  of IpAddressFamily.IPv6:
    # ff00::/8 is multicast
    ip.address_v6 != AnyAddress6.address_v6 and ip.address_v6[0] != 0xff'u8

proc isRelayed(ma: MultiAddress): bool =
  ma.contains(multiCodec("p2p-circuit")).get(false)

proc isObservableAddr(ma: MultiAddress): bool =
  if not (ma.hasIp() and ma.hasTransport()) or ma.isRelayed():
    return false
  let ip = ma.getIp().valueOr:
    return false
  ip.isObservableIp()

proc addObservation*(
    self: AddressManager, observer: PeerId, observedAddr: MultiAddress
): bool =
  ## Records the address `observer` reports for us, replacing its previous report and evicting the oldest peer observation past `maxSize`.
  if not self.started:
    return false

  # a remote peer picks what it reports: junk would only evict a useful entry
  if not observedAddr.isObservableAddr():
    return false

  self.observations.keepItIf(it.observer != observer)
  if self.observations.len >= self.maxSize:
    self.observations.delete(0)
  self.observations.add(Observation(observer: observer, address: observedAddr))
  true

func observedAddrs(self: AddressManager): seq[MultiAddress] =
  ## One address per peer, so a count over them counts the peers which agree.
  self.observations.mapIt(it.address)

func firstProtoCode(ma: MultiAddress): MaResult[MultiCodec] =
  ma[0].flatMap(protoCode)

func mostObserved(
    self: AddressManager, observations: seq[MultiAddress], code: MultiCodec
): Opt[MultiAddress] =
  var countTable = toCountTable(observations)
  countTable.sort()
  for ma, count in countTable.pairs:
    let maCode = ma.firstProtoCode().valueOr:
      continue
    if maCode == code and count >= self.minCount:
      return Opt.some(ma)
  Opt.none(MultiAddress)

func mostObservedIp(self: AddressManager, code: MultiCodec): Opt[MultiAddress] =
  var ips: seq[MultiAddress]
  for observation in self.observations:
    let ip = observation.address[0].valueOr:
      continue
    ips.add(ip)
  self.mostObserved(ips, code)

func mostObservedProtosAndPorts*(self: AddressManager): seq[MultiAddress] =
  ## The most observed IP4/Port and IP6/Port addresses, empty below `minCount` peers.
  let observed = self.observedAddrs()
  var res: seq[MultiAddress]
  self.mostObserved(observed, multiCodec("ip4")).ifValue(ip4):
    res.add(ip4)
  self.mostObserved(observed, multiCodec("ip6")).ifValue(ip6):
    res.add(ip6)
  res

func externalAddrFor*(self: AddressManager, listenAddr: MultiAddress): MultiAddress =
  ## Replaces the IP of a local listen address by the most observed IP of the
  ## same protocol, keeping the rest. Returns `listenAddr` while no IP of that
  ## protocol reaches `minCount`.
  let
    rest = listenAddr[1 ..^ 1].valueOr:
      return listenAddr
    code = listenAddr.firstProtoCode().valueOr:
      return listenAddr

  let observed = self.mostObservedIp(code).valueOr:
    return listenAddr

  concat(observed, rest).valueOr:
    listenAddr

func getMostObservedProtosAndPorts*(
    self: AddressManager
): seq[MultiAddress] {.deprecated: "use mostObservedProtosAndPorts".} =
  self.mostObservedProtosAndPorts()

func guessDialableAddr*(
    self: AddressManager, ma: MultiAddress
): MultiAddress {.deprecated: "use externalAddrFor".} =
  self.externalAddrFor(ma)

proc addSources(
    self: AddressManager, address: MultiAddress, sources: set[AddrSource]
): bool {.discardable.} =
  let
    isNew = address notin self.candidates
    fresh = AddrCandidate(address: address, state: AddrState.Unverified)
  self.candidates.mgetOrPut(address, fresh).sources.incl(sources)
  isNew

proc add*(
    self: AddressManager, address: MultiAddress, source: AddrSource
): bool {.discardable.} =
  ## Adds a candidate, or adds `source` to the producers of the one already under
  ## `address`, keeping the state a verifier assigned. True for a new candidate.
  self.addSources(address, {source})

proc update*(
    self: AddressManager, address: MultiAddress, state: AddrState
): bool {.discardable.} =
  if address notin self.candidates:
    return false
  self.candidates.mgetOrPut(address, AddrCandidate()).state = state
  true

proc remove*(self: AddressManager, address: MultiAddress): bool {.discardable.} =
  if address notin self.candidates:
    return false
  self.candidates.del(address)
  true

func candidates*(self: AddressManager): seq[AddrCandidate] =
  toSeq(self.candidates.values)

func confirmedAddrs*(self: AddressManager): seq[MultiAddress] =
  ## The addresses a verifier confirmed. Empty while no verifier runs.
  toSeq(self.candidates.values).filterIt(it.state == AddrState.Confirmed).mapIt(
    it.address
  )

func refutedReachability(self: AddressManager): NetworkReachability =
  ## A refuted guess is no candidate any more, and it still proves a failed dial-back.
  if self.refutedGuesses.len > 0:
    NetworkReachability.NotReachable
  else:
    NetworkReachability.Unknown

func reachability*(self: AddressManager): NetworkReachability =
  ## Read-only summary of the per-address states: any Confirmed wins, else any Unreachable.
  var summary = self.refutedReachability()
  for candidate in self.candidates.values:
    case candidate.state
    of AddrState.Confirmed:
      return NetworkReachability.Reachable
    of AddrState.Unreachable:
      summary = NetworkReachability.NotReachable
    of AddrState.Unverified:
      discard
  summary

proc `onReachabilityChange=`*(
    self: AddressManager, handler: ReachabilityChangeHandler
) =
  ## Called from the verification heartbeat when the `reachability` summary changed; one slot.
  self.onReachabilityChange = handler

proc `deriveIdentifyCandidates=`*(self: AddressManager, enabled: bool) =
  ## Each verification run then turns the identify observations into `Identify` candidates.
  self.deriveIdentify = enabled

func isChainProduced(self: AddressManager, address: MultiAddress): bool =
  address in self.chainAddrs

proc addMapper*(self: AddressManager, mapper: AddressMapper, source: AddrSource) =
  ## Each address this mapper adds becomes a candidate of `source`. `stop` drops
  ## every mapper: an owner registers its own again on `start`.
  if mapper.isNil():
    return
  self.mappers.add(SourcedMapper(mapper: mapper, source: source))

proc removeMapper*(self: AddressManager, mapper: AddressMapper) =
  self.mappers.keepItIf(it.mapper != mapper)

func mapperSources*(self: AddressManager): seq[AddrSource] =
  ## In the order the chain runs them.
  self.mappers.mapIt(it.source)

proc `networkInterfaceProvider=`*(
    self: AddressManager, provider: NetworkInterfaceProvider
) =
  ## A nil provider announces the wildcard listen addresses as they are.
  self.networkInterfaceProvider = provider

func isLoopbackOrUp(networkInterface: NetworkInterface): bool =
  networkInterface.ifType == IfSoftwareLoopback or networkInterface.state == StatusUp

proc getAddresses*(addrFamily: AddressFamily): seq[InterfaceAddress] =
  ## The addresses of every loopback or running interface of `addrFamily`.
  let interfaces = getInterfaces().filterIt(it.isLoopbackOrUp())
  concat(interfaces.mapIt(it.addresses)).filterIt(it.host.family == addrFamily)

proc isWildcardIp(ip: IpAddress): bool =
  case ip.family
  of IpAddressFamily.IPv4:
    ip.address_v4 == AnyAddress.address_v4
  of IpAddressFamily.IPv6:
    ip.address_v6 == AnyAddress6.address_v6

proc expandWildcardAddresses*(
    networkInterfaceProvider: NetworkInterfaceProvider, listenAddrs: seq[MultiAddress]
): seq[MultiAddress] =
  ## Expands each bound wildcard address (``0.0.0.0`` / ``::``) into one address
  ## per matching network interface, keeping the port and any suffix (e.g.
  ## ``/quic-v1``, ``/ws``, ``/tls/ws``). The others pass through unchanged.
  var addresses: seq[MultiAddress]
  for listenAddr in listenAddrs:
    let listenIp = listenAddr.getIp().valueOr:
      addresses.add(listenAddr)
      continue

    if not isWildcardIp(listenIp):
      addresses.add(listenAddr)
      continue

    let families =
      case listenIp.family
      of IpAddressFamily.IPv4:
        @[AddressFamily.IPv4]
      of IpAddressFamily.IPv6:
        # IPv6 dual stack: also expand to IPv4 interfaces
        @[AddressFamily.IPv6, AddressFamily.IPv4]

    for family in families:
      for ifaddr in networkInterfaceProvider(family):
        listenAddr.replaceIp(ifaddr.host.toIpAddress()).ifValue(remapped):
          addresses.add(remapped)
  addresses

proc expandWildcards(
    self: AddressManager, listenAddrs: seq[MultiAddress]
): seq[MultiAddress] =
  if self.networkInterfaceProvider.isNil():
    return listenAddrs
  expandWildcardAddresses(self.networkInterfaceProvider, listenAddrs)

proc withdraw(self: AddressManager, produced: Table[MultiAddress, set[AddrSource]]) =
  ## Drops every chain source which no longer produces its address, e.g. an
  ## expired NAT mapping or a lost relay reservation. A candidate goes with its
  ## last source, so one another producer still offers stays.
  for address, sources in self.chainAddrs:
    let gone = sources - produced.getOrDefault(address)
    if gone == {}:
      continue
    var candidate = self.candidates.getOrDefault(address)
    candidate.sources.excl(gone)
    if candidate.sources == {}:
      self.candidates.del(address)
    else:
      self.candidates[address] = candidate

proc track(
    self: AddressManager,
    produced: Table[MultiAddress, set[AddrSource]],
    kept: seq[MultiAddress],
) =
  ## Makes each address the chain still produces a candidate of the sources which
  ## produced it, and withdraws the chain sources of the ones it dropped.
  var chainAddrs: Table[MultiAddress, set[AddrSource]]
  for address in kept:
    let sources = produced.getOrDefault(address)
    self.addSources(address, sources)
    chainAddrs[address] = sources

  self.withdraw(chainAddrs)
  self.chainAddrs = chainAddrs

func isAnnounceable(self: AddressManager, address: MultiAddress): bool =
  ## An observation-derived guess is remote input: it announces only once confirmed.
  let candidate = self.candidates.getOrDefault(address)
  case candidate.state
  of AddrState.Unreachable:
    # a remote peer proves nothing about a LAN address it was never going to reach
    not address.isPublicMA()
  of AddrState.Confirmed:
    true
  of AddrState.Unverified:
    candidate.sources != {AddrSource.Identify}

func confirmedFamilies(self: AddressManager): set[IpAddressFamily] =
  ## A confirmed private address proves only LAN reachability, so it stays out.
  var families: set[IpAddressFamily]
  for candidate in self.candidates.values:
    if candidate.state != AddrState.Confirmed or candidate.address.isRelayed() or
        not candidate.address.isPublicMA():
      continue
    candidate.address.getIp().ifValue(ip):
      families.incl(ip.family)
  families

func isRedundantRelay(
    self: AddressManager, address: MultiAddress, confirmed: set[IpAddressFamily]
): bool =
  ## A relay address is redundant once a direct address of its IP family is confirmed.
  if not address.isRelayed():
    return false
  let ip = address.getIp().valueOr:
    return false
  ip.family in confirmed

func fedAddrs(self: AddressManager): seq[MultiAddress] =
  ## The candidates a feeder offers, which no mapper of the chain produces.
  toSeq(self.candidates.keys).filterIt(not self.isChainProduced(it))

func announceSet(
    self: AddressManager, mappedAddrs: seq[MultiAddress]
): seq[MultiAddress] =
  ## Every confirmed or unverified candidate; unreachable and redundant ones stay out.
  let confirmed = self.confirmedFamilies()
  var res: seq[MultiAddress]
  for address in mappedAddrs & self.fedAddrs():
    if address in res or not self.isAnnounceable(address) or
        self.isRedundantRelay(address, confirmed):
      continue
    res.add(address)
  res

proc notifyReachability(self: AddressManager) {.async: (raises: [CancelledError]).} =
  let
    currentReachability = self.reachability()
    previousReachability = self.notifiedReachability

  if currentReachability == previousReachability:
    return

  info "Network reachability changed",
    previous = previousReachability, current = currentReachability

  self.notifiedReachability = currentReachability

  if not self.onReachabilityChange.isNil():
    await self.onReachabilityChange(currentReachability)

proc queueReachabilityNotification(self: AddressManager): Future[void].Raising([]) =
  ## Each notification waits for its predecessor before observing the summary.
  ## Besides preserving notification order, this keeps handlers from overlapping.
  let previous = self.reachabilityNotifyTail

  proc notify() {.async: (raises: []).} =
    try:
      if not previous.isNil():
        await previous
      await self.notifyReachability()
    except CancelledError:
      discard

  let current = notify()
  self.reachabilityNotifyTail = current
  # Keep every queued future so stop can cancel both the active handler and
  # notifications still waiting on it.
  self.reachabilityNotifyFuts.trackFut(current)
  current

proc notifyReachabilitySoon(self: AddressManager) =
  ## resolve can run under PeerInfo's mapper lock. A handler may update
  ## PeerInfo and acquire that lock again, so the mapper must not await it.
  discard self.queueReachabilityNotification()

func explicitAddrs(self: AddressManager): seq[MultiAddress] =
  if self.peerInfo.isNil():
    return @[]
  self.peerInfo.announcedAddrs

proc resolve(
    self: AddressManager, inputAddrs: seq[MultiAddress]
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  let announced = self.explicitAddrs()
  var
    addrs = self.expandWildcards(inputAddrs)
    produced: Table[MultiAddress, set[AddrSource]]

  for address in addrs:
    produced.mgetOrPut(address, {}).incl(AddrSource.Listen)

  # An owner may remove a mapper while this pass is suspended in an earlier
  # mapper's await. Iterate a snapshot to avoid changing the sequence during
  # iteration, and do not call a mapper removed meanwhile.
  let snapshot = self.mappers
  for sourced in snapshot:
    if not self.mappers.anyIt(it.mapper == sourced.mapper):
      continue
    let mapped = await sourced.mapper(addrs)
    for address in mapped.filterIt(it notin addrs):
      produced.mgetOrPut(address, {}).incl(sourced.source)
    addrs = mapped

  for address in announced:
    produced.mgetOrPut(address, {}).incl(AddrSource.Announced)

  self.track(produced, addrs & announced)
  # a withdrawal changes the summary without a verdict: tell the observers now
  self.notifyReachabilitySoon()

  # the operator picks what is announced; no mapper rewrites that choice
  if announced.len > 0:
    return announced

  self.announceSet(addrs)

proc resolveMapper(self: AddressManager): AddressMapper =
  ## Built here, not inside `new`: `new` is generic over its `typedesc`, so an
  ## async closure in its body is re-expanded at every instantiation site and
  ## fails in modules which lack the chronos internals.
  proc(
      listenAddrs: seq[MultiAddress]
  ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    await self.resolve(listenAddrs)

func identifyGuesses(self: AddressManager): seq[MultiAddress] =
  ## Listen addresses with the most observed IP, and the most observed proto/ports.
  var guesses: seq[MultiAddress]
  for listenAddr in self.peerInfo.listenAddrs:
    let guessed = self.externalAddrFor(listenAddr)
    if guessed != listenAddr:
      guesses.add(guessed)
  guesses & self.mostObservedProtosAndPorts()

func isRefuted(self: AddressManager, address: MultiAddress): bool =
  self.refutedGuesses.anyIt(it.address == address)

proc addIdentifyCandidates(self: AddressManager) =
  if not self.deriveIdentify or self.peerInfo.isNil():
    return
  for guess in self.identifyGuesses().filterIt(not self.isRefuted(it)):
    self.add(guess, AddrSource.Identify)

proc rememberRefuted(self: AddressManager, address: MultiAddress) =
  ## A wrongly refuted guess returns through expiry, ring eviction or a restart.
  if self.refutedGuesses.len >= self.maxSize:
    self.refutedGuesses.delete(0)
  self.refutedGuesses.add(RefutedGuess(address: address, runsLeft: RefutedGuessRuns))

proc expireRefuted(self: AddressManager) =
  for guess in self.refutedGuesses.mitems:
    guess.runsLeft.dec()
  self.refutedGuesses.keepItIf(it.runsLeft > 0)

proc applyVerdict(self: AddressManager, address: MultiAddress, state: AddrState): bool =
  ## True when the state changed. One random peer decides a verdict; later runs heal it.
  if address notin self.candidates:
    return false

  let candidate = self.candidates.getOrDefault(address)
  # a refuted guess is dropped, or an attacker could grow the table without cap
  if state == AddrState.Unreachable and candidate.sources == {AddrSource.Identify}:
    self.remove(address)
    self.rememberRefuted(address)
    return true

  if candidate.state == state:
    return false
  self.update(address, state)
  true

proc allowedByPolicy(self: AddressManager, address: MultiAddress): bool =
  ## The policy gates the dial requests too: a banned address never reaches a verifier.
  self.peerInfo.isNil() or self.peerInfo.addressPolicy.accepts(address)

proc verifyEach(
    self: AddressManager, addresses: seq[MultiAddress]
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## One address at a time until the run runs out of time; true when a state changed.
  var changed = false
  var attempted, verified, reachable, unreachable: int
  var outcome = "cancelled"
  defer:
    debug "Address verification finished",
      outcome,
      addresses = addresses.len,
      attempted,
      verified,
      reachable,
      unreachable,
      inconclusive = verified - reachable - unreachable,
      unverified = addresses.len - verified,
      changed

  let deadline = Moment.now() + self.verifyTimeout
  for address in addresses:
    let left = deadline - Moment.now()
    if left <= ZeroDuration:
      trace "Address verification timed out", timeout = self.verifyTimeout
      break

    attempted.inc()
    let state =
      try:
        await self.verifier.verify(address).wait(left)
      except AsyncTimeoutError:
        trace "Address verification timed out", address, timeout = self.verifyTimeout
        break

    verified.inc()
    state.ifValue(verdict):
      if self.applyVerdict(address, verdict):
        changed = true
      if verdict == AddrState.Confirmed:
        reachable.inc()
      elif verdict == AddrState.Unreachable:
        unreachable.inc()
  outcome = if verified == addresses.len: "completed" else: "timedOut"
  changed

proc runVerifier(self: AddressManager) {.async: (raises: [CancelledError]).} =
  if self.verifier.isNil():
    return
  self.expireRefuted()
  self.addIdentifyCandidates()

  # a relayed candidate stays unverified: no AutoNAT peer dials a circuit address back
  let addresses = toSeq(self.candidates.keys).filterIt(
      not it.isRelayed() and self.allowedByPolicy(it)
    )
  if addresses.len == 0:
    return

  if not await self.verifyEach(addresses):
    return
  if not self.peerInfo.isNil():
    await self.peerInfo.update()

proc verifyCandidates(self: AddressManager) {.async: (raises: [CancelledError]).} =
  self.verifying = true
  defer:
    self.verifying = false
  await self.runVerifier()
  # a withdrawn candidate changes the summary without a verdict, so reconcile every run
  await self.queueReachabilityNotification()

proc verifyHeartbeat(self: AddressManager) {.async: (raises: [CancelledError]).} =
  heartbeat "AddressManager candidate verification", self.verifyInterval:
    await self.verifyCandidates()

proc restartHeartbeat(self: AddressManager) =
  ## A sleeping heartbeat holds its old wake-up time; the restart applies changes now.
  if not self.started:
    return
  if not self.verifyFut.isNil():
    self.verifyFut.cancelSoon()
  self.verifyFut = self.verifyHeartbeat()

proc triggerVerification*(self: AddressManager) =
  ## Runs a pass now; a running pass keeps its awaited dial-backs instead.
  if self.verifying:
    return
  self.restartHeartbeat()

proc `verifier=`*(self: AddressManager, verifier: Verifier) =
  ## The verifier is optional. Without one, every candidate stays `Unverified`.
  self.verifier = verifier
  self.restartHeartbeat()

proc `verifyInterval=`*(self: AddressManager, interval: Duration) =
  ## The cadence only: a run gets `verifyTimeout`, however short the cadence is.
  self.verifyInterval = max(interval, 1.milliseconds)
  self.restartHeartbeat()

proc setPeerInfo*(self: AddressManager, peerInfo: PeerInfo) =
  ## Installs the manager's mapper as the first one `peerInfo` runs.
  self.peerInfo = peerInfo
  peerInfo.addressMappers.keepItIf(it != self.addressMapper)
  peerInfo.addressMappers.insert(self.addressMapper, 0)

proc start*(self: AddressManager) =
  if self.started:
    return
  self.started = true
  self.verifyFut = self.verifyHeartbeat()

proc stop*(self: AddressManager) =
  self.started = false
  if not self.verifyFut.isNil():
    self.verifyFut.cancelSoon()
    self.verifyFut = nil
  self.reachabilityNotifyFuts.cancelSoon()
  self.reachabilityNotifyFuts.setLen(0)
  self.reachabilityNotifyTail = nil
  self.observations.setLen(0)
  self.candidates.clear()
  self.chainAddrs.clear()
  self.mappers.setLen(0)
  self.onReachabilityChange = nil
  self.notifiedReachability = NetworkReachability.Unknown
  self.refutedGuesses.setLen(0)

  if self.peerInfo.isNil():
    return
  self.peerInfo.addressMappers.keepItIf(it != self.addressMapper)
  self.peerInfo = nil

func `$`*(self: AddressManager): string =
  let addresses = toSeq(self.candidates.keys)
  "observations: " & $self.observedAddrs() & ", candidates: " & $addresses

proc new*(
    T: typedesc[AddressManager], config: AddressManagerConfig = AddressManagerConfig()
): T =
  ## A threshold below one is raised to one: a minCount of zero would let a
  ## single peer decide the external address.
  let manager = T(
    maxSize: max(config.maxSize, 1),
    minCount: max(config.minCount, 1),
    verifyInterval: max(config.verifyInterval, 1.milliseconds),
    verifyTimeout: max(config.verifyTimeout, 1.milliseconds),
  )
  manager.addressMapper = manager.resolveMapper()
  manager
