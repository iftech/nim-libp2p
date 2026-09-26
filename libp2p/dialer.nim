# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sequtils, tables]

import pkg/[chronos, chronicles, metrics, results]

import
  dial,
  dial_backoff,
  dialcandidate,
  peerid,
  peerinfo,
  peerstore,
  peeraddrpolicy,
  multicodec,
  muxers/muxer,
  multistream,
  connmanager,
  stream/connection,
  transports/transport,
  nameresolving/nameresolver,
  rankeddial,
  upgrademngrs/upgrade,
  utils/future,
  errors

export dial, dial_backoff, errors, results, MaxDialCandidates, MaxParallelDials

logScope:
  topics = "libp2p dialer"

declareCounter(libp2p_total_dial_attempts, "total attempted dials")
declareCounter(libp2p_successful_dials, "dialed successful peers")
declareCounter(libp2p_failed_dials, "failed dials")
declarePublicHistogram libp2p_dial_duration_ms,
  "dial and connection upgrade duration in milliseconds",
  ["result"],
  buckets =
    [10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0, 30000.0]

const DefaultDialerTimeout* = 30.seconds
  ## Budget for reaching one peer. Every address it advertises shares it, and
  ## identify gets the same budget again once a connection stands. The transport
  ## dial and the upgrade have no bound of their own, so without this a remote
  ## that goes quiet mid-handshake holds the peer's dial lock forever.

type
  DialReach* = ref object
    ## Shared by every address of one dial, so the peer answers for a real dial only.
    dialed: bool
    attempted, succeeded, failed, cancelled: int

  DialLock = ref object
    lock: AsyncLock
    users: int ## dials holding or waiting for `lock`

  DialResult[T] = Result[T, string]

  Dialer* = ref object of Dial
    localPeerId*: PeerId
    connManager: ConnManager
    dialLocks: Table[PeerId, DialLock]
    dialTimeout: Duration
    transports: seq[Transport]
    peerStore: PeerStore
    nameResolver: NameResolver
    ms: MultistreamSelect
    dialRanking: bool ## overlap the name lookups with the dials, and rank the dials
    dialBackoff: Opt[DialBackoff] ## none unless the switch opted in
    ongoingReleaseOnClose: seq[Future[void].Raising([])]

proc transportFor(self: Dialer, address: MultiAddress): Opt[Transport] =
  for transport in self.transports:
    if transport.handles(address):
      return Opt.some(transport)
  Opt.none(Transport)

proc dialAndUpgrade*(
    self: Dialer,
    peerId: Opt[PeerId],
    hostname: string,
    addrs: MultiAddress,
    dir = Direction.Out,
    deadline = Moment.now() + self.dialTimeout,
    forceDial = false,
    reach = DialReach(),
): Future[Muxer] {.async: (raises: [CancelledError]).} =
  ## Dial one resolved address, below candidate selection. Nil when no transport connects.

  let transport = self.transportFor(addrs).valueOr:
    return nil

  let backoffKey = backoffKey(addrs, peerId)
  self.dialBackoff.ifValue(backoff):
    # `forceDial` already overrides the connection limits, so it overrides the wait too.
    if not forceDial and backoff.blocked(backoffKey):
      return nil

  reach.dialed = true
  reach.attempted.inc()
  var attemptOutcome = "cancelled"
  defer:
    case attemptOutcome
    of "succeeded":
      reach.succeeded.inc()
    of "failed":
      reach.failed.inc()
    else:
      reach.cancelled.inc()

  let dialStarted = Moment.now()
  trace "Address dial started", peerId, address = addrs, hostname
  let dialed =
    try:
      libp2p_total_dial_attempts.inc()
      transport.dial(hostname, addrs, peerId, dir).awaitWithDeadline(deadline)
    except CancelledError as e:
      trace "Address dial canceled", err = e.msg, peerId, address = addrs
      raise e
    except CatchableError as e:
      attemptOutcome = "failed"
      trace "Address dial failed", err = e.msg, peerId, address = addrs, hostname
      libp2p_failed_dials.inc()
      libp2p_dial_duration_ms.observe(
        (Moment.now() - dialStarted).milliseconds, labelValues = ["failed"]
      )
      self.dialBackoff.ifValue(backoff):
        backoff.recordFailure(backoffKey)
      return nil # Try the next address

  libp2p_successful_dials.inc()

  let mux =
    try:
      # A DCUtR simultaneous dial leaves both sides Outbound, so the initiator takes `dir`.
      dialed.dir = dir
      transport.upgrade(dialed, peerId).awaitWithDeadline(deadline)
    except CancelledError as e:
      await dialed.close()
      raise e
    except CatchableError as e:
      # Another transport for the same address fails the same way, so give this one up.
      await dialed.close()
      attemptOutcome = "failed"
      trace "Connection upgrade failed", err = e.msg, peerId, address = addrs, hostname
      if dialed.dir == Direction.Out:
        libp2p_failed_upgrades_outgoing.inc()
      else:
        libp2p_failed_upgrades_incoming.inc()
      libp2p_dial_duration_ms.observe(
        (Moment.now() - dialStarted).milliseconds, labelValues = ["upgrade_failed"]
      )
      self.dialBackoff.ifValue(backoff):
        backoff.recordFailure(backoffKey)

      # Try other address
      return nil

  doAssert not isNil(mux), "connection died after upgrade " & $dialed.dir
  attemptOutcome = "succeeded"
  trace "Peer connection established", peerId = mux.connection.peerId, address = addrs
  libp2p_dial_duration_ms.observe(
    (Moment.now() - dialStarted).milliseconds, labelValues = ["success"]
  )

  self.dialBackoff.ifValue(backoff):
    backoff.recordSuccess(backoffKey)

  let filtered = self.peerStore.addressPolicy.filterAddrs(@[addrs])
  if filtered.len > 0:
    self.peerStore[AddressBook].markConnected(mux.connection.peerId, filtered[0])

  mux

proc expandDnsAddr(
    self: Dialer, peerId: Opt[PeerId], address: MultiAddress, deadline: Moment
): Future[DialResult[seq[(MultiAddress, Opt[PeerId])]]] {.
    async: (raises: [CancelledError])
.} =
  if not DNS.matchPartial(address):
    return ok(@[(address, peerId)])
  if isNil(self.nameResolver):
    warn "Can't resolve DNSADDR without NameResolver", address = address
    return ok(newSeq[(MultiAddress, Opt[PeerId])]())

  trace "Address resolution started"
  let toResolve =
    if peerId.isSome:
      ?concat(address, ?MultiAddress.init(multiCodec("p2p"), peerId.get()))
    else:
      address
  # A dnsaddr record points at more dnsaddr records, and each lookup can take
  # seconds, so the chain answers to the dial deadline like the dial itself.
  let resolved =
    try:
      self.nameResolver.resolveDnsAddr(toResolve).awaitWithDeadline(deadline)
    except AsyncTimeoutError:
      trace "DNSADDR resolution timed out", address = toResolve
      return ok(newSeq[(MultiAddress, Opt[PeerId])]())
    except MaError as e:
      return err(e.msg)
    except TransportAddressError as e:
      return err(e.msg)

  trace "Address resolution completed",
    originalAddresses = toResolve, resolvedAddresses = resolved

  var addrs: seq[(MultiAddress, Opt[PeerId])]
  for resolvedAddress in resolved:
    let lastPart = ?resolvedAddress[^1]
    if lastPart.protoCode == Result[MultiCodec, string].ok(multiCodec("p2p")):
      let addrPeerId = PeerId.init(?lastPart.protoArgument()).valueOr:
        return err($error)
      addrs.add((?resolvedAddress[0 ..^ 2], Opt.some(addrPeerId)))
    else:
      addrs.add((resolvedAddress, peerId))
  ok(addrs)

proc resolveWithDeadline(
    self: Dialer, address: MultiAddress, deadline: Moment
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  ## Empty when the resolver has no answer left in the dial's budget.
  if isNil(self.nameResolver):
    return @[address]
  try:
    self.nameResolver.resolveMAddress(address).awaitWithDeadline(deadline)
  except AsyncTimeoutError:
    trace "Address resolution timed out", address
    @[]

proc tryExpandDnsAddr(
    self: Dialer, peerId: Opt[PeerId], address: MultiAddress, deadline: Moment
): Future[seq[(MultiAddress, Opt[PeerId])]] {.async: (raises: [CancelledError]).} =
  ## Empty when the record is unusable, so one bad record cannot fail the dial.
  (await self.expandDnsAddr(peerId, address, deadline)).valueOr:
    trace "Address skipped after DNSADDR expansion failed", err = error, peerId, address
    @[]

proc tryResolve(
    self: Dialer, address: MultiAddress, deadline: Moment
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  ## Empty when the name does not resolve, so one bad name cannot fail the dial.
  try:
    await self.resolveWithDeadline(address, deadline)
  except CancelledError as e:
    raise e
  except CatchableError as e:
    trace "Address skipped after name resolution failed", err = e.msg, address
    @[]

proc normalizedDialAddrs(
    peerId: Opt[PeerId], addrs: seq[MultiAddress]
): seq[MultiAddress] =
  if peerId.isSome:
    addrs.mapIt(it.stripPeerId)
  else:
    addrs

func fromNameLookup(candidate: DialCandidate): bool =
  ## Named directly, or reached through the dnsaddr chain that named it.
  candidate.fromName or DNS.matchPartial(candidate.address)

proc expandCandidate(
    self: Dialer, candidate: DialCandidate, deadline: Moment
): Future[seq[DialCandidate]] {.async: (raises: [CancelledError]).} =
  ## The addresses one dnsaddr record stands for, each of them still unresolved.

  let fromName = candidate.fromNameLookup()

  var expanded: seq[DialCandidate]
  for (address, addrPeerId) in await self.tryExpandDnsAddr(
    candidate.peerId, candidate.address, deadline
  ):
    expanded.add(
      DialCandidate(
        address: address,
        hostname: address.getHostname(),
        peerId: addrPeerId,
        fromName: fromName,
      )
    )

  expanded

proc resolveCandidate(
    self: Dialer, candidate: DialCandidate, deadline: Moment
): Future[seq[DialCandidate]] {.async: (raises: [CancelledError]).} =
  ## The wire addresses one name resolves to, minus the ones no transport handles.

  let resolved = await self.tryResolve(candidate.address, deadline)

  trace "Resolved address",
    expandedAddress = candidate.address,
    hostname = candidate.hostname,
    resolvedAddresses = resolved

  # The policy passes a name on sight, so the answer it stands for is checked here.
  let fromName = candidate.fromNameLookup()

  var candidates: seq[DialCandidate]
  for address in resolved:
    if self.transportFor(address).isNone():
      trace "Address skipped because no transport supports it",
        peerId = candidate.peerId, address
      continue

    if fromName and not self.peerStore.addressPolicy.accepts(address):
      trace "Resolved address skipped by the address policy",
        peerId = candidate.peerId, name = candidate.address, address
      continue

    candidates.add(
      DialCandidate(
        address: address,
        hostname: candidate.hostname,
        peerId: candidate.peerId,
        fromName: fromName,
      )
    )

  candidates

proc directCandidates(
    self: Dialer, peerId: Opt[PeerId], addrs: seq[MultiAddress]
): seq[DialCandidate] =
  ## The advertised addresses a transport can dial with no lookup at all.

  var candidates: seq[DialCandidate]
  for address in addrs:
    if DNS.matchPartial(address):
      continue
    if self.transportFor(address).isNone():
      trace "Address skipped because no transport supports it", peerId, address
      continue

    # `wstransport` sends this as the Host header, so a wire address needs it too.
    candidates.add(
      DialCandidate(address: address, hostname: address.getHostname(), peerId: peerId)
    )

  candidates

proc dnsCandidates(peerId: Opt[PeerId], addrs: seq[MultiAddress]): seq[DialCandidate] =
  ## The advertised addresses that need a lookup before anything can dial them.

  addrs.filterIt(DNS.matchPartial(it)).mapIt(DialCandidate(address: it, peerId: peerId))

proc dialInOrder(
    self: Dialer,
    peerId: Opt[PeerId],
    addrs: seq[MultiAddress],
    dir: Direction,
    deadline: Moment,
    forceDial: bool,
    reach: DialReach,
): Future[Muxer] {.async: (raises: [CancelledError]).} =
  ## Resolve one address at a time and dial it right away.

  for rawAddress in addrs:
    if deadline.timeLeft().isZero():
      trace "Peer dial timed out", peerId, addresses = addrs
      return nil

    let advertised = DialCandidate(address: rawAddress, peerId: peerId)
    # Retain lookup results across awaits in the loop bodies.
    let expandedCandidates = await self.expandCandidate(advertised, deadline)
    for expanded in expandedCandidates:
      let resolvedCandidates = await self.resolveCandidate(expanded, deadline)
      for candidate in resolvedCandidates:
        let mux = await self.dialAndUpgrade(
          candidate.peerId, candidate.hostname, candidate.address, dir, deadline,
          forceDial, reach,
        )
        if not isNil(mux):
          return mux

proc dialRanked(
    self: Dialer,
    peerId: Opt[PeerId],
    addrs: seq[MultiAddress],
    dir: Direction,
    deadline: Moment,
    forceDial: bool,
    reach: DialReach,
): DialAttempt =
  ## Dial the wire addresses at once and each name's addresses as it resolves, best rank first.

  let dial = RankedDial.new(
    deadline,
    attempt = proc(candidate: DialCandidate): DialAttempt =
      self.dialAndUpgrade(
        candidate.peerId, candidate.hostname, candidate.address, dir, deadline,
        forceDial, reach,
      ),
    expand = proc(candidate: DialCandidate): CandidateLookup =
      self.expandCandidate(candidate, deadline),
    resolve = proc(candidate: DialCandidate): CandidateLookup =
      self.resolveCandidate(candidate, deadline),
  )
  dial.run(self.directCandidates(peerId, addrs), dnsCandidates(peerId, addrs))

proc tryDialAndUpgrade(
    self: Dialer,
    peerId: Opt[PeerId],
    addrs: seq[MultiAddress],
    dir: Direction,
    deadline: Moment,
    forceDial: bool,
    reach: DialReach,
): Future[DialResult[Muxer]] {.async: (raises: [CancelledError]).} =
  let dialAddrs = normalizedDialAddrs(peerId, addrs)
  trace "Peer dial started", peerId, addresses = dialAddrs

  var outcome = "cancelled"
  defer:
    debug "Peer address dial finished",
      peerId,
      addresses = dialAddrs,
      outcome,
      attempted = reach.attempted,
      succeeded = reach.succeeded,
      failed = reach.failed,
      cancelled = reach.cancelled

  let mux =
    if self.dialRanking:
      await self.dialRanked(peerId, dialAddrs, dir, deadline, forceDial, reach)
    else:
      await self.dialInOrder(peerId, dialAddrs, dir, deadline, forceDial, reach)
  if not mux.isNil:
    outcome = "connected"
    return ok(mux)

  outcome = if deadline.timeLeft().isZero(): "timedOut" else: "exhausted"
  err("peer dial " & outcome)

proc dialAndUpgrade*(
    self: Dialer,
    peerId: Opt[PeerId],
    addrs: seq[MultiAddress],
    dir = Direction.Out,
    deadline = Moment.now() + self.dialTimeout,
    forceDial = false,
    reach = DialReach(),
): Future[Muxer] {.async: (raises: [CancelledError]).} =
  ## Dial the addresses, sharing one `deadline`. Nil when all of them fail.
  (await self.tryDialAndUpgrade(peerId, addrs, dir, deadline, forceDial, reach)).valueOr:
    nil

proc tryReusingConnection(self: Dialer, peerId: PeerId): Opt[Muxer] =
  let muxer = self.connManager.selectMuxer(peerId)
  if muxer == nil:
    return Opt.none(Muxer)

  trace "Reusing existing connection", muxer, direction = $muxer.connection.dir
  return Opt.some(muxer)

proc dropUser(self: Dialer, peerId: PeerId, dialLock: DialLock) {.raises: [].} =
  ## Drop the entry once nobody holds or waits for it, so the table stays bounded
  ## by the number of concurrent dials instead of by every peer ever dialed.
  dialLock.users.dec()
  if dialLock.users == 0 and self.dialLocks.getOrDefault(peerId) == dialLock:
    self.dialLocks.del(peerId)

proc releaseDialLock(self: Dialer, peerId: PeerId, dialLock: DialLock) {.raises: [].} =
  try:
    dialLock.lock.release()
  except AsyncLockError as e:
    raiseAssert "dial lock released without acquire: " & e.msg
  self.dropUser(peerId, dialLock)

proc acquireDialLock(
    self: Dialer, peerId: PeerId
): Future[DialLock] {.async: (raises: [CancelledError]).} =
  let dialLock = self.dialLocks.mgetOrPut(peerId, DialLock(lock: newAsyncLock()))
  dialLock.users.inc()
  try:
    await dialLock.lock.acquire()
  except CancelledError as e:
    # The lock is not ours: chronos leaves the waiter in the queue and skips it
    # on the next handover.
    self.dropUser(peerId, dialLock)
    raise e
  dialLock

proc finishUpgrade(
    self: Dialer, muxed: Muxer, dir: Direction
): Future[DialResult[void]] {.async: (raises: [CancelledError]).} =
  ## Store the muxer, learn who is on the other end, and announce the peer.
  var finished = false
  defer:
    if not finished:
      await muxed.close()

  (await self.connManager.storeMuxer(muxed)).isOkOr:
    return err("failed storeMuxer in finishUpgrade: " & error)

  try:
    # Its own budget, not the dial's leftovers: the connection stands at this
    # point, and a remote that never answers identify would otherwise hold the
    # peer's dial lock for as long as that connection lives.
    await self.peerStore.identify(muxed, dir).wait(self.dialTimeout)
  except AsyncTimeoutError, IdentityNoMatchError, IdentityInvalidMsgError,
      MultiStreamError, LPStreamError, MuxerError:
    return err("failed identify in finishUpgrade: " & getCurrentExceptionMsg())
  await self.connManager.triggerPeerEvents(
    muxed.connection.peerId, PeerEvent(kind: PeerEventKind.Identified, initiator: true)
  )

  finished = true
  ok()

proc establishConnection(
    self: Dialer,
    peerId: Opt[PeerId],
    addrs: seq[MultiAddress],
    forceDial: bool,
    reuseConnection: bool,
    dir: Direction,
): Future[DialResult[Muxer]] {.async: (raises: [CancelledError]).} =
  if reuseConnection:
    peerId.ifValue(peerId):
      self.tryReusingConnection(peerId).ifValue(mux):
        return ok(mux)

  if addrs.len == 0:
    return err("no addresses to dial in establishConnection")

  self.dialBackoff.ifValue(backoff):
    if not forceDial and backoff.blocked(peerId):
      return err("peer on dial backoff in establishConnection")

  let slot = self.connManager.getOutgoingSlot(forceDial).valueOr:
    return err("failed getOutgoingSlot in establishConnection: " & error)

  let
    dialAddrs = normalizedDialAddrs(peerId, addrs)
    reach = DialReach()
  let muxed =
    try:
      await self.dialAndUpgrade(
        peerId, dialAddrs, dir, Moment.now() + self.dialTimeout, forceDial, reach
      )
    except CancelledError as e:
      slot.release()
      raise e
  if isNil(muxed): # None of the addresses connected
    slot.release()
    if reach.dialed:
      self.dialBackoff.ifValue(backoff):
        backoff.recordFailure(peerId)
    return err("Unable to establish outgoing link in establishConnection")

  slot.trackMuxer(muxed)
  (await self.finishUpgrade(muxed, dir)).isOkOr:
    trace "Outgoing connection upgrade failed",
      err = error, peerId = muxed.connection.peerId
    self.dialBackoff.ifValue(backoff):
      backoff.recordFailure(peerId)
    return err(error)

  self.dialBackoff.ifValue(backoff):
    backoff.recordSuccess(peerId)
  ok(muxed)

proc internalConnect(
    self: Dialer,
    peerId: Opt[PeerId],
    addrs: seq[MultiAddress],
    forceDial: bool,
    reuseConnection = true,
    dir = Direction.Out,
): Future[DialResult[Muxer]] {.async: (raises: [CancelledError]).} =
  if Opt.some(self.localPeerId) == peerId:
    return err("internalConnect can't dial self!")

  # A dial without a peer id has no connection to reuse and no identity to
  # serialize on. Sharing one lock for all of them would make an unreachable
  # address block every other address dial.
  let pid = peerId.valueOr:
    return
      await self.establishConnection(peerId, addrs, forceDial, reuseConnection, dir)

  # Ensure there's only one in-flight attempt per peer
  let dialLock = await self.acquireDialLock(pid)
  defer:
    self.releaseDialLock(pid, dialLock)

  await self.establishConnection(peerId, addrs, forceDial, reuseConnection, dir)

method connect*(
    self: Dialer,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    forceDial = false,
    reuseConnection = true,
    dir = Direction.Out,
) {.async: (raises: [DialFailedError, CancelledError]).} =
  ## connect remote peer without negotiating
  ## a protocol
  ##

  if self.connManager.connCount(peerId) > 0 and reuseConnection:
    return

  (await self.internalConnect(Opt.some(peerId), addrs, forceDial, reuseConnection, dir)).isOkOr:
    raise newException(
      DialFailedError,
      "failed connect: peer_id=" & $peerId & " addrs=" & $addrs & ": " & error,
    )

method connect*(
    self: Dialer, address: MultiAddress, allowUnknownPeerId = false
): Future[PeerId] {.async: (raises: [DialFailedError, CancelledError]).} =
  ## Connects to a peer and retrieve its PeerId

  parseFullAddress(address).toOpt().ifValue(fullAddress):
    let muxed = (
      await self.internalConnect(Opt.some(fullAddress[0]), @[fullAddress[1]], false)
    ).valueOr:
      raise newException(
        DialFailedError, "failed connect: address=" & $address & ": " & error
      )
    return muxed.connection.peerId

  if allowUnknownPeerId == false:
    raise newException(
      DialFailedError, "Address without PeerID and unknown peer id disabled in connect"
    )

  let muxed = (await self.internalConnect(Opt.none(PeerId), @[address], false)).valueOr:
    raise newException(
      DialFailedError, "failed connect: address=" & $address & ": " & error
    )
  return muxed.connection.peerId

proc negotiateStream*(
    self: Dialer, stream: Stream, protos: seq[string]
): Future[Stream] {.async: (raises: [CancelledError, LPError]).} =
  ## Negotiate one of `protos` over an open stream.
  ## Raises DialFailedError when negotiation selects no supported protocol or
  ## the selected protocol's outgoing stream budget is exhausted.

  var negotiated = false
  defer:
    if not negotiated:
      await stream.reset()

  trace "Protocol negotiation started", stream, protocols = protos
  let selected = await MultistreamSelect.select(stream, protos)
  if not protos.contains(selected):
    raise newException(
      DialFailedError,
      "Unable to select sub-protocol. None of the offered protocols were accepted: " &
        $protos,
    )

  self.ms.lookupProtocol(selected).ifValue(protocol):
    if not protocol.reserveOutgoing(stream.peerId):
      raise newException(
        DialFailedError, "Outbound stream budget exceeded for protocol: " & selected
      )

    proc releaseOnClose() {.async: (raises: []).} =
      await noCancel stream.join()
      protocol.releaseOutgoing(stream.peerId)

    let fut = releaseOnClose()
    self.ongoingReleaseOnClose.add(fut)
    fut.addCallback proc(udata: pointer) =
      let idx = self.ongoingReleaseOnClose.find(fut)
      if idx >= 0:
        self.ongoingReleaseOnClose.del(idx)

  negotiated = true
  return stream

proc tryDial*(
    self: Dialer, peerId: PeerId, addrs: seq[MultiAddress]
): Future[Opt[MultiAddress]] {.async: (raises: [DialFailedError, CancelledError]).} =
  ## Create a protocol stream in order to check
  ## if a connection is possible.
  ## Doesn't use the Connection Manager to save it.
  ## Returns the observed address when the probe succeeds.
  ##

  trace "Peer reachability probe started", peerId, addresses = addrs
  let mux = (
    await self.tryDialAndUpgrade(
      Opt.some(peerId),
      addrs,
      Direction.Out,
      Moment.now() + self.dialTimeout,
      forceDial = false,
      reach = DialReach(),
    )
  ).valueOr:
    raise newException(DialFailedError, "tryDial failed: " & error)
  await mux.close()
  mux.connection.observedAddr

method dial*(
    self: Dialer, peerId: PeerId, protos: seq[string]
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  ## create a protocol stream over an
  ## existing connection
  ##

  trace "Protocol stream establishment started", peerId, protocols = protos

  try:
    let stream = await self.connManager.getStream(peerId)
    if stream.isNil:
      raise newException(
        DialFailedError, "Couldn't get muxed stream in dial for peer_id: " & $peerId
      )
    return await self.negotiateStream(stream, protos)
  except CancelledError as exc:
    trace "Protocol stream establishment canceled",
      err = exc.msg, peerId, protocols = protos
    raise exc
  except CatchableError as exc:
    trace "Protocol stream establishment failed",
      err = exc.msg, peerId, protocols = protos
    raise newException(DialFailedError, "failed dial existing: " & exc.msg)

method dial*(
    self: Dialer,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  ## create a protocol stream and establish
  ## a connection if one doesn't exist already
  ##

  var conn: Muxer

  let dialAddrs = normalizedDialAddrs(Opt.some(peerId), addrs)

  try:
    trace "Peer dial started", peerId, addresses = dialAddrs
    conn = (await self.internalConnect(Opt.some(peerId), dialAddrs, forceDial)).valueOrRaise(
      DialFailedError
    )
    trace "Protocol stream opening started", peerId, protocols = protos, conn
    let stream = await self.connManager.getStream(conn)

    if isNil(stream):
      raise newException(
        DialFailedError,
        "Couldn't get muxed stream in new dial for remote_peer_id: " & $peerId,
      )

    return await self.negotiateStream(stream, protos)
  except CancelledError as exc:
    trace "Protocol stream establishment canceled",
      err = exc.msg, peerId, protocols = protos, conn
    raise exc
  except CatchableError as exc:
    debug "Protocol stream establishment failed",
      err = exc.msg, peerId, protocols = protos, addresses = dialAddrs, conn
    raise newException(
      DialFailedError,
      "failed new dial: peer_id=" & $peerId & " protos=" & $protos & " addrs=" &
        $dialAddrs & ": " & exc.msg,
      exc,
    )

method addTransport*(self: Dialer, t: Transport) {.raises: [].} =
  self.transports &= t

proc new*(
    T: type Dialer,
    localPeerId: PeerId,
    connManager: ConnManager,
    peerStore: PeerStore,
    transports: seq[Transport],
    ms: MultistreamSelect,
    nameResolver: NameResolver = nil,
    dialTimeout = DefaultDialerTimeout,
    dialRanking = false,
    dialBackoff = Opt.none(DialBackoffConfig),
): Dialer {.raises: [].} =
  var backoff = Opt.none(DialBackoff)
  dialBackoff.ifValue(backoffConfig):
    backoff = Opt.some(DialBackoff.new(backoffConfig))

  T(
    localPeerId: localPeerId,
    connManager: connManager,
    transports: transports,
    peerStore: peerStore,
    nameResolver: nameResolver,
    ms: ms,
    dialTimeout: dialTimeout,
    dialRanking: dialRanking,
    dialBackoff: backoff,
  )
