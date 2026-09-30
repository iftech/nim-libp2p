# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[tables, sequtils, algorithm, sets, strutils]
import chronos, chronicles, results
import ../../[peerid, peerinfo, switch, multihash, peeraddrpolicy]
import ../protocol
import ../../utils/future
import
  ./[routing_table, protobuf, probe_backoff, types, rpc, kademlia_metrics, ip_diversity]

logScope:
  topics = "libp2p kademlia"

type RespondedStatus* = enum
  Failed
  Success

type LookupState* = ref object
  kad: KadDHT
  rtable: RoutingTable
  target*: Key
  shortlist*: Table[PeerId, XorDistance]
  responded*: Table[PeerId, RespondedStatus]
  attempts*: Table[PeerId, int]

type DispatchProc* = proc(
  kad: KadDHT, peer: PeerId, target: Key
): Future[LPResult[Message]] {.async: (raises: [CancelledError]), gcsafe, closure.}

type ReplyHandler* = proc(
  peer: PeerId, msg: Opt[Message], state: LookupState
): Future[void] {.async: (raises: []), gcsafe.}

type EarlyExit* = proc(state: LookupState): bool {.raises: [], gcsafe.}
  ## External early exit. ``iterativeLookup`` converges and confirms the k
  ## closest peers on its own, so a caller passes this only to stop sooner than
  ## that, once it already has what it asked for.

proc getFarthest(
    t: Table[PeerId, XorDistance]
): Opt[(PeerId, XorDistance)] {.raises: [].} =
  var worstPid: PeerId
  var worstDist: XorDistance
  var found = false
  for pid, d in t.pairs():
    if not found or worstDist < d:
      worstPid = pid
      worstDist = d
      found = true
  if found:
    Opt.some((worstPid, worstDist))
  else:
    Opt.none((PeerId, XorDistance))

proc dropPeer(state: LookupState, pid: PeerId) {.raises: [].} =
  state.shortlist.del(pid)
  state.attempts.del(pid)
  state.responded.del(pid)

proc isDialable(kad: KadDHT, peerId: PeerId): bool {.raises: [].} =
  kad.dialAddrs(peerId).len > 0 or kad.switch.isConnected(peerId)

proc admissibleAddrs(
    switch: Switch,
    addressPolicy: PeerAddressPolicy,
    rtable: RoutingTable,
    p: PeerInfo,
    caps: DiversityCaps,
    pending: seq[PeerId] = @[],
): seq[MultiAddress] {.raises: [].} =
  let addrs =
    addressPolicy.dialableAddrs(p.addrs, switch.peerStore.allowUndialableAddrs)
  if addrs.len == 0:
    return @[]
  if not switch.peerStore[AddressBook].hasIpDiversity(
    rtable, p.peerId, addrs, caps, pending
  ):
    return @[]
  addrs

proc admissibleAddrs(
    kad: KadDHT, rtable: RoutingTable, p: PeerInfo, pending: seq[PeerId]
): seq[MultiAddress] {.raises: [].} =
  kad.switch.admissibleAddrs(
    kad.config.addressPolicy, rtable, p, kad.config.limits.diversityCaps(), pending
  )

proc pendingAdmissions(kad: KadDHT, tableId: Key): seq[PeerId] {.raises: [].} =
  ## A probe for another table holds no slot in this one.
  kad.admissionProbes.keys.toSeq().filterIt(it.tableId == tableId).mapIt(it.peerId)

proc canBecomeDialable(
    state: LookupState, peerId: PeerId, addrs: seq[MultiAddress], pending: seq[PeerId]
): bool {.raises: [].} =
  ## Same conditions as ``admitPeers``, since nothing else records addresses.
  let p = PeerInfo(peerId: peerId, addrs: addrs)
  state.kad.admissibleAddrs(state.rtable, p, pending).len > 0 or
    state.kad.isDialable(peerId)

proc tryEvictFarthest(state: LookupState, newDist: XorDistance): bool {.raises: [].} =
  ## Drop the worst (farthest) peer from the shortlist if it is farther than
  ## ``newDist``. Considers all peers — including ones that already responded —
  ## because the iterative lookup needs the closer candidate to make progress.
  ## A responded peer's contribution is already merged into the shortlist, so
  ## evicting it costs nothing beyond bookkeeping.
  let (pid, dist) = state.shortlist.getFarthest().valueOr:
    return false
  if newDist >= dist:
    return false
  state.dropPeer(pid)
  return true

proc updateShortlist*(state: LookupState, msg: Message): seq[PeerInfo] {.raises: [].} =
  var newPeerInfos: seq[PeerInfo]
  let cap = state.kad.config.limits.maxShortlistSize
  let pending = state.kad.pendingAdmissions(state.rtable.selfId)

  for newPeer in msg.closerPeers:
    let raw = newPeer.id.valueOr:
      continue
    let pid = PeerId.init(raw).valueOr:
      continue
    if state.shortlist.contains(pid):
      continue
    if not state.canBecomeDialable(pid, newPeer.addrs, pending):
      continue

    let dist = xorDistance(pid, state.target, state.rtable.config.hasher)

    if state.shortlist.len >= cap and not state.tryEvictFarthest(dist):
      continue

    state.shortlist[pid] = dist
    newPeerInfos.add(PeerInfo(peerId: pid, addrs: newPeer.addrs))

  return newPeerInfos

proc dialBackedOff(kad: KadDHT, peerId: PeerId): bool {.raises: [].} =
  ## A refused dial holds the peer back until its backoff ends; then it gets asked again.
  kad.probeBackedOff(peerId, kad.dialAddrs(peerId))

proc sortedShortlist(
    state: LookupState, excludeResponded: bool = true
): seq[(PeerId, XorDistance)] =
  ## Closest first, without peers we cannot dial, so lookup results skip them too.
  var sortedShortlist = newSeqOfCap[(PeerId, XorDistance)](state.shortlist.len)

  let selfPid = state.kad.switch.peerInfo.peerId

  for pid, dist in state.shortlist.pairs():
    if pid == selfPid:
      # do not return self
      continue
    if excludeResponded and state.responded.getOrDefault(pid) == Success:
      continue
    if state.attempts.getOrDefault(pid, 0) > state.kad.config.retries:
      # depleted retries, do not query again
      continue
    if state.kad.dialBackedOff(pid):
      continue
    sortedShortlist.add((pid, dist))

  sortedShortlist.sort(
    proc(a, b: (PeerId, XorDistance)): int =
      cmp(a[1], b[1])
  )

  return sortedShortlist

proc selectCloserPeers*(
    state: LookupState, amount: int, excludeResponded: bool = true
): seq[PeerId] =
  ## Select closer `amount` peers
  return state
    .sortedShortlist(excludeResponded)
    # get pid
    .mapIt(it[0])
    # take at most alpha peers
    .take(amount)

proc hasResponsesFromClosest*(
    state: LookupState, amount: int
): bool {.raises: [], gcsafe.} =
  ## True when `amount` of the closest peers already answered successfully,
  ## counting from the closest and stopping at the first one never queried.
  ## An empty shortlist counts as converged: there is nobody left to wait for.
  let candidates = state.sortedShortlist(excludeResponded = false)
  if candidates.len == 0:
    return true

  var closestRespondedCnt = 0
  for (c, _) in candidates:
    if not state.responded.hasKey(c):
      # It's a close peer but has not been queried yet
      break
    if state.responded.getOrDefault(c) == RespondedStatus.Success:
      closestRespondedCnt.inc(1)

  closestRespondedCnt >= amount

proc hasConverged*(state: LookupState): bool {.raises: [], gcsafe.} =
  # Both config fields are public and mutable, so pin the range at the point of use.
  let beta = max(1, min(state.kad.config.beta, state.kad.config.replication))
  state.hasResponsesFromClosest(beta)

proc followUpPeers*(state: LookupState): HashSet[PeerId] {.raises: [].} =
  ## The `replication` closest peers heard about that never answered.
  state
    .selectCloserPeers(amount = state.kad.config.replication, excludeResponded = false)
    .filterIt(state.responded.getOrDefault(it) != RespondedStatus.Success)
    .toHashSet()

proc allSortedPeers*(state: LookupState): seq[PeerId] =
  ## Returns all peers discovered during lookup sorted by XOR distance to target (closest first).
  state.sortedShortlist(excludeResponded = false).mapIt(it[0])

proc init*(
    T: type LookupState, kad: KadDHT, target: Key, rtable: RoutingTable
): T {.raises: [].} =
  ## Seeds and ranks with `rtable`; falls back to the main table when it has nobody to ask.
  let res = LookupState(kad: kad, rtable: rtable, target: target)

  var seeds = rtable.findClosestPeerIds(target, kad.config.replication)
  if seeds.len == 0:
    seeds = kad.rtable.findClosestPeerIds(target, kad.config.replication)

  for pid in seeds:
    res.shortlist[pid] = xorDistance(pid, target, rtable.config.hasher)

  res

proc init*(T: type LookupState, kad: KadDHT, target: Key): T {.raises: [].} =
  LookupState.init(kad, target, kad.rtable)

proc dispatchFindNode*(
    kad: KadDHT,
    peer: PeerId,
    target: Key,
    addrs: Opt[seq[MultiAddress]] = Opt.none(seq[MultiAddress]),
): Future[LPResult[Message]] {.async: (raises: [CancelledError]), gcsafe.} =
  let msg = Message(msgType: Opt.some(MessageType.findNode), key: Opt.some(target))
  await kad.dispatchRpc(peer, msg, addrs)

proc recordAddrs(
    switch: Switch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    confidence = AddressConfidence.Low,
) {.raises: [].} =
  switch.peerStore[AddressBook].extend(peerId, addrs, confidence)

proc updatePeers*(
    switch: Switch,
    addressPolicy: PeerAddressPolicy,
    rtable: RoutingTable,
    peerInfos: seq[PeerInfo],
    caps: DiversityCaps,
) {.raises: [].} =
  ## Unprobed admission, for trusted seed peers only; see ``admitPeers``.
  for p in peerInfos:
    let addrs = switch.admissibleAddrs(addressPolicy, rtable, p, caps)
    if addrs.len == 0:
      continue
    switch.recordAddrs(p.peerId, addrs, AddressConfidence.Medium)
    discard rtable.insert(p.peerId)

proc updatePeers*(kad: KadDHT, peerInfos: seq[PeerInfo]) {.raises: [].} =
  updatePeers(
    kad.switch,
    kad.config.addressPolicy,
    kad.rtable,
    peerInfos,
    kad.config.limits.diversityCaps(),
  )

func toPeerInfos*(peers: seq[(PeerId, seq[MultiAddress])]): seq[PeerInfo] =
  peers.mapIt(PeerInfo(peerId: it[0], addrs: it[1]))

proc updatePeers*(kad: KadDHT, peers: seq[(PeerId, seq[MultiAddress])]) {.raises: [].} =
  kad.updatePeers(peers.toPeerInfos())

proc lookupCheck*(
    kad: KadDHT, peerId: PeerId, addrs: seq[MultiAddress]
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## A FIND_NODE for the peer's own key proves it is reachable and speaks DHT.
  ## Used for admission probes and for routing-table liveness checks.
  let probe = kad.dispatchFindNode(peerId, peerId.toKey(), Opt.some(addrs))
  # A probe abandoned on timeout keeps its stream open, so always settle it.
  defer:
    await noCancel probe.cancelAndWait()
  discard await probe.withTimeout(kad.config.timeout)
  if not probe.completed():
    trace "Kad probe timed out", peerId, timeout = kad.config.timeout
    return false
  let reply = probe.value().valueOr:
    trace "Kademlia probe failed", peerId, err = error
    return false
  reply.msgType == Opt.some(MessageType.findNode)

proc admitPeer(
    kad: KadDHT,
    rtable: RoutingTable,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    onAdmit: AdmitHook,
) {.async: (raises: []).} =
  let reachable =
    try:
      await kad.lookupCheck(peerId, addrs)
    except CancelledError:
      return
  if not reachable:
    trace "Kad admission probe failed, not inserting peer", peerId
    kad.probeRecordFailure(peerId, addrs)
    return
  kad.probeClearFailures(peerId)
  # A seat outlives Low's TTL, so the addresses behind it must outlive it too.
  kad.switch.recordAddrs(peerId, addrs, AddressConfidence.Medium)

  # Table may have been detachAll'd (e.g. service uninterest) while the probe ran.
  if rtable.detached:
    trace "Kad admission probe abandoned: table detached", peerId
    return
  if rtable.insert(peerId, probed = true) and not onAdmit.isNil():
    onAdmit(peerId)

proc trackProbe(kad: KadDHT, probeKey: ProbeKey, probe: Future[void]) {.raises: [].} =
  ## ``probe`` may already be done — a dial can fail without ever suspending.
  if probe.finished():
    return
  kad.admissionProbes[probeKey] = probe
  probe.addCallback(
    proc(udata: pointer) {.gcsafe, raises: [].} =
      if kad.admissionProbes.getOrDefault(probeKey) == probe:
        kad.admissionProbes.del(probeKey)
  )

proc tryRefreshAdmitted(rtable: RoutingTable, peerId: PeerId): bool {.raises: [].} =
  ## True when the peer already holds a seat, refreshing it instead of re-probing.
  if peerId.toKey() notin rtable:
    return false
  discard rtable.insert(peerId)
  true

proc scheduleAdmissionProbe(
    kad: KadDHT,
    rtable: RoutingTable,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    onAdmit: AdmitHook,
): bool {.raises: [].} =
  ## False when no probe starts; the candidate is retried on a later reply.
  let probeKey: ProbeKey = (rtable.selfId, peerId)
  if kad.admissionProbes.hasKey(probeKey):
    return false

  if kad.probeBackedOff(peerId, addrs):
    trace "Kad admission probe backed off", peerId
    kad_admission_probes_backed_off.inc()
    return false

  if not kad.admissionSem.tryAcquire():
    trace "Kad admission probe dropped: no free slot", peerId
    kad_admission_probes_dropped.inc()
    return false

  let probe = kad.admitPeer(rtable, peerId, addrs, onAdmit)
  probe.addCallback(
    proc(udata: pointer) {.gcsafe, raises: [].} =
      try:
        kad.admissionSem.release()
      except AsyncSemaphoreError:
        raiseAssert "admissionSem released without acquire"
  )
  kad.trackProbe(probeKey, probe)
  true

proc admitPeers*(
    kad: KadDHT,
    rtable: RoutingTable,
    peerInfos: seq[PeerInfo],
    onAdmit: AdmitHook = nil,
) {.raises: [].} =
  ## Records the addresses, then admits into ``rtable`` behind a background probe.

  # A probe launched while stopping dials past the drain loop and leaks its stream.
  if kad.stopping:
    return
  let selfPid = kad.switch.peerInfo.peerId
  var pending = kad.pendingAdmissions(rtable.selfId)
  for p in peerInfos:
    if p.peerId == selfPid:
      continue
    let addrs = kad.admissibleAddrs(rtable, p, pending)
    if addrs.len == 0:
      continue
    kad.switch.recordAddrs(p.peerId, addrs)
    if rtable.tryRefreshAdmitted(p.peerId):
      continue
    if not kad.scheduleAdmissionProbe(rtable, p.peerId, addrs, onAdmit):
      continue
    pending.add(p.peerId)

proc admitPeers*(kad: KadDHT, peerInfos: seq[PeerInfo]) {.raises: [].} =
  kad.admitPeers(kad.rtable, peerInfos)

proc noopReply*(
    peerId: PeerId, msgOpt: Opt[Message], state: LookupState
): Future[void] {.async: (raises: []), gcsafe.} =
  discard

proc noEarlyExit*(state: LookupState): bool {.raises: [], gcsafe.} =
  ## Default for a lookup that wants the k closest peers and nothing else.
  false

proc findNodeDispatch*(
    kad: KadDHT, peer: PeerId, target: Key
): Future[LPResult[Message]] {.async: (raises: [CancelledError]), gcsafe.} =
  return await dispatchFindNode(kad, peer, target)

type DispatchOutcome = enum
  Completed
  Errored
  Unreachable

type DispatchResult = object
  peer: PeerId
  outcome: DispatchOutcome
  msg: Message

type RpcFuture = Future[DispatchResult].Raising([CancelledError])

type Attempt = object
  peer: PeerId
  fut: RpcFuture
  deadline: Moment
  abandoned: bool
    ## its ``timeout`` elapsed; the slot is freed but the RPC
    ## keeps running so it can still deliver, and its late result is ignored.

proc dispatchPeer(
    kad: KadDHT, peerId: PeerId, target: Key, dispatch: DispatchProc
): Future[DispatchResult] {.async: (raises: [CancelledError]).} =
  let res = await dispatch(kad, peerId, target)
  if res.isErr():
    let err = res.error()
    if res.isOfError($refusedStage):
      trace "Kademlia RPC dial failed", err, peerId, protocol = kad.codec
      return DispatchResult(peer: peerId, outcome: Unreachable)

    if res.isOfError($dialStage):
      trace "Kademlia RPC stream establishment failed",
        err, peerId, protocol = kad.codec
    elif res.isOfError($waitStage):
      trace "Kademlia RPC stream wait timed out", err, peerId, protocol = kad.codec
    elif res.isOfError($writeStage):
      trace "Kademlia RPC write failed", err, peerId, protocol = kad.codec
    else:
      trace "Kademlia RPC read failed", err, peerId, protocol = kad.codec
    return DispatchResult(peer: peerId, outcome: Errored)
  DispatchResult(peer: peerId, outcome: Completed, msg: res.value())

func activePeers(pending: seq[Attempt]): HashSet[PeerId] {.raises: [].} =
  var peers = initHashSet[PeerId]()
  for a in pending:
    if not a.abandoned:
      peers.incl(a.peer)
  peers

proc dropUndialable(
    kad: KadDHT, state: LookupState, candidates: seq[PeerId]
): seq[PeerId] {.raises: [].} =
  ## Returns the candidates that can still be dialed, dropping the rest.
  var dialable: seq[PeerId]
  for peerId in candidates:
    if kad.isDialable(peerId):
      dialable.add(peerId)
    else:
      state.dropPeer(peerId)
      kad_lookup_undialable_peers.inc()
  dialable

proc fillSlots(
    kad: KadDHT,
    state: LookupState,
    pending: var seq[Attempt],
    dispatch: DispatchProc,
    candidates: seq[PeerId],
) {.raises: [].} =
  ## Keep up to ``alpha`` RPCs in flight by dispatching the next-closest
  ## not-yet-active ``candidates`` into any free slots.
  var active = pending.activePeers()
  let target = state.target
  for peerId in candidates:
    if active.len >= kad.config.alpha:
      break
    if peerId in active:
      continue
    state.attempts[peerId] = state.attempts.getOrDefault(peerId, 0) + 1
    trace "Kademlia lookup query started", peerId
    pending.add(
      Attempt(
        peer: peerId,
        fut: kad.dispatchPeer(peerId, target, dispatch),
        deadline: Moment.now() + kad.config.timeout,
        abandoned: false,
      )
    )
    active.incl(peerId)

proc awaitProgress(pending: seq[Attempt]) {.async: (raises: [CancelledError]).} =
  ## Wake as soon as any in-flight RPC finishes or the earliest active slot's
  ## ``timeout`` elapses, whichever comes first.
  var earliest = Opt.none(Moment)
  for a in pending:
    if not a.abandoned and (earliest.isNone or a.deadline < earliest.get()):
      earliest = Opt.some(a.deadline)

  let timer = sleepAsync(
    if earliest.isSome:
      max(earliest.get() - Moment.now(), ZeroDuration)
    else:
      InfiniteDuration
  )
  defer:
    timer.cancelSoon()

  var futs = pending.mapIt(FutureBase(it.fut))
  futs.add(FutureBase(timer))
  try:
    discard await race(futs)
  except ValueError:
    raiseAssert "race() cannot raise ValueError on a non-empty future list"

proc harvestInflight(
    pending: var seq[Attempt], now: Moment
): seq[DispatchResult] {.raises: [].} =
  ## Collect the replies of finished, still-relevant RPCs and drop them, and
  ## mark overdue in-flight RPCs abandoned so their slot frees while they keep
  ## running. A late reply is ignored, except a failed dial, which ends the retries.
  var completed: seq[DispatchResult]
  var stillPending: seq[Attempt]
  for a in pending:
    if a.fut.finished():
      if not a.fut.cancelled() and
          (not a.abandoned or a.fut.value().outcome == Unreachable):
        completed.add(a.fut.value())
      continue
    if not a.abandoned and now >= a.deadline:
      stillPending.add(
        Attempt(peer: a.peer, fut: a.fut, deadline: a.deadline, abandoned: true)
      )
    else:
      stillPending.add(a)
  pending = stillPending
  completed

proc applyReplies(
    kad: KadDHT,
    state: LookupState,
    rtable: RoutingTable,
    completed: seq[DispatchResult],
    onReply: ReplyHandler,
) {.async: (raises: [CancelledError]).} =
  # Successes first, so a retry that answered outranks a late failure of the same peer.
  for res in completed.sortedByIt(it.outcome != Completed):
    if state.responded.getOrDefault(res.peer) == RespondedStatus.Success:
      continue

    case res.outcome
    of Errored:
      state.responded[res.peer] = RespondedStatus.Failed
    of Unreachable:
      state.responded[res.peer] = RespondedStatus.Failed
      kad.probeRecordFailure(res.peer, kad.dialAddrs(res.peer))
    of Completed:
      state.responded[res.peer] = RespondedStatus.Success
      # A reply proves the peer useful; retain it through eviction.
      rtable.markUseful(res.peer)
      kad.probeClearFailures(res.peer)
      let newPeerInfos = state.updateShortlist(res.msg)
      kad.admitPeers(rtable, newPeerInfos)
      await onReply(res.peer, Opt.some(res.msg), state)

proc dropDonePeers(
    state: LookupState, pending: var seq[Attempt]
): seq[RpcFuture] {.raises: [].} =
  ## Remove the attempts of done peers (answered, evicted from the shortlist, backed
  ## off, or abandoned with no retries left) and return their live RPCs to cancel.
  ## Any other failure keeps the peer, so the retry that `fillSlots` sent keeps running.
  var keep: seq[Attempt]
  var stale: seq[RpcFuture]
  for a in pending:
    let succeeded = state.responded.getOrDefault(a.peer) == RespondedStatus.Success
    let retriesDepleted =
      a.abandoned and state.attempts.getOrDefault(a.peer, 0) > state.kad.config.retries
    if succeeded or not state.shortlist.hasKey(a.peer) or retriesDepleted or
        state.kad.dialBackedOff(a.peer):
      stale.add(a.fut)
    else:
      keep.add(a)
  pending = keep
  stale

type LookupPhase = enum
  Core ## converge on the closest `beta` peers
  FollowUp ## sweep the k closest peers that have not answered

type LookupPhases = object
  phase: LookupPhase
  sweep: HashSet[PeerId] ## the peers the running sweep targets
  swept: HashSet[PeerId] ## every peer some sweep already targeted

proc targets(phases: LookupPhases, state: LookupState): seq[PeerId] {.raises: [].} =
  ## Peers still worth querying in the running phase, closest first.
  let closest = state.sortedShortlist().mapIt(it[0])
  case phases.phase
  of Core:
    if state.hasConverged():
      @[]
    else:
      closest
  of FollowUp:
    # The set is fixed when the sweep starts, so a peer heard about mid-sweep
    # waits for the next round and one sweep cannot grow without end.
    closest.filterIt(it in phases.sweep)

proc advance(phases: var LookupPhases, state: LookupState): bool {.raises: [].} =
  ## Open the next phase now that the running one has nothing left in flight.
  ## False when neither phase has work left, which ends the lookup.
  if phases.phase == FollowUp:
    # The sweep drained, and its replies may name closer peers. Let the core
    # phase converge on those before sweeping again.
    phases.phase = Core
    return true

  # Sweeping a peer twice is what would let the two phases alternate forever.
  let sweep = state.followUpPeers() - phases.swept
  if sweep.len == 0:
    return false

  if phases.swept.len == 0:
    kad_lookup_followups.inc()
  phases.swept.incl(sweep)
  phases.sweep = sweep
  phases.phase = FollowUp
  true

proc iterativeLookup*(
    kad: KadDHT,
    target: Key,
    rtable: RoutingTable,
    dispatch: DispatchProc,
    onReply: ReplyHandler,
    earlyExit: EarlyExit = noEarlyExit,
): Future[LookupState] {.async: (raises: [CancelledError]).} =
  ## Drive lookup with continuous ``alpha`` concurrency instead of synchronized
  ## rounds. Timed-out RPCs free their slot and may be retried; late replies are
  ## ignored. An ``earlyExit`` ends the lookup on the spot, follow-up sweep
  ## included, since its caller already has what it asked for. Until it holds,
  ## the lookup alternates core and follow-up until the k closest peers it knows
  ## of have all been queried.
  let state = LookupState.init(kad, target, rtable)
  var pending: seq[Attempt]
  var phases = LookupPhases(phase: Core)
  var queried, replies, failed: int
  var outcome = "cancelled"

  # `noCancel`: when the lookup itself is cancelled, still wait for every RPC to
  # unwind, otherwise we return while their streams are still closing.
  defer:
    let inflight = pending.mapIt(it.fut)
    await noCancel inflight.cancelAndWait()
    debug "Kademlia lookup finished",
      target,
      outcome,
      queried,
      replies,
      failed,
      withoutReply = queried - replies - failed,
      peers = state.shortlist.len

  while true:
    let completed = pending.harvestInflight(Moment.now())
    for reply in completed:
      if reply.outcome == Completed:
        replies.inc()
      else:
        failed.inc()
    await kad.applyReplies(state, rtable, completed, onReply)
    # `dropDonePeers` already removed these from `pending`, so the `defer` above
    # no longer covers them: they must be awaited to completion here. Bind first:
    # `cancelAndWait` is a template that would evaluate the call more than once.
    let stale = state.dropDonePeers(pending)
    await noCancel stale.cancelAndWait()

    if not earlyExit(state):
      let candidates = kad.dropUndialable(state, phases.targets(state))
      let before = pending.len
      kad.fillSlots(state, pending, dispatch, candidates)
      queried += pending.len - before

    # Dispatching nothing new only stops the lookup once the RPCs already in
    # flight have drained, so the returned peer set stays complete.
    if pending.activePeers().len > 0:
      await awaitProgress(pending)
      continue

    if earlyExit(state):
      outcome = "earlyExit"
      break
    if not phases.advance(state):
      outcome = "completed"
      break

  state

proc iterativeLookup*(
    kad: KadDHT,
    target: Key,
    dispatch: DispatchProc,
    onReply: ReplyHandler,
    earlyExit: EarlyExit = noEarlyExit,
): Future[LookupState] {.async: (raises: [CancelledError]).} =
  await kad.iterativeLookup(target, kad.rtable, dispatch, onReply, earlyExit)

method findNode*(
    kad: KadDHT, target: Key, rtable: RoutingTable
): Future[seq[PeerId]] {.base, async: (raises: [CancelledError]).} =
  ## Iteratively search for the k closest peers to a `target` key.
  let state = await kad.iterativeLookup(target, rtable, findNodeDispatch, noopReply)

  return state.selectCloserPeers(kad.config.replication, excludeResponded = false)

method findNode*(
    kad: KadDHT, target: Key
): Future[seq[PeerId]] {.base, async: (raises: [CancelledError]).} =
  await kad.findNode(target, kad.rtable)

proc findPeer*(
    kad: KadDHT, target: PeerId
): Future[LPResult[PeerInfo]] {.async: (raises: [CancelledError]).} =
  ## Walks the key space until it finds candidate addresses for a `target` peer Id

  if kad.switch.peerInfo.peerId == target:
    # Looking for yourself.
    return ok(kad.switch.peerInfo)

  if kad.switch.isConnected(target):
    # Return known info about already connected peer
    return
      ok(PeerInfo(peerId: target, addrs: kad.switch.peerStore[AddressBook][target]))

  let foundNodes = await kad.findNode(target.toKey())
  if not foundNodes.contains(target):
    return err("peer not found")

  return ok(PeerInfo(peerId: target, addrs: kad.switch.peerStore[AddressBook][target]))

proc findClosestPeers*(kad: KadDHT, target: Key, requester: PeerId): seq[Peer] =
  ## Over-fetches by `excluded.len` so dropping self and `requester` still fills the reply.
  let excluded = [kad.switch.peerInfo.peerId.toKey(), requester.toKey()]
  let closestPeerKeys = kad.rtable
    .findClosest(target, kad.config.replication + excluded.len)
    .filterIt(it notin excluded)

  return kad.switch.toPeers(
    closestPeerKeys[0 ..< min(kad.config.replication, closestPeerKeys.len)]
  )

proc findNodeCloserPeers(kad: KadDHT, target: Key, requester: PeerId): seq[Peer] =
  ## Also returns the target itself, which keeps client-mode peers resolvable.
  let closest = kad.findClosestPeers(target, requester)
  if target == requester.toKey():
    return closest

  let targetPeer = target.toPeer(kad.switch).valueOr:
    return closest

  if closest.len > 0 and closest[0].id == targetPeer.id:
    return closest

  return @[targetPeer] & closest

method handleFindNode*(
    kad: KadDHT, stream: Stream, msg: Message
) {.base, async: (raises: [CancelledError]).} =
  let msgKey = msg.key.valueOr:
    trace "Find-node request rejected",
      reason = "missingKey", messageType = "findNode", stream
    return

  let response = Message(
    msgType: Opt.some(MessageType.findNode),
    closerPeers: kad.findNodeCloserPeers(msgKey, stream.peerId),
  )
  let encoded = response.encode(kad.config.hideConnectionStatus)
  kad_message_bytes_sent.inc(encoded.len.int64, labelValues = [$MessageType.findNode])
  try:
    await stream.writeLp(encoded)
  except LPStreamError as exc:
    trace "Kademlia find-node RPC reply write failed",
      err = exc.msg, stream, messageType = $MessageType.findNode
    return

  # Only admit senders with known dialable addresses; an inbound connection
  # may use an ephemeral source port.
  let addrs = kad.switch.peerStore[AddressBook][stream.peerId]
  if addrs.len > 0:
    kad.admitPeers(@[PeerInfo(peerId: stream.peerId, addrs: addrs)])
