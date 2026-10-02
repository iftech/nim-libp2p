# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sequtils, tables]
import chronos, chronicles, results
import ../utils/[heartbeat, future]
import ../logging
import ../[peerid, switch, multihash]
import ./protocol
import
  ./kademlia/[
    routing_table, peer_registry, protobuf, types, find, get, put, keyspace, provider,
    ping, ip_diversity,
  ]
import ./kademlia/[kademlia_metrics, netsize, probe_backoff, rpc]

export
  chronicles, routing_table, peer_registry, protobuf, types, find, get, put, keyspace,
  provider, ping, kademlia_metrics, netsize, probe_backoff, ip_diversity

logScope:
  topics = "libp2p kademlia"

const KadCodec* = "/ipfs/kad/1.0.0"

proc peersPastGracePeriod(
    rtable: RoutingTable, gracePeriod: Duration
): seq[PeerId] {.raises: [].} =
  ## Peers past the liveness grace period that should be probed.
  let now = Moment.now()
  var peers: seq[PeerId]
  for bucket in rtable.buckets:
    for nodeId in bucket.peers:
      if not rtable.registry.isReplaceable(nodeId, rtable.selfId, gracePeriod, now):
        continue
      nodeId.toPeerId().ifValue(pid):
        peers.add(pid)
  peers

method maintainableTables*(
    kad: KadDHT
): seq[RoutingTable] {.base, gcsafe, raises: [].} =
  ## Routing tables the liveness loop should keep healthy. Service discovery
  ## overrides this to include per-service tables.
  @[kad.rtable]

proc trackLivenessProbe(
    kad: KadDHT, peerId: PeerId, probe: Future[void]
) {.raises: [].} =
  ## ``probe`` may already be done — a dial can fail without ever suspending.
  if probe.finished():
    return
  kad.livenessProbes[peerId] = probe
  probe.addCallback(
    proc(udata: pointer) {.gcsafe, raises: [].} =
      if kad.livenessProbes.getOrDefault(peerId) == probe:
        kad.livenessProbes.del(peerId)
  )

proc checkAndEvictPeer(
    kad: KadDHT, peerId: PeerId
) {.async: (raises: [CancelledError]).} =
  ## Probes a peer once and applies the result to every maintainable table
  ## where that peer is past the liveness grace period. Returns immediately
  ## when all liveness probe slots are occupied.
  if kad.stopping:
    return
  if not kad.livenessSem.tryAcquire():
    trace "Liveness probe skipped: no free slot", peerId
    kad_routing_table_liveness_probes.inc(labelValues = ["skipped"])
    return
  defer:
    try:
      kad.livenessSem.release()
    except AsyncSemaphoreError:
      raiseAssert "livenessSem released without acquire"

  # Candidate list is a snapshot; by the time a slot is free the peer may have
  # been refreshed (markUseful) or removed, and stop may have begun.
  if kad.stopping:
    return
  let grace = kad.config.livenessGracePeriod
  var dueTables: seq[RoutingTable]
  for rtable in kad.maintainableTables():
    if rtable.isReplaceable(peerId, grace, Moment.now()):
      dueTables.add(rtable)
  if dueTables.len == 0:
    trace "Liveness probe skipped: peer no longer replaceable", peerId
    return

  let addrs = kad.dialAddrs(peerId)
  if addrs.len == 0:
    var evicted = 0
    for rtable in dueTables:
      # Re-check: peer may have been markUseful'd after the snapshot.
      if not rtable.isReplaceable(peerId, grace, Moment.now()):
        continue
      discard rtable.removePeer(peerId, reason = "liveness")
      inc evicted
    if evicted > 0:
      trace "Evicting peer with no known addresses", peer = peerId, tables = evicted
      kad_routing_table_liveness_probes.inc(labelValues = ["no_addrs"])
    else:
      trace "Liveness probe skipped: peer no longer replaceable", peer = peerId
    return

  trace "Probing peer for liveness", peerId, tables = dueTables.len
  if (await kad.lookupCheck(peerId, addrs)):
    trace "Liveness probe succeeded", peerId
    # Peer is reachable: one registry write refreshes usefulness for every index.
    kad.rtable.markUseful(peerId)
    kad_routing_table_liveness_probes.inc(labelValues = ["ok"])
    return

  # Probe can race with unrelated traffic that markUseful'd the peer mid-flight.
  var evicted = 0
  for rtable in dueTables:
    if not rtable.isReplaceable(peerId, grace, Moment.now()):
      continue
    discard rtable.removePeer(peerId, reason = "liveness")
    inc evicted
  if evicted == 0:
    trace "Liveness probe failed but peer refreshed mid-flight", peer = peerId
    return

  trace "Evicting unresponsive peer after liveness probe",
    peer = peerId, tables = evicted
  kad_routing_table_liveness_probes.inc(labelValues = ["fail"])

proc launchLivenessProbe(kad: KadDHT, peers: openArray[PeerId]): int {.raises: [].} =
  ## Starts a liveness probe unless one is already in flight
  var launchedProbesCount = 0
  for peerId in peers:
    if not kad.livenessProbes.hasKey(peerId):
      trace "Launching liveness probe", peerId
      launchedProbesCount.inc
      kad.trackLivenessProbe(peerId, kad.checkAndEvictPeer(peerId))
  launchedProbesCount

proc probeAndEvictPeers*(
    kad: KadDHT, rtable: RoutingTable
) {.async: (raises: [CancelledError]).} =
  ## One-shot batch: probes routing-table peers past the liveness grace period
  ## and removes those that fail to answer a FIND_NODE. Used by tests and any
  ## explicit maintenance call; production traffic uses ``maintainLiveness``.
  ## Peers already being probed (e.g. from another table) are awaited, not
  ## re-probed.
  if kad.stopping:
    return

  let peers = rtable.peersPastGracePeriod(kad.config.livenessGracePeriod)
  if peers.len == 0:
    return

  trace "Liveness batch starting", peers = peers.len
  var futs = newSeqOfCap[Future[void]](peers.len)
  var reused = 0
  defer:
    debug "Liveness batch finished",
      peers = peers.len,
      reused,
      completed = futs.countIt(it.completed()),
      cancelled = futs.countIt(it.cancelled()),
      remainingInTable = peers.countIt(rtable.contains(it.toKey()))

  for peerId in peers:
    kad.livenessProbes.withValue(peerId, existing):
      reused.inc()
      futs.add(existing[])
      continue
    let fut = kad.checkAndEvictPeer(peerId)
    kad.trackLivenessProbe(peerId, fut)
    futs.add(fut)

  if futs.len > 0:
    try:
      await allFutures(futs)
    except CancelledError as exc:
      await noCancel futs.cancelAndWait()
      raise exc

proc maintainLiveness(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  ## Continuous background task: drain replaceable peers via liveness probes
  ## as soon as they become due, bounded by ``livenessSem``. Independent of
  ## bucket refresh so dead peers are not held until the next refresh tick.
  ## At most one probe is in flight per peer across all maintainable tables.

  while not kad.stopping:
    var launchedProbesCount = 0
    for rtable in kad.maintainableTables():
      let peers = rtable.peersPastGracePeriod(kad.config.livenessGracePeriod)
      launchedProbesCount += kad.launchLivenessProbe(peers)

    if launchedProbesCount > 0:
      trace "Liveness scan found replaceable peers", launchedProbesCount

    # one() on a finished future completes without a yield, so the loop spins.
    let inFlight = kad.livenessProbes.values.toSeq().filterIt(not it.finished())
    if inFlight.len == 0:
      await sleepAsync(kad.config.livenessIdleInterval)
      continue

    trace "Waiting for in-flight liveness probes", inFlight = inFlight.len
    try:
      discard await one(inFlight)
    except ValueError:
      raiseAssert "inFlight is not empty"
    except CancelledError as exc:
      await noCancel inFlight.cancelAndWait()
      raise exc

proc centerTarget(kad: KadDHT, rtable: RoutingTable): Opt[Key] {.raises: [].} =
  ## A table with no peers of its own borrows the main table's peers to start the walk.
  rtable.refreshSelfTarget().ifValue(own):
    return Opt.some(own)
  rtable.nearestToCenter(kad.rtable.allKeys())

proc refreshCenter(
    kad: KadDHT, rtable: RoutingTable
) {.async: (raises: [CancelledError]).} =
  let target = kad.centerTarget(rtable).valueOr:
    trace "No refresh target for table center", table = rtable.selfId
    return
  discard await kad.findNode(target, rtable)

proc refreshTable*(
    kad: KadDHT, rtable: RoutingTable, forceRefresh = false
) {.async: (raises: [CancelledError]).} =
  ## Sends a findNode toward the table's own center, then one per non-empty k-bucket.

  await kad.refreshCenter(rtable)

  var targets = newSeqOfCap[Key](rtable.buckets.len)
  for i in 0 ..< rtable.buckets.len:
    let bucket = rtable.buckets[i]

    # skip empty buckets
    if bucket.peers.len == 0:
      continue

    # skip if refresh conditions not met (forceRefresh OR stale bucket)
    if not (forceRefresh or rtable.isStale(i)):
      continue

    let target = rtable.refreshTarget(i, kad.rng).valueOr:
      trace "No refresh target for bucket", bucket = i
      continue

    targets.add(target)

  let futs = targets.mapIt(kad.findNode(it, rtable))

  try:
    await allFutures(futs)
  except CancelledError as exec:
    await noCancel futs.cancelAndWait()
    raise exec

proc bootstrap*(
    kad: KadDHT, forceRefresh = false
) {.async: (raises: [CancelledError]).} =
  await kad.refreshTable(kad.rtable, forceRefresh)
  debug "Bootstrap complete"

proc bootstrapWithTimeout(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  let boot = kad.bootstrap(forceRefresh = true)
  if not await boot.withTimeout(kad.config.bootstrapTimeout):
    await noCancel boot.cancelAndWait()
    warn "Bootstrap timed out", timeout = kad.config.bootstrapTimeout

proc waitBootstrap*(
    kad: KadDHT
): Future[void].Raising([CancelledError]) {.raises: [].} =
  ## Completes once the bootstrap launched by ``start`` ends. Cancelling the
  ## returned future leaves the bootstrap running.
  if kad.bootstrapFut.isNil():
    let done = Future[void].Raising([CancelledError]).init("KadDHT.waitBootstrap")
    done.complete()
    return done
  join(kad.bootstrapFut)

proc maintainBuckets(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  var timedOut = false
  var warnings: LogRateLimit

  heartbeat "Refreshing buckets", kad.config.bucketRefreshTime, sleepFirst = true:
    let refresh = kad.refreshTable(kad.rtable, false)
    if not await refresh.withTimeout(kad.config.bucketRefreshTime):
      await noCancel refresh.cancelAndWait()
      if timedOut and warnings.allowLog():
        warn "Routing table refresh repeatedly timed out",
          timeout = kad.config.bucketRefreshTime, peers = kad.rtable.peerCount()
      timedOut = true
    else:
      timedOut = false

proc connectedPeerInfos(kad: KadDHT): seq[PeerInfo] {.raises: [].} =
  ## Currently connected peers that we know an address for.
  let addressBook = kad.switch.peerStore[AddressBook]
  var infos: seq[PeerInfo]
  for peerId in kad.switch.connectedPeers():
    let addrs = addressBook[peerId]
    if addrs.len == 0:
      continue
    infos.add(PeerInfo(peerId: peerId, addrs: addrs))
  infos

proc fixLowPeers*(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  ## Re-seed a table that shrank below ``config.minRoutingTableSize``.
  if kad.stopping or kad.config.disableBootstrapping:
    return

  let count = kad.rtable.peerCount()
  if count >= kad.config.minRoutingTableSize:
    return

  debug "Routing table below minimum, re-seeding",
    peers = count, minimum = kad.config.minRoutingTableSize
  kad_routing_table_reseeds.inc()

  kad.admitPeers(kad.rtable, kad.connectedPeerInfos())
  # Seed the trusted nodes too: the probes above only land after this pass.
  kad.updatePeers(kad.bootstrapNodes)

  await kad.refreshTable(kad.rtable, forceRefresh = true)

proc maintainMinPeers(kad: KadDHT) {.async.} =
  var
    timedOut = false
    previouslyLow = false
    reportedLow = false
    timeoutWarnings: LogRateLimit
    lowPeerWarnings: LogRateLimit

  heartbeat "Checking routing table size",
    kad.config.fixLowPeersInterval, sleepFirst = true:
    let peers = kad.rtable.peerCount()
    let lowPeers =
      not kad.config.disableBootstrapping and peers < kad.config.minRoutingTableSize
    if lowPeers and previouslyLow and lowPeerWarnings.allowLog():
      warn "Routing table remains below minimum",
        peers, minimum = kad.config.minRoutingTableSize
      reportedLow = true
    elif not lowPeers and reportedLow:
      info "Routing table recovered", peers, minimum = kad.config.minRoutingTableSize
      reportedLow = false
    previouslyLow = lowPeers
    let fix = kad.fixLowPeers()
    if not await fix.withTimeout(kad.config.fixLowPeersInterval):
      await noCancel fix.cancelAndWait()
      if timedOut and timeoutWarnings.allowLog():
        warn "Minimum peer maintenance repeatedly timed out",
          timeout = kad.config.fixLowPeersInterval,
          peers = kad.rtable.peerCount(),
          minimum = kad.config.minRoutingTableSize
      timedOut = true
    else:
      timedOut = false

proc initKadBase*(
    kad: KadDHT,
    switch: Switch,
    config: KadDHTConfig,
    rng: Rng,
    isServer: bool,
    codec: string,
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
) {.raises: [].} =
  ## Set the shared fields and seed the table, so a constructor cannot miss one.
  kad.rng = rng
  kad.switch = switch
  kad.rtable = RoutingTable.new(
    switch.peerInfo.peerId.toKey(),
    config = RoutingTableConfig.new(
      replication = config.replication,
      usefulnessGracePeriod = config.usefulnessGracePeriod,
      bucketStaleTime = config.bucketStaleTime,
    ),
  )
  kad.config = config
  kad.providerManager =
    ProviderManager.new(config.providerRecordCapacity, config.providedKeyCapacity)
  kad.nsEstimator = NetworkSizeEstimator.new(config.replication)
  kad.rpcSem = newAsyncSemaphore(config.limits.maxConcurrentRpcs)
  kad.admissionSem = newAsyncSemaphore(config.limits.maxConcurrentProbes)
  kad.livenessSem = newAsyncSemaphore(config.limits.maxConcurrentLivenessProbes)
  kad.isServer = isServer
  kad.codec = codec
  kad.msgSender = MessageSender.new(switch, codec, MaxMsgSize)
  kad.bootstrapNodes = bootstrapNodes.toPeerInfos()
  kad.updatePeers(kad.bootstrapNodes)

# K instead of T to avoid clashing with the T type param in ifValue[T] when
# called inside a ifValue block, which causes a compiler error under --lineDir:on
proc new*(
    K: typedesc[KadDHT],
    switch: Switch,
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
    config: KadDHTConfig = KadDHTConfig.new(),
    rng: Rng,
    isServer: bool = true,
    codec: string = KadCodec,
): K {.raises: [].} =
  let kad = K()
  kad.initKadBase(switch, config, rng, isServer, codec, bootstrapNodes)

  kad.handler = proc(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    if not kad.isServer:
      trace "Refusing inbound query while not serving", stream
      await stream.reset()
      return

    kad.serverStreams.incl(stream)
    defer:
      kad.serverStreams.excl(stream)
      await stream.close()
    while not stream.atEof:
      var buf =
        try:
          await stream.readLp(MaxMsgSize)
        except LPStreamEOFError:
          return
        except LPStreamError as exc:
          trace "Kademlia RPC request read failed",
            err = exc.msg, stream, peerId = stream.peerId, protocol = proto
          return
      let bufLen = buf.len
      let msg = Message.decode(move(buf)).valueOr:
        trace "Kademlia RPC request decode failed",
          err = error, peerId = stream.peerId, protocol = proto
        return

      let msgType = msg.msgType.get(MessageType.putValue)

      kad_messages_received.inc(labelValues = [$msgType])
      kad_message_bytes_received.inc(bufLen.int64, labelValues = [$msgType])

      case msgType
      of MessageType.findNode:
        await kad.handleFindNode(stream, msg)
      of MessageType.putValue:
        await kad.handlePutValue(stream, msg)
      of MessageType.getValue:
        await kad.handleGetValue(stream, msg)
      of MessageType.addProvider:
        await kad.handleAddProvider(stream, msg)
      of MessageType.getProviders:
        await kad.handleGetProviders(stream, msg)
      of MessageType.ping:
        await kad.handlePing(stream, msg)
      of MessageType.register:
        trace "Kademlia RPC request rejected",
          messageType = $MessageType.register, reason = "unsupported message type"
        continue
      of MessageType.getAds:
        trace "Kademlia RPC request rejected",
          messageType = $MessageType.getAds, reason = "unsupported message type"
        continue

  return kad

proc resetServerStreams(kad: KadDHT) {.async: (raises: []).} =
  let streams = kad.serverStreams
  kad.serverStreams.clear()
  await noCancel allFutures(streams.mapIt(it.reset()))
  trace "Reset inbound Kad DHT streams", streams = streams.len

proc changeMode*(kad: KadDHT, isServer: bool): Future[bool] {.async: (raises: []).} =
  ## Start or stop serving inbound queries, and report whether the mode changed.
  ## Stopping resets the in-flight inbound streams; the codec stays mounted (no
  ## unmount exists), so peers drop us once the handler refuses to serve.
  if isServer == kad.isServer:
    return false

  kad.isServer = isServer
  if not isServer:
    await kad.resetServerStreams()
  info "Kad DHT changed mode", previousIsServer = not isServer, isServer
  true

method start*(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  if kad.started:
    warn "Kademlia DHT already started"
    return

  kad.started = true
  kad.stopping = false
  kad.msgSender.start()

  if not kad.config.disableBootstrapping:
    kad.bootstrapFut = kad.bootstrapWithTimeout()
    reportBackgroundFailure(kad.bootstrapFut, "kademlia bootstrap")

  kad.maintenanceLoop = kad.maintainBuckets()
  kad.livenessLoop = kad.maintainLiveness()
  kad.fixLowPeersLoop = kad.maintainMinPeers()
  kad.republishLoop = kad.manageRepublishProvidedKeys()
  kad.expiredLoop = kad.manageExpiredProviders()
  kad.recordExpirationLoop = kad.manageExpiredRecords()

  reportBackgroundFailure(kad.maintenanceLoop, "kademlia bucket maintenance")
  reportBackgroundFailure(kad.livenessLoop, "kademlia peer liveness")
  reportBackgroundFailure(kad.fixLowPeersLoop, "kademlia minimum peer maintenance")
  reportBackgroundFailure(kad.republishLoop, "kademlia provider republishing")
  reportBackgroundFailure(kad.expiredLoop, "kademlia provider expiration")
  reportBackgroundFailure(kad.recordExpirationLoop, "kademlia record expiration")

  info "Kademlia DHT started"

method stop*(kad: KadDHT) {.async: (raises: []).} =
  if not kad.started:
    return

  # Set before any await so handlers racing shutdown stop launching probes; the
  # drain loop below can then finish for good rather than chasing new arrivals.
  kad.stopping = true
  kad.started = false

  if not kad.bootstrapFut.isNil():
    await noCancel kad.bootstrapFut.cancelAndWait()
    kad.bootstrapFut = nil

  await noCancel allFutures(
    kad.maintenanceLoop.cancelAndWait(),
    kad.livenessLoop.cancelAndWait(),
    kad.fixLowPeersLoop.cancelAndWait(),
    kad.republishLoop.cancelAndWait(),
    kad.expiredLoop.cancelAndWait(),
    kad.recordExpirationLoop.cancelAndWait(),
  )
  kad.maintenanceLoop = nil
  kad.livenessLoop = nil
  kad.fixLowPeersLoop = nil
  kad.republishLoop = nil
  kad.expiredLoop = nil
  kad.recordExpirationLoop = nil

  # loop: a handler racing shutdown can register a probe while we await a batch
  while kad.admissionProbes.len > 0 or kad.livenessProbes.len > 0:
    let admissionProbes = move kad.admissionProbes
    let livenessProbes = move kad.livenessProbes
    await noCancel allFutures(
      admissionProbes.values.toSeq().cancelAndWait(),
      livenessProbes.values.toSeq().cancelAndWait(),
    )

  # Optimistic provide returns before its ADD_PROVIDER RPCs finish.
  let provideTasks = move kad.provideTasks
  await noCancel provideTasks.cancelAndWait()

  # After the drain: nothing is left to reuse a stream, and `stop` refuses new ones.
  await kad.msgSender.stop()
