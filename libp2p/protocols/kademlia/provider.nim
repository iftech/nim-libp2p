# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Provider record management for the Kademlia DHT.
## Receivers always enforce ``KadDHTConfig.limits.maxProvidersPerKey``; when
## ``providerRejection`` is true they additionally reply accepted/rejected on
## field 11 so senders can spill over to farther peers. Without
## ``providerRejection`` the limit is enforced silently — over-cap
## advertisements are dropped without a reply.
## Re-advertisements are always accepted.

import std/[math, sequtils, tables, sets, heapqueue]
import chronos, chronicles, results
import ../../[peerid, switch, multihash, cid]
import ../../utils/[collections, heartbeat, future]
import ../protocol
import ./[protobuf, types, find, rpc, keyspace, netsize, kademlia_metrics]

logScope:
  topics = "libp2p kademlia"

proc `==`*(a, b: ProviderRecord): bool =
  a.provider.id == b.provider.id and a.key == b.key

# for HeapQueue
proc `<`*(a, b: ProviderRecord): bool =
  a.expiresAt < b.expiresAt

proc `<`*(a: ProviderRecord, b: chronos.Moment): bool =
  a.expiresAt < b

proc deleteOldest(pk: ProvidedKeys) =
  ## Delete oldest provided key from ProvidedKeys
  var oldest: Key
  var oldestMoment = chronos.Moment.now()
  for key, moment in pk.provided:
    if oldestMoment > moment:
      oldest = key
      oldestMoment = moment
  pk.provided.del(oldest)

proc isFull*(pk: ProvidedKeys): bool =
  pk.provided.len() >= pk.capacity

proc len*(pk: ProvidedKeys): int =
  pk.provided.len()

proc hasKey*(pk: ProvidedKeys, k: Key): bool =
  pk.provided.hasKey(k)

proc del*(pk: ProvidedKeys, k: Key) =
  pk.provided.del(k)

proc pop*(pr: ProviderRecords): ProviderRecord =
  pr.records.pop()

proc len*(pr: ProviderRecords): int =
  pr.records.len()

proc del*(pr: ProviderRecords, index: int) =
  pr.records.del(index)

proc find*(pr: ProviderRecords, record: ProviderRecord): int =
  pr.records.find(record)

proc push*(pr: ProviderRecords, record: ProviderRecord) =
  pr.records.push(record)

proc isFull*(pr: ProviderRecords): bool =
  pr.records.len() >= pr.capacity

proc `[]`*(pr: ProviderRecords, i: int): ProviderRecord =
  pr.records[i]

proc removeProviderRecord(pm: ProviderManager, record: ProviderRecord) =
  ## Remove provider record and related keys

  let recordIdx = pm.providerRecords.find(record)
  if recordIdx != -1:
    pm.providerRecords.del(recordIdx)

  try:
    pm.knownKeys[record.key].excl(record.provider)
    if pm.knownKeys[record.key].len() == 0:
      pm.knownKeys.del(record.key)
  except KeyError:
    return

proc addProviderRecord(pm: ProviderManager, record: ProviderRecord) =
  # remove previous providerRecord if any
  pm.removeProviderRecord(record)

  if pm.providerRecords.isFull():
    let oldest = pm.providerRecords.pop()
    pm.removeProviderRecord(oldest)

  if not pm.knownKeys.hasKey(record.key):
    pm.knownKeys[record.key] = initHashSet[Provider]()

  try:
    pm.knownKeys[record.key].incl(record.provider)

    pm.providerRecords.push(record)
  except KeyError:
    raiseAssert("checked with hasKey")

proc dispatchAddProvider(
    kad: KadDHT, peer: PeerId, key: Key
): Future[LPResult[AddProviderStatus]] {.async: (raises: [CancelledError]).} =
  withRpcSlot(kad)
  let addrs = kad.switch.peerStore[AddressBook][peer]

  let msg = Message(
    msgType: Opt.some(MessageType.addProvider),
    key: Opt.some(key),
    providerPeers: @[kad.switch.peerInfo.toPeer()],
  )
  var encoded = msg.encode(kad.config.hideConnectionStatus)
  let sentBytes = encoded.len.int64

  if not kad.config.providerRejection:
    let sendRes =
      await kad.msgSender.sendMessage(peer, addrs, move encoded, kad.config.timeout)
    sendRes.countSent(MessageType.addProvider, sentBytes)
    sendRes.isOkOr:
      return err(error)
    return ok(AddProviderStatus.accepted)

  let sendRes =
    await kad.msgSender.sendRequest(peer, addrs, move encoded, kad.config.timeout)
  sendRes.countSent(MessageType.addProvider, sentBytes)

  # Remotes without the accepted/rejected reply simply never answer, so only a
  # failure to reach the peer is an error; a silent read counts as accepted.
  let replyBuf = sendRes.valueOr:
    if error.stage != readStage:
      return err(error)
    return ok(AddProviderStatus.accepted)

  let reply = Message.decode(replyBuf).valueOr:
    return ok(AddProviderStatus.accepted)

  return ok(reply.providerStatus.get(AddProviderStatus.accepted))

proc sendBatch(kad: KadDHT, peers: seq[PeerId], key: Key): auto =
  peers.mapIt(kad.dispatchAddProvider(it, key))

proc countResults[T](rpcBatch: seq[T]): (int, int) =
  var accepted, rejected: int
  for fut in rpcBatch:
    if not fut.finished():
      discard # batch timeout fired before request completed
    elif not fut.completed():
      discard # transport/connection error or cancellation
    elif not fut.value().isOk():
      discard # protocol/decode error
    else:
      case fut.value().value()
      of AddProviderStatus.accepted:
        accepted.inc()
      of AddProviderStatus.rejected:
        rejected.inc()
  (accepted, rejected)

proc storeProviderAt(
    kad: KadDHT, key: Key, peers: seq[PeerId]
) {.async: (raises: [CancelledError]).} =
  ## Store this node as a provider of `key` at `peers`, ordered closest first.
  ## With `providerRejection`, a fully rejected batch spills over to the next,
  ## farther batch until `replication` peers accepted.
  var attempted, acceptedTotal, rejectedTotal, failed, cancelled, pending: int
  var outcome = "cancelled"
  defer:
    debug "Provider replication finished",
      key,
      outcome,
      attempted,
      accepted = acceptedTotal,
      rejected = rejectedTotal,
      failed,
      cancelled,
      pending

  template recordBatch(batch: untyped) =
    let (accepted, rejected) = batch.countResults()
    acceptedTotal += accepted
    rejectedTotal += rejected
    for fut in batch:
      if not fut.finished():
        pending.inc()
      elif fut.cancelled():
        cancelled.inc()
      elif fut.failed() or not fut.value().isOk():
        failed.inc()

  if not kad.config.providerRejection:
    for chunk in peers.take(kad.config.replication).toChunks(kad.config.alpha):
      let batch = kad.sendBatch(chunk, key)
      attempted += batch.len
      try:
        await batch.allFuturesWaitOrTimeout(kad.config.timeout)
      finally:
        recordBatch(batch)
    outcome = "completed"
    return

  var stored = 0
  for chunk in peers.toChunks(kad.config.alpha):
    if stored >= kad.config.replication:
      break
    let batch = kad.sendBatch(chunk, key)
    attempted += batch.len
    # Batch timeout must exceed the per-peer reply timeout to account for dial
    # time. Each future waits up to `timeout` for a reply *after* the dial
    # completes, so the batch timeout must outlast that wait; otherwise
    # non-rejection peers (which default to accepted on reply timeout) may
    # still be mid-wait when countResults runs and get skipped, causing the
    # stored count to be too low and triggering unnecessary spillover rounds.
    try:
      await batch.allFuturesWaitOrTimeout(kad.config.timeout + kad.config.timeout div 4)
    finally:
      recordBatch(batch)
    let (accepted, rejected) = batch.countResults()
    stored += accepted
    if accepted == 0 and rejected == chunk.len:
      kad_provider_spillover_rounds.inc()
      trace "ADD_PROVIDER batch fully rejected, spilling over",
        key = key, batchSize = chunk.len
  outcome = "completed"

const
  CertaintyPeerIsInClosestSet = 0.9
  ProbabilityOfStoppingWhileCloserPeersExist = 0.1
  FractionOfPutsAwaitedBeforeReturn = 0.75

type OptimisticState = ref object
  kad: KadDHT
  key: Key
  individualThreshold: float64 ## a peer closer than this is stored with right away
  setThreshold: float64 ## once the k closest average below this, the walk stops
  returnThreshold: int ## completed RPCs to wait for before returning
  scheduled: HashSet[PeerId]
  failed: int
  completed: int
  doneEvent: AsyncEvent

proc new(
    T: typedesc[OptimisticState], kad: KadDHT, key: Key, netSize: int
): T {.raises: [].} =
  let k = float64(kad.config.replication)
  let scale = 1.0 / float64(netSize)
  T(
    kad: kad,
    key: key,
    individualThreshold: gammaIncRegInv(k, 1.0 - CertaintyPeerIsInClosestSet) * scale,
    setThreshold:
      gammaIncRegInv(k / 2.0 + 1.0, 1.0 - ProbabilityOfStoppingWhileCloserPeersExist) *
      scale,
    returnThreshold: int(ceil(k * FractionOfPutsAwaitedBeforeReturn)),
    doneEvent: newAsyncEvent(),
  )

proc putProviderRecord(
    os: OptimisticState, pid: PeerId
) {.async: (raises: [CancelledError]).} =
  ## A rejected record still counts: the walk only needs the peer to answer.
  defer:
    os.completed.inc()
    os.doneEvent.fire()
  if (await os.kad.dispatchAddProvider(pid, os.key)).isErr():
    os.failed.inc()

proc schedulePut(os: OptimisticState, pid: PeerId) {.raises: [].} =
  if os.kad.stopping:
    return
  os.scheduled.incl(pid)
  os.kad.provideTasks.trackFut(os.putProviderRecord(pid))

proc maybeTrackNetsize(kad: KadDHT, key: Key, closest: seq[PeerId]) =
  ## Feed a converged lookup's closest-first peers into the estimator, so classic
  ## provides bootstrap the estimate that optimistic provide needs. `track`
  ## rejects a short list on its own.
  discard kad.nsEstimator.track(kad.rtable, key, closest.take(kad.config.replication))
  kad.nsEstimator.networkSize().ifValue(ns):
    kad_network_size_estimate.set(ns.float64)

proc optimisticStop(
    os: OptimisticState, state: LookupState
): bool {.raises: [], gcsafe.} =
  ## Stop condition that doubles as the mid-walk store trigger: schedule
  ## ADD_PROVIDER with any new peer inside the individual threshold, and stop
  ## once enough peers are covered.
  let k = os.kad.config.replication
  let hasher = os.kad.rtable.config.hasher

  let closest = state.allSortedPeers().take(k)
  var distances = newSeq[float64](closest.len)
  for i, pid in closest:
    distances[i] = normedDistance(xorDistance(pid, state.target, hasher))
    if pid notin os.scheduled and distances[i] <= os.individualThreshold:
      os.schedulePut(pid)

  if os.scheduled.len - os.failed >= k:
    return true

  # Judge the set only on k real distances. A shorter shortlist has to grow
  # first, otherwise the missing entries would end the walk too early.
  if closest.len < k:
    return false

  (distances.sum() / float64(distances.len)) < os.setThreshold

proc waitForReturn(os: OptimisticState) {.async: (raises: [CancelledError]).} =
  ## Return once ``returnThreshold`` RPCs completed, or all of them if fewer ran.
  ## `completed` only grows and is re-read after each clear, so no wakeup is lost.
  let target = min(os.returnThreshold, os.scheduled.len)
  while os.completed < target:
    await os.doneEvent.wait()
    os.doneEvent.clear()

proc optimisticProvide(
    kad: KadDHT, key: Key, netSize: int
) {.async: (raises: [CancelledError]), gcsafe.} =
  let os = OptimisticState.new(kad, key, netSize)
  let stop = proc(state: LookupState): bool {.raises: [], gcsafe.} =
    os.optimisticStop(state)

  let state = await kad.iterativeLookup(key, findNodeDispatch, noopReply, stop)

  # Store with any of the final closest peers we did not reach during the walk.
  let closest = state.allSortedPeers()
  for pid in closest.take(kad.config.replication):
    if pid notin os.scheduled:
      os.schedulePut(pid)

  await os.waitForReturn()
  kad.maybeTrackNetsize(key, closest)

proc addProvider*(kad: KadDHT, key: Key) {.async: (raises: [CancelledError]), gcsafe.} =
  if kad.config.optimisticProvide:
    kad.nsEstimator.networkSize().ifValue(ns):
      await kad.optimisticProvide(key, ns)
      return

  let state = await kad.iterativeLookup(key, findNodeDispatch, noopReply)
  let closest = state.allSortedPeers()
  kad.maybeTrackNetsize(key, closest)

  let peers =
    if kad.config.providerRejection:
      # Spillover needs the peers past the closest `replication` ones too.
      closest
    else:
      state.selectCloserPeers(kad.config.replication, excludeResponded = false)
  await kad.storeProviderAt(key, peers)

proc addProvider*(kad: KadDHT, cid: Cid) {.async: (raises: [CancelledError]), gcsafe.} =
  await addProvider(kad, cid.toKey())

proc startProviding*(kad: KadDHT, c: Cid) {.async: (raises: [CancelledError]).} =
  let k = c.toKey()
  if not kad.providerManager.providedKeys.hasKey(k) and
      kad.providerManager.providedKeys.isFull():
    kad.providerManager.providedKeys.deleteOldest()

  kad.providerManager.providedKeys.provided[k] = chronos.Moment.now()
  await kad.addProvider(k)

proc stopProviding*(kad: KadDHT, c: Cid) =
  kad.providerManager.providedKeys.del(c.toKey())

proc providedKeyRegions*(kad: KadDHT): seq[seq[Key]] =
  ## Provided keys grouped into keyspace regions, one group per DHT walk. Falls
  ## back to a group per key while the routing table cannot size a region.
  let keys = kad.providerManager.providedKeys.provided.keys().toSeq()
  let bits = kad.config.republishRegionBits.valueOr:
    kad.rtable.regionBits().valueOr:
      return keys.mapIt(@[it])
  keys.keyspaceRegions(bits, kad.rtable.config.hasher)

proc stillProvided(kad: KadDHT, keys: seq[Key]): seq[Key] =
  ## A region waits for its slot, so `stopProviding` can drop a key between the
  ## grouping and the walk.
  keys.filterIt(kad.providerManager.providedKeys.hasKey(it))

proc republishRegion(
    kad: KadDHT, region: seq[Key]
) {.async: (raises: [CancelledError]).} =
  ## One walk for the whole region, then advertise every key to the peers it
  ## found. Any member key is a valid walk target.
  let keys = kad.stillProvided(region)
  if keys.len == 0:
    return

  let regionPeers =
    (await kad.iterativeLookup(keys[0], findNodeDispatch, noopReply)).allSortedPeers()

  kad_provider_republish_regions.inc()
  kad_provider_republish_keys.inc(keys.len.int64)

  let hasher = kad.rtable.config.hasher
  let futs = keys.mapIt(kad.storeProviderAt(it, regionPeers.closestFirst(it, hasher)))
  try:
    await allFutures(futs)
  except CancelledError as e:
    await noCancel futs.cancelAndWait()
    raise e

func regionStartSpacing(interval: chronos.Duration, regions: int): chronos.Duration =
  ## Regions start evenly spread over the first half of the republish interval;
  ## the second half is headroom for the last region to finish.
  if regions <= 1:
    ZeroDuration
  else:
    (interval div 2) div regions

proc republishRegionAfter(
    kad: KadDHT, delay: chronos.Duration, keys: seq[Key]
) {.async: (raises: [CancelledError]).} =
  await sleepAsync(delay)
  await kad.republishRegion(keys)

proc republishProvidedKeys(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  let regions = kad.providedKeyRegions()
  let spacing =
    regionStartSpacing(kad.config.republishProvidedKeysInterval, regions.len)

  var futs = newSeqOfCap[Future[void]](regions.len)
  for i, region in regions:
    futs.add(kad.republishRegionAfter(spacing * i, region))

  try:
    await allFutures(futs)
  except CancelledError as exec:
    await noCancel futs.cancelAndWait()
    raise exec

proc manageRepublishProvidedKeys*(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  heartbeat "republish provided keys", kad.config.republishProvidedKeysInterval:
    if not await kad.republishProvidedKeys().withTimeout(
      kad.config.republishProvidedKeysInterval
    ):
      warn "Provider republishing timed out",
        timeout = kad.config.republishProvidedKeysInterval,
        providedKeys = kad.providerManager.providedKeys.provided.len

proc anyExpired(pr: ProviderRecords): bool =
  pr.len() > 0 and pr.records[0] < chronos.Moment.now()

proc manageExpiredProviders*(kad: KadDHT) {.async: (raises: [CancelledError]).} =
  heartbeat "cleanup expired provider records", kad.config.cleanupProvidersInterval:
    while kad.providerManager.providerRecords.anyExpired():
      let expired = kad.providerManager.providerRecords.pop()
      kad.providerManager.removeProviderRecord(expired)

proc sendAddProviderResponse(
    stream: Stream, kad: KadDHT, status: AddProviderStatus
) {.async: (raises: [CancelledError]).} =
  let response = Message(
    msgType: Opt.some(MessageType.addProvider), providerStatus: Opt.some(status)
  )
  try:
    await stream.writeLp(response.encode(kad.config.hideConnectionStatus))
  except LPStreamError as exc:
    trace "Failed to send add-provider response", err = exc.msg, stream, status = status

method handleAddProvider*(
    kad: KadDHT, stream: Stream, msg: Message
) {.base, async: (raises: [CancelledError]).} =
  let msgKey = msg.key.valueOr:
    trace "Add-provider request rejected",
      reason = "missingKey", messageType = "addProvider", stream
    return

  if msgKey.len == 0 or msgKey.len > MaxProviderKeyLen:
    trace "Add-provider request rejected",
      reason = "invalidKeyLength",
      stream,
      messageType = "addProvider",
      keySize = msgKey.len,
      maxKeySize = MaxProviderKeyLen
    if kad.config.providerRejection:
      await stream.sendAddProviderResponse(kad, AddProviderStatus.rejected)
    return

  # filter out infos that do not match sender's
  let peerBytes = stream.peerId.getBytes()
  let validPeers = msg.providerPeers.filterIt(
    it.id.isSome and it.id.get() == peerBytes and PeerId.init(it.id.get()).isOk()
  )

  # Per-key cap is enforced regardless of providerRejection: when rejection is
  # disabled the receiver still drops over-cap providers, just silently.
  var atCap = false
  kad.config.limits.maxProvidersPerKey.ifValue(limit):
    let existingProviders =
      kad.providerManager.knownKeys.getOrDefault(msgKey, initHashSet[Provider]())
    let senderIsKnown =
      existingProviders.anyIt(it.id.isSome and it.id.get() == peerBytes)
    # Re-advertisements by the same provider are exempt: addProviderRecord
    # replaces the existing record so the set size doesn't grow.
    let effectiveCount = existingProviders.len - (if senderIsKnown: 1 else: 0)
    if effectiveCount >= limit:
      atCap = true
      trace "Add-provider request rejected",
        reason = "perKeyLimit", keySize = msgKey.len, limit = limit

  if not atCap:
    for peer in validPeers:
      let providerId = PeerId.init(peer.id.get()).valueOr:
        continue
      kad.admitPeers(@[PeerInfo(peerId: providerId, addrs: peer.addrs)])
      kad.providerManager.addProviderRecord(
        ProviderRecord(
          provider: peer,
          expiresAt: chronos.Moment.now() + kad.config.providerExpirationInterval,
          key: msgKey,
        )
      )

  if kad.config.providerRejection:
    let status =
      if atCap or validPeers.len == 0:
        AddProviderStatus.rejected
      else:
        AddProviderStatus.accepted
    if status == AddProviderStatus.rejected:
      kad_provider_rejections_sent.inc()
    await stream.sendAddProviderResponse(kad, status)

proc dispatchGetProviders*(
    kad: KadDHT, peer: PeerId, key: Key
): Future[LPResult[Message]] {.async: (raises: [CancelledError]), gcsafe.} =
  let msg = Message(msgType: Opt.some(MessageType.getProviders), key: Opt.some(key))
  let reply = ?await kad.dispatchRpc(peer, msg)

  trace "Get-providers reply received",
    peerId = peer, messageType = "getProviders", providerCount = reply.providerPeers.len

  ok(reply)

proc getProviders*(
    kad: KadDHT, key: Key
): Future[HashSet[Provider]] {.
    async: (raises: [LPStreamError, CancelledError]), gcsafe
.} =
  ## Get providers for a given `key` from the nodes closest to that `key`.

  var allProviders: HashSet[Provider]

  # Include ourselves if we already provide the key
  if kad.providerManager.providedKeys.provided.hasKey(key):
    allProviders.incl(kad.switch.peerInfo.toPeer())

  let onReply = proc(
      peerId: PeerId, msgOpt: Opt[Message], state: LookupState
  ): Future[void] {.async: (raises: []), gcsafe.} =
    let reply = msgOpt.valueOr:
      return

    for provider in reply.providerPeers:
      let idraw = provider.id.valueOr:
        continue
      if PeerId.init(idraw).isErr:
        trace "Invalid peer id received", peerId = provider.id
        continue
      allProviders.incl(provider)

  let enoughProviders = proc(state: LookupState): bool {.gcsafe.} =
    allProviders.len() >= kad.config.replication

  discard await kad.iterativeLookup(key, dispatchGetProviders, onReply, enoughProviders)

  return allProviders

proc handleGetProviders*(
    kad: KadDHT, stream: Stream, msg: Message
) {.async: (raises: [CancelledError]).} =
  let msgKey = msg.key.valueOr:
    trace "Get-providers request rejected",
      reason = "missingKey", messageType = "getProviders", stream
    return

  var providers =
    kad.providerManager.knownKeys.getOrDefault(msgKey, initHashSet[Provider]())

  # check if we are providing the key as well
  if kad.providerManager.providedKeys.provided.hasKey(msgKey):
    providers.incl(kad.switch.peerInfo.toPeer())

  let response = Message(
    msgType: Opt.some(MessageType.getProviders),
    key: Opt.some(msgKey),
    closerPeers: kad.findClosestPeers(msgKey, stream.peerId),
    providerPeers: providers.toSeq(),
  )
  let encoded = response.encode(kad.config.hideConnectionStatus)
  kad_message_bytes_sent.inc(
    encoded.len.int64, labelValues = [$MessageType.getProviders]
  )
  try:
    await stream.writeLp(encoded)
  except LPStreamError as exc:
    trace "Failed to send get-providers RPC reply", err = exc.msg, stream
