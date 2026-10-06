# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sequtils, sets]
import chronos, chronicles, results
import ../../[peerid, switch, multiaddress, extended_peer_record]
import ../kademlia
import ../kademlia/types
import
  ./[
    types, routing_table_manager, service_discovery_metrics, registrar, connection,
    discovery_tracker,
  ]
import ../../utils/future

logScope:
  topics = "libp2p service-discovery"

type LookupLog = ref object
  queried, succeeded, failed, pending: int

type GetAdsResult = object
  ads: seq[Advertisement]
  closerPeers: seq[PeerInfo]

type BucketAds = object
  found: HashSet[Advertisement]
  closerPeers: seq[PeerInfo]

proc validAds(ads: seq[seq[byte]], serviceId: ServiceId): seq[Advertisement] =
  var validAds: seq[Advertisement] = @[]
  for adBuf in ads:
    if adBuf.len == 0 or adBuf.len > MaxXPRSize:
      continue

    let ad = Advertisement.decode(adBuf).valueOr:
      trace "Failed to decode advertisement", error
      continue

    if not ad.advertisesService(serviceId):
      trace "Advert service mismatch", serviceId
      continue

    if not ad.isValid():
      trace "Advertisement violates XPR or ServiceInfo size limits", serviceId
      continue

    validAds.add(ad)
  return validAds

proc atMostOnePerBucket(
    disco: ServiceDiscovery, searchTable: RoutingTable, closerPeers: seq[PeerInfo]
): seq[PeerInfo] =
  ## Cap each responder to one peer per service bucket before merging
  ## replies. Exclude self before counting.
  var capped: seq[PeerInfo] = @[]
  var filled = initHashSet[int]()
  for peer in closerPeers:
    if peer.peerId == disco.switch.peerInfo.peerId:
      continue
    let bucketIdx = searchTable.bucketIndex(peer.peerId.toKey())
    if filled.containsOrIncl(bucketIdx):
      trace "Closer peer beyond one per bucket", bucket = bucketIdx, peer = peer.peerId
      continue
    capped.add(peer)
  return capped

proc localGetAds(disco: ServiceDiscovery, msg: Message): LPResult[Message] =
  return ok(disco.getAdvertisements(disco.switch.peerInfo.peerId, msg))

proc dispatchGetAds(
    disco: ServiceDiscovery, peerId: PeerId, serviceId: ServiceId
): Future[LPResult[GetAdsResult]] {.async: (raises: [CancelledError]), gcsafe.} =
  trace "Getting adverts", serviceId, registrar = peerId

  let msg = Message(msgType: Opt.some(MessageType.getAds), key: Opt.some(serviceId))

  let replyRes =
    if peerId == disco.switch.peerInfo.peerId:
      disco.localGetAds(msg)
    else:
      await disco.send(peerId, msg)

  let reply = replyRes.valueOr:
    return err($error)

  let getAdsMsg = reply.getAds.valueOr:
    return err("get ads message response not found")

  trace "Adverts found",
    serviceId, remote = peerId, count = getAdsMsg.advertisements.len

  return ok(
    GetAdsResult(
      ads: getAdsMsg.advertisements.validAds(serviceId),
      closerPeers: reply.closerPeers.toPeerInfos(),
    )
  )

proc peersToQuery(disco: ServiceDiscovery, peers: seq[Key]): seq[PeerId] =
  let peersToPick = min(disco.discoConfig.kLookup, peers.len)
  disco.rng.pick(peers, peersToPick).ifValue(picked):
    return picked.toPeerIds()
  else:
    return @[]

proc admitCloserPeers(
    disco: ServiceDiscovery, serviceId: ServiceId, peers: seq[PeerInfo]
) =
  disco.admitPeers(peers)
  disco.rtManager.admitPeers(disco, serviceId, peers)

proc processResponse(
    disco: ServiceDiscovery,
    serviceId: ServiceId,
    response: GetAdsResult,
    found: var HashSet[Advertisement],
    limit: int,
) =
  disco.admitCloserPeers(serviceId, response.closerPeers)

  # an ad past the caller's limit is still a provider this node found
  disco.tracker.recordProviders(serviceId, response.ads, FromLookup)

  for ad in response.ads:
    if found.len >= limit:
      break
    found.incl(ad)

proc drainCompletedPeers(
    disco: ServiceDiscovery,
    serviceId: ServiceId,
    searchTable: RoutingTable,
    pending: seq[Future[LPResult[GetAdsResult]]],
) =
  for fut in pending.filterIt(it.completed()):
    let res = fut.value()
    if res.isOk():
      disco.admitCloserPeers(
        serviceId, disco.atMostOnePerBucket(searchTable, res.value().closerPeers)
      )
      disco.tracker.recordProviders(serviceId, res.value().ads, FromLookup)

proc collectBucketAds(
    disco: ServiceDiscovery,
    serviceId: ServiceId,
    searchTable: RoutingTable,
    peers: seq[PeerId],
    known: HashSet[Advertisement],
    limit: int,
    stats: LookupLog,
): Future[BucketAds] {.async: (raises: [CancelledError]).} =
  var bucketAds = BucketAds(found: known)
  var pending: seq[Future[LPResult[GetAdsResult]]] =
    peers.mapIt(Future[LPResult[GetAdsResult]](dispatchGetAds(disco, it, serviceId)))
  let queries = pending
  stats.queried += queries.len
  defer:
    for fut in queries:
      if not fut.finished():
        stats.pending.inc()
      elif fut.completed() and fut.value().isOk():
        stats.succeeded.inc()
      else:
        stats.failed.inc()
    pending.cancelSoon()

  let deadline = Moment.fromNow(disco.config.timeout)
  for _ in 0 ..< pending.len:
    let timeLeft = deadline - Moment.now()
    if timeLeft <= ZeroDuration:
      break

    let wrapper = one(pending)
    if not (await wrapper.withTimeout(timeLeft)):
      break

    let completedFut = wrapper.value()
    pending.del(pending.find(completedFut))

    if completedFut.completed():
      let res = completedFut.value()
      if res.isOk():
        var reply = res.value()
        reply.closerPeers = disco.atMostOnePerBucket(searchTable, reply.closerPeers)
        bucketAds.closerPeers.add(reply.closerPeers)
        disco.processResponse(serviceId, reply, bucketAds.found, limit)

    if bucketAds.found.len >= limit:
      disco.drainCompletedPeers(serviceId, searchTable, pending)
      break

  return bucketAds

proc registerInterest*(disco: ServiceDiscovery, serviceId: string): bool =
  ## Register interest in a service so its routing table is created and kept
  ## fresh by the refresh loop. No messages are sent and no ads are fetched
  ## here. This only prepopulates the per-service routing table to make subsequent
  ## `lookup` calls faster.
  let serviceHash = serviceId.hashServiceId()

  debug "Register interest", service = serviceId, serviceId = serviceHash

  disco.tracker.startInterest(serviceHash)

  disco.rtManager.addService(
    serviceHash, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
    Interest,
  )

proc unregisterInterest*(disco: ServiceDiscovery, serviceId: string) =
  ## Drop interest in a service. The per-service routing table is removed
  ## unless this node is also providing the service, in which case the table
  ## is kept for advertising.
  let serviceHash = serviceId.hashServiceId()

  debug "Unregister interest", service = serviceId, serviceId = serviceHash

  disco.tracker.stopInterest(serviceHash)

  disco.rtManager.removeService(serviceHash, Interest)

proc recordCloserPeers(
    disco: ServiceDiscovery,
    searchTable: RoutingTable,
    closerPeers: openArray[PeerInfo],
    afterBucket: int,
    learned: var seq[seq[Key]],
) =
  ## File closer peers into buckets the walk has not reached yet. Peers
  ## without a recorded address are skipped since they cannot be dialed.
  for peer in closerPeers:
    if peer.peerId == disco.switch.peerInfo.peerId or
        disco.switch.peerStore[AddressBook][peer.peerId].len == 0:
      continue
    let key = peer.peerId.toKey()
    let peerIdx = searchTable.bucketIndex(key)
    if peerIdx > afterBucket:
      learned[peerIdx].add(key)

proc lookup*(
    disco: ServiceDiscovery, serviceId: ServiceId
): Future[LPResult[seq[Advertisement]]] {.async: (raises: [CancelledError]).} =
  ## Look up providers for a specific service id.
  cd_lookup_requests.inc()

  disco.tracker.startInterest(serviceId)

  discard disco.rtManager.addService(
    serviceId, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
    Interest,
  )

  let searchTable = disco.rtManager.getTable(serviceId).valueOr:
    return err("service table not found for service id: " & $serviceId)

  var found = initHashSet[Advertisement]()
  let stats = LookupLog()
  var outcome = "cancelled"
  defer:
    debug "Service provider lookup finished",
      serviceId,
      outcome,
      advertisements = found.len,
      queried = stats.queried,
      succeeded = stats.succeeded,
      failed = stats.failed,
      pending = stats.pending

  let local = await dispatchGetAds(disco, disco.switch.peerInfo.peerId, serviceId)
  local.ifValue(response):
    disco.processResponse(serviceId, response, found, disco.discoConfig.fLookup)

  var learned = newSeq[seq[Key]](bucketCount(searchTable.config.maxBuckets))
  for bucketIdx in 0 ..< learned.len:
    if found.len >= disco.discoConfig.fLookup:
      break

    var candidates = learned[bucketIdx]
    if bucketIdx < searchTable.buckets.len:
      candidates.add(searchTable.buckets[bucketIdx].peers)
    candidates = candidates.deduplicate()
    if candidates.len == 0:
      continue

    let peers = disco.peersToQuery(candidates)
    let bucketAds = await disco.collectBucketAds(
      serviceId, searchTable, peers, found, disco.discoConfig.fLookup, stats
    )
    found = bucketAds.found
    disco.recordCloserPeers(searchTable, bucketAds.closerPeers, bucketIdx, learned)

  outcome = if found.len >= disco.discoConfig.fLookup: "limitReached" else: "completed"
  cd_lookup_peers_found.inc(found.len.int64)
  return ok(found.toSeq)
