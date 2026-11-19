# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[tables, math, sequtils, net, strformat]
from std/times import getTime, toUnix
import chronos, chronicles, results
import
  ../../[
    peerid, peerinfo, switch, multihash, cid, multicodec, multiaddress, routing_record,
    extended_peer_record,
  ]
import ../../crypto/crypto
import ../kademlia
import ../kademlia/types
import ../kademlia/protobuf as kademlia_protobuf
import
  ./[
    types, routing_table_manager, service_discovery_metrics, advertisement_cache,
    discovery_tracker,
  ]

logScope:
  topics = "libp2p service-discovery"

proc updateRegistrarMetrics(registrar: Registrar) {.raises: [].} =
  cd_registrar_cache_ads.set(registrar.ads.len.float64)
  cd_registrar_cache_services.set(registrar.ads.serviceLen.float64)
  cd_iptree_total_ips.set(registrar.ads.ipTree.ipsLen.float64)

proc isExpired(now, ts: Moment, expiry: Duration): bool =
  now - ts > expiry

proc pruneExpiredEntries[K](
    timestamps: var Table[K, Moment],
    bounds: var Table[K, Moment],
    now: Moment,
    expiry: Duration,
) =
  var toRemove: seq[K] = @[]

  for k, ts in timestamps:
    if isExpired(now, ts, expiry):
      toRemove.add(k)

  for k in toRemove:
    timestamps.del(k)
    bounds.del(k)

proc pruneExpiredAds*(registrar: Registrar, advertExpiry: Duration) =
  #Always use seconds granularity
  let now = Moment.init(Moment.now().epochSeconds, Second)

  let expiredCount = registrar.ads.pruneExpired(now, advertExpiry)

  if expiredCount > 0:
    cd_registrar_ads_expired.inc(expiredCount.float64)
    registrar.updateRegistrarMetrics()

  # Expire service-level bounds
  pruneExpiredEntries(
    registrar.timestampService, registrar.boundService, now, advertExpiry
  )

  # Expire IP-level bounds
  pruneExpiredEntries(registrar.timestampIp, registrar.boundIp, now, advertExpiry)

  debug "Pruned expired adverts", count = expiredCount

proc advertiserIps*(
    disco: ServiceDiscovery, advertiser: PeerId, connectionIps: seq[IpAddress] = @[]
): seq[IpAddress] {.raises: [].} =
  ## Prefer IPs from the live connection (`stream.observedAddr`).
  ## Fall back to peerstore, then self listen addrs for local registration
  ## when no connection IP is available.
  if connectionIps.len > 0:
    return connectionIps

  var addrs = disco.switch.peerStore[AddressBook][advertiser]
  if addrs.len == 0 and advertiser == disco.switch.peerInfo.peerId:
    addrs = disco.switch.peerInfo.addrs

  addrs.getIPs()

func remainingBound[K](
    timestamps, bounds: Table[K, Moment], key: K, now: Moment
): Duration =
  if key notin timestamps:
    return ZeroDuration
  bounds.getOrDefault(key, now) - now

proc waitingTime*(
    registrar: Registrar,
    discoConfig: ServiceDiscoveryConfig,
    serviceIds: openArray[ServiceId],
    advertiserIps: seq[IpAddress],
    now: Moment,
): Duration {.raises: [].} =
  ## One wait for a batch: the service terms take the max over `serviceIds`.
  let advertCacheCap = registrar.ads.capacity
  let c = registrar.ads.len.uint64
  var c_s = 0
  for id in serviceIds:
    c_s = max(c_s, registrar.ads.serviceCacheAdsLen(id))

  let occupancy =
    if c >= advertCacheCap:
      100.0
    else:
      let ratio = c.float64 / advertCacheCap.float64
      let base = max(1e-9, 1.0 - ratio)
      let exp = min(discoConfig.occupancyExp, 10.0)
      1.0 / pow(base, exp)

  let serviceSim: float64 = c_s.float64 / advertCacheCap.float64
  let ipSim = registrar.ads.ipTree.ipsMaxScore(advertiserIps)

  var w: float64 =
    discoConfig.advertExpiry.seconds.float64 * occupancy *
    (serviceSim + discoConfig.ipSimCoefficient * ipSim + discoConfig.safetyParam)

  # Bound & Quantize W
  w = w.clamp(0.0, float64(uint32.high))
  w = round(w)

  var waitDuration = w.int64.secs

  for id in serviceIds:
    waitDuration = max(
      waitDuration,
      remainingBound(registrar.timestampService, registrar.boundService, id, now),
    )

  for ip in advertiserIps:
    waitDuration = max(
      waitDuration, remainingBound(registrar.timestampIp, registrar.boundIp, $ip, now)
    )

  return waitDuration

proc waitingTime*(
    registrar: Registrar,
    discoConfig: ServiceDiscoveryConfig,
    serviceId: ServiceId,
    advertiserIps: seq[IpAddress],
    now: Moment,
): Duration {.raises: [].} =
  registrar.waitingTime(discoConfig, [serviceId], advertiserIps, now)

proc updateLowerBounds*(
    registrar: Registrar,
    serviceId: ServiceId,
    advertiserIps: seq[IpAddress],
    waitDuration: Duration,
    now: Moment,
) =
  let prevTimestamp = registrar.timestampService.getOrDefault(serviceId, now)
  let prevBoundTimestamp = registrar.boundService.getOrDefault(serviceId, now)
  let prevWait = prevBoundTimestamp - prevTimestamp
  let elapsedDuration = now - prevTimestamp

  if waitDuration >= prevWait - elapsedDuration:
    registrar.boundService[serviceId] = now + waitDuration
    registrar.timestampService[serviceId] = now

  for ip in advertiserIps:
    let ipKey = $ip
    let prevTimestamp = registrar.timestampIp.getOrDefault(ipKey, now)
    let prevBoundTimestamp = registrar.boundIp.getOrDefault(ipKey, now)
    let prevWait = prevBoundTimestamp - prevTimestamp
    let elapsedDuration = now - prevTimestamp

    if waitDuration >= prevWait - elapsedDuration:
      registrar.boundIp[ipKey] = now + waitDuration
      registrar.timestampIp[ipKey] = now

const OversizedAdvertisementCause* = "oversized"

proc isValidAdvertisement*(
    regMsg: RegisterMessage, serviceId: ServiceId
): LPResult[Advertisement] =
  let advertisment = regMsg.advertisement.valueOr:
    return err("advertisement not set")

  if advertisment.len > MaxXPRSize:
    return err(OversizedAdvertisementCause)

  let ad = Advertisement.decode(advertisment).valueOr:
    return err(error, "cannot decode")

  for svc in ad.data.services:
    if not svc.isValid():
      return err("oversized service data")

  if not ad.advertisesService(serviceId):
    return err("message & advertisement service mismatch")

  return ok(ad)

func batchServiceIds*(
    key: ServiceId, extra: openArray[seq[byte]], maxBatch: int
): LPResult[seq[ServiceId]] {.raises: [].} =
  ## `key` first, then the extra ids in message order, without duplicates.
  var batch = @[key]
  for raw in extra:
    if raw.len != IdLength:
      return err(fmt"service id length {raw.len} != {IdLength}")
    let id = ServiceId(raw)
    if id notin batch:
      batch.add(id)

  if batch.len > maxBatch:
    return err(fmt"{batch.len} > {maxBatch} service ids in one batch")

  ok(batch)

func bindsBatch(ticket: Ticket, batch: openArray[ServiceId]): bool =
  ## A ticket with no ids covers `Message.key` alone.
  if ticket.serviceIds.len == 0:
    return batch.len == 1
  ticket.serviceIds == batch.mapIt(seq[byte](it))

proc updateWaitAfterRetry*(
    disco: ServiceDiscovery,
    ticketOpt: Opt[Ticket],
    now: UnixTimestamp,
    wait: var Duration,
) =
  ticketOpt.ifValue(ticket):
    let totalWaitSoFar = now - ticket.tInit.get()
    wait -= totalWaitSoFar.seconds

proc isValidTicket(
    disco: ServiceDiscovery,
    regMsg: RegisterMessage,
    batch: openArray[ServiceId],
    now: UnixTimestamp,
): LPResult[Opt[Ticket]] {.raises: [].} =
  let ticket = regMsg.ticket.valueOr:
    return ok(Opt.none(Ticket))

  if ticket.advertisement.get(@[]) != regMsg.advertisement.get(@[]):
    return err("message & ticket advertisement mismatch")

  let registrarPubKey = disco.switch.peerInfo.privateKey.getPublicKey().valueOr:
    return err(error, "failed to get registrar public key")

  if not ticket.verify(registrarPubKey):
    return err("ticket fails verification")

  if not ticket.bindsBatch(batch):
    return err("message & ticket service ids mismatch")

  let
    windowStart = ticket.tMod.get() + ticket.tWaitFor.get().seconds
    windowEnd = windowStart + disco.discoConfig.registrationWindow.seconds

  if now notin windowStart .. windowEnd:
    return err("ticket outside valid time window")

  return ok(Opt.some(ticket))

proc acceptAdvertisement*(
    disco: ServiceDiscovery,
    now: Moment,
    serviceId: ServiceId,
    advertiser: PeerId,
    ad: Advertisement,
    advertiserIps: seq[IpAddress],
) =
  # Put first: a full cache can evict this service's last ad and drop its table.
  disco.registrar.ads.put(serviceId, advertiser, ad, advertiserIps, now)
  disco.registrar.updateRegistrarMetrics()

  discard disco.rtManager.addService(
    serviceId, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
    Registered,
  )

  let advertiserAddrs = disco.switch.peerStore[AddressBook][advertiser]
  if advertiserAddrs.len > 0:
    disco.rtManager.admitPeers(
      disco, serviceId, @[PeerInfo(peerId: advertiser, addrs: advertiserAddrs)]
    )

proc seatSender(disco: ServiceDiscovery, serviceId: ServiceId, peerId: PeerId) =
  ## The admission probe dials the codec, so a querier that does not serve it gets no seat.
  let senderAddrs = disco.switch.peerStore[AddressBook][peerId]
  if senderAddrs.len == 0:
    return

  let sender = @[PeerInfo(peerId: peerId, addrs: senderAddrs)]
  disco.admitPeers(sender)
  disco.rtManager.admitPeers(disco, serviceId, sender)

proc getCloserPeers(
    disco: ServiceDiscovery, serviceId: ServiceId, requester: PeerId, count: int
): seq[Peer] =
  let maxPerBucket = CloserPeersPerBucket
  # Exclude the requester from its own reply.
  let exclude = [requester.toKey()]
  let table = disco.rtManager.getTable(serviceId)
  let keys =
    if table.isSome():
      table.get().randomPeersClosestFirst(disco.rng, count, maxPerBucket, exclude)
    else:
      # No table for this service: view the main table by distance to the
      # service (the spec's GETPEERS), not by distance to this node.
      disco.rtable.randomPeersClosestFirst(
        serviceId, disco.rng, count, maxPerBucket, disco.discoConfig.bucketsCount,
        exclude,
      )

  return disco.switch.toPeers(keys)

proc registration*(
    disco: ServiceDiscovery,
    peerId: PeerId,
    inMsg: Message,
    connectionIps: seq[IpAddress] = @[],
): Message =
  let serviceId = inMsg.key.valueOr:
    trace "Key not set: registration", msg = inMsg
    return

  if serviceId.len != IdLength:
    trace "Key does not have service id length: registration", msg = inMsg

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return Message(
      msgType: Opt.some(MessageType.register),
      register: Opt.some(
        RegisterMessage(
          advertisement: Opt.none(seq[byte]),
          status: Opt.some(kademlia_protobuf.RegistrationStatus.Rejected),
          ticket: Opt.none(Ticket),
        )
      ),
    )

  let closerPeers = disco.getCloserPeers(serviceId, peerId, disco.discoConfig.fReturn)

  var msg = Message(
    msgType: Opt.some(MessageType.register),
    register: Opt.some(
      RegisterMessage(
        advertisement: Opt.none(seq[byte]),
        status: Opt.some(kademlia_protobuf.RegistrationStatus.Rejected),
        ticket: Opt.none(Ticket),
      )
    ),
    closerPeers: closerPeers,
  )

  let regMsg = inMsg.register.valueOr:
    trace "No register message"

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return msg

  let batch = batchServiceIds(
    serviceId, regMsg.serviceIds, disco.discoConfig.maxBatchServices
  ).valueOr:
    trace "Invalid service id batch", error

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return msg

  let ad = isValidAdvertisement(regMsg, serviceId).valueOr:
    trace "Invalid advertisement", error

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return msg

  if not batch.allIt(ad.advertisesService(it)):
    trace "Advertisement does not advertise every service of the batch",
      services = batch.len

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return msg

  let fresh = batch.filterIt(not disco.registrar.ads.hasNewer(it, ad))
  if fresh.len == 0:
    trace "Stale advertisement", peerId = ad.data.peerId, seqNo = ad.data.seqNo

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return msg

  for id in fresh:
    disco.tracker.recordProvider(id, ad.data.peerId, FromRegistration)

  #Always use seconds granularity
  let now = Moment.init(Moment.now().epochSeconds, Second)

  let unixNow = getTime().toUnix()

  let ticketOpt = disco.isValidTicket(regMsg, batch, unixNow).valueOr:
    trace "Invalid ticket", error

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return msg

  for id in fresh:
    disco.seatSender(id, peerId)

  let ips = disco.advertiserIps(peerId, connectionIps)
  var tWait = disco.registrar.waitingTime(disco.discoConfig, fresh, ips, now)

  disco.updateWaitAfterRetry(ticketOpt, unixNow, tWait)

  if tWait <= ZeroDuration:
    for id in fresh:
      disco.acceptAdvertisement(now, id, peerId, ad, ips)

    msg.register.get().status.get() = kademlia_protobuf.RegistrationStatus.Confirmed
    msg.register.get().accepted = fresh.mapIt(seq[byte](it))

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Confirmed]
    )

    return msg

  tWait = min(disco.discoConfig.advertExpiry, tWait)

  for id in fresh:
    disco.registrar.updateLowerBounds(id, ips, tWait, now)

  var ticket = Ticket(
    advertisement: regMsg.advertisement,
    tInit: Opt.some(unixNow),
    tMod: Opt.some(unixNow),
    tWaitFor: Opt.some(tWait),
    serviceIds:
      # An old advertiser drops field 6 on decode, and the signature then fails.
      if batch.len > 1:
        batch.mapIt(seq[byte](it))
      else:
        @[],
  )

  ticketOpt.ifValue(t):
    ticket.tInit = t.tInit

  if ticket.sign(disco.switch.peerInfo.privateKey).isErr:
    error "Failed to sign ticket"

    cd_register_requests.inc(
      labelValues = [$kademlia_protobuf.RegistrationStatus.Rejected]
    )

    return msg

  msg.register.get().status.get() = kademlia_protobuf.RegistrationStatus.Wait
  msg.register.get().ticket = Opt.some(ticket)

  cd_register_requests.inc(labelValues = [$kademlia_protobuf.RegistrationStatus.Wait])

  return msg

proc getAdvertisements*(
    disco: ServiceDiscovery, peerId: PeerId, msg: Message
): Message =
  let serviceId = msg.key.valueOr:
    trace "Key not set: getAdvertisements", msg
    return

  if serviceId.len != IdLength:
    trace "Key does not have service id length: getAdvertisements", msg
    return Message(
      msgType: Opt.some(MessageType.getAds),
      getAds: Opt.some(GetAdsMessage(advertisements: @[])),
    )

  disco.seatSender(serviceId, peerId)

  let cap = disco.discoConfig.fReturn
  let ads = disco.registrar.ads.getServiceCachedAds(serviceId, cap).mapIt(it.ad)

  let closerPeers = disco.getCloserPeers(serviceId, peerId, cap)

  let response = Message(
    msgType: Opt.some(MessageType.getAds),
    getAds: Opt.some(GetAdsMessage(advertisements: ads.encode(cap))),
    closerPeers: closerPeers,
  )

  return response
