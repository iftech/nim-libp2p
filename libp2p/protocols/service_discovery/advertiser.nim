# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sets, tables, sequtils]
import chronos, chronicles, results
import ../../utils/[heartbeat, opt]
import
  ../../[peerid, switch, multihash, cid, multicodec, multiaddress, extended_peer_record]
import ../../crypto/crypto
import ../kademlia
import ../kademlia/[types, protobuf as kademlia_protobuf]
import
  ./[types, routing_table_manager, service_discovery_metrics, registrar, connection]

logScope:
  topics = "libp2p service-discovery"

type
  RegistrationResponse* = object
    status*: kademlia_protobuf.RegistrationStatus
    ticket*: Opt[Ticket]
    closerPeers*: seq[PeerInfo]

  SignedXpr* = object
    peerId*: PeerId
    bytes*: seq[byte]

proc cancelRunningTasks*(a: Advertiser) {.async: (raises: []).} =
  var running = move a.running
  var runningFuts: seq[Future[void]]
  for task in running:
    runningFuts.add(task.fut)

  await runningFuts.cancelAndWait()

  cd_advertiser_pending_actions.set(0)

proc clear*(a: Advertiser) {.async: (raises: []).} =
  await a.cancelRunningTasks()
  a.providedAdverts = initTable[ServiceId, ProvidedAdvert]()

proc cleanupFinishedTasks(a: Advertiser) =
  var toRemove: HashSet[AdvertiseTask]
  for t in a.running:
    if t.fut.finished:
      toRemove.incl(t)
  if toRemove.len > 0:
    a.running.excl(toRemove)
    cd_advertiser_pending_actions.set(a.running.len.float64)

proc getAdvertBytes(disco: ServiceDiscovery, explicit: Opt[seq[byte]]): Opt[seq[byte]] =
  if explicit.isSome():
    return Opt.some(explicit.get())

  let extRecord = disco.record().valueOr:
    trace "Failed to create extended peer record", error
    return Opt.none(seq[byte])
  Opt.some(extRecord.encode())

proc advertiseToRegistrar*(
  disco: ServiceDiscovery,
  serviceId: ServiceId,
  registrar: PeerId,
  ticket: Opt[Ticket],
  advert: seq[byte],
) {.async: (raises: [CancelledError]).}

proc advertiseAfter(
    disco: ServiceDiscovery,
    superseded: seq[Future[void]],
    serviceId: ServiceId,
    registrar: PeerId,
    advert: seq[byte],
) {.async: (raises: [CancelledError]).} =
  ## A superseded advert that lands later with an equal seqNo would win the cache.
  await allFutures(superseded)
  await disco.advertiseToRegistrar(serviceId, registrar, Opt.none(Ticket), advert)

proc trackAdvertiseTask(
    disco: ServiceDiscovery,
    serviceId: ServiceId,
    registrar: PeerId,
    bucketIdx: int,
    advertBytes: seq[byte],
    superseded: seq[Future[void]] = @[],
) =
  let fut =
    if superseded.len == 0:
      disco.advertiseToRegistrar(serviceId, registrar, Opt.none(Ticket), advertBytes)
    else:
      disco.advertiseAfter(superseded, serviceId, registrar, advertBytes)
  disco.advertiser.running.incl(
    AdvertiseTask(
      fut: fut, serviceId: serviceId, registrar: registrar, bucketIdx: bucketIdx
    )
  )
  cd_advertiser_pending_actions.inc()

func anyProvidedService(a: Advertiser): Opt[ServiceId] =
  ## A Table has no first-element accessor, so take the first key iterated.
  for id in a.providedAdverts.keys:
    return Opt.some(id)
  Opt.none(ServiceId)

proc startLocalRegistration(disco: ServiceDiscovery) =
  ## Starts (or restarts) the single long-lived local self-registration task.

  if not disco.isServer:
    trace "Not registering locally while in client mode",
      services = disco.advertiser.providedAdverts.len
    return

  if not disco.localRegistrationLoop.isNil and not disco.localRegistrationLoop.finished:
    return

  let sid = disco.advertiser.anyProvidedService().valueOr:
    return

  let selfPeer = disco.switch.peerInfo.peerId
  disco.localRegistrationLoop = disco.advertiseToRegistrar(
    sid,
    selfPeer,
    Opt.none(Ticket),
    disco.advertiser.providedAdverts.getOrDefault(sid).bytes,
  )

proc stopLocalRegistration(
    disco: ServiceDiscovery
) {.async: (raises: [CancelledError]).} =
  if disco.localRegistrationLoop.isNil:
    return

  await disco.localRegistrationLoop.cancelAndWait()

  disco.localRegistrationLoop = nil

proc restartLocalRegistration(disco: ServiceDiscovery) =
  if not disco.localRegistrationLoop.isNil:
    disco.localRegistrationLoop.cancelSoon()
    disco.localRegistrationLoop = nil
  disco.startLocalRegistration()

proc maintainRegistrations*(
    disco: ServiceDiscovery
) {.async: (raises: [CancelledError]).} =
  ## Periodic enforcement of the remote registration invariant:
  ##
  ## We maintain (up to) kRegister live registrars per bucket from each
  ## service's routing table. On Confirmed we terminate the task so the
  ## maintenance loop can rotate the slot to another peer in the bucket.

  cleanupFinishedTasks(disco.advertiser)

  if not disco.isServer:
    trace "No registration maintenance while in client mode"
    return

  let selfPeer = disco.switch.peerInfo.peerId

  for sid, advert in disco.advertiser.providedAdverts:
    let table = disco.rtManager.getTable(sid).valueOr:
      continue

    # --- Remote registrars (bucketIdx >= 0) ---
    var activePerBucket = initTable[int, HashSet[PeerId]]()
    for t in disco.advertiser.running:
      if t.serviceId == sid and not t.fut.finished and t.bucketIdx >= 0:
        activePerBucket.mgetOrPut(t.bucketIdx, initHashSet[PeerId]()).incl(t.registrar)

    for bucketIdx, bucket in table.buckets.pairs:
      if bucket.peers.len == 0:
        continue

      var active = activePerBucket.getOrDefault(bucketIdx)

      # Drop tasks for peers that are no longer in this bucket (stale after refresh)
      var stale: seq[AdvertiseTask]
      for t in disco.advertiser.running:
        if t.serviceId == sid and t.bucketIdx == bucketIdx and not t.fut.finished:
          let regKey = t.registrar.toKey()
          if regKey notin bucket.peers:
            stale.add(t)
      for t in stale:
        t.fut.cancelSoon()
        disco.advertiser.running.excl(t)
        cd_advertiser_pending_actions.dec()
        active.excl(t.registrar)

      let target = min(disco.discoConfig.kRegister, bucket.peers.len)
      let deficit = target - active.len
      if deficit <= 0:
        continue

      var candidates: seq[PeerId]
      for nodeId in bucket.peers:
        let pid = nodeId.toPeerId().valueOr:
          continue
        if pid notin active and pid != selfPeer:
          candidates.add(pid)

      let toAdd = disco.rng.pick(candidates, deficit).valueOr:
        continue

      for registrar in toAdd:
        disco.trackAdvertiseTask(sid, registrar, bucketIdx, advert.bytes)

  # Defensive restart of the local registration loop if it died unexpectedly
  # while we still provide services.
  if disco.advertiser.providedAdverts.len > 0 and
      (disco.localRegistrationLoop.isNil or disco.localRegistrationLoop.finished):
    disco.startLocalRegistration()

proc republishProvidedAdverts*(
    disco: ServiceDiscovery
) {.async: (raises: [CancelledError]).} =
  ## Registrars keep serving the bytes cached at `addProvidedService`.
  let fresh = disco.getAdvertBytes(Opt.none(seq[byte])).valueOr:
    return

  var refreshed = false
  for advert in disco.advertiser.providedAdverts.mvalues:
    if advert.callerSupplied:
      continue
    advert.bytes = fresh
    refreshed = true

  if not refreshed:
    return

  await disco.advertiser.cancelRunningTasks()
  await disco.stopLocalRegistration()
  disco.startLocalRegistration()
  await disco.maintainRegistrations()

proc maintainAdvertiser*(
    disco: ServiceDiscovery
) {.async: (raises: [CancelledError]).} =
  heartbeat "advertiser registration maintenance",
    disco.config.bucketRefreshTime, sleepFirst = true:
    await disco.maintainRegistrations()

proc localRegister(disco: ServiceDiscovery, msg: Message): LPResult[Message] =
  return ok(disco.registration(disco.switch.peerInfo.peerId, msg))

proc sendRegister*(
    disco: ServiceDiscovery,
    peerId: PeerId,
    serviceId: ServiceId,
    ad: seq[byte],
    ticket: Opt[Ticket] = Opt.none(Ticket),
): Future[LPResult[RegistrationResponse]] {.async: (raises: [CancelledError]).} =
  let msg = Message(
    msgType: Opt.some(MessageType.register),
    key: Opt.some(serviceId),
    register: Opt.some(
      RegisterMessage(
        advertisement: Opt.some(ad),
        status: Opt.none(kademlia_protobuf.RegistrationStatus),
        ticket: ticket,
      )
    ),
  )

  let replyRes =
    if peerId == disco.switch.peerInfo.peerId:
      disco.localRegister(msg)
    else:
      await disco.send(peerId, msg)

  let reply = replyRes.valueOr:
    return err($error)

  let registerMsg = reply.register.valueOr:
    return err("register reply not found")
  let status = registerMsg.status.valueOr:
    return err("register reply status not found")

  cd_register_responses.inc(labelValues = [$status])

  let closerPeers = reply.closerPeers.toPeerInfos()

  return ok(
    RegistrationResponse(
      status: status, ticket: registerMsg.ticket, closerPeers: closerPeers
    )
  )

proc advertiseToRegistrar*(
    disco: ServiceDiscovery,
    serviceId: ServiceId,
    registrar: PeerId,
    ticket: Opt[Ticket],
    advert: seq[byte],
) {.async: (raises: [CancelledError]).} =
  if not disco.rtManager.hasService(serviceId):
    error "No service routing table found", serviceId
    return

  cd_advertiser_actions_executed.inc()

  let isSelf = registrar == disco.switch.peerInfo.peerId
  var currentTicket = ticket

  trace "Registering advert", serviceId, registrar, isSelf

  # `changeMode` can flip the mode at any point, so every iteration re-reads it
  while true:
    if not disco.isServer:
      trace "Not advertising while in client mode", serviceId, registrar
      return

    let response = (
      await disco.sendRegister(registrar, serviceId, advert, currentTicket)
    ).valueOr:
      trace "Failed to register ad", serviceId, registrar, error
      return

    disco.admitPeers(response.closerPeers)
    disco.rtManager.admitPeers(disco, serviceId, response.closerPeers)

    case response.status
    of kademlia_protobuf.RegistrationStatus.Confirmed:
      trace "Advert accepted", serviceId, registrar

      # Drop any ticket used for this Confirm.
      # Self-registration reuses this loop after advertExpiry.
      currentTicket = Opt.none(Ticket)

      await sleepAsync(disco.discoConfig.advertExpiry)

      if isSelf:
        # Local registration task (the single long-lived one stored in
        # localRegistrationLoop). Keep refreshing so our advert stays
        # current in the local registrar.
        continue
      else:
        # For remote registrars: terminate the task after one lifetime.
        # The maintenance loop will then rotate this slot to another peer
        # in the same bucket.
        return
    of kademlia_protobuf.RegistrationStatus.Wait:
      let newTicket = response.ticket.valueOr:
        trace "No ticket to retry with", serviceId, registrar
        return

      currentTicket = Opt.some(newTicket)

      let waitSecs = min(disco.discoConfig.advertExpiry, newTicket.tWaitFor.get())

      trace "Waiting for registrar", serviceId, registrar, wait = $waitSecs

      await sleepAsync(waitSecs)
    of kademlia_protobuf.RegistrationStatus.Rejected:
      trace "Registrar rejection, aborting", serviceId, registrar
      return

proc validateAdvert(advert: seq[byte], service: ServiceInfo): LPResult[PeerId] =
  ## Applies the checks a registrar applies in `isValidAdvertisement`, so a bad
  ## record fails here instead of being republished on every rotation.

  # measured before the decode, which skips (and so hides) unknown fields
  if advert.len > MaxXPRSize:
    return err(
      "oversized advertisement: " & $advert.len & " bytes, the limit is " & $MaxXPRSize
    )

  let ad = Advertisement.decode(advert).valueOr:
    return err("cannot decode advertisement: " & $error)

  if not ad.isValid():
    return err(
      "invalid advertisement: the record must stay at most " & $MaxXPRSize &
        " bytes and each service data at most " & $MaxServiceDataSize & " bytes"
    )

  if not ad.advertisesService(service.id.hashServiceId()):
    return err("advertisement does not advertise service '" & service.id & "'")

  ok(ad.data.peerId)

proc scheduleRegistrations(
    disco: ServiceDiscovery,
    serviceId: ServiceId,
    table: RoutingTable,
    advertBytes: seq[byte],
    superseded: seq[Future[void]] = @[],
) =
  ## Spawns up to kRegister registration tasks per populated bucket.
  for bucketIdx, bucket in table.buckets.pairs:
    if bucket.peers.len == 0:
      continue

    let peers = disco.rng.pick(bucket.peers, disco.discoConfig.kRegister).valueOr:
      continue

    for peer in peers:
      let registrar = peer.toPeerId().valueOr:
        trace "Cannot convert key to peer id", error
        continue

      disco.trackAdvertiseTask(serviceId, registrar, bucketIdx, advertBytes, superseded)

proc dropOwnService(disco: ServiceDiscovery, serviceId: string): Opt[ServiceInfo] =
  for s in disco.services:
    if s.id == serviceId:
      disco.services.excl(s)
      return Opt.some(s)
  Opt.none(ServiceInfo)

proc ownXpr(disco: ServiceDiscovery): LPResult[SignedXpr] =
  let record = disco.record().valueOr:
    return err("cannot build own signed peer record: " & $error)
  ok(SignedXpr(peerId: disco.switch.peerInfo.peerId, bytes: record.encode()))

proc xprsToPublish*(disco: ServiceDiscovery): seq[SignedXpr] =
  ## One DHT key holds one record per signer, so a caller XPR signed with this
  ## node's key replaces the own XPR, which a newer seqNo would otherwise win.
  var xprs: seq[SignedXpr]
  for advert in disco.advertiser.providedAdverts.values:
    if not advert.callerSupplied or xprs.anyIt(it.bytes == advert.bytes):
      continue
    xprs.add(SignedXpr(peerId: advert.signer, bytes: advert.bytes))

  let ownPeerId = disco.switch.peerInfo.peerId
  if not disco.xprPublishing or xprs.anyIt(it.peerId == ownPeerId):
    return xprs

  let own = disco.ownXpr().valueOr:
    debug "Own signed peer record not published", err = error
    return xprs
  xprs.add(own)
  xprs

proc publishXpr(
    disco: ServiceDiscovery, xpr: SignedXpr
) {.async: (raises: [CancelledError]).} =
  ## A random walk finds the record only when its signer is a DHT peer.
  (await disco.putValue(xpr.peerId.toKey(), Value.fromBytes(xpr.bytes))).isOkOr:
    debug "Failed to put signed peer record", err = error, peerId = xpr.peerId

proc publishXprs(disco: ServiceDiscovery) {.async: (raises: [CancelledError]).} =
  let futs = disco.xprsToPublish().mapIt(disco.publishXpr(it))
  try:
    await allFutures(futs)
  except CancelledError as e:
    await noCancel futs.cancelAndWait()
    raise e

proc maintainXprs*(disco: ServiceDiscovery) {.async: (raises: [CancelledError]).} =
  heartbeat "refresh signed peer records", disco.config.bucketRefreshTime:
    if not await disco.publishXprs().withTimeout(disco.config.bucketRefreshTime):
      warn "Signed peer record refresh timed out",
        timeout = disco.config.bucketRefreshTime

proc maintainXprsAfter(
    disco: ServiceDiscovery, previous: Future[void]
) {.async: (raises: [CancelledError]).} =
  await noCancel previous.cancelAndWait()
  await disco.maintainXprs()

proc restartXprPublishing*(disco: ServiceDiscovery) =
  ## Publishes the current XPRs at once. The new loop waits for the old one to
  ## stop, so a stale record cannot land after a fresh one.
  if disco.xprPublishLoop.isNil():
    return

  disco.xprPublishLoop = disco.maintainXprsAfter(disco.xprPublishLoop)

proc takeServiceTasks(a: Advertiser, serviceId: ServiceId): seq[Future[void]] =
  var kept: HashSet[AdvertiseTask]
  var taken: seq[Future[void]]
  for t in a.running:
    if t.serviceId == serviceId:
      taken.add(t.fut)
    else:
      kept.incl(t)

  a.running = kept
  cd_advertiser_pending_actions.set(a.running.len.float64)
  taken

proc cancelServiceTasks(
    disco: ServiceDiscovery, serviceId: ServiceId
): seq[Future[void]] =
  let cancelled = disco.advertiser.takeServiceTasks(serviceId)
  for fut in cancelled:
    fut.cancelSoon()
  cancelled

proc addProvidedService*(
    disco: ServiceDiscovery,
    service: ServiceInfo,
    advert: Opt[seq[byte]] = Opt.none(seq[byte]),
): LPResult[void] =
  ## A caller-supplied `advert` is published as is and never enters this node's
  ## own record. A second call for the same service replaces its advert.
  if not disco.isServer:
    return err("cannot advertise in client mode")

  if not service.isValid():
    return err("service data exceeds the maximum of " & $MaxServiceDataSize & " bytes")

  let signer =
    if advert.isSome():
      ?validateAdvert(advert.get(), service)
    else:
      disco.switch.peerInfo.peerId

  let serviceId = service.id.hashServiceId()
  let replacing = serviceId in disco.advertiser.providedAdverts

  if not replacing and
      not disco.rtManager.addService(
        serviceId, disco.rtable, disco.config.replication,
        disco.discoConfig.bucketsCount, Provided,
      ):
    return err("service '" & service.id & "' is already advertised")

  let previous =
    if replacing or advert.isSome():
      disco.dropOwnService(service.id)
    else:
      Opt.none(ServiceInfo)
  if advert.isNone():
    disco.services.incl(service)

  let advertBytes = disco.getAdvertBytes(advert).valueOr:
    discard disco.dropOwnService(service.id)
    previous.ifValue(p):
      disco.services.incl(p)
    if not replacing:
      disco.rtManager.removeService(serviceId, Provided)
    return err("cannot build the extended peer record to advertise")

  let superseded = disco.cancelServiceTasks(serviceId)

  # Rotations reuse these bytes; a later seqNo would duplicate this node in a lookup.
  disco.advertiser.providedAdverts[serviceId] =
    ProvidedAdvert(bytes: advertBytes, callerSupplied: advert.isSome(), signer: signer)

  debug "Provided service advert stored", service = service.id, serviceId, replacing
  if not replacing:
    cd_advertiser_services_added.inc()

  disco.rtManager.getTable(serviceId).ifValue(table):
    disco.scheduleRegistrations(serviceId, table, advertBytes, superseded)

  if replacing:
    disco.restartLocalRegistration()
  else:
    disco.startLocalRegistration()
  disco.restartXprPublishing()

  ok()

proc removeProvidedService*(
    disco: ServiceDiscovery, serviceId: string
) {.async: (raises: [CancelledError]).} =
  let sid = serviceId.hashServiceId()

  await disco.advertiser.takeServiceTasks(sid).cancelAndWait()

  disco.advertiser.providedAdverts.del(sid)

  disco.rtManager.removeService(sid, Provided)
  discard disco.dropOwnService(serviceId)

  # The local loop may still register the removed advert, so move it to a remaining one.
  await disco.stopLocalRegistration()
  disco.startLocalRegistration()
  disco.restartXprPublishing()

  debug "Removed provided service", service = serviceId, serviceId = sid

  cd_advertiser_services_removed.inc()

proc startAdvertising*(
    disco: ServiceDiscovery,
    service: ServiceInfo,
    advert: Opt[seq[byte]] = Opt.none(seq[byte]),
): LPResult[void] =
  disco.addProvidedService(service, advert = advert)

proc stopAdvertising*(
    disco: ServiceDiscovery, serviceId: string
) {.async: (raises: [CancelledError]).} =
  await disco.removeProvidedService(serviceId)
