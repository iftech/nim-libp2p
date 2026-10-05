# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, results, sets, tables, sequtils
import ../utils/[heartbeat, future]
import ../[peerid, switch, multihash, peerinfo, extended_peer_record]
import ./kademlia
import
  ./service_discovery/[
    random_find, types, routing_table_manager, advertiser, registrar, discoverer,
    connection, advertisement_cache, discovery_tracker,
  ]

export chronicles, random_find, types, discoverer, advertiser, advertisement_cache
export discovery_tracker

logScope:
  topics = "libp2p service-discovery"

method maintainableTables*(
    disco: ServiceDiscovery
): seq[RoutingTable] {.gcsafe, raises: [].} =
  ## Main Kad table plus every per-service routing table.
  var tables = @[disco.rtable]
  for table in disco.rtManager.tables.values:
    tables.add(table)
  return tables

template withBucketRefreshTimeout(fut: untyped, disco: ServiceDiscovery): untyped =
  fut.withTimeout(disco.config.bucketRefreshTime)

proc republishAddresses(
    disco: ServiceDiscovery, previous: Future[void]
) {.async: (raises: [CancelledError]).} =
  if not previous.isNil():
    await previous.cancelAndWait()

  # A restart publishes the new record at once and keeps one record publisher.
  if disco.xprPublishing:
    disco.restartXprPublishing()

  if not await disco.republishProvidedAdverts().withBucketRefreshTimeout(disco):
    warn "Provided advert republish timed out", timeout = disco.config.bucketRefreshTime

proc republishOnAddressChange(disco: ServiceDiscovery): PeerInfoObserver =
  ## Without this, a moved address stays stale in the DHT for a `bucketRefreshTime`.
  proc(p: PeerInfo) {.gcsafe, raises: [].} =
    disco.addressRepublish = disco.republishAddresses(disco.addressRepublish)

proc maintainRegistrar(disco: ServiceDiscovery) {.async: (raises: [CancelledError]).} =
  heartbeat "prune expired advertisements",
    disco.discoConfig.advertExpiry, sleepFirst = true:
    disco.registrar.pruneExpiredAds(disco.discoConfig.advertExpiry)

proc maintainServiceTables(
    disco: ServiceDiscovery
) {.async: (raises: [CancelledError]).} =
  heartbeat "refresh service routing tables",
    disco.config.bucketRefreshTime, sleepFirst = true:
    if not await disco.rtManager.refreshAllTables(disco).withBucketRefreshTimeout(disco):
      warn "Service routing table refresh timed out",
        timeout = disco.config.bucketRefreshTime, tables = disco.rtManager.tables.len

proc bootstrapServiceTable*(
    disco: ServiceDiscovery, serviceId: ServiceId
) {.async: (raises: [CancelledError]).} =
  let rtable = disco.rtManager.getTable(serviceId).valueOr:
    return

  await disco.refreshTable(rtable, forceRefresh = true)
  debug "Service table bootstrap complete", serviceId

proc new*(
    T: typedesc[ServiceDiscovery],
    switch: Switch,
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
    config: KadDHTConfig = KadDHTConfig.new(),
    rng: Rng,
    client: bool = false,
    codec: string = ExtendedServiceDiscoveryCodec,
    services: seq[ServiceInfo] = @[],
    discoConfig: ServiceDiscoveryConfig = ServiceDiscoveryConfig.new(),
    xprPublishing: bool = true,
): T {.raises: [].} =
  # Every value in this DHT is an XPR keyed by its signer, whatever the caller configured.
  var kadConfig = config
  kadConfig.validator = ExtEntryValidator()
  kadConfig.selector = ExtEntrySelector()

  let disco = ServiceDiscovery(
    rtManager: ServiceRoutingTableManager.new(),
    advertiser: Advertiser.new(),
    registrar: Registrar.new(discoConfig.advertCacheCap),
    tracker: DiscoveryTracker.new(switch.peerInfo.peerId),
    services: toHashSet(services),
    discoConfig: discoConfig,
    xprPublishing: xprPublishing,
  )
  disco.initKadBase(
    switch,
    kadConfig,
    rng,
    isServer = not client,
    codec = codec,
    bootstrapNodes = bootstrapNodes,
  )

  disco.rtManager.onServiceTableCreated = proc(serviceId: ServiceId) =
    if disco.config.disableBootstrapping:
      return

    disco.serviceBootstrapFuts[serviceId] = disco.bootstrapServiceTable(serviceId)

  disco.registrar.ads.onServiceRemoved = proc(serviceId: ServiceId) =
    disco.rtManager.removeService(serviceId, Registered)

  disco.rtManager.onServiceTableRemoved = proc(serviceId: ServiceId) =
    disco.serviceBootstrapFuts.withValue(serviceId, fut):
      fut[].cancelSoon()
    disco.serviceBootstrapFuts.del(serviceId)

  disco.handler = proc(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    if not disco.isServer:
      trace "Refusing inbound query while not serving", stream
      await stream.reset()
      return

    disco.serverStreams.incl(stream)
    defer:
      disco.serverStreams.excl(stream)
      await stream.close()
    while not stream.atEof:
      let buf =
        try:
          await stream.readLp(ServiceDiscoveryMaxMsgSize)
        except LPStreamEOFError:
          return
        except LPStreamError as exc:
          trace "Read error when handling service-discovery RPC", err = exc.msg, stream
          return
      let msg = Message.decode(buf).valueOr:
        trace "Failed to decode message", err = error
        return

      let msgType = msg.msgType.get(MessageType.putValue)
      case msgType
      of MessageType.findNode:
        await disco.handleFindNode(stream, msg)
      of MessageType.putValue:
        await disco.handlePutValue(stream, msg)
      of MessageType.getValue:
        await disco.handleGetValue(stream, msg)
      of MessageType.addProvider:
        await disco.handleAddProvider(stream, msg)
      of MessageType.getProviders:
        await disco.handleGetProviders(stream, msg)
      of MessageType.ping:
        await disco.handlePing(stream, msg)
      else:
        if msgType in @[MessageType.register, MessageType.getAds]:
          await disco.handleMessage(stream, msg)
        else:
          trace "Received invalid message type", msgType = msgType
          return

  return disco

method start*(disco: ServiceDiscovery) {.async: (raises: [CancelledError]).} =
  if disco.started:
    warn "Starting kad-disco twice"
    return

  await procCall start(KadDHT(disco))

  for serviceInfo in disco.services:
    disco.addProvidedService(serviceInfo).isOkOr:
      warn "Cannot advertise configured service", err = error, service = serviceInfo.id

  disco.xprPublishLoop = disco.maintainXprs()
  reportBackgroundFailure(disco.xprPublishLoop, "service discovery XPR publishing")

  disco.addressObserver = disco.republishOnAddressChange()
  disco.switch.peerInfo.addObserver(disco.addressObserver)

  disco.pruneExpiredAdsLoop = disco.maintainRegistrar()
  disco.refreshServiceTablesLoop = disco.maintainServiceTables()
  disco.advertiserMaintenanceLoop = disco.maintainAdvertiser()

  info "Service Discovery started"

method stop*(disco: ServiceDiscovery) {.async: (raises: []).} =
  if not disco.started:
    return

  # every loop that schedules advertiser tasks stops before the drain below
  if not disco.addressObserver.isNil():
    disco.switch.peerInfo.removeObserver(disco.addressObserver)
    disco.addressObserver = nil

  if not disco.addressRepublish.isNil():
    await disco.addressRepublish.cancelAndWait()
    disco.addressRepublish = nil

  if not disco.xprPublishLoop.isNil():
    let loop = disco.xprPublishLoop
    disco.xprPublishLoop = nil
    await loop.cancelAndWait()

  if not disco.advertiserMaintenanceLoop.isNil:
    await disco.advertiserMaintenanceLoop.cancelAndWait()
    disco.advertiserMaintenanceLoop = nil

  await disco.advertiser.clear()

  let serviceBootstrapFuts = move disco.serviceBootstrapFuts
  await noCancel serviceBootstrapFuts.values.toSeq().cancelAndWait()

  if not disco.pruneExpiredAdsLoop.isNil:
    await disco.pruneExpiredAdsLoop.cancelAndWait()
    disco.pruneExpiredAdsLoop = nil

  if not disco.refreshServiceTablesLoop.isNil:
    await disco.refreshServiceTablesLoop.cancelAndWait()
    disco.refreshServiceTablesLoop = nil

  if not disco.localRegistrationLoop.isNil:
    await disco.localRegistrationLoop.cancelAndWait()
    disco.localRegistrationLoop = nil

  await procCall stop(KadDHT(disco))

proc lookup*(
    disco: ServiceDiscovery, service: ServiceInfo
): Future[LPResult[seq[Advertisement]]] {.async: (raises: [CancelledError]).} =
  return await disco.lookup(service.id.hashServiceId())
