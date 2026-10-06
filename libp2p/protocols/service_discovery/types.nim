# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sequtils, sets, tables, hashes, net]
import chronicles, chronos, results, stew/byteutils
import nimcrypto/sha2
import
  ../../[
    peerid, switch, multihash, cid, multicodec, routing_record, extended_peer_record
  ]
import ../../utils/iptree
import ../kademlia/[types, protobuf]

export iptree
export extended_peer_record.MaxServiceDataSize
export extended_peer_record.MaxXPRSize
export extended_peer_record.isValid
export types

const
  DefaultSelfSPRRereshTime* = 10.minutes

  ExtendedServiceDiscoveryCodec* = "/logos/service-discovery/1.0.0"
  ServiceDiscoveryMaxMsgSize* = 4096

  Default_K_register* = 3
  Default_K_lookup* = 5
  CloserPeersPerBucket* = 1
    ## GETPEERS returns one peer per bucket, so a reply stays spread across
    ## buckets instead of concentrating in whichever the responder picks.
  Default_F_lookup* = 30
  Default_F_return* = 10
  Default_E* = 900.secs
  Default_C*: uint64 = 1_000
  Default_P_occ* = 10.0
  Default_G* = 1e-7
  Default_Delta* = 1.secs
  Default_M_buckets* = 16
  Default_IpSimCoefficient* = 1.0
  Default_DialBackoffBase* = 30.secs
  Default_DialBackoffMax* = 30.minutes
  Default_MaxDialFailures* = 5

type
  ServiceId* = Key

  ServiceStatus* = enum
    Interest
    Provided
    Registered

  ServiceRoutingTableManager* = ref object
    tables*: Table[ServiceId, RoutingTable]
    serviceStatus*: Table[ServiceId, set[ServiceStatus]]
    onServiceTableCreated*: proc(serviceId: ServiceId) {.gcsafe, closure, raises: [].}
    onServiceTableRemoved*: proc(serviceId: ServiceId) {.gcsafe, closure, raises: [].}

  Advertisement* = SignedExtendedPeerRecord

  CachedAd* = object
    ad*: Advertisement
    advertiser*: PeerId
    ips*: seq[IpAddress]
    timestamp*: Moment

  AdvertisementCache* = ref object
    byService*: Table[ServiceId, Table[PeerId, CachedAd]]
    ipTree*: IpTree
    capacity*: uint64
    count*: int
    onServiceRemoved*: proc(serviceId: ServiceId) {.gcsafe, closure, raises: [].}

  Registrar* = ref object
    ads*: AdvertisementCache
    boundService*: Table[ServiceId, Moment]
    timestampService*: Table[ServiceId, Moment]
    boundIp*: Table[string, Moment]
    timestampIp*: Table[string, Moment]

  AdvertiseTask* = ref object
    fut*: Future[void]
    serviceId*: ServiceId
    registrar*: PeerId
    bucketIdx*: int

  ProvidedAdvert* = object
    bytes*: seq[byte]
    callerSupplied*: bool ## Bytes we did not build carry addresses we cannot refresh.
    signer*: PeerId

  Advertiser* = ref object
    running*: HashSet[AdvertiseTask]
    seqNo*: uint64
    providedAdverts*: Table[ServiceId, ProvidedAdvert]

  ServiceDiscoveryConfig* = object
    kRegister*: int
    kLookup*: int
    fLookup*: int
    fReturn*: int
    advertExpiry*: Duration
    advertCacheCap*: uint64
    occupancyExp*: float64
    safetyParam*: float64
    ipSimCoefficient*: float64
    registrationWindow*: Duration
    bucketsCount*: int
    dialBackoffBase*: Duration
    dialBackoffMax*: Duration ## Cap of the exponential dial backoff.
    maxDialFailures*: int
      ## Consecutive failed dials before the peer leaves every service table.

  DiscoverySource* = enum
    FromLookup
    FromRegistration

  ProviderDiscovery* = object
    provider*: PeerId
    rank*: int
    elapsed*: Duration
    source*: DiscoverySource

  ServiceInterest* = object
    active*: bool
    startedAt*: Moment
    seen*: HashSet[PeerId]
    found*: seq[ProviderDiscovery]

  DiscoveryTracker* = ref object
    selfId*: PeerId
    maxProviders*: int
    interests*: Table[ServiceId, ServiceInterest]

  ServiceDiscovery* = ref object of KadDHT
    advertiser*: Advertiser
    registrar*: Registrar
    rtManager*: ServiceRoutingTableManager
    tracker*: DiscoveryTracker
    services*: HashSet[ServiceInfo]
    discoConfig*: ServiceDiscoveryConfig
      # can't use name "config", clashes with KadDHT's config
    xprPublishing*: bool
    xprPublishLoop*: Future[void]
    pruneExpiredAdsLoop*: Future[void]
    refreshServiceTablesLoop*: Future[void]
    advertiserMaintenanceLoop*: Future[void]
    localRegistrationLoop*: Future[void]
    serviceBootstrapFuts*: Table[ServiceId, Future[void]]
    addressRepublish*: Future[void]
    addressObserver*: PeerInfoObserver
    dialFailures*: Table[PeerId, ProbeFailure]

proc new*(
    T: typedesc[ServiceDiscoveryConfig],
    kRegister = Default_K_register,
    kLookup = Default_K_lookup,
    fLookup = Default_F_lookup,
    fReturn = Default_F_return,
    advertExpiry = Default_E,
    advertCacheCap = Default_C,
    occupancyExp = Default_P_occ,
    safetyParam = Default_G,
    ipSimCoefficient = Default_IpSimCoefficient,
    registrationWindow = Default_Delta,
    bucketsCount = Default_M_buckets,
    dialBackoffBase = Default_DialBackoffBase,
    dialBackoffMax = Default_DialBackoffMax,
    maxDialFailures = Default_MaxDialFailures,
): T {.raises: [].} =
  doAssert advertCacheCap > 0, "advertCacheCap must be > 0"
  doAssert ipSimCoefficient >= 0.0, "ipSimCoefficient must be >= 0"
  doAssert maxDialFailures > 0, "maxDialFailures must be > 0"
  doAssert dialBackoffBase > 0.nanoseconds, "dialBackoffBase must be > 0"
  doAssert dialBackoffMax > 0.nanoseconds, "dialBackoffMax must be > 0"
  ServiceDiscoveryConfig(
    kRegister: kRegister,
    kLookup: kLookup,
    fLookup: fLookup,
    fReturn: fReturn,
    advertExpiry: advertExpiry,
    advertCacheCap: advertCacheCap,
    occupancyExp: occupancyExp,
    safetyParam: safetyParam,
    ipSimCoefficient: ipSimCoefficient,
    registrationWindow: registrationWindow,
    bucketsCount: bucketsCount,
    dialBackoffBase: dialBackoffBase,
    dialBackoffMax: dialBackoffMax,
    maxDialFailures: maxDialFailures,
  )

proc hash*(t: AdvertiseTask): Hash =
  hash(cast[pointer](t))

proc hash*(ad: Advertisement): Hash {.raises: [].} =
  hash(ad.envelope.signature.data)

proc new*(
    T: typedesc[AdvertisementCache], capacity: uint64 = Default_C
): T {.raises: [].} =
  doAssert capacity > 0, "capacity must be > 0"
  T(
    byService: initTable[ServiceId, Table[PeerId, CachedAd]](),
    ipTree: IpTree.new(),
    capacity: capacity,
    count: 0,
  )

proc encode*(ads: seq[Advertisement], fReturn: int): seq[seq[byte]] {.raises: [].} =
  var adBytes: seq[seq[byte]]
  for ad in ads:
    if adBytes.len >= fReturn:
      break
    adBytes.add(ad.encode())
  adBytes

proc hashServiceId*(serviceStr: string): ServiceId =
  let digest = sha256.digest(serviceStr)
  ServiceId.fromBytes(@(digest.data))

proc advertisesService*(ad: Advertisement, serviceId: ServiceId): bool =
  ad.data.services.anyIt(hashServiceId(it.id) == serviceId)

proc new*(T: typedesc[Registrar], advertCacheCap: uint64 = Default_C): T =
  T(
    ads: AdvertisementCache.new(advertCacheCap),
    boundService: initTable[ServiceId, Moment](),
    timestampService: initTable[ServiceId, Moment](),
    boundIp: initTable[string, Moment](),
    timestampIp: initTable[string, Moment](),
  )

proc new*(T: typedesc[Advertiser]): T =
  T(
    running: initHashSet[AdvertiseTask](),
    seqNo: nowUnixSeconds().uint64,
    providedAdverts: initTable[ServiceId, ProvidedAdvert](),
  )

proc toKey*(service: ServiceInfo): Key =
  return MultiHash.digest("sha2-256", service.id.toBytes()).get().toKey()

proc init*(
    T: typedesc[ExtendedPeerRecord],
    peerInfo: PeerInfo,
    seqNo: uint64 = nowUnixSeconds().uint64,
    services: seq[ServiceInfo] = @[],
): T =
  T(
    peerId: peerInfo.peerId,
    seqNo: seqNo,
    addresses: peerInfo.addrs.mapIt(AddressInfo(address: it)),
    services: services,
  )

proc boundXpr*(key: Key, value: Value): Opt[SignedExtendedPeerRecord] =
  ## Accepts a valid signed XPR only when its subject is the peer that `key` names.
  let expectedPeerId = key.toPeerId().valueOr:
    return Opt.none(SignedExtendedPeerRecord)

  let sxpr = SignedExtendedPeerRecord.decode(value.toBytes()).valueOr:
    return Opt.none(SignedExtendedPeerRecord)

  if sxpr.data.peerId != expectedPeerId or not sxpr.isValid():
    return Opt.none(SignedExtendedPeerRecord)

  Opt.some(sxpr)

type ExtEntryValidator* = ref object of EntryValidator
method isValid*(
    self: ExtEntryValidator, key: Key, record: EntryRecord
): bool {.raises: [], gcsafe.} =
  boundXpr(key, record.value).isSome()

type ExtEntrySelector* = ref object of EntrySelector
method select*(
    self: ExtEntrySelector, key: Key, records: seq[EntryRecord]
): LPResult[int] {.raises: [], gcsafe.} =
  if records.len == 0:
    return err("No records to choose from")

  var maxSeqNo: uint64 = 0
  var bestIdx: int = -1

  for i, rec in records:
    let spr = SignedExtendedPeerRecord.decode(rec.value.toBytes()).valueOr:
      continue

    let seqNo = spr.data.seqNo
    if seqNo > maxSeqNo or bestIdx == -1:
      maxSeqNo = seqNo
      bestIdx = i

  if bestIdx == -1:
    return err("No valid records")

  return ok(bestIdx)

proc record*(disco: ServiceDiscovery): LPResult[SignedExtendedPeerRecord] =
  let peerInfo = disco.switch.peerInfo
  let filteredAddresses = disco.config.addressPolicy.dialableAddrs(
    peerInfo.addrs, disco.switch.peerStore.allowUndialableAddrs
  )
  # Before the transports bind, `addrs` still holds the raw listen address.
  if filteredAddresses.len == 0:
    return err("no dialable address to publish yet")

  let peerRecord = ExtendedPeerRecord.init(
    peerId = peerInfo.peerId,
    addresses = filteredAddresses,
    seqNo = nowUnixSeconds().uint64,
    services = disco.services.toSeq(),
  )

  SignedExtendedPeerRecord.build(peerInfo.privateKey, peerRecord)

proc toPeerInfos*(peers: seq[Peer]): seq[PeerInfo] =
  var peerInfos: seq[PeerInfo]

  for p in peers:
    let raw = p.id.valueOr:
      continue
    let pid = PeerId.init(raw).valueOr:
      continue

    let peerInfo = PeerInfo(peerId: pid, addrs: p.addrs)

    peerInfos.add(peerInfo)

  return peerInfos
