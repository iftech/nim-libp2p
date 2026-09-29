# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/net
import chronos, results, sequtils, tables
import
  ../../../libp2p/[
    builders,
    crypto/crypto,
    extended_peer_record,
    multiaddress,
    peerid,
    peerinfo,
    protobuf/minprotobuf,
    protocols/kademlia,
    protocols/kademlia/protobuf,
    protocols/service_discovery,
    protocols/service_discovery/registrar,
    protocols/service_discovery/routing_table_manager,
    protocols/service_discovery/types,
    routing_record,
    switch,
  ]
import ../../tools/[switch_builder, multiaddress]
import ../../tools/crypto as testcrypto

export protobuf, registrar, routing_table_manager, types, testcrypto

converter toOptKey*(key: Key): Opt[Key] =
  Opt.some(key)

converter toOptValue*(value: Value): Opt[Value] =
  Opt.some(value)

converter toOptTimestamp*(a: UnixTimestamp): Opt[UnixTimestamp] =
  Opt.some(a)

converter toOptDuration*(a: Duration): Opt[Duration] =
  Opt.some(a)

converter toOptMessageType*(a: MessageType): Opt[MessageType] =
  Opt.some(a)

converter toOptSeqByte*(a: seq[byte]): Opt[seq[byte]] =
  Opt.some(a)

proc randomKey*(): PrivateKey =
  PrivateKey.random(rng()).get()

proc makePeerInfo*(
    peerId: PeerId = randomPeerId(), addrs: seq[MultiAddress] = @[]
): PeerInfo =
  PeerInfo(peerId: peerId, addrs: addrs)

proc makeServiceId*(id: byte = 1'u8): ServiceId =
  var buf = newSeq[byte](IdLength)
  buf[0] = id
  return ServiceId.fromBytes(buf)

proc makeServiceInfo*(id: string = "test-service"): ServiceInfo =
  ServiceInfo(id: id, data: @[1'u8, 2, 3, 4])

proc makeTicket*(): Ticket =
  Ticket(
    advertisement: @[1'u8, 2, 3, 4],
    tInit: 1_000_000'i64,
    tMod: 2_000_000'i64,
    tWaitFor: 3000.secs,
    signature: Opt.none(seq[byte]),
  )

proc signedTicket*(privateKey: PrivateKey): Ticket =
  var t = makeTicket()
  let res = t.sign(privateKey)
  doAssert res.isOk(), "sign failed in test helper"
  t

proc makeMultiAddress*(ip: string): MultiAddress =
  ma("/ip4/" & ip & "/tcp/9000")

proc makeAdvertisement*(
    serviceId: string = $1,
    privateKey: PrivateKey = PrivateKey.random(rng()).get(),
    addrs: seq[MultiAddress] = @[],
    seqNo: uint64 = nowUnixSeconds().uint64,
): Advertisement =
  let peerId = PeerId.init(privateKey).get()
  let extRecord = ExtendedPeerRecord(
    peerId: peerId,
    seqNo: seqNo,
    addresses: addrs.mapIt(AddressInfo(address: it)),
    services: @[makeServiceInfo(serviceId)],
  )
  SignedExtendedPeerRecord.init(privateKey, extRecord).get()

proc makeOversizedAdvertisement*(
    serviceId: string, privateKey: PrivateKey = PrivateKey.random(rng()).get()
): Advertisement =
  ## Decodes cleanly but fails `isValid`: its service data exceeds `MaxServiceDataSize`.
  let extRecord = ExtendedPeerRecord(
    peerId: PeerId.init(privateKey).get(),
    seqNo: 1,
    addresses: @[],
    services: @[ServiceInfo(id: serviceId, data: newSeq[byte](MaxServiceDataSize + 1))],
  )
  SignedExtendedPeerRecord.init(privateKey, extRecord).get()

const UnknownEnvelopeField = 15 ## no `Envelope` field carries this number

proc padAdvertisement*(advert: seq[byte], paddingBytes: int): seq[byte] =
  ## Grows the encoded record with a field the decoder skips, so only its
  ## incoming length reveals the padding.
  var pb = initProtoBuffer()
  pb.write(UnknownEnvelopeField, newSeq[byte](paddingBytes))
  pb.finish()
  advert & pb.buffer

proc createSwitch*(
    privateKey: Opt[PrivateKey] = Opt.none(PrivateKey),
    addresses: seq[MultiAddress] = @[TcpAutoAddress()],
): Switch =
  makeStandardSwitchBuilder(addresses).withPrivateKey(privateKey).build()

proc testKadDHTConfig(): KadDHTConfig =
  KadDHTConfig.new(
    ExtEntryValidator(),
    ExtEntrySelector(),
    timeout = 3.secs,
    cleanupProvidersInterval = 100.millis,
    providerExpirationInterval = 1.secs,
    republishProvidedKeysInterval = 50.millis,
    disableBootstrapping = true, # component tests wire up their own topology explicitly
  )

proc setupServiceDiscoveryNode*(
    discoConfig: ServiceDiscoveryConfig = ServiceDiscoveryConfig.new(),
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
    xprPublishing: bool = true,
    services: seq[ServiceInfo] = @[],
    client: bool = false,
    privateKey: Opt[PrivateKey] = Opt.none(PrivateKey),
    kadConfig: KadDHTConfig = testKadDHTConfig(),
    addresses: seq[MultiAddress] = @[TcpAutoAddress()],
    mount: bool = true,
): ServiceDiscovery =
  let switch = createSwitch(privateKey, addresses)
  # `addrs` stays empty until `switch.start()`, and `record()` refuses empty `addrs`.
  switch.peerInfo.addrs = @[makeMultiAddress("127.0.0.1")]

  let node = ServiceDiscovery.new(
    switch,
    bootstrapNodes = bootstrapNodes,
    config = kadConfig,
    rng = rng(),
    services = services,
    client = client,
    discoConfig = discoConfig,
    xprPublishing = xprPublishing,
  )
  if mount:
    switch.mount(node)
  node

proc setupServiceDiscoveryNodes*(
    count: int,
    discoConfig: ServiceDiscoveryConfig = ServiceDiscoveryConfig.new(),
    bootstrapNodes: seq[(PeerId, seq[MultiAddress])] = @[],
    xprPublishing: bool = true,
    kadConfig: KadDHTConfig = testKadDHTConfig(),
): seq[ServiceDiscovery] =
  var nodes: seq[ServiceDiscovery]
  for i in 0 ..< count:
    nodes.add(
      setupServiceDiscoveryNode(
        discoConfig, bootstrapNodes, xprPublishing, kadConfig = kadConfig
      )
    )
  nodes

proc connect*(disco1, disco2: ServiceDiscovery) {.async.} =
  ## Bidirectionally connect two ServiceDiscovery instances.
  discard disco1.rtable.insert(disco2.switch.peerInfo.peerId)
  discard disco2.rtable.insert(disco1.switch.peerInfo.peerId)
  disco1.switch.peerStore[AddressBook][disco2.switch.peerInfo.peerId] =
    disco2.switch.peerInfo.addrs
  disco2.switch.peerStore[AddressBook][disco1.switch.peerInfo.peerId] =
    disco1.switch.peerInfo.addrs

proc hasPeer*(rtable: RoutingTable, peerKey: Key): bool =
  peerKey in rtable

proc hasPeerInMainTable*(disco: ServiceDiscovery, peerId: PeerId): bool =
  disco.rtable.hasPeer(peerId.toKey())

proc populateRoutingTable*(disco: ServiceDiscovery, count: int) =
  for i in 0 ..< count:
    discard disco.rtable.insert(randomPeerId())

proc populateAdvertisementTable*(disco: ServiceDiscovery, serviceId: ServiceId) =
  for i in 0 ..< disco.discoConfig.kRegister:
    discard disco.rtable.insert(randomPeerId())
  discard disco.rtManager.addService(
    serviceId, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
    Interest,
  )

proc getAdsInCache*(disco: ServiceDiscovery, serviceId: ServiceId): seq[Advertisement] =
  disco.registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)

proc countAdsInCache*(disco: ServiceDiscovery, serviceId: ServiceId): int =
  disco.getAdsInCache(serviceId).len

proc ipsFromAd*(ad: Advertisement): seq[IpAddress] =
  ## Extract IPs from the ad payload (test convenience when advertiser IPs
  ## are not set up in the peerstore).
  ad.data.addresses.getIPs()

proc putAd*(
    ads: AdvertisementCache,
    serviceId: ServiceId,
    ad: Advertisement,
    now: Moment = Moment.now(),
    advertiser: PeerId = PeerId(),
    ips: seq[IpAddress] = @[],
) =
  ## Test helper for AdvertisementCache.put with advertiser defaults.
  let adv = if advertiser.len > 0: advertiser else: ad.data.peerId
  let advertiserIps =
    if ips.len > 0:
      ips
    else:
      ad.ipsFromAd()
  ads.put(serviceId, adv, ad, advertiserIps, now)

proc seedOccupancy*(ads: AdvertisementCache, n: int, now: Moment = Moment.now()) =
  ## Fills the cache with `n` ads under distinct services, so serviceSim stays 0.
  for i in 0 ..< n:
    let sid = makeServiceId(byte(i mod 250 + 1))
    let ad = makeAdvertisement($sid)
    ads.put(sid, ad.data.peerId, ad, ad.ipsFromAd(), now)

proc acceptAd*(
    disco: ServiceDiscovery,
    now: Moment,
    serviceId: ServiceId,
    ad: Advertisement,
    advertiser: PeerId = PeerId(),
    ips: seq[IpAddress] = @[],
) =
  let adv = if advertiser.len > 0: advertiser else: ad.data.peerId
  let advertiserIps =
    if ips.len > 0:
      ips
    else:
      ad.ipsFromAd()
  disco.acceptAdvertisement(now, serviceId, adv, ad, advertiserIps)

proc registerAd*(
    disco: ServiceDiscovery, serviceId: ServiceId, ad: Advertisement
): RegisterMessage =
  let inMsg = Message(
    msgType: MessageType.register,
    key: serviceId,
    register: Opt.some(
      RegisterMessage(
        advertisement: ad.encode().get(),
        status: Opt.none(RegistrationStatus),
        ticket: Opt.none(Ticket),
      )
    ),
  )
  disco.registration(ad.data.peerId, inMsg).register.get()

proc seedAd*(
    reg: Registrar,
    serviceId: ServiceId,
    ad: Advertisement,
    now: Moment = Moment.now(),
    advertiser: PeerId = PeerId(),
    ips: seq[IpAddress] = @[],
) =
  ## Test helper: admit `ad` into the registrar cache via the public API.
  ## Defaults advertiser to `ad.data.peerId` and ips to the ad's addresses.
  reg.ads.putAd(serviceId, ad, now, advertiser, ips)

proc seedAds*(
    reg: Registrar,
    serviceId: ServiceId,
    ads: seq[Advertisement],
    now: Moment = Moment.now(),
) =
  for ad in ads:
    reg.seedAd(serviceId, ad, now)

proc containsPeer*(
    response: LPResult[seq[Advertisement]], node: ServiceDiscovery
): bool =
  response.isOk() and response.get().anyIt(
    it.data.peerId == node.switch.peerInfo.peerId
  )

const
  serviceName = "service"
  serviceBucketLookupTable* = block:
    # A lookup table that contains keys that fall into bucket 0 and 1 for the service "service"
    var bucketKeysTable = initTable[int, seq[string]]()

    # bucket 0
    bucketKeysTable[0] = @[
      "080112406A0C233F564BA1CB6DA689116CE39E86AEE6B1977029EC97789DF6BB9D40B276BA3BA74215B1AF35C91ECB643460AEC4F11958E8677F7772F28F848F1BF9CCE1",
      "08011240AC354633944891C4415D24DBC7D8B22946041727F0568493414305C5172272BAD7A72F15240237D5CE35820AEF77CD703B8466702607862B60F15C5106E7D837",
      "08011240F14AA4CEF941B92C3A74E8880CCA1DCCCF200E7ED0E92A643E0122A6C4F4BB4203829378B9E4B3CA01809D344F21CA1A6F432038F2130EA5F66557A434A3ECFF",
      "080112409A9526F2DA05A0E0704CCE40FA122298B8B4E20765A204C43D7919CBA94C42CB9D36F61EB4A5E035F202763745A417B794F335F1C0B781FF777D3EFAB8710162",
      "08011240462968B39BC1810729472A0CC9E626D4C5B39FB117755C11EDAB1571AC86D0D82EEE3E9A9DF8972543314EC14F08EA9D5DA6B5D669BBF5DCAB3370B35125EFCD",
      "080112404B0C32A8E8F50628193A76590D155E15F8FA57E3581D162A36AC59EEF89B0DDCA95AFC22114F6A848C27484B352CF5F6D2D7ECB4FDA801AB88AD0A9B9CF5957F",
      "08011240CD04A0C51250F7A2545C61FC084E160BFD01E760D7D88016111F8CE175890D605D25CDE8DFA9C3EAA70D9C8D8AD4F7F7792C63CD3C83AA8F8FEF031103A91261",
      "08011240DD6480FA1CC5CF3C86E496CAC93093F8F9CC2C85C212E4C84DDB59DA6E407AE54A0ACF94451A00CED3C59FDBCFCBBE28F780637A4B984153D4EB72A566C88DD1",
    ]

    # bucket 1
    bucketKeysTable[1] = @[
      "0801124021B12E50EF13E4E40597DFAC04309E811969A9E76DB0130E7837AF3AA2D1E95F4726D31731A6956F8FE7CA59DFFC918A323758D6ACCE01ECDBC4F00C974BC197",
      "080112401A9447EB01AF2E716212E19EF7A217A3629226AF7A25977CCE2E11EB55CA83B58BDB4B193C2A0E0B055C07C943A610AA6DD8755CDB7BEE9061300FB1980696A9",
    ]

    var m = initTable[string, Table[int, seq[string]]]()
    m[serviceName] = bucketKeysTable
    m

proc setupRegistrarsInDistinctBuckets*(
    conf: ServiceDiscoveryConfig
): (ServiceDiscovery, ServiceDiscovery, string) =
  ## Registrars that land in two service routing table buckets.

  let lookupTable = serviceBucketLookupTable[serviceName]
  let key1 = PrivateKey.init(lookupTable[0][0]).get()
  let key2 = PrivateKey.init(lookupTable[1][0]).get()

  let node0 = setupServiceDiscoveryNode(discoConfig = conf, privateKey = Opt.some(key1))
  let node1 = setupServiceDiscoveryNode(discoConfig = conf, privateKey = Opt.some(key2))

  return (node0, node1, serviceName)

proc setupRegistrarsInSameBucket*(
    conf: ServiceDiscoveryConfig, count: int
): (seq[ServiceDiscovery], string) =
  ## Registrars that land in one service routing table bucket.

  doAssert count > 0, "count must be > 0"

  let lookupTable = serviceBucketLookupTable[serviceName]
  let keys = lookupTable[0]

  doAssert keys.len >= count,
    "static table not populated with enough keys for " & serviceName

  var nodes: seq[ServiceDiscovery]
  for i in 0 ..< count:
    let pk = PrivateKey.init(keys[i]).get()
    nodes.add(setupServiceDiscoveryNode(discoConfig = conf, privateKey = Opt.some(pk)))

  return (nodes, serviceName)
