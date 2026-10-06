# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/sequtils
from std/times import getTime, toUnix
import chronos, math, results, tables, net
import
  ../../../libp2p/[
    crypto/crypto,
    extended_peer_record,
    multiaddress,
    peerid,
    peerstore,
    protocols/service_discovery/advertisement_cache,
    protocols/service_discovery/connection,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/registrar,
    protocols/service_discovery/types,
    routing_record,
    signed_envelope,
    stream/connection,
  ]
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../../libp2p/utils/future
import ../../tools/[crypto, unittest, multiaddress]
import ./utils

func initMoment(secs: int64): Moment =
  Moment.init(secs, Second)

func inFloatSecs(d: Duration): float64 =
  d.secs.float64

proc makeAdvertisementWithServices(
    services: seq[ServiceInfo],
    privateKey: PrivateKey = PrivateKey.random(rng()).get(),
    addrs: seq[MultiAddress] = @[],
    seqNo: uint64 = nowUnixSeconds().uint64,
): Advertisement =
  let peerId = PeerId.init(privateKey).get()
  var addressInfos: seq[AddressInfo]
  for address in addrs:
    addressInfos.add(AddressInfo(address: address))

  let extRecord = ExtendedPeerRecord(
    peerId: peerId, seqNo: seqNo, addresses: addressInfos, services: services
  )
  SignedExtendedPeerRecord.init(privateKey, extRecord).get()

suite "Service Discovery Registrar - waitingTime":
  test "waitingTime returns low value for empty cache with no IP similarity":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let now = Moment.now()
    let serviceId = makeServiceId()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    let expected =
      round(discoConfig.advertExpiry.seconds.float64 * discoConfig.safetyParam)

    check abs(w.inFloatSecs - expected) < 0.001

  test "waitingTime increases with cache occupancy":
    # Small capacity so occupancy steps after round() are distinguishable.
    let registrar = Registrar.new(100)
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId1 = makeServiceId(1)
    let serviceId2 = makeServiceId(2)
    let ad1 = makeAdvertisement($serviceId1)
    let ad2 = makeAdvertisement($serviceId2)
    let now = Moment.now()

    registrar.seedAd(serviceId1, ad1, now)
    let w1 = registrar.waitingTime(discoConfig, serviceId1, ad1.ipsFromAd(), now)

    registrar.seedAd(serviceId2, ad2, now)
    let w2 = registrar.waitingTime(discoConfig, serviceId2, ad2.ipsFromAd(), now)

    check w1 < w2

  test "waitingTime increases with service similarity":
    let registrar = Registrar.new(100)
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId1 = makeServiceId(1)
    let serviceId4 = makeServiceId(4)
    let ad1 = makeAdvertisement($serviceId1)
    let ad4 = makeAdvertisement($serviceId4)
    let ad5 = makeAdvertisement($serviceId4)
    let ad6 = makeAdvertisement($serviceId4)
    let now = Moment.now()

    # Three ads across three services → low serviceSim for serviceId1
    registrar.seedAd(serviceId1, ad1, now)
    registrar.seedAd(makeServiceId(2), makeAdvertisement($makeServiceId(2)), now)
    registrar.seedAd(makeServiceId(3), makeAdvertisement($makeServiceId(3)), now)
    let w1 = registrar.waitingTime(discoConfig, serviceId1, ad1.ipsFromAd(), now)

    registrar.ads.clear()

    # Three ads under one service → higher serviceSim
    registrar.seedAd(serviceId4, ad4, now)
    registrar.seedAd(serviceId4, ad5, now)
    registrar.seedAd(serviceId4, ad6, now)
    let w2 = registrar.waitingTime(discoConfig, serviceId4, ad4.ipsFromAd(), now)

    check w1 < w2

  test "waitingTime returns 0.0 IP similarity for IPs not in tree":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("192.168.1.1")])
    let now = Moment.now()

    check registrar.ads.ipTree.ipScore(
      IpAddress(family: IpAddressFamily.IPv4, address_v4: [192'u8, 168, 1, 1])
    ) == 0.0

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w == ZeroDuration

  test "waitingTime uses maximum IP score across multiple addresses":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let now = Moment.now()

    # Seed three nearby IPs under a filler service so the subject serviceSim is 0
    let filler = makeServiceId(99)
    for i in 10 .. 30:
      if i mod 10 == 0:
        let ip = "192.168.1." & $i
        registrar.seedAd(
          filler, makeAdvertisement(addrs = @[makeMultiAddress(ip)]), now
        )

    let ad = makeAdvertisement(
      addrs = @[
        makeMultiAddress("10.0.0.1"), # Different subnet – low score
        makeMultiAddress("192.168.1.50"), # Same subnet – high score
      ]
    )
    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w > ZeroDuration

  test "waitingTime at cache capacity returns high occupancy":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ad = makeAdvertisement()
    let serviceId = makeServiceId()
    let now = Moment.now()

    registrar.ads.seedOccupancy(1000, now)

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    let expectedSecs =
      round(discoConfig.advertExpiry.seconds.float64 * 100.0 * discoConfig.safetyParam)
    check w.inFloatSecs >= expectedSecs - 1e-9

  test "waitingTime formula includes safety parameter":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new(safetyParam = 0.5)
    # No addresses → ipsMaxScore is 1.0 (max penalty when IPs are missing).
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    # occupancy≈1, serviceSim=0, ipSim=1.0 for empty IP set
    let expected = ceil(
      discoConfig.advertExpiry.seconds.float64 *
        (discoConfig.ipSimCoefficient * 1.0 + discoConfig.safetyParam)
    )
    check abs(w.inFloatSecs - expected) < 1.0

  test "waitingTime ipSimCoefficient=0 eliminates IP similarity penalty":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new(ipSimCoefficient = 0.0)
    let serviceId = makeServiceId()
    let now = Moment.now()
    let filler = makeServiceId(99)

    for i in 1 .. 6:
      let ip = "192.168.1." & $i
      registrar.seedAd(filler, makeAdvertisement(addrs = @[makeMultiAddress(ip)]), now)
    # serviceSim for subject service is 0; occupancy is small
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("192.168.1.7")])

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w < 10.seconds

  test "waitingTime ipSimCoefficient=1 (default) preserves IP similarity penalty":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new(ipSimCoefficient = 1.0)
    let serviceId = makeServiceId()
    let now = Moment.now()
    let filler = makeServiceId(99)

    for i in 1 .. 6:
      let ip = "192.168.1." & $i
      registrar.seedAd(filler, makeAdvertisement(addrs = @[makeMultiAddress(ip)]), now)
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("192.168.1.7")])

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w > 500.seconds

  test "waitingTime enforces service lower bound when exists":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = initMoment(1000)

    registrar.boundService[serviceId] = initMoment(1500)
    registrar.timestampService[serviceId] = initMoment(1000)

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= 500.secs

  test "waitingTime enforces IP lower bound when exists":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ip = "192.168.1.50"
    let ad = makeAdvertisement(addrs = @[makeMultiAddress(ip)])
    let now = initMoment(1000)
    let serviceId = makeServiceId()

    registrar.boundIp[ip] = initMoment(1500)
    registrar.timestampIp[ip] = initMoment(1000)

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= 500.secs

  test "waitingTime IP lower bound is per IP address":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ip1 = "192.168.1.1"
    let ip2 = "10.0.0.1"
    let now = initMoment(1000)
    let serviceId = makeServiceId()

    registrar.boundIp[ip1] = initMoment(1500)
    registrar.timestampIp[ip1] = initMoment(1000)

    let ad2 = makeAdvertisement(addrs = @[makeMultiAddress(ip2)])
    let w2 = registrar.waitingTime(discoConfig, serviceId, ad2.ipsFromAd(), now)

    let ad1 = makeAdvertisement(addrs = @[makeMultiAddress(ip1)])
    let w1 = registrar.waitingTime(discoConfig, serviceId, ad1.ipsFromAd(), now)

    check w1 > w2

  test "waitingTime uses most restrictive lower bound":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new(advertExpiry = 2500.secs)
    let serviceId = makeServiceId()
    let ip1 = "192.168.1.1"
    let ip2 = "10.0.0.1"
    let now = initMoment(1000)

    registrar.boundService[serviceId] = initMoment(2000)
    registrar.timestampService[serviceId] = initMoment(1000)

    registrar.boundIp[ip1] = initMoment(3000)
    registrar.timestampIp[ip1] = initMoment(1000)

    registrar.boundIp[ip2] = initMoment(1500)
    registrar.timestampIp[ip2] = initMoment(1000)

    let ad = makeAdvertisement(
      $serviceId, addrs = @[makeMultiAddress(ip1), makeMultiAddress(ip2)]
    )

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= 2000.secs

  test "waitingTime with advertisement with no addresses":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ad = makeAdvertisement(addrs = @[])
    let now = Moment.now()
    let serviceId = makeServiceId()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

  test "waitingTime with IPv6 addresses only, tree empty":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let ipv6Addr = ma("/ip6/::1/tcp/9000")
    let ad = makeAdvertisement(addrs = @[ipv6Addr])
    let now = Moment.now()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

  test "waitingTime with IPv6 addresses contributes IP similarity":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let now = Moment.now()
    let filler = makeServiceId(99)

    let ipv6Addr = ma("/ip6/::1/tcp/9000")
    registrar.seedAd(filler, makeAdvertisement(addrs = @[ipv6Addr]), now)

    let ad = makeAdvertisement(addrs = @[ipv6Addr])
    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w > ZeroDuration

  test "waitingTime with mixed IPv4 and IPv6 addresses":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let now = Moment.now()
    let filler = makeServiceId(99)

    registrar.seedAd(
      filler, makeAdvertisement(addrs = @[makeMultiAddress("192.168.1.1")]), now
    )

    let ipv4Addr = makeMultiAddress("192.168.1.50")
    let ipv6Addr = ma("/ip6/::1/tcp/9000")
    let ad = makeAdvertisement(addrs = @[ipv4Addr, ipv6Addr])

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w > ZeroDuration

  test "waitingTime with service ID not in boundService":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

  test "waitingTime with IP not in boundIp":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let now = Moment.now()
    let serviceId = makeServiceId()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

  test "different advertCacheCap affects occupancy":
    let registrar = Registrar.new(10_000)
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    registrar.ads.seedOccupancy(100, now)

    let discoConfig = ServiceDiscoveryConfig.new()
    registrar.ads.capacity = 100
    let w1 = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)
    registrar.ads.capacity = 10_000
    let w2 = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w1 >= w2

  test "different occupancyExp changes wait time curve":
    let registrar = Registrar.new()
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    registrar.ads.seedOccupancy(500, now)

    let discoConfig1 = ServiceDiscoveryConfig.new(occupancyExp = 1.0)
    let w1 = registrar.waitingTime(discoConfig1, serviceId, ad.ipsFromAd(), now)

    let discoConfig2 = ServiceDiscoveryConfig.new(occupancyExp = 20.0)
    let w2 = registrar.waitingTime(discoConfig2, serviceId, ad.ipsFromAd(), now)

    check w2 >= w1

  test "different advertExpiry scales base wait time":
    let registrar = Registrar.new()
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    let discoConfig1 =
      ServiceDiscoveryConfig.new(safetyParam = 1.0, advertExpiry = 100.secs)
    let w1 = registrar.waitingTime(discoConfig1, serviceId, ad.ipsFromAd(), now)

    let discoConfig2 =
      ServiceDiscoveryConfig.new(safetyParam = 1.0, advertExpiry = 10000.secs)
    let w2 = registrar.waitingTime(discoConfig2, serviceId, ad.ipsFromAd(), now)

    check w2 > w1

  test "different safetyParam adds to wait time":
    let registrar = Registrar.new()
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    let discoConfig1 = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    let w1 = registrar.waitingTime(discoConfig1, serviceId, ad.ipsFromAd(), now)

    let discoConfig2 = ServiceDiscoveryConfig.new(safetyParam = 1.0)
    let w2 = registrar.waitingTime(discoConfig2, serviceId, ad.ipsFromAd(), now)

    check w2 > w1

  test "occupancyExp of 0 gives occupancy of 1.0":
    let registrar = Registrar.new()
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    registrar.ads.seedOccupancy(500, now)

    let discoConfig = ServiceDiscoveryConfig.new(occupancyExp = 0.0)
    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

  test "occupancyExp of 1 gives linear occupancy":
    let registrar = Registrar.new()
    let ad = makeAdvertisement()
    let now = Moment.now()
    let serviceId = makeServiceId()

    registrar.ads.seedOccupancy(500, now)

    let discoConfig = ServiceDiscoveryConfig.new(occupancyExp = 1.0)
    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

  test "waitingTime returns non-negative with stale high service lower bound":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)

    registrar.boundService[serviceId] = initMoment(100)
    registrar.timestampService[serviceId] = initMoment(0)

    let now = Moment.now()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

  test "waitingTime returns non-negative with stale high IP lower bound":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let serviceId = makeServiceId()
    let ip = "10.0.0.1"

    registrar.boundIp[ip] = initMoment(50)
    registrar.timestampIp[ip] = initMoment(0)

    let ad = makeAdvertisement(addrs = @[makeMultiAddress(ip)])
    let now = Moment.now()

    let w = registrar.waitingTime(discoConfig, serviceId, ad.ipsFromAd(), now)

    check w >= ZeroDuration

suite "Service Discovery Registrar - request handlers":
  test "registration caps the offered tWaitFor at advertExpiry":
    let advertExpiry = 100.secs
    let conf = ServiceDiscoveryConfig.new(
      advertExpiry = advertExpiry, safetyParam = 1.0, advertCacheCap = 10
    )
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let advertiserKey = PrivateKey.random(rng()).get()
    let advertiserId = PeerId.init(advertiserKey).get()
    let adBytes = makeAdvertisement(serviceName, advertiserKey).encode().get()

    disco.registrar.ads.seedOccupancy(10)

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )
    let reply = disco.registration(advertiserId, inMsg).register.get()

    check reply.status.get() == kadprotobuf.RegistrationStatus.Wait
    check reply.ticket.get().tWaitFor.get() == advertExpiry

  test "sustained overload keeps offering advertExpiry-length waits across retries":
    let advertExpiry = 100.secs
    let registrationWindow = 10.secs
    let conf = ServiceDiscoveryConfig.new(
      advertExpiry = advertExpiry,
      safetyParam = 1.0,
      advertCacheCap = 10,
      registrationWindow = registrationWindow,
    )
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let advertiserKey = PrivateKey.random(rng()).get()
    let advertiserId = PeerId.init(advertiserKey).get()
    let adBytes = makeAdvertisement(serviceName, advertiserKey).encode().get()

    disco.registrar.ads.seedOccupancy(10)

    let firstAttemptTime = getTime().toUnix() - advertExpiry.seconds
    var retryTicket = Ticket(
      advertisement: adBytes,
      tInit: firstAttemptTime,
      tMod: firstAttemptTime,
      tWaitFor: advertExpiry,
      signature: Opt.none(seq[byte]),
    )
    check retryTicket.sign(disco.switch.peerInfo.privateKey).isOk()

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.some(retryTicket),
        )
      ),
    )
    let reply = disco.registration(advertiserId, inMsg).register.get()

    check reply.status.get() == kadprotobuf.RegistrationStatus.Wait
    check reply.ticket.get().tWaitFor.get() == advertExpiry

  test "getAdvertisements replies empty to a message without a key":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()
    disco.registrar.seedAd(serviceId, makeAdvertisement($serviceId))

    let reply = disco.getAdvertisements(
      randomPeerId(), kadprotobuf.Message(msgType: kadprotobuf.MessageType.getAds)
    )

    check:
      reply.msgType.isNone()
      reply.getAds.isNone()
      reply.closerPeers.len == 0

  test "updateWaitAfterRetry subtracts accumulated wait for retry":
    let disco = setupServiceDiscoveryNode()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let adBuf = ad.encode().get()

    let now = getTime().toUnix()
    var ticket = Ticket(
      advertisement: adBuf,
      tInit: now - 150,
      tMod: now,
      tWaitFor: 0.secs,
      signature: Opt.none(seq[byte]),
    )
    check ticket.sign(disco.switch.peerInfo.privateKey).isOk()

    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: adBuf,
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.some(ticket),
    )
    var tWait = 300.secs

    disco.updateWaitAfterRetry(regMsg.ticket, now, tWait)

    check abs(tWait.secs - 150) <= 1

  test "registration with mismatched ticket advertisement yields Rejected":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let adBuf = ad.encode().get()
    let otherAd = makeAdvertisement("other-service")
    let otherBuf = otherAd.encode().get()

    var ticket = Ticket(
      advertisement: otherBuf,
      tInit: 1_000'i64,
      tMod: getTime().toUnix(),
      tWaitFor: 0.secs,
      signature: Opt.none(seq[byte]),
    )
    check ticket.sign(disco.switch.peerInfo.privateKey).isOk()

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBuf,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.some(ticket),
        )
      ),
    )

    let reply = disco.registration(ad.data.peerId, inMsg).register.get()
    check reply.status.get() == kadprotobuf.RegistrationStatus.Rejected
    check reply.ticket.isNone()
    check disco.countAdsInCache(serviceId) == 0

  test "registration with invalid-signature ticket yields Rejected":
    let disco = setupServiceDiscoveryNode()
    let otherDisco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let adBuf = ad.encode().get()

    var ticket = Ticket(
      advertisement: adBuf,
      tInit: 1_000'i64,
      tMod: getTime().toUnix(),
      tWaitFor: 0.secs,
      signature: Opt.none(seq[byte]),
    )
    check ticket.sign(otherDisco.switch.peerInfo.privateKey).isOk()

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBuf,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.some(ticket),
        )
      ),
    )

    let reply = disco.registration(ad.data.peerId, inMsg).register.get()
    check reply.status.get() == kadprotobuf.RegistrationStatus.Rejected
    check reply.ticket.isNone()
    check disco.countAdsInCache(serviceId) == 0

  test "same advertiser different payload replaces the slot":
    # Subsecond expiry rounds wait to zero so a new ad is Confirmed, not Wait.
    let disco = setupServiceDiscoveryNode(
      discoConfig =
        ServiceDiscoveryConfig.new(safetyParam = 0.0, advertExpiry = 999.millis)
    )
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let ad1 = makeAdvertisement(
      serviceName,
      privateKey = privateKey,
      seqNo = 1,
      addrs = @[makeMultiAddress("10.0.0.1")],
    )
    let ad2 = makeAdvertisement(
      serviceName,
      privateKey = privateKey,
      seqNo = 1,
      addrs = @[makeMultiAddress("10.0.0.2")],
    )
    let now = Moment.now()

    disco.registrar.seedAd(serviceId, ad1, now)

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: ad2.encode().get(),
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply = disco.registration(ad2.data.peerId, inMsg).register.get()
    check reply.status.get() == kadprotobuf.RegistrationStatus.Confirmed
    check disco.countAdsInCache(serviceId) == 1
    check disco.getAdsInCache(serviceId)[0].envelope.signature.data ==
      ad2.envelope.signature.data

  test "lower seqNo than the cached ad is rejected without a ticket":
    let disco = setupServiceDiscoveryNode(
      discoConfig =
        ServiceDiscoveryConfig.new(safetyParam = 0.0, advertExpiry = 999.millis)
    )
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let newerAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 10)
    let olderAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 5)

    disco.registrar.seedAd(serviceId, newerAd, Moment.now())

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: olderAd.encode().get(),
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply = disco.registration(randomPeerId(), inMsg).register.get()
    check reply.status.get() == kadprotobuf.RegistrationStatus.Rejected
    check reply.ticket.isNone()
    check disco.countAdsInCache(serviceId) == 1
    check disco.getAdsInCache(serviceId)[0].data.seqNo == 10

  test "wait response records the wait time and does not cache the ad":
    let config = ServiceDiscoveryConfig.new(safetyParam = 1.0)
    let disco = setupServiceDiscoveryNode(discoConfig = config)
    let serviceId1 = makeServiceId(1)
    let serviceIdName = "service"
    let serviceId2 = serviceIdName.hashServiceId()
    let ad1 = makeAdvertisement($serviceId1)
    let ad2 = makeAdvertisement(serviceIdName)
    let adBytes = ad2.encode().get()
    let advertiserId = ad2.data.peerId
    let now = Moment.now()

    disco.registrar.seedAd(serviceId1, ad1, now)

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId2,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply = disco.registration(advertiserId, inMsg).register.get()

    check:
      reply.status.get() == kadprotobuf.RegistrationStatus.Wait
      reply.ticket.isSome()
      disco.countAdsInCache(serviceId2) == 0
      serviceId2 in disco.registrar.boundService
      serviceId2 in disco.registrar.timestampService

    let ticket = reply.ticket.get()
    let registrarPubKey = disco.switch.peerInfo.privateKey.getPublicKey().get()
    check:
      ticket.advertisement == adBytes
      ticket.tWaitFor.isSome
      ticket.tWaitFor.get() > ZeroDuration
      ticket.verify(registrarPubKey)

  test "registration uses Unix seconds for tickets and monotonic cache timestamps":
    let config = ServiceDiscoveryConfig.new(safetyParam = 1.0)
    let disco = setupServiceDiscoveryNode(discoConfig = config)
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName)
    let adBytes = ad.encode().get()
    let advertiserId = ad.data.peerId

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let beforeRegistration = getTime().toUnix()
    let reply = disco.registration(advertiserId, inMsg).register.get()

    check reply.status.get() == kadprotobuf.RegistrationStatus.Wait
    check reply.ticket.isSome()

    let ticket = reply.ticket.get()
    let tInit = ticket.tInit.get()
    let tMod = ticket.tMod.get()
    check tInit in beforeRegistration .. getTime().toUnix()
    check tMod == tInit

    check serviceId in disco.registrar.timestampService
    let ts = disco.registrar.timestampService[serviceId]
    check ts == Moment.init(ts.epochSeconds, Second)

  test "retrying with a valid ticket inside the window caches the ad":
    let conf = ServiceDiscoveryConfig.new(registrationWindow = 10.secs)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let advertiserKey = PrivateKey.random(rng()).get()
    let advertiserId = PeerId.init(advertiserKey).get()
    let maddr = makeMultiAddress("10.0.0.1")
    let adBytes =
      makeAdvertisement(serviceName, advertiserKey, addrs = @[maddr]).encode().get()
    # Peerstore IP so scoring is not max-penalized for a missing address set.
    disco.switch.peerStore[AddressBook][advertiserId] = @[maddr]

    let pastNow = getTime().toUnix() - 5
    var ticket = Ticket(
      advertisement: adBytes,
      tInit: pastNow,
      tMod: pastNow,
      tWaitFor: 1.secs,
      signature: Opt.none(seq[byte]),
    )
    check ticket.sign(disco.switch.peerInfo.privateKey).isOk()

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.some(ticket),
        )
      ),
    )

    let reply = disco.registration(advertiserId, inMsg).register.get()

    check:
      reply.status.get() == kadprotobuf.RegistrationStatus.Confirmed
      disco.countAdsInCache(serviceId) == 1
      disco.getAdsInCache(serviceId)[0].data.peerId == advertiserId

  test "registration does not insert the sender into the main routing table":
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    )
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName)
    let senderId = ad.data.peerId
    disco.switch.peerStore[AddressBook][senderId] = @[makeMultiAddress("198.51.100.7")]

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: ad.encode().get(),
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply = disco.registration(senderId, inMsg).register.get()

    check reply.status.get() == kadprotobuf.RegistrationStatus.Confirmed
    check not disco.hasPeerInMainTable(senderId)

  test "registration does not return the sender among its own closerPeers":
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(safetyParam = 0.0)
    )
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName)
    let senderId = ad.data.peerId
    disco.switch.peerStore[AddressBook][senderId] = @[makeMultiAddress("198.51.100.10")]

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: ad.encode().get(),
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    check disco.registration(senderId, inMsg).closerPeers.len == 0

suite "Service Discovery Registrar - updateLowerBounds":
  test "updateLowerBounds stores service bound as w":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = initMoment(1000)
    let w = 500.secs

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), w, now)

    check serviceId in registrar.boundService
    check registrar.boundService[serviceId] == now + w
    check registrar.timestampService[serviceId] == now

  test "updateLowerBounds updates service bound when w exceeds effective bound":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = initMoment(1000)

    registrar.boundService[serviceId] = initMoment(1500)
    registrar.timestampService[serviceId] = initMoment(500)

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), 1200.secs, now)

    check registrar.boundService[serviceId] == initMoment(2200)
    check registrar.timestampService[serviceId] == initMoment(1000)

  test "updateLowerBounds does not decrease service bound":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = initMoment(1000)

    registrar.boundService[serviceId] = initMoment(2500)
    registrar.timestampService[serviceId] = initMoment(500)
    let oldBound = registrar.boundService[serviceId]

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), 1000.secs, now)

    check registrar.boundService[serviceId] == oldBound

  test "updateLowerBounds updates IP bound for each address":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ip1 = "192.168.1.1"
    let ip2 = "10.0.0.1"
    let ad = makeAdvertisement(
      $serviceId, addrs = @[makeMultiAddress(ip1), makeMultiAddress(ip2)]
    )
    let now = initMoment(1000)
    let w = 500.secs

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), w, now)

    check ip1 in registrar.boundIp
    check registrar.boundIp[ip1] == now + w
    check registrar.timestampIp[ip1] == now

    check ip2 in registrar.boundIp
    check registrar.boundIp[ip2] == now + w
    check registrar.timestampIp[ip2] == now

  test "updateLowerBounds accumulates bounds correctly across multiple calls":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), 500.secs, initMoment(1000))
    check registrar.boundService[serviceId] == initMoment(1500)

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), 800.secs, initMoment(1500))
    check registrar.boundService[serviceId] == initMoment(2300)

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), 1200.secs, initMoment(2000))
    check registrar.boundService[serviceId] == initMoment(3200)

  test "updateLowerBounds with empty addresses does not crash":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId, addrs = @[])
    let now = initMoment(1000)

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), 500.secs, now)

    check registrar.boundService[serviceId] == initMoment(1500)

  test "updateLowerBounds with zero w":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = initMoment(1000)

    updateLowerBounds(registrar, serviceId, ad.ipsFromAd(), ZeroDuration, now)

    check serviceId in registrar.boundService
    check registrar.boundService[serviceId] == now

suite "Service Discovery Registrar - pruneExpiredAds":
  test "pruneExpiredAds does nothing on empty registrar":
    let registrar = Registrar.new()

    pruneExpiredAds(registrar, 900.secs)

    check registrar.ads.len == 0
    check registrar.ads.serviceLen == 0

  test "pruneExpiredAds keeps ad within expiry time":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = Moment.now()

    registrar.seedAd(serviceId, ad, now)

    pruneExpiredAds(registrar, 900.secs)

    check ad in registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
    check registrar.ads.len == 1

  test "pruneExpiredAds removes ad past expiry time":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = Moment.now()

    registrar.seedAd(serviceId, ad, now - 1000.secs)

    pruneExpiredAds(registrar, 900.secs)

    check ad notin registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
    check registrar.ads.len == 0

  test "pruneExpiredAds removes ad from IP tree":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId, addrs = @[makeMultiAddress("192.168.1.1")])

    registrar.seedAd(serviceId, ad, Moment.now() - 1000.secs)

    check registrar.ads.ipTree.ipsLen == 1

    pruneExpiredAds(registrar, 900.secs)

    check registrar.ads.ipTree.ipsLen == 0

  test "pruneExpiredAds removes empty services":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)

    registrar.seedAd(serviceId, ad, Moment.now() - 1000.secs)

    check serviceId in registrar.ads

    pruneExpiredAds(registrar, 900.secs)

    check serviceId notin registrar.ads
    check registrar.ads.len == 0

  test "pruneExpiredAds handles multiple ads for same service":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad1 = makeAdvertisement($serviceId)
    let ad2 = makeAdvertisement($serviceId)
    let ad3 = makeAdvertisement($serviceId)
    let now = Moment.now()

    registrar.seedAd(serviceId, ad1, now - 1000.secs)
    registrar.seedAd(serviceId, ad2, now)
    registrar.seedAd(serviceId, ad3, now - 2000.secs)

    pruneExpiredAds(registrar, 900.secs)

    let remaining = registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
    check remaining.len == 1
    check ad2 in remaining
    check ad1 notin remaining
    check ad3 notin remaining

  test "pruneExpiredAds handles ad with no valid IP addresses":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId, addrs = @[])

    registrar.seedAd(serviceId, ad, Moment.now() - 1000.secs)

    pruneExpiredAds(registrar, 900.secs)

    check ad notin registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)

  test "pruneExpiredAds removes same expired ad from all services independently":
    let registrar = Registrar.new()
    let serviceId1 = makeServiceId(1)
    let serviceId2 = makeServiceId(2)
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let expired = Moment.now() - 1000.secs

    registrar.seedAd(serviceId1, ad, expired)
    registrar.seedAd(serviceId2, ad, expired)
    check registrar.ads.ipTree.ipsLen == 2
    check registrar.ads.len == 2

    pruneExpiredAds(registrar, 900.secs)

    check:
      registrar.ads.serviceLen == 0
      registrar.ads.len == 0
      registrar.ads.ipTree.ipsLen == 0

    pruneExpiredAds(registrar, 900.secs)
    check registrar.ads.len == 0

  test "pruneExpiredAds progresses past mixed fresh and expired ads":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let fresh = makeAdvertisement($serviceId)
    let expired = makeAdvertisement($serviceId)
    let now = Moment.now()

    registrar.seedAd(serviceId, fresh, now)
    registrar.seedAd(serviceId, expired, now - 1000.secs)

    pruneExpiredAds(registrar, 900.secs)

    check:
      registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad).len == 1
      fresh in registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
      expired notin registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
      registrar.ads.len == 1

  test "pruneExpiredAds removes multi-service slots from IP tree once per slot":
    let registrar = Registrar.new()
    let serviceId1 = makeServiceId(1)
    let serviceId2 = makeServiceId(2)
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("192.168.1.1")])
    let expired = Moment.now() - 1000.secs

    registrar.seedAd(serviceId1, ad, expired)
    registrar.seedAd(serviceId2, ad, expired)
    check registrar.ads.ipTree.ipsLen == 2

    pruneExpiredAds(registrar, 900.secs)

    check:
      registrar.ads.serviceLen == 0
      registrar.ads.ipTree.ipsLen == 0

  test "pruneExpiredAds with very old timestamp":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)

    registrar.seedAd(serviceId, ad, initMoment(0))

    check ad in registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
    check registrar.ads.len == 1

    pruneExpiredAds(registrar, 1.secs)

    check ad notin registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
    check registrar.ads.len == 0

suite "Service Discovery Registrar - AdvertisementCache":
  test "cache can store multiple ads for same service ID":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad1 = makeAdvertisement($serviceId)
    let ad2 = makeAdvertisement($serviceId)
    let ad3 = makeAdvertisement($serviceId)

    registrar.seedAds(serviceId, @[ad1, ad2, ad3])

    check registrar.ads.serviceCacheAdsLen(serviceId) == 3
    check ad1 in registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
    check ad2 in registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)
    check ad3 in registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)

  test "cache can store ads for different service IDs":
    let registrar = Registrar.new()
    let serviceId1 = makeServiceId(1)
    let serviceId2 = makeServiceId(2)
    let ad1 = makeAdvertisement($serviceId1)
    let ad2 = makeAdvertisement($serviceId2)

    registrar.seedAd(serviceId1, ad1)
    registrar.seedAd(serviceId2, ad2)

    check registrar.ads.serviceLen == 2
    check serviceId1 in registrar.ads
    check serviceId2 in registrar.ads

  test "timestamps correctly track insertion time":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement()
    let timestamp = initMoment(12345)

    registrar.seedAd(serviceId, ad, timestamp)

    check registrar.ads.getCachedAd(serviceId, ad.data.peerId).get().timestamp ==
      timestamp

  test "put couples ad storage and IP tree":
    let registrar = Registrar.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId, addrs = @[makeMultiAddress("192.168.1.1")])

    check registrar.ads.ipTree.ipsLen == 0
    registrar.seedAd(serviceId, ad)
    check registrar.ads.ipTree.ipsLen == 1
    check ad in registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)

  test "getServiceCachedAds with limit 0 returns nothing":
    let ads = AdvertisementCache.new()
    let serviceId = makeServiceId()
    ads.putAd(serviceId, makeAdvertisement($serviceId))

    check:
      ads.serviceCacheAdsLen(serviceId) == 1
      ads.getServiceCachedAds(serviceId, 0).len == 0

  test "put replaces same advertiser and refreshes timestamp":
    let ads = AdvertisementCache.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let oldTime = initMoment(1000)
    let newTime = initMoment(2000)

    ads.putAd(serviceId, ad, oldTime)
    let counterBefore = ads.ipTree.ipsLen

    ads.putAd(serviceId, ad, newTime)

    check ads.serviceCacheAdsLen(serviceId) == 1
    check ads.len == 1
    check ads.ipTree.ipsLen == counterBefore
    check ads.getCachedAd(serviceId, ad.data.peerId).get().timestamp == newTime

  test "contains reports by advertiser peerId":
    let ads = AdvertisementCache.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let other = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.2")])

    check not ads.contains(serviceId, ad.data.peerId)
    ads.putAd(serviceId, ad, initMoment(1000))
    check ads.contains(serviceId, ad.data.peerId)
    check not ads.contains(serviceId, other.data.peerId)
    check not ads.contains(makeServiceId(2), ad.data.peerId)

  test "stale seqNo keeps the newer entry and its timestamp":
    let ads = AdvertisementCache.new()
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let oldAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 1)
    let newAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 2)
    let staleAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 0)

    ads.putAd(serviceId, oldAd, initMoment(1000))
    ads.putAd(serviceId, newAd, initMoment(2000))
    ads.putAd(serviceId, staleAd, initMoment(3000))

    check ads.serviceCacheAdsLen(serviceId) == 1
    let cached = ads.getCachedAd(serviceId, newAd.data.peerId).get()
    check:
      cached.ad.data.seqNo == 2
      cached.timestamp == initMoment(2000)

  test "hasNewer compares seqNo per signer and service":
    let ads = AdvertisementCache.new()
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let ad = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 10)

    ads.putAd(serviceId, ad, initMoment(1000))

    check:
      ads.hasNewer(
        serviceId, makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 9)
      )
      not ads.hasNewer(serviceId, ad)
      not ads.hasNewer(
        serviceId, makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 11)
      )
      not ads.hasNewer(serviceId, makeAdvertisement(serviceName, seqNo = 1))
      not ads.hasNewer(
        makeServiceId(2),
        makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 1),
      )

  test "service maps are independent; multi-service puts are separate slots":
    let ads = AdvertisementCache.new()
    let serviceId1 = makeServiceId(1)
    let serviceId2 = makeServiceId(2)
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let now = initMoment(1000)

    ads.putAd(serviceId1, ad, now)
    ads.putAd(serviceId2, ad, now)

    check ads.len == 2
    check ads.ipTree.ipsLen == 2
    check ads.serviceLen == 2
    check ads.serviceCacheAdsLen(serviceId1) == 1
    check ads.serviceCacheAdsLen(serviceId2) == 1

  test "inserts ad into cache, IP tree, and timestamps":
    let ads = AdvertisementCache.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let now = initMoment(1000)

    ads.putAd(serviceId, ad, now)
    check ads.serviceCacheAdsLen(serviceId) == 1
    check ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)[0].data.peerId ==
      ad.data.peerId
    check ads.getCachedAd(serviceId, ad.data.peerId).get().timestamp == now
    check ads.ipTree.ipsLen > 0

  test "same ad accepted for three services counts three slots and three IP inserts":
    let ads = AdvertisementCache.new()
    let serviceId1 = makeServiceId(1)
    let serviceId2 = makeServiceId(2)
    let serviceId3 = makeServiceId(3)
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let now = initMoment(1000)

    ads.putAd(serviceId1, ad, now)
    ads.putAd(serviceId2, ad, now)
    ads.putAd(serviceId3, ad, now)

    check ads.len == 3
    check ads.ipTree.ipsLen == 3
    check ads.serviceLen == 3

  test "two advertisers with same ad bytes each get a slot":
    let ads = AdvertisementCache.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let advertiserA = randomPeerId()
    let advertiserB = randomPeerId()
    let now = initMoment(1000)

    ads.putAd(serviceId, ad, now, advertiser = advertiserA)
    ads.putAd(serviceId, ad, now, advertiser = advertiserB)

    check ads.serviceCacheAdsLen(serviceId) == 2
    check ads.contains(serviceId, advertiserA)
    check ads.contains(serviceId, advertiserB)

  test "replace does not increase len at capacity":
    let ads = AdvertisementCache.new(2)
    let ad1 = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let privateKey = PrivateKey.random(rng()).get()
    let serviceName = "s"
    let sid = serviceName.hashServiceId()
    let first = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 1)
    let second = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 2)

    ads.putAd(makeServiceId(1), ad1, initMoment(1000))
    ads.putAd(sid, first, initMoment(2000))
    check ads.len == 2

    ads.putAd(sid, second, initMoment(3000))
    check ads.len == 2
    check ads.getServiceCachedAds(sid, int.high).mapIt(it.ad)[0].data.seqNo == 2
    check ad1 in ads.getServiceCachedAds(makeServiceId(1), int.high).mapIt(it.ad)

  test "inserts ad without eviction when cache is under capacity":
    let ads = AdvertisementCache.new(10)
    let serviceId = makeServiceId()
    let existingAd = makeAdvertisement($makeServiceId(99))
    ads.putAd(makeServiceId(99), existingAd, initMoment(1000))

    let newAd = makeAdvertisement()
    ads.putAd(serviceId, newAd, initMoment(2000))

    check ads.len == 2
    check existingAd in ads.getServiceCachedAds(makeServiceId(99), int.high).mapIt(
      it.ad
    )
    check newAd in ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)

  test "evicts oldest slot when cache is at capacity":
    let cap = 5'u64
    let ads = AdvertisementCache.new(cap)
    let now = initMoment(5000)

    var oldestAd: Advertisement
    var oldestServiceId: ServiceId
    for i in 0 ..< int(cap):
      let sid = makeServiceId(byte(i + 1))
      let a = makeAdvertisement($sid)
      let ts =
        if i == 0:
          initMoment(100)
        else:
          now
      ads.putAd(sid, a, ts)
      if i == 0:
        oldestAd = a
        oldestServiceId = sid

    let newServiceId = makeServiceId(100)
    let newAd = makeAdvertisement()
    ads.putAd(newServiceId, newAd, now)

    check oldestAd notin ads.getServiceCachedAds(oldestServiceId, int.high).mapIt(it.ad)
    check oldestServiceId notin ads
    check newAd in ads.getServiceCachedAds(newServiceId, int.high).mapIt(it.ad)
    check ads.len == int(cap)

  test "eviction removes only the oldest slot, not other services":
    let cap = 2'u64
    let ads = AdvertisementCache.new(cap)
    let serviceId1 = makeServiceId(1)
    let serviceId2 = makeServiceId(2)
    let now = initMoment(5000)

    let oldestAd = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    let otherAd = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.2")])

    ads.putAd(serviceId1, oldestAd, initMoment(100))
    ads.putAd(serviceId2, otherAd, now)
    check ads.len == 2

    let newServiceId = makeServiceId(3)
    let newAd = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.3")])
    ads.putAd(newServiceId, newAd, now)

    check:
      oldestAd notin ads.getServiceCachedAds(serviceId1, int.high).mapIt(it.ad)
      serviceId1 notin ads
      otherAd in ads.getServiceCachedAds(serviceId2, int.high).mapIt(it.ad)
      newAd in ads.getServiceCachedAds(newServiceId, int.high).mapIt(it.ad)
      ads.len == 2

  test "clear empties maps and IP tree":
    let ads = AdvertisementCache.new()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement(addrs = @[makeMultiAddress("10.0.0.1")])
    ads.putAd(serviceId, ad, Moment.now())

    ads.clear()
    check ads.len == 0
    check ads.ipTree.ipsLen == 0
    check serviceId notin ads

suite "Service Discovery Registrar - Register Message Validation":
  test "isValidAdvertisement rejects empty advertisement":
    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: @[],
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.none(Ticket),
    )

    check isValidAdvertisement(regMsg, makeServiceId()).isErr()

  test "isValidAdvertisement rejects malformed advertisement bytes":
    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: @[1'u8, 2, 3, 4],
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.none(Ticket),
    )

    check isValidAdvertisement(regMsg, makeServiceId()).isErr()

  test "isValidAdvertisement accepts decodable advertisement":
    let serviceStr = $1
    let serviceId = hashServiceId(serviceStr)
    let ad = makeAdvertisement(serviceStr, addrs = @[makeMultiAddress("10.0.0.1")])
    let adBuf = ad.encode().get()

    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: adBuf,
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.none(Ticket),
    )

    let decoded = isValidAdvertisement(regMsg, serviceId)

    check decoded.isOk()
    check decoded.get().data.peerId == ad.data.peerId
    check decoded.get().data.seqNo == ad.data.seqNo

  test "isValidAdvertisement rejects advertisement for different service":
    let serviceId = "service".hashServiceId()
    let ad = makeAdvertisement("other-service")
    let adBuf = ad.encode().get()
    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: adBuf,
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.none(Ticket),
    )

    check isValidAdvertisement(regMsg, serviceId).isErr()

  test "isValidAdvertisement rejects advertisement with no services":
    let serviceId = "service".hashServiceId()
    let ad = makeAdvertisementWithServices(@[])
    let adBuf = ad.encode().get()
    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: adBuf,
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.none(Ticket),
    )

    check isValidAdvertisement(regMsg, serviceId).isErr()

  test "isValidAdvertisement accepts multi-service advertisement":
    let services = @[
      makeServiceInfo("service-a"),
      makeServiceInfo("service-b"),
      makeServiceInfo("service-c"),
    ]
    let serviceId = services[0].id.hashServiceId()
    let ad = makeAdvertisementWithServices(services)
    let adBuf = ad.encode().get()
    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: adBuf,
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.none(Ticket),
    )

    let decoded = isValidAdvertisement(regMsg, serviceId)

    check:
      decoded.isOk()
      decoded.get().data.peerId == ad.data.peerId
      decoded.get().data.services.len == 3

  test "isValidAdvertisement rejects advertisement over MaxXPRSize":
    let regMsg = kadprotobuf.RegisterMessage(
      advertisement: newSeq[byte](MaxXPRSize + 1),
      status: Opt.none(kadprotobuf.RegistrationStatus),
      ticket: Opt.none(Ticket),
    )

    check isValidAdvertisement(regMsg, makeServiceId()).error == "oversized"

suite "Service Discovery Registrar - acceptAdvertisement":
  teardown:
    checkTrackers()

  test "new peer ad is added to cache":
    let disco =
      setupServiceDiscoveryNode(discoConfig = ServiceDiscoveryConfig.new(fReturn = 3))
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId)
    let now = Moment.now()

    disco.acceptAd(now, serviceId, ad)

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
    check disco.registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)[0].data.peerId ==
      ad.data.peerId

  test "expiry of the last ad removes the service table":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()
    let now = Moment.now()

    disco.acceptAd(now - 1000.secs, serviceId, makeAdvertisement($serviceId))
    disco.acceptAd(now - 500.secs, serviceId, makeAdvertisement($serviceId))
    disco.registrar.pruneExpiredAds(900.secs)
    check disco.rtManager.hasService(serviceId)

    disco.registrar.pruneExpiredAds(100.secs)
    check:
      disco.registrar.ads.len == 0
      not disco.rtManager.hasService(serviceId)

  test "eviction of the last ad removes the service table":
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(advertCacheCap = 1)
    )
    let evicted = makeServiceId(1)
    let kept = makeServiceId(2)
    let now = Moment.now()

    disco.acceptAd(now - 10.secs, evicted, makeAdvertisement($evicted))
    disco.acceptAd(now, kept, makeAdvertisement($kept))

    check:
      not disco.rtManager.hasService(evicted)
      disco.rtManager.hasService(kept)
      disco.rtManager.count() == 1

  test "clearing the ad cache removes the service tables":
    let disco = setupServiceDiscoveryNode()
    let first = makeServiceId(1)
    let second = makeServiceId(2)
    let now = Moment.now()

    disco.acceptAd(now, first, makeAdvertisement($first))
    disco.acceptAd(now, second, makeAdvertisement($second))
    disco.registrar.ads.clear()

    check:
      not disco.rtManager.hasService(first)
      not disco.rtManager.hasService(second)
      disco.rtManager.count() == 0

  test "eviction of another advertiser's ad for the same service keeps the table":
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(advertCacheCap = 1)
    )
    let serviceId = makeServiceId()
    let now = Moment.now()

    disco.acceptAd(now - 10.secs, serviceId, makeAdvertisement($serviceId))
    disco.acceptAd(now, serviceId, makeAdvertisement($serviceId))

    check:
      disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
      disco.rtManager.serviceStatus.getOrDefault(serviceId) == {Registered}

  test "ad expiry keeps a service table the node has local interest in":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    check disco.registerInterest(service.id)
    disco.acceptAd(Moment.now() - 1000.secs, serviceId, makeAdvertisement(service.id))
    disco.registrar.pruneExpiredAds(900.secs)

    check disco.rtManager.serviceStatus.getOrDefault(serviceId) == {Interest}

  asyncTest "advertising peer is not seated when its admission probe fails":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()
    let ad = makeAdvertisement($serviceId, addrs = @[ma("/ip4/127.0.0.1/tcp/59996")])
    let advertisingPeer = randomPeerId()
    disco.switch.peerStore[AddressBook][advertisingPeer] =
      @[ma("/ip4/127.0.0.1/tcp/59997")]

    disco.acceptAd(Moment.now(), serviceId, ad, advertiser = advertisingPeer)
    check not disco.hasPeerInServiceTable(serviceId, advertisingPeer)

    checkUntilTimeout:
      disco.admissionProbes.len == 0
    check:
      disco.probeFailures.getOrDefault(advertisingPeer).count == 1
      ad.data.peerId notin disco.probeFailures
      not disco.hasPeerInServiceTable(serviceId, advertisingPeer)
      not disco.hasPeerInServiceTable(serviceId, ad.data.peerId)
      disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1

  test "same advertiser higher seqNo replaces existing ad":
    let disco =
      setupServiceDiscoveryNode(discoConfig = ServiceDiscoveryConfig.new(fReturn = 3))
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let now = Moment.now()

    let oldAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 1)
    let newAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 2)

    disco.acceptAd(now, serviceId, oldAd)
    disco.acceptAd(now, serviceId, newAd)

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
    check disco.registrar.ads.getServiceCachedAds(serviceId, int.high).mapIt(it.ad)[0].data.seqNo ==
      2

  test "same advertiser lower seqNo is ignored":
    let disco =
      setupServiceDiscoveryNode(discoConfig = ServiceDiscoveryConfig.new(fReturn = 3))
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let now = Moment.now()

    let newerAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 10)
    let olderAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 5)

    disco.acceptAd(now, serviceId, newerAd)
    disco.acceptAd(now + 1.seconds, serviceId, olderAd)

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
    let cached = disco.registrar.ads.getCachedAd(serviceId, newerAd.data.peerId).get()
    check:
      cached.ad.data.seqNo == 10
      cached.timestamp == now

  test "relayed lower seqNo of a cached signer is ignored":
    let disco =
      setupServiceDiscoveryNode(discoConfig = ServiceDiscoveryConfig.new(fReturn = 3))
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let relay = randomPeerId()
    let now = Moment.now()

    let newerAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 10)
    let olderAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 5)

    disco.acceptAd(now, serviceId, newerAd)
    disco.acceptAd(now, serviceId, olderAd, advertiser = relay)

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
    check not disco.registrar.ads.contains(serviceId, relay)

  test "higher seqNo drops older ads of the signer from every advertiser":
    let disco =
      setupServiceDiscoveryNode(discoConfig = ServiceDiscoveryConfig.new(fReturn = 3))
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let relay = randomPeerId()
    let now = Moment.now()

    let olderAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 5)
    let newerAd = makeAdvertisement(serviceName, privateKey = privateKey, seqNo = 10)

    disco.acceptAd(now, serviceId, olderAd, advertiser = relay)
    disco.acceptAd(now, serviceId, newerAd)

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
    check disco.registrar.ads.len == 1
    check not disco.registrar.ads.contains(serviceId, relay)
    check disco.registrar.ads
      .getCachedAd(serviceId, newerAd.data.peerId)
      .get().ad.data.seqNo == 10

  test "different advertisers each store their own ad":
    let disco =
      setupServiceDiscoveryNode(discoConfig = ServiceDiscoveryConfig.new(fReturn = 3))
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let ad1 = makeAdvertisement(serviceName)
    let ad2 = makeAdvertisement(serviceName)
    let now = Moment.now()

    disco.acceptAd(now, serviceId, ad1)
    disco.acceptAd(now, serviceId, ad2)

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 2

  asyncTest "replace updates IP tree without doubling":
    let disco =
      setupServiceDiscoveryNode(discoConfig = ServiceDiscoveryConfig.new(fReturn = 3))
    let serviceName = "service"
    let serviceId = serviceName.hashServiceId()
    let privateKey = PrivateKey.random(rng()).get()
    let now = Moment.now()

    let oldAd = makeAdvertisement(
      serviceName,
      privateKey = privateKey,
      seqNo = 1,
      addrs = @[makeMultiAddress("10.0.0.1")],
    )
    let newAd = makeAdvertisement(
      serviceName,
      privateKey = privateKey,
      seqNo = 2,
      addrs = @[makeMultiAddress("10.0.0.2")],
    )

    disco.acceptAd(now, serviceId, oldAd)
    let counterAfterFirst = disco.registrar.ads.ipTree.ipsLen
    check counterAfterFirst > 0

    disco.acceptAd(now, serviceId, newAd)

    check disco.registrar.ads.serviceCacheAdsLen(serviceId) == 1
    check disco.registrar.ads.ipTree.ipsLen == counterAfterFirst

    let probes = move disco.admissionProbes
    await noCancel probes.values.toSeq().cancelAndWait()

suite "Service Discovery Registrar - connection IPs":
  asyncTest "observedIps extracts IP from stream.observedAddr":
    let peerId = randomPeerId()
    let maddr = makeMultiAddress("203.0.113.10")
    let stream = Connection.new(peerId, Direction.In, observedAddr = Opt.some(maddr))
    defer:
      await stream.close()
    check stream.observedIps() == @[parseIpAddress("203.0.113.10")]

  asyncTest "observedIps is empty when observedAddr is missing":
    let stream = Connection.new(randomPeerId(), Direction.In)
    defer:
      await stream.close()
    check stream.observedIps().len == 0

  test "advertiserIps prefers connectionIps over peerstore":
    let disco = setupServiceDiscoveryNode()
    let peerId = randomPeerId()
    disco.switch.peerStore[AddressBook][peerId] = @[makeMultiAddress("10.0.0.1")]
    let connectionIps = @[parseIpAddress("198.51.100.7")]
    check disco.advertiserIps(peerId, connectionIps) == connectionIps

  test "advertiserIps falls back to peerstore when connectionIps empty":
    let disco = setupServiceDiscoveryNode()
    let peerId = randomPeerId()
    disco.switch.peerStore[AddressBook][peerId] = @[makeMultiAddress("10.0.0.1")]
    check disco.advertiserIps(peerId) == @[parseIpAddress("10.0.0.1")]

  test "advertiserIps falls back to self listen addrs for local registration":
    let disco = setupServiceDiscoveryNode()
    let selfId = disco.switch.peerInfo.peerId
    let listenAddr = makeMultiAddress("127.0.0.1")
    disco.switch.peerInfo.addrs = @[listenAddr]
    # Clear peerstore entry so self listen path is used.
    disco.switch.peerStore[AddressBook][selfId] = @[]
    check disco.advertiserIps(selfId) == @[parseIpAddress("127.0.0.1")]

  test "registration caches connectionIps not peerstore or ad payload IPs":
    let disco = setupServiceDiscoveryNode(
      discoConfig =
        ServiceDiscoveryConfig.new(safetyParam = 0.0, advertExpiry = 999.millis)
    )
    let serviceName = "conn-ip-service"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName, addrs = @[makeMultiAddress("10.0.0.99")])
    let adBytes = ad.encode().get()
    let advertiserId = ad.data.peerId

    # Peerstore claims a different IP than the connection.
    disco.switch.peerStore[AddressBook][advertiserId] = @[makeMultiAddress("10.0.0.1")]

    let connectionIps = @[parseIpAddress("198.51.100.42")]
    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply = disco.registration(advertiserId, inMsg, connectionIps).register.get()
    check reply.status.get() == kadprotobuf.RegistrationStatus.Confirmed

    let slot = disco.registrar.ads.getCachedAd(serviceId, advertiserId).get()
    check slot.ips == connectionIps
    check slot.ips != @[parseIpAddress("10.0.0.1")]
    check slot.ips != @[parseIpAddress("10.0.0.99")]
