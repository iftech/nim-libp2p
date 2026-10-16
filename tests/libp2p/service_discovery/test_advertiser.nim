# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/sequtils
import chronos, results, sets, tables
import
  ../../../libp2p/[
    extended_peer_record,
    peeraddrpolicy,
    peerinfo,
    peerstore,
    protocols/kademlia,
    protocols/service_discovery,
    protocols/service_discovery/advertiser,
    stream/connection,
  ]
import ../../tools/[fault_stream, lifecycle, multiaddress, unittest]
import ./utils

proc holdUntil(gate: AsyncEvent) {.async: (raises: [CancelledError]).} =
  ## A republish caught mid-flight: a cancel lands only once `gate` fires.
  await noCancel gate.wait()

proc settleStartupRepublish(disco: ServiceDiscovery) {.async.} =
  if disco.addressRepublish.isNil():
    return
  await disco.addressRepublish

proc dropCachedAds(disco: ServiceDiscovery) =
  discard disco.registrar.ads.pruneExpired(Moment.now() + 1.hours, 0.secs)

suite "Advertiser - republish on address change":
  teardown:
    checkTrackers()

  asyncTest "a newer address change waits for the pending republish to drain":
    let disco = setupServiceDiscoveryNode(services = @[makeServiceInfo()])
    startAndDeferStop(@[disco])
    await disco.settleStartupRepublish()

    let gate = newAsyncEvent()
    let held = holdUntil(gate)
    disco.addressRepublish = held
    let loopBefore = disco.xprPublishLoop

    disco.switch.peerInfo.notifyObservers()
    let first = disco.addressRepublish
    disco.switch.peerInfo.notifyObservers()
    let second = disco.addressRepublish

    check:
      first != held
      second != first
      not first.finished()
      not second.finished()
      disco.xprPublishLoop == loopBefore

    gate.fire()
    await second
    check:
      held.completed()
      first.finished()
      second.completed()
      disco.xprPublishLoop != loopBefore

  asyncTest "stop drains the pending republish before it clears the advertiser":
    let disco = setupServiceDiscoveryNode(services = @[makeServiceInfo()])
    startAndDeferStop(@[disco])
    await disco.settleStartupRepublish()

    let gate = newAsyncEvent()
    disco.addressRepublish = holdUntil(gate)
    disco.switch.peerInfo.notifyObservers()
    let pending = disco.addressRepublish

    let stopping = disco.stop()
    check:
      not stopping.finished()
      not pending.finished()
      disco.advertiser.providedAdverts.len == 1

    gate.fire()
    await stopping
    check:
      pending.finished()
      disco.addressRepublish.isNil()
      disco.addressObserver.isNil()
      disco.advertiser.providedAdverts.len == 0

    disco.switch.peerInfo.notifyObservers()
    check disco.addressRepublish.isNil()

suite "Advertiser - addProvidedService":
  teardown:
    checkTrackers()

  test "creates routing table entry for the service":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    disco.populateRoutingTable(1)
    check disco.addProvidedService(service).isOk()

    check disco.rtManager.hasService(serviceId)

  test "caches this node's record when the caller supplies no advertisement":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    disco.populateRoutingTable(1)
    check disco.addProvidedService(service).isOk()

    let cached = disco.advertiser.providedAdverts[serviceId].bytes
    let ad = Advertisement.decode(cached).get()
    check:
      ad.data.peerId == disco.switch.peerInfo.peerId
      ad.advertisesService(serviceId)

    disco.switch.peerInfo.addrs = @[makeMultiAddress("10.0.0.2")]
    check disco.record().get().encode() != cached
    check disco.advertiser.providedAdverts[serviceId].bytes == cached

  asyncTest "a moved address rebuilds the cached record":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    check disco.addProvidedService(service).isOk()

    let moved = makeMultiAddress("10.0.0.2")
    disco.switch.peerInfo.addrs = @[moved]
    await disco.republishProvidedAdverts()

    let ad =
      Advertisement.decode(disco.advertiser.providedAdverts[serviceId].bytes).get()
    check:
      ad.data.addresses.len == 1
      ad.data.addresses[0].address == moved

  asyncTest "a moved address keeps a caller-supplied advertisement":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    let advert = makeAdvertisement(service.id).encode()

    check disco.addProvidedService(service, Opt.some(advert)).isOk()

    disco.switch.peerInfo.addrs = @[makeMultiAddress("10.0.0.2")]
    await disco.republishProvidedAdverts()

    check disco.advertiser.providedAdverts[serviceId].bytes == advert

  test "with empty routing table: creates table but schedules no actions":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    check disco.addProvidedService(service).isOk()

    check disco.rtManager.hasService(serviceId)
    check disco.advertiser.running.len() == 0

  test "schedules up to kRegister actions per populated bucket":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    disco.populateAdvertisementTable(serviceId)
    check disco.addProvidedService(service).isOk()

    check disco.advertiser.running.len() == disco.discoConfig.kRegister

  test "scheduling caps at kRegister tasks per populated bucket":
    let kRegister = 3
    let conf = ServiceDiscoveryConfig.new(kRegister = kRegister)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    disco.populateRoutingTable(100)

    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    check disco.rtManager.addService(
      serviceId, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
      Interest,
    )

    let table = disco.rtManager.getTable(serviceId).get()
    var overpopulatedBuckets = 0
    for bucket in mitems(table.buckets):
      if bucket.peers.len <= kRegister:
        bucket.peers = @[]
      else:
        overpopulatedBuckets.inc
    check overpopulatedBuckets > 0

    check disco.addProvidedService(service).isOk()

    check disco.advertiser.running.len() == overpopulatedBuckets * kRegister

  test "adding the same service twice replaces its scheduled registrations":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    disco.populateAdvertisementTable(serviceId)
    check disco.addProvidedService(service).isOk()
    let firstTasks = toSeq(disco.advertiser.running)

    check disco.addProvidedService(service).isOk()

    check:
      disco.rtManager.hasService(serviceId)
      disco.advertiser.running.len() == firstTasks.len()
      firstTasks.allIt(it notin disco.advertiser.running)
      disco.services.len == 1

  test "a failed record build leaves no half-added service behind":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()

    var addrs: seq[MultiAddress]
    for _ in 1 .. 200: # enough that the record no longer fits MaxXPRSize
      addrs.add(makeMultiAddress("10.0.0.1"))
    disco.switch.peerInfo.addrs = addrs
    check disco.record().isErr()

    check disco.addProvidedService(service).isErr()
    check not disco.rtManager.hasService(serviceId)

    disco.switch.peerInfo.addrs = @[makeMultiAddress("10.0.0.1")]
    check disco.addProvidedService(service).isOk()

  test "multiple distinct services each get their own routing table":
    let disco = setupServiceDiscoveryNode()
    let s1 = makeServiceInfo("svc-1")
    let s2 = makeServiceInfo("svc-2")
    let s3 = makeServiceInfo("svc-3")

    disco.populateRoutingTable(1)
    check disco.addProvidedService(s1).isOk()
    check disco.addProvidedService(s2).isOk()
    check disco.addProvidedService(s3).isOk()

    check disco.rtManager.hasService(s1.id.hashServiceId())
    check disco.rtManager.hasService(s2.id.hashServiceId())
    check disco.rtManager.hasService(s3.id.hashServiceId())
    check disco.advertiser.running.len() == 3

suite "Advertiser - caller-supplied advertisement":
  teardown:
    checkTrackers()

  test "stores a valid advertisement for reuse on rotation":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let advert = makeAdvertisement(service.id).encode()

    disco.populateRoutingTable(1)

    check disco.addProvidedService(service, Opt.some(advert)).isOk()
    check disco.advertiser.providedAdverts[service.id.hashServiceId()].bytes == advert

  test "rejects an advertisement that does not decode":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()

    check disco.addProvidedService(service, Opt.some(@[1'u8, 2, 3, 4])).isErr()
    check not disco.rtManager.hasService(service.id.hashServiceId())

  test "rejects an advertisement for another service":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo("wanted-service")
    let advert = makeAdvertisement("other-service").encode()

    check disco.addProvidedService(service, Opt.some(advert)).isErr()
    check not disco.rtManager.hasService(service.id.hashServiceId())

  test "rejects an advertisement with oversized service data":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let advert = makeOversizedAdvertisement(service.id).encode()

    check disco.addProvidedService(service, Opt.some(advert)).isErr()
    check not disco.rtManager.hasService(service.id.hashServiceId())

  test "rejects an advertisement padded past MaxXPRSize with unknown fields":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let advert = padAdvertisement(makeAdvertisement(service.id).encode(), MaxXPRSize)

    # the decoder skips the padding, so only the incoming length rejects this
    check advert.len > MaxXPRSize
    check Advertisement.decode(advert).isOk()

    check disco.addProvidedService(service, Opt.some(advert)).isErr()
    check not disco.rtManager.hasService(service.id.hashServiceId())

  test "a second startAdvertising replaces the advertisement in place":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    let first = makeAdvertisement(service.id).encode()
    let second = makeAdvertisement(service.id).encode()
    check first != second # each helper call signs with a fresh key

    disco.populateRoutingTable(1)

    check disco.startAdvertising(service, Opt.some(first)).isOk()
    check disco.startAdvertising(service, Opt.some(second)).isOk()
    check disco.advertiser.providedAdverts[serviceId].bytes == second

  test "a rejected replacement keeps the current advertisement":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    let advert = makeAdvertisement(service.id).encode()

    check disco.startAdvertising(service, Opt.some(advert)).isOk()
    let other = makeAdvertisement("other-service").encode()
    check disco.startAdvertising(service, Opt.some(other)).isErr()
    check disco.advertiser.providedAdverts[serviceId].bytes == advert

  test "a caller-supplied advertisement stays out of this node's record":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let advert = makeAdvertisement(service.id).encode()

    check disco.startAdvertising(service, Opt.some(advert)).isOk()

    check:
      disco.services.len == 0
      not disco.record().get().advertisesService(service.id.hashServiceId())

  test "replacing this node's record with a caller-supplied one drops the service":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let advert = makeAdvertisement(service.id).encode()

    check disco.startAdvertising(service).isOk()
    check disco.services.len == 1

    check disco.startAdvertising(service, Opt.some(advert)).isOk()
    check disco.services.len == 0

  asyncTest "registrations run for a caller-supplied advertisement":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    let advert = makeAdvertisement(service.id).encode()

    disco.populateAdvertisementTable(serviceId)
    check disco.startAdvertising(service, Opt.some(advert)).isOk()

    await disco.stopRegistrations()
    await disco.maintainRegistrations()

    check:
      disco.advertiser.running.len() == disco.discoConfig.kRegister
      not disco.localRegistrationLoop.finished()

  asyncTest "an advertisement set before start replaces the configured service":
    let service = makeServiceInfo()
    let disco = setupServiceDiscoveryNode(services = @[service])
    let advert = makeAdvertisement(service.id).encode()

    check disco.startAdvertising(service, Opt.some(advert)).isOk()
    check disco.services.len == 0

    startAndDeferStop(@[disco])
    check disco.advertiser.providedAdverts[service.id.hashServiceId()].bytes == advert

  test "an advertisement signed with this node's key replaces the own XPR":
    let key = PrivateKey.random(rng()).get()
    let disco = setupServiceDiscoveryNode(privateKey = Opt.some(key))
    let service = makeServiceInfo()
    let advert = makeAdvertisement(service.id, key).encode()

    check disco.xprsToPublish().len == 1
    check disco.startAdvertising(service, Opt.some(advert)).isOk()
    check disco.xprsToPublish().mapIt(it.bytes) == @[advert]

  asyncTest "an advert change restarts XPR publishing after the old loop stops":
    let disco = setupServiceDiscoveryNode()
    startAndDeferStop(@[disco])
    let before = disco.xprPublishLoop

    check disco.startAdvertising(makeServiceInfo()).isOk()
    check disco.xprPublishLoop != before

    discard await before.join().withTimeout(1.seconds)
    check:
      before.cancelled()
      not disco.xprPublishLoop.finished()

suite "Advertiser - maintainRegistrations":
  teardown:
    checkTrackers()

  asyncTest "stops scheduling in client mode and resumes on an upgrade":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()

    disco.populateAdvertisementTable(service.id.hashServiceId())
    check disco.addProvidedService(service).isOk()

    await disco.stopRegistrations()
    check await disco.changeMode(isServer = false)

    await disco.maintainRegistrations()

    check disco.advertiser.running.len() == 0
    check disco.localRegistrationLoop.isNil()

    check await disco.changeMode(isServer = true)

    await disco.maintainRegistrations()

    check disco.advertiser.running.len() > 0
    check not disco.localRegistrationLoop.finished()

  asyncTest "a republish in client mode leaves the local registration stopped":
    let disco = setupServiceDiscoveryNode()
    check disco.addProvidedService(makeServiceInfo()).isOk()
    check await disco.changeMode(isServer = false)

    await disco.republishProvidedAdverts()

    check:
      disco.localRegistrationLoop.isNil()
      disco.advertiser.running.len() == 0

  asyncTest "skips a routing table key that is not a peer id":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    var raw: array[IdLength, byte]
    raw[^1] = 1
    check disco.rtable.insert(Key.init(raw))

    check disco.addProvidedService(service).isOk()

    check:
      disco.rtManager.getTable(service.id.hashServiceId()).get().allKeys().len == 1
      disco.advertiser.running.len() == 0

    await disco.localRegistrationLoop.cancelAndWait()

  asyncTest "a registrar that left its bucket loses its stalled task":
    let disco = setupServiceDiscoveryNode()
    let stream = FaultStream.new(onWrite = Fault.Hang)
    disco.switch = FaultSwitch.new(disco.switch, stream)
    defer:
      await disco.stopRegistrations()
      await stream.close()

    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    disco.populateAdvertisementTable(serviceId)
    for key in disco.rtable.allKeys():
      disco.switch.peerStore[AddressBook][key.toPeerId().get()] =
        @[makeMultiAddress("127.0.0.1")]
    check disco.addProvidedService(service).isOk()
    await stream.hung.wait()

    let stalled = toSeq(disco.advertiser.running)[0]
    let replacement = randomPeerId()
    disco.switch.peerStore[AddressBook][replacement] = @[makeMultiAddress("127.0.0.1")]
    let table = disco.rtManager.getTable(serviceId).get()
    let pos = table.buckets[stalled.bucketIdx].peers.find(stalled.registrar.toKey())
    require pos >= 0
    table.buckets[stalled.bucketIdx].peers[pos] = replacement.toKey()

    await disco.maintainRegistrations()

    await stalled.fut.join()
    check:
      stalled notin disco.advertiser.running
      toSeq(disco.advertiser.running).anyIt(it.registrar == replacement)
      stalled.fut.cancelled()

suite "Advertiser - removeProvidedService":
  teardown:
    checkTrackers()

  asyncTest "removes routing table and clears its pending actions":
    let disco = setupServiceDiscoveryNode()
    let s1 = makeServiceInfo("svc-1")
    let s2 = makeServiceInfo("svc-2")
    let sid1 = s1.id.hashServiceId()
    let sid2 = s2.id.hashServiceId()

    disco.populateRoutingTable(1)
    check disco.addProvidedService(s1).isOk()
    check disco.addProvidedService(s2).isOk()

    await disco.removeProvidedService(s1.id)
    disco.dropCachedAds() # the local registrar holds the self-ad

    check:
      not disco.rtManager.hasService(sid1)
      disco.rtManager.hasService(sid2)
      disco.advertiser.running.len() == 1

  asyncTest "cancels the service bootstrap future once the table is gone":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()
    let sid = service.id.hashServiceId()

    disco.populateRoutingTable(1)
    check disco.addProvidedService(service).isOk()
    discard disco.registerInterest(service.id)
    check disco.rtManager.serviceStatus[sid] == {Interest, Provided, Registered}

    let bootstrapFut = newFuture[void]("test service bootstrap")
    disco.serviceBootstrapFuts[sid] = bootstrapFut

    await disco.removeProvidedService(service.id)
    check sid in disco.serviceBootstrapFuts # interest keeps the table alive

    disco.unregisterInterest(service.id)
    check sid in disco.serviceBootstrapFuts # the self-ad keeps the table alive

    disco.dropCachedAds()
    await sleepAsync(0.millis) # let the pending cancellation run

    check:
      sid notin disco.serviceBootstrapFuts
      bootstrapFut.cancelled()

  asyncTest "removing non-existent service is a no-op":
    let disco = setupServiceDiscoveryNode()
    let service = makeServiceInfo()

    await disco.removeProvidedService(service.id)
    check not disco.rtManager.hasService(service.id.hashServiceId())

  asyncTest "removing one service leaves others intact":
    let disco = setupServiceDiscoveryNode()
    let s1 = makeServiceInfo("svc-1")
    let s2 = makeServiceInfo("svc-2")

    disco.populateRoutingTable(1)
    check disco.addProvidedService(s1).isOk()
    check disco.addProvidedService(s2).isOk()

    await disco.removeProvidedService(s1.id)
    disco.dropCachedAds() # the local registrar holds the self-ad

    check not disco.rtManager.hasService(s1.id.hashServiceId())
    check disco.rtManager.hasService(s2.id.hashServiceId())

suite "Advertiser - record creation":
  teardown:
    checkTrackers()

  test "record creation rejects service data larger than MaxServiceDataSize":
    let validData = newSeq[byte](MaxServiceDataSize)
    let discoValid = setupServiceDiscoveryNode(
      services = @[ServiceInfo(id: "service", data: validData)]
    )
    let recordValid = discoValid.record()
    check recordValid.isOk()
    let svc = recordValid.get().data.services[0]
    check:
      svc.isValid()
      svc.data.get().len == MaxServiceDataSize

    let oversizedData = newSeq[byte](MaxServiceDataSize + 1)
    let badSvc = ServiceInfo(id: "service", data: oversizedData)
    let discoBad = setupServiceDiscoveryNode(services = @[badSvc])
    let recordBad = discoBad.record()
    check:
      not badSvc.isValid()
      recordBad.isErr()

  test "record creation rejects encoded XPR larger than MaxXPRSize":
    let discoSmall = setupServiceDiscoveryNode(services = @[makeServiceInfo("service")])
    let recordSmall = discoSmall.record()
    check recordSmall.isOk()
    let smallXpr = recordSmall.get()
    check:
      smallXpr.isValid()
      smallXpr.encode().get().len <= MaxXPRSize

    let discoBig = setupServiceDiscoveryNode(services = @[makeServiceInfo("service")])
    let baseAddr = makeMultiAddress("10.0.0.1")
    var addrs: seq[MultiAddress]
    var foundOversized = false

    for _ in 1 .. 10_000:
      addrs.add(baseAddr)
      discoBig.switch.peerInfo.addrs = addrs
      let rec = discoBig.record()
      if rec.isErr():
        foundOversized = true
        break
      let enc = rec.get().encode()
      if enc.isOk and enc.get().len > MaxXPRSize:
        foundOversized = true
        break

    check foundOversized

    let recordBig = discoBig.record()
    check recordBig.isErr()

  test "record creation filters addresses using kadConfig.addressPolicy":
    let
      publicAddr = makeMultiAddress("1.1.1.1")
      privateAddr = makeMultiAddress("192.168.1.1")
      mixed = @[privateAddr, publicAddr]

    let policyConf = KadDHTConfig.new(addressPolicy = publicRoutableAddressPolicy)
    let disco = setupServiceDiscoveryNode(
      services = @[makeServiceInfo("service")], kadConfig = policyConf
    )
    disco.switch.peerInfo.addrs = mixed

    let rec = disco.record()
    check rec.isOk()
    let xprAddrs = rec.get().data.addresses
    check:
      xprAddrs.len == 1
      xprAddrs[0].address == publicAddr

    # default policy (no filtering) keeps all addresses
    let discoDef = setupServiceDiscoveryNode(services = @[makeServiceInfo("service")])
    discoDef.switch.peerInfo.addrs = mixed
    let recDef = discoDef.record()
    check recDef.isOk()
    check recDef.get().data.addresses.len == 2

  test "record creation drops an undialable address by default":
    let disco = setupServiceDiscoveryNode(services = @[makeServiceInfo("service")])
    let routable = makeMultiAddress("10.0.0.1")
    disco.switch.peerInfo.addrs =
      @[ma("/ip4/0.0.0.0/tcp/60000"), ma("/ip4/127.0.0.1/tcp/0"), routable]

    let rec = disco.record()
    check rec.isOk()
    let xprAddrs = rec.get().data.addresses
    check:
      xprAddrs.len == 1
      xprAddrs[0].address == routable

  test "record creation fails while nothing dialable is announced":
    let disco = setupServiceDiscoveryNode(services = @[makeServiceInfo("service")])

    disco.switch.peerInfo.addrs = @[ma("/ip4/0.0.0.0/tcp/60000")]
    check disco.record().isErr()

    disco.switch.peerInfo.addrs = @[]
    check disco.record().isErr()

  test "record creation keeps an undialable address for a local test network":
    let disco = setupServiceDiscoveryNode(services = @[makeServiceInfo("service")])
    disco.switch.peerStore.allowUndialableAddrs = true

    let wildcard = ma("/ip4/0.0.0.0/tcp/60000")
    disco.switch.peerInfo.addrs = @[wildcard]

    let rec = disco.record()
    check rec.isOk()
    let xprAddrs = rec.get().data.addresses
    check:
      xprAddrs.len == 1
      xprAddrs[0].address == wildcard
