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
    stream/connection,
  ]
import ../../../libp2p/protocols/service_discovery/advertiser {.all.}
import ../../tools/[fault_stream, lifecycle, multiaddress, protobuf, unittest]
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
    let advert = pad(makeAdvertisement(service.id).encode(), MaxXPRSize)

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
    let replacement = PeerId.random()
    disco.switch.peerStore[AddressBook][replacement] = @[makeMultiAddress("127.0.0.1")]
    let table = disco.rtManager.getTable(serviceId).get()
    let bucketIdx = stalled.slots[0].bucketIdx
    let pos = table.buckets[bucketIdx].peers.find(stalled.registrar.toKey())
    require pos >= 0
    table.buckets[bucketIdx].peers[pos] = replacement.toKey()

    await disco.maintainRegistrations()

    await stalled.fut.join()
    check:
      stalled notin disco.advertiser.running
      toSeq(disco.advertiser.running).anyIt(it.registrar == replacement)
      stalled.fut.cancelled()

suite "Advertiser - ticket retry":
  teardown:
    checkTrackers()

  asyncTest "a retry after a wait capped at advertExpiry lands in the window":
    # safetyParam 1.0 on an empty cache makes the wait exactly advertExpiry.
    let conf = ServiceDiscoveryConfig.new(
      advertExpiry = 3.secs, registrationWindow = 1.secs, safetyParam = 1.0
    )
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    let advert = makeAdvertisement(service.id).encode().get()
    check disco.rtManager.addService(
      serviceId, disco.rtable, disco.config.replication, conf.bucketsCount, Provided
    )

    let task = disco.advertiseToRegistrar(
      serviceId, disco.switch.peerInfo.peerId, Opt.none(Ticket), advert
    )

    check:
      serviceId in disco.registrar.boundService
      disco.countAdsInCache(serviceId) == 0
    checkUntilTimeoutCustom(
      conf.advertExpiry + 2 * conf.registrationWindow, 100.milliseconds
    ):
      disco.countAdsInCache(serviceId) == 1

    await task.cancelAndWait()

proc setupWithRegistrars(conf: ServiceDiscoveryConfig): ServiceDiscovery =
  let disco = setupServiceDiscoveryNode(discoConfig = conf)
  disco.populateRoutingTable(6)
  # An address keeps each task in its dial, so the task is still running.
  for key in disco.rtable.allKeys():
    disco.switch.peerStore[AddressBook][key.toPeerId().get()] =
      @[makeMultiAddress("127.0.0.1")]
  disco

proc advertiseBoth(conf: ServiceDiscoveryConfig): ServiceDiscovery =
  ## Two services with one caller-supplied advert, so their picks can share a REGISTER.
  let disco = setupWithRegistrars(conf)
  let services = @[makeServiceInfo("service-a"), makeServiceInfo("service-b")]
  let advert = sharedAdvert(services)
  for service in services:
    doAssert disco.startAdvertising(service, Opt.some(advert)).isOk()
  disco

suite "Advertiser - batch registration":
  teardown:
    checkTrackers()

  # kRegister above the table size picks every peer for both services.
  let conf = ServiceDiscoveryConfig.new(kRegister = 10)

  asyncTest "services that share a registrar and an advert go out in one task":
    let disco = advertiseBoth(conf)

    await disco.stopRegistrations()
    await disco.maintainRegistrations()

    check:
      disco.advertiser.running.len == 6
      toSeq(disco.advertiser.running).allIt(it.slots.len == 2)

    await disco.stopRegistrations()

  asyncTest "maxBatchServices caps the services of one task":
    let disco =
      advertiseBoth(ServiceDiscoveryConfig.new(kRegister = 10, maxBatchServices = 1))

    await disco.stopRegistrations()
    await disco.maintainRegistrations()

    check:
      disco.advertiser.running.len == 12
      toSeq(disco.advertiser.running).allIt(it.slots.len == 1)

    await disco.stopRegistrations()

  asyncTest "a registrar that ignores batches gets one task per service":
    let disco = advertiseBoth(conf)
    let single = disco.rtable.allKeys()[0].toPeerId().get()
    disco.advertiser.singleRegistrars[single] = Moment.now() + 1.hours

    await disco.stopRegistrations()
    await disco.maintainRegistrations()

    let tasks = toSeq(disco.advertiser.running).filterIt(it.registrar == single)
    check:
      tasks.len == 2
      tasks.allIt(it.slots.len == 1)

    await disco.stopRegistrations()

  asyncTest "an expired single-service mark lets the registrar batch again":
    let disco = advertiseBoth(conf)
    let single = disco.rtable.allKeys()[0].toPeerId().get()
    disco.advertiser.singleRegistrars[single] = Moment.now() - 1.seconds

    await disco.stopRegistrations()
    await disco.maintainRegistrations()

    check:
      single notin disco.advertiser.singleRegistrars
      toSeq(disco.advertiser.running).filterIt(it.registrar == single).len == 1

    await disco.stopRegistrations()

  asyncTest "removing a service restarts the rest of its batches without it":
    let disco = advertiseBoth(conf)
    await disco.stopRegistrations()
    await disco.maintainRegistrations()
    let batches = toSeq(disco.advertiser.running)

    await disco.stopAdvertising("service-a")

    let kept = "service-b".hashServiceId()
    check:
      batches.allIt(it notin disco.advertiser.running)
      disco.advertiser.running.len == 6
      toSeq(disco.advertiser.running).allIt(it.slots.mapIt(it.serviceId) == @[kept])

    await disco.stopRegistrations()

  asyncTest "re-advertising a service restarts the rest of its batches without it":
    let disco = advertiseBoth(conf)
    await disco.stopRegistrations()
    await disco.maintainRegistrations()
    let batches = toSeq(disco.advertiser.running)
    let idA = "service-a".hashServiceId()
    let idB = "service-b".hashServiceId()
    var bucketOfB = initTable[PeerId, int]()
    for batch in batches:
      bucketOfB[batch.registrar] = batch.bucketOf(idB).get()
    let advertA = disco.advertiser.providedAdverts[idA].bytes

    check disco.startAdvertising(makeServiceInfo("service-a"), Opt.some(advertA)).isOk()

    let running = toSeq(disco.advertiser.running)
    let restarted = running.filterIt(it.slots.mapIt(it.serviceId) == @[idB])
    let fresh = running.filterIt(it.slots.mapIt(it.serviceId) == @[idA])
    check:
      batches.allIt(it notin disco.advertiser.running)
      running.len == 12
      restarted.len == 6
      fresh.len == 6
    for task in restarted:
      check task.slots[0].bucketIdx == bucketOfB[task.registrar]

    await disco.stopRegistrations()

  asyncTest "picks with different advert bytes for one registrar make separate tasks":
    let disco = setupWithRegistrars(conf)
    let serviceA = makeServiceInfo("service-a")
    let serviceB = makeServiceInfo("service-b")
    let serviceC = makeServiceInfo("service-c")
    let shared = sharedAdvert([serviceA, serviceB])
    let own = sharedAdvert([serviceC])
    check:
      disco.startAdvertising(serviceA, Opt.some(shared)).isOk()
      disco.startAdvertising(serviceB, Opt.some(shared)).isOk()
      disco.startAdvertising(serviceC, Opt.some(own)).isOk()

    await disco.stopRegistrations()
    await disco.maintainRegistrations()

    let idC = "service-c".hashServiceId()
    let tasks = toSeq(disco.advertiser.running)
    let batched = tasks.filterIt(it.slots.len == 2)
    let alone = tasks.filterIt(it.slots.len == 1)
    check:
      tasks.len == 12
      batched.len == 6
      alone.len == 6
      batched.allIt(it.bucketOf(idC).isNone())
      alone.allIt(it.slots[0].serviceId == idC)
      batched.mapIt(it.registrar).toHashSet().len == 6
      alone.mapIt(it.registrar).toHashSet().len == 6

    await disco.stopRegistrations()

suite "Advertiser - batch split":
  teardown:
    checkTrackers()

  let ids = @["service-a", "service-b", "service-c"].mapIt(it.hashServiceId())

  proc batchTask(registrar: PeerId): AdvertiseTask =
    AdvertiseTask(
      registrar: registrar,
      slots: ids.mapIt(ServiceSlot(serviceId: it, bucketIdx: ids.find(it))),
    )

  proc addTables(disco: ServiceDiscovery, serviceIds: openArray[ServiceId]) =
    for id in serviceIds:
      doAssert disco.rtManager.addService(
        id, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
        Provided,
      )

  asyncTest "splitBatch keeps the key and restarts each other service alone":
    let disco = setupServiceDiscoveryNode()
    disco.addTables(ids)
    let registrar = PeerId.random()
    let task = batchTask(registrar)
    let before = Moment.now()

    disco.splitBatch(task, @[1'u8, 2, 3])

    let restarted = toSeq(disco.advertiser.running)
    check:
      task.slots == @[ServiceSlot(serviceId: ids[0], bucketIdx: 0)]
      restarted.len == ids.len - 1
      restarted.allIt(it.registrar == registrar and it.slots.len == 1)
      restarted.mapIt(it.slots[0]).toHashSet() ==
        toHashSet(
          [
            ServiceSlot(serviceId: ids[1], bucketIdx: 1),
            ServiceSlot(serviceId: ids[2], bucketIdx: 2),
          ]
        )
      disco.advertiser.singleRegistrars[registrar] >=
        before + disco.discoConfig.advertExpiry

    await disco.stopRegistrations()

  asyncTest "a batch that the registrar accepts in full is not split":
    let disco = setupServiceDiscoveryNode(
      discoConfig =
        ServiceDiscoveryConfig.new(safetyParam = 0.0, ipSimCoefficient = 0.0)
    )
    let selfId = disco.switch.peerInfo.peerId
    let services = @["service-a", "service-b", "service-c"].mapIt(makeServiceInfo(it))
    for id in ids:
      check disco.rtManager.addService(
        id, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
        Provided,
      )
    let task = batchTask(selfId)

    task.fut = disco.runTask(
      task, Opt.none(Ticket), sharedAdvert(services, disco.switch.peerInfo.privateKey)
    )

    checkUntilTimeout:
      ids.allIt(disco.countAdsInCache(it) == 1)
    check:
      task.slots.len == ids.len
      selfId notin disco.advertiser.singleRegistrars
      disco.advertiser.running.len == 0

    await task.fut.cancelAndWait()

  asyncTest "splitUnaccepted restarts only the ids the registrar left out":
    let disco = setupServiceDiscoveryNode()
    disco.addTables(ids)
    let registrar = PeerId.random()

    type Case = object
      name: string
      accepted: seq[ServiceId]
      kept: seq[ServiceId]
      restarted: seq[seq[ServiceId]]

    let cases = [
      Case(
        name: "subset",
        accepted: @[ids[0], ids[2]],
        kept: @[ids[0], ids[2]],
        restarted: @[@[ids[1]]],
      ),
      Case(name: "every id", accepted: ids, kept: ids, restarted: @[]),
      Case(name: "only foreign ids", accepted: @[makeServiceId(9)], kept: ids),
    ]

    for c in cases:
      checkpoint c.name
      let task = batchTask(registrar)

      disco.splitUnaccepted(task, c.accepted.mapIt(seq[byte](it)), @[1'u8, 2, 3])

      let restarted = toSeq(disco.advertiser.running)
      check:
        task.slots.mapIt(it.serviceId) == c.kept
        restarted.mapIt(it.slots.mapIt(it.serviceId)) == c.restarted
        registrar notin disco.advertiser.singleRegistrars
      await disco.stopRegistrations()

  proc selfDisco(maxBatchServices = Default_MaxBatchServices): ServiceDiscovery =
    setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(
        safetyParam = 0.0, ipSimCoefficient = 0.0, maxBatchServices = maxBatchServices
      )
    )

  let services = @["service-a", "service-b", "service-c"].mapIt(makeServiceInfo(it))

  asyncTest "a rejected batch retries each service alone":
    let disco = selfDisco(maxBatchServices = ids.len - 1)
    let selfId = disco.switch.peerInfo.peerId
    disco.addTables(ids)
    let task = batchTask(selfId)

    task.fut = disco.runTask(
      task, Opt.none(Ticket), sharedAdvert(services, disco.switch.peerInfo.privateKey)
    )

    checkUntilTimeout:
      ids.allIt(disco.countAdsInCache(it) == 1)
    check:
      task.slots.len == 1
      disco.advertiser.running.len == ids.len - 1
      selfId in disco.advertiser.singleRegistrars

    await task.fut.cancelAndWait()
    await disco.stopRegistrations()

  asyncTest "a slot without a routing table leaves the rest of the batch running":
    let disco = selfDisco()
    disco.addTables([ids[0], ids[2]])
    let task = batchTask(disco.switch.peerInfo.peerId)

    task.fut = disco.runTask(
      task, Opt.none(Ticket), sharedAdvert(services, disco.switch.peerInfo.privateKey)
    )

    checkUntilTimeout:
      disco.countAdsInCache(ids[0]) == 1 and disco.countAdsInCache(ids[2]) == 1
    check:
      task.slots.mapIt(it.serviceId) == @[ids[0], ids[2]]
      disco.countAdsInCache(ids[1]) == 0

    await task.fut.cancelAndWait()

  asyncTest "removing a service skips the rest of a batch whose advert is gone":
    let disco = setupServiceDiscoveryNode()
    let gate = newFuture[void]("test.batch.gate")
    let task = batchTask(PeerId.random())
    task.fut = gate
    disco.advertiser.running.incl(task)

    let taken = disco.takeServiceTasks(ids[0])

    check:
      taken == @[gate]
      disco.advertiser.running.len == 0

    await gate.cancelAndWait()

suite "Advertiser - batch staleness":
  teardown:
    checkTrackers()

  proc parked(): Future[void] {.async: (raises: [CancelledError]).} =
    await sleepAsync(1.hours)

  proc batchOfTwo(disco: ServiceDiscovery, registrar: PeerId): AdvertiseTask =
    ## A running two-service task whose registrar sits in bucket 0 of both tables.
    let idA = "service-a".hashServiceId()
    let idB = "service-b".hashServiceId()
    for id in [idA, idB]:
      doAssert disco.rtManager.addService(
        id, disco.rtable, disco.config.replication, disco.discoConfig.bucketsCount,
        Interest,
      )
      disco.rtManager.getTable(id).get().buckets =
        @[Bucket(peers: @[registrar.toKey()])]
    let task = AdvertiseTask(
      registrar: registrar,
      slots: @[
        ServiceSlot(serviceId: idA, bucketIdx: 0),
        ServiceSlot(serviceId: idB, bucketIdx: 0),
      ],
    )
    task.fut = parked()
    disco.advertiser.running.incl(task)
    task

  asyncTest "a registrar that left only one bucket of the batch loses the whole task":
    let disco = setupServiceDiscoveryNode()
    let registrar = PeerId.random()
    let task = disco.batchOfTwo(registrar)
    let tableB = disco.rtManager.getTable("service-b".hashServiceId()).get()
    tableB.buckets[0].peers = @[PeerId.random().toKey()]

    await disco.maintainRegistrations()

    await task.fut.join()
    check:
      task notin disco.advertiser.running
      task.fut.cancelled()

  asyncTest "a registrar that stays in every bucket of the batch keeps its task":
    let disco = setupServiceDiscoveryNode()
    let registrar = PeerId.random()
    let task = disco.batchOfTwo(registrar)

    await disco.maintainRegistrations()

    check:
      task in disco.advertiser.running
      not task.fut.finished()

    await disco.stopRegistrations()

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
    await stepsAsync(1) # let the pending cancellation run

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
