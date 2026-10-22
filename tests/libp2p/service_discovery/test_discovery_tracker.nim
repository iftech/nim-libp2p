# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results, strutils, stew/byteutils
import
  ../../../libp2p/[
    peerid,
    protocols/service_discovery,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/discovery_tracker,
    protocols/service_discovery/types,
  ]
import ../../tools/unittest
import ./utils

suite "Discovery tracker":
  teardown:
    checkTrackers()

  test "records nothing without a registered interest":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()
    let ad = makeAdvertisement(service)

    discard disco.registerAd(serviceId, ad)

    check disco.tracker.discoveries(serviceId).len == 0

  test "records the first provider with rank 1":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()
    let ad = makeAdvertisement(service)

    check disco.registerInterest(service)
    discard disco.registerAd(serviceId, ad)

    let found = disco.tracker.discoveries(serviceId)
    check found.len == 1
    check found[0].provider == ad.data.peerId
    check found[0].rank == 1
    check found[0].source == FromRegistration

  test "records the provider of a registration that gets a Wait reply":
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(
        advertExpiry = 100.secs, safetyParam = 1.0, advertCacheCap = 10
      )
    )
    let service = "svc"
    let serviceId = service.hashServiceId()
    let ad = makeAdvertisement(service)
    disco.registrar.ads.seedOccupancy(10)

    check disco.registerInterest(service)
    let reply = disco.registerAd(serviceId, ad)

    check reply.status.get() == RegistrationStatus.Wait
    check disco.tracker.discoveries(serviceId).len == 1

  test "records the same provider once":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()
    let ad = makeAdvertisement(service)

    check disco.registerInterest(service)
    discard disco.registerAd(serviceId, ad)
    discard disco.registerAd(serviceId, ad)

    check disco.tracker.discoveries(serviceId).len == 1

  test "ranks providers in discovery order":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()
    let ad1 = makeAdvertisement(service)
    let ad2 = makeAdvertisement(service)

    check disco.registerInterest(service)
    discard disco.registerAd(serviceId, ad1)
    discard disco.registerAd(serviceId, ad2)

    let found = disco.tracker.discoveries(serviceId)
    check found.len == 2
    check found[0].provider == ad1.data.peerId
    check found[1].provider == ad2.data.peerId
    check found[0].rank == 1
    check found[1].rank == 2
    check found[0].elapsed <= found[1].elapsed

  test "measures the time since the interest started":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()
    let ad = makeAdvertisement(service)

    check disco.registerInterest(service)
    let startedAt = disco.tracker.startedAt(serviceId)
    check startedAt.isSome()

    discard disco.registerAd(serviceId, ad)

    let found = disco.tracker.discoveries(serviceId)
    check found.len == 1
    check found[0].elapsed <= Moment.now() - startedAt.get()

  test "skips the node itself":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()

    check disco.registerInterest(service)
    disco.tracker.recordProvider(serviceId, disco.switch.peerInfo.peerId, FromLookup)

    check disco.tracker.discoveries(serviceId).len == 0

  test "stops recording at the provider cap":
    let tracker = DiscoveryTracker.new(PeerId.random(), maxProviders = 2)
    let serviceId = makeServiceId()

    tracker.startInterest(serviceId)
    for i in 0 ..< 5:
      tracker.recordProvider(serviceId, PeerId.random(), FromLookup)

    check tracker.discoveries(serviceId).len == 2

  test "clear drops every interest":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()

    check disco.registerInterest(service)
    discard disco.registerAd(serviceId, makeAdvertisement(service))
    disco.tracker.clear()

    check disco.tracker.discoveries(serviceId).len == 0
    check disco.tracker.startedAt(serviceId).isNone()

  test "keeps services independent":
    let disco = setupServiceDiscoveryNode()
    let s1 = "svc-1"
    let s2 = "svc-2"
    let ad = makeAdvertisement(s1)

    check disco.registerInterest(s1)
    check disco.registerInterest(s2)
    discard disco.registerAd(s1.hashServiceId(), ad)

    check disco.discoveries(s1).len == 1
    check disco.discoveries(s2).len == 0

  test "stops recording after unregisterInterest":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()

    check disco.registerInterest(service)
    discard disco.registerAd(serviceId, makeAdvertisement(service))
    disco.unregisterInterest(service)
    discard disco.registerAd(serviceId, makeAdvertisement(service))

    check disco.tracker.discoveries(serviceId).len == 1

  test "restarts the measurement on a new interest":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()

    check disco.registerInterest(service)
    discard disco.registerAd(serviceId, makeAdvertisement(service))
    disco.unregisterInterest(service)
    check disco.registerInterest(service)

    check disco.tracker.discoveries(serviceId).len == 0

    discard disco.registerAd(serviceId, makeAdvertisement(service))
    check disco.tracker.discoveries(serviceId)[0].rank == 1

  asyncTest "lookup starts the interest":
    let disco = setupServiceDiscoveryNode()
    let serviceId = makeServiceId()

    check disco.tracker.startedAt(serviceId).isNone()

    discard await disco.lookup(serviceId)

    check disco.tracker.startedAt(serviceId).isSome()

  test "keeps the start time of a running interest":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()

    check disco.registerInterest(service)
    let startedAt = disco.tracker.startedAt(serviceId).get()
    discard disco.registerInterest(service)

    check disco.tracker.startedAt(serviceId).get() == startedAt

  test "dumps raw rows as csv":
    let disco = setupServiceDiscoveryNode()
    let service = "svc"
    let serviceId = service.hashServiceId()
    let ad = makeAdvertisement(service)

    check disco.registerInterest(service)
    discard disco.registerAd(serviceId, ad)

    let rows = disco.tracker.toCsv().splitLines()
    check rows.len == 2
    check rows[0] == "service_id,provider,rank,elapsed_ms,source"
    check rows[1].startsWith(
      serviceId.toBytes().toHex() & "," & $ad.data.peerId & ",1,"
    )
    check rows[1].endsWith(",FromRegistration")
