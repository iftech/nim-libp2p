# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import algorithm, chronos, results, sets, sequtils, tables, stew/byteutils
import
  ../../../libp2p/[protocols/kademlia, switch, builders, multicodec, multihash, cid]
import ../../tools/[lifecycle, topology, unittest, multiaddress]
import ./[mock_kademlia, utils]

proc isAtMaxCapacity(providerRecords: ProviderRecords): bool =
  providerRecords.len == providerRecords.capacity

proc isAtMaxCapacity(providedKeys: ProvidedKeys): bool =
  providedKeys.len == providedKeys.capacity

proc setupOptimisticHub(): seq[KadDHT] =
  var cfg = testKadConfig(replication = 2, beta = 1)
  cfg.optimisticProvide = true
  (0 ..< 6).mapIt(setupKad(cfg))

proc holdsProviderRecord(kad: KadDHT): bool =
  kad.providerManager.providerRecords.len == 1

proc mineKeyWithTwoReceiversWithin(
    receivers: seq[KadDHT], maxDistance: float64, hasher: Opt[XorDHasher]
): (Key, seq[KadDHT]) =
  ## Two receivers share the top bit, so a key with both in range exists.
  for _ in 0 ..< 10000:
    let key = randomServiceId()
    let closest = receivers
      .mapIt((normedDistance(xorDistance(it.switch.peerInfo.peerId, key, hasher)), it))
      .sortedByIt(it[0])
    if closest[1][0] < maxDistance:
      return (key, closest[0 .. 1].mapIt(it[1]))
  raiseAssert "no key puts two receivers within " & $maxDistance

suite "KadDHT - Add Provider":
  teardown:
    checkTrackers()

  asyncTest "Add provider":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId

    # ensure providermanager is empty
    check kads[0].providerManager.providerRecords.len == 0

    await kads[1].addProvider(key.toCid())

    # kads[0] has kads[1] in its providermanager after adding provider
    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 1
      kads[0].providerManager.providerRecords[0].provider.id.get() ==
        kads[1].rtable.selfId

  asyncTest "Provider expired":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let
      key1 = kads[0].rtable.selfId
      key2 = kads[1].rtable.selfId

    # ensure providermanager is empty
    check kads[0].providerManager.providerRecords.len == 0

    await kads[1].addProvider(key1.toCid())
    await kads[1].addProvider(key2.toCid())

    # provider records added
    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 2

    # provider records expired and evicted after expiration time
    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 0

  asyncTest "Adding providers again refreshes expiration time":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let
      key1 = kads[0].rtable.selfId
      key2 = kads[1].rtable.selfId

    # ensure providermanager is empty
    check kads[0].providerManager.providerRecords.len == 0

    await kads[1].addProvider(key1.toCid())
    await kads[1].addProvider(key2.toCid())

    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 2

    let
      originalExpiresAt1 = kads[0].providerManager.providerRecords[0].expiresAt
      originalExpiresAt2 = kads[0].providerManager.providerRecords[1].expiresAt

    # refresh providers
    await kads[1].addProvider(key1.toCid())
    await kads[1].addProvider(key2.toCid())

    checkUntilTimeout:
      kads[0].providerManager.providerRecords[0].expiresAt > originalExpiresAt1
      kads[0].providerManager.providerRecords[1].expiresAt > originalExpiresAt2

  asyncTest "Start/stop providing":
    let kads = setupKadSwitches(2, republishProvidedKeysInterval = 2.secs)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let
      key1 = kads[0].rtable.selfId
      key2 = kads[1].rtable.selfId

    # key1 is provided with startProviding
    # key2 is manually sent once with addProvider
    await kads[0].startProviding(key1.toCid())
    await kads[0].addProvider(key2.toCid())

    checkUntilTimeout:
      kads[1].providerManager.providerRecords.len == 2
      kads[1].providerManager.knownKeys.len == 2
      kads[0].providerManager.providedKeys.len == 1

    # after the expiration time only key2 expired
    checkUntilTimeout:
      kads[1].providerManager.providerRecords.len == 1
      kads[1].providerManager.knownKeys.len == 1
      kads[0].providerManager.providedKeys.len == 1

    # stop providing key
    kads[0].stopProviding(key1.toCid())

    checkUntilTimeout:
      kads[1].providerManager.providerRecords.len == 0
      kads[1].providerManager.knownKeys.len == 0
      kads[0].providerManager.providedKeys.len == 0

  asyncTest "Refreshing a provided key at capacity preserves other keys":
    let kad = setupKad()
    startAndDeferStop(@[kad])
    let keys = kad.providerManager.providedKeys
    keys.capacity = 2
    let first = Cid
      .init(CIDv1, multiCodec("raw"), MultiHash.digest("sha2-256", @[1.byte]).get())
      .get()
    let second = Cid
      .init(CIDv1, multiCodec("raw"), MultiHash.digest("sha2-256", @[2.byte]).get())
      .get()
    keys.provided[first.toKey()] = Moment.now() - 2.seconds
    keys.provided[second.toKey()] = Moment.now() - 1.seconds

    await kad.startProviding(second)

    check:
      keys.len == 2
      keys.hasKey(first.toKey())
      keys.hasKey(second.toKey())

  asyncTest "Provider limits":
    let kads = setupKadSwitches(2, republishProvidedKeysInterval = chronos.hours(1))
    startAndDeferStop(kads)

    await connectStar(kads)

    let
      key1 = kads[0].rtable.selfId
      cid1 = key1.toCid()
      key2 = kads[1].rtable.selfId
      cid2 = key2.toCid()
      mhash3 = MultiHash.digest("sha2-256", @[1.byte, 2, 3]).get()
      cid3 = Cid.init(CIDv1, multiCodec("raw"), mhash3).get()

    kads[0].providerManager.providedKeys.capacity = 2 # max keys node can store
    kads[1].providerManager.providerRecords.capacity = 1
      # max provider records node stores from others

    await kads[0].startProviding(cid1)

    checkUntilTimeout:
      kads[0].providerManager.providedKeys.hasKey(cid1.toKey())
      kads[0].providerManager.providedKeys.len == 1
      kads[1].providerManager.knownKeys.hasKey(cid1.toKey())
      kads[1].providerManager.providerRecords.isAtMaxCapacity()

    await kads[0].startProviding(cid2)

    checkUntilTimeout:
      # kads[0] (sender): capacity=2, so both cid1 and cid2 fit
      kads[0].providerManager.providedKeys.hasKey(cid1.toKey())
      kads[0].providerManager.providedKeys.hasKey(cid2.toKey())
      kads[0].providerManager.providedKeys.isAtMaxCapacity()
      # kads[1] (receiver): capacity=1, cid1 evicted, only cid2 remains
      not kads[1].providerManager.knownKeys.hasKey(cid1.toKey())
      kads[1].providerManager.knownKeys.hasKey(cid2.toKey())
      kads[1].providerManager.providerRecords.isAtMaxCapacity()

    await kads[0].startProviding(cid3)

    checkUntilTimeout:
      # kads[0] (sender): cid1 (oldest) evicted, cid2 and cid3 remain
      not kads[0].providerManager.providedKeys.hasKey(cid1.toKey())
      kads[0].providerManager.providedKeys.hasKey(cid2.toKey())
      kads[0].providerManager.providedKeys.hasKey(cid3.toKey())
      kads[0].providerManager.providedKeys.isAtMaxCapacity()
      # kads[1] (receiver): capacity=1, cid2 evicted, only cid3 remains
      not kads[1].providerManager.knownKeys.hasKey(cid1.toKey())
      not kads[1].providerManager.knownKeys.hasKey(cid2.toKey())
      kads[1].providerManager.knownKeys.hasKey(cid3.toKey())
      kads[1].providerManager.providerRecords.isAtMaxCapacity()

  asyncTest "Add provider accepts matching PeerID and rejects mismatched PeerID":
    # Setup sender and imposter KadDHT instances
    let kads = setupKadSwitches(2)

    let
      senderKad = kads[0]
      imposterKad = kads[1]

    # Setup receiver
    var receiverKad = setupMockKad()

    startAndDeferStop(kads & receiverKad)

    await connect(senderKad, receiverKad)

    let
      targetKey = senderKad.rtable.selfId
      imposterPeer = imposterKad.switch.peerInfo.toPeer() # Invalid: doesn't match sender

    check receiverKad.providerManager.providerRecords.len == 0

    # Inject a custom message with an imposter peer
    receiverKad.handleAddProviderMessage = Opt.some(
      Message(
        msgType: MessageType.addProvider, key: targetKey, providerPeers: @[imposterPeer]
      )
    )
    await senderKad.addProvider(targetKey.toCid())

    # Verify imposter provider was filtered out
    await sleepAsync(200.milliseconds)
    check receiverKad.providerManager.providerRecords.len == 0

    # Verify valid provider is stored
    receiverKad.handleAddProviderMessage = Opt.none(Message)
    await senderKad.addProvider(targetKey.toCid())

    checkUntilTimeout:
      receiverKad.providerManager.providerRecords.len == 1
      receiverKad.providerManager.providerRecords[0].provider.id.get() ==
        senderKad.switch.peerInfo.peerId.getBytes()

  asyncTest "Add provider accepts a non-multihash key within length bound":
    # Interop parity: go/js/py/dotnet advertise raw, non-multihash provider keys
    let kads = setupKadSwitches(1)
    let senderKad = kads[0]
    var receiverKad = setupMockKad()

    startAndDeferStop(kads & receiverKad)

    await connect(senderKad, receiverKad)

    check receiverKad.providerManager.providerRecords.len == 0

    let keyBytes = "interop-test-key-0123".toBytes()
    check not MultiHash.validate(keyBytes) # sanity: not a valid multihash

    receiverKad.handleAddProviderMessage = Opt.some(
      Message(
        msgType: MessageType.addProvider,
        key: Key.fromBytes(keyBytes),
        providerPeers: @[senderKad.switch.peerInfo.toPeer()],
      )
    )
    await senderKad.addProvider(senderKad.rtable.selfId.toCid())

    checkUntilTimeout:
      receiverKad.providerManager.providerRecords.len == 1
      receiverKad.providerManager.knownKeys.hasKey(Key.fromBytes(keyBytes))

  asyncTest "Add provider rejects an empty key":
    let kads = setupKadSwitches(1)
    let senderKad = kads[0]
    var receiverKad = setupMockKad()

    startAndDeferStop(kads & receiverKad)

    await connect(senderKad, receiverKad)

    receiverKad.handleAddProviderMessage = Opt.some(
      Message(
        msgType: MessageType.addProvider,
        key: Key.fromBytes(newSeq[byte](0)),
        providerPeers: @[senderKad.switch.peerInfo.toPeer()],
      )
    )
    await senderKad.addProvider(senderKad.rtable.selfId.toCid())

    # Empty key is out of bounds, record must not be stored
    await sleepAsync(200.milliseconds) # sleep needed for negative assertion
    check receiverKad.providerManager.providerRecords.len == 0

  asyncTest "Add provider rejects a key exceeding the length bound":
    let kads = setupKadSwitches(1)
    let senderKad = kads[0]
    var receiverKad = setupMockKad()

    startAndDeferStop(kads & receiverKad)

    await connect(senderKad, receiverKad)

    receiverKad.handleAddProviderMessage = Opt.some(
      Message(
        msgType: MessageType.addProvider,
        key: Key.fromBytes(newSeq[byte](MaxProviderKeyLen + 1)),
        providerPeers: @[senderKad.switch.peerInfo.toPeer()],
      )
    )
    await senderKad.addProvider(senderKad.rtable.selfId.toCid())

    # Over-size key is out of bounds, record must not be stored
    await sleepAsync(200.milliseconds) # sleep needed for negative assertion
    check receiverKad.providerManager.providerRecords.len == 0

  asyncTest "Add provider with CID key extracts multihash":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    # Create a multihash and two CIDs with same multihash but different codecs
    let
      testData = @[1.byte, 2, 3, 4, 5]
      mhash = MultiHash.digest("sha2-256", testData).get()
      cidDagPb = Cid.init(CIDv1, multiCodec("dag-pb"), mhash).get()
      cidRaw = Cid.init(CIDv1, multiCodec("raw"), mhash).get()
      expectedKey = mhash.toKey()

    check:
      cidDagPb.data.buffer != cidRaw.data.buffer # Different CID bytes
      cidDagPb.toKey() == cidRaw.toKey() # Same extracted key
      cidDagPb.toKey() == expectedKey

    check kads[0].providerManager.providerRecords.len == 0

    # Add provider using CIDv1 dag-pb
    await kads[1].addProvider(cidDagPb)

    # Provider record should be stored with multihash as key
    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 1
      kads[0].providerManager.providerRecords[0].key == expectedKey
      kads[0].providerManager.providerRecords[0].provider.id.get() ==
        kads[1].rtable.selfId

    let originalExpiresAt = kads[0].providerManager.providerRecords[0].expiresAt

    # Add provider using CIDv1 raw with same multihash - should update same key
    await kads[1].addProvider(cidRaw)

    # Should still have one record (same key) with refreshed expiration
    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 1
      kads[0].providerManager.providerRecords[0].key == expectedKey
      kads[0].providerManager.providerRecords[0].expiresAt > originalExpiresAt

  asyncTest "Multiple providers for same CID":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    # kads[0] is receiver, kads[1] and kads[2] are providers
    await connectHub(kads[0], kads[1 ..^ 1])

    let targetCid = kads[0].rtable.selfId.toCid()

    check kads[0].providerManager.providerRecords.len == 0

    # First provider announces
    await kads[1].addProvider(targetCid)

    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 1

    # Second provider announces same CID
    await kads[2].addProvider(targetCid)

    # Both providers should be stored
    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 2

    let providers = kads[0].providerManager.knownKeys[targetCid.toKey()]
    check:
      providers.len == 2
      kads[1].rtable.selfId in providers.mapIt(it.id.get())
      kads[2].rtable.selfId in providers.mapIt(it.id.get())

  asyncTest "Provider address storage policy - addresses may be omitted":
    let kads = setupKadSwitches(1)
    let senderKad = kads[0]
    var receiverKad = setupMockKad()

    startAndDeferStop(kads & receiverKad)

    await connect(senderKad, receiverKad)

    check receiverKad.providerManager.providerRecords.len == 0

    # Inject message with provider that has no addresses
    let
      targetKey = senderKad.rtable.selfId
      # Provider with empty addresses
      providerWithNoAddrs = Peer(
        id: senderKad.switch.peerInfo.peerId.getBytes(),
        addrs: @[],
        connection: ConnectionStatus.connected,
      )
    receiverKad.handleAddProviderMessage = Opt.some(
      Message(
        msgType: MessageType.addProvider,
        key: targetKey,
        providerPeers: @[providerWithNoAddrs],
      )
    )
    await senderKad.addProvider(targetKey.toCid())

    # Provider should be stored even without addresses
    checkUntilTimeout:
      receiverKad.providerManager.providerRecords.len == 1
      receiverKad.providerManager.providerRecords[0].provider.id.get() ==
        senderKad.switch.peerInfo.peerId.getBytes()
      receiverKad.providerManager.providerRecords[0].provider.addrs.len == 0

  asyncTest "Add provider includes local multiaddresses":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId

    # Inject additional multiaddresses to verify all are included
    kads[1].switch.peerInfo.addrs.add(ma("/ip4/192.168.1.100/tcp/4001"))
    kads[1].switch.peerInfo.addrs.add(ma("/ip6/::1/tcp/4001"))

    check kads[0].providerManager.providerRecords.len == 0

    await kads[1].addProvider(key.toCid())

    # Verify provider record includes sender's multiaddresses
    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 1

    let storedProvider = kads[0].providerManager.providerRecords[0].provider
    check:
      storedProvider.id.get() == kads[1].rtable.selfId
      storedProvider.addrs == kads[1].switch.peerInfo.addrs

  asyncTest "Add provider completes when some peers fail":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    # Setup: kads[0] is sender, kads[1] and kads[2] are potential receivers
    await connectHub(kads[0], kads[1 ..^ 1])

    let key = kads[0].rtable.selfId

    # Stop one receiver to simulate failure
    await kads[2].switch.stop()

    # Add provider should complete despite one peer failing
    await kads[0].addProvider(key.toCid())

    # Verify provider was stored at the successful receiver
    checkUntilTimeout:
      kads[1].providerManager.providerRecords.len == 1
      kads[1].providerManager.providerRecords[0].provider.id.get() ==
        kads[0].rtable.selfId

  template optimisticProvideStores(seedEstimate: bool) =
    ## Without a seeded estimate `addProvider` takes the classic path, with one
    ## the optimistic path. Both must store the record.
    var cfg = testKadConfig()
    cfg.optimisticProvide = true
    let kads = @[setupKad(cfg), setupKad(cfg)]
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    if seedEstimate:
      kads[1].nsEstimator.seedLinearMeasurements(1000)
    check kads[1].nsEstimator.networkSize().isOk() == seedEstimate

    await kads[1].addProvider(kads[0].rtable.selfId.toCid())

    checkUntilTimeout:
      kads[0].providerManager.providerRecords.len == 1
      kads[0].providerManager.providerRecords[0].provider.id.get() ==
        kads[1].rtable.selfId

  asyncTest "Optimistic provider RPCs belong to the DHT before the lookup returns":
    var cfg = testKadConfig(timeout = 3.seconds, providerRejection = true)
    cfg.optimisticProvide = true
    let sender = setupKad(cfg)
    let receiver = setupMockKad(cfg)
    receiver.handleAddProviderDelay = 1.seconds
    startAndDeferStop(@[sender, KadDHT(receiver)])
    await connect(sender, receiver)
    sender.nsEstimator.seedLinearMeasurements(1000)

    let pending = sender.addProvider(receiver.rtable.selfId.toCid())
    checkUntilTimeout:
      receiver.handleAddProviderCalls > 0
    check not pending.finished()
    let owned = sender.provideTasks
    check owned.len > 0
    await sender.stop()
    await pending.wait(receiver.handleAddProviderDelay * 2)
    check owned.allIt(it.finished())

  asyncTest "Optimistic provide falls back to classic without a size estimate":
    optimisticProvideStores(seedEstimate = false)

  asyncTest "Optimistic provide stores records once the estimator has data":
    optimisticProvideStores(seedEstimate = true)

  asyncTest "Optimistic provide stops once k close peers are scheduled":
    let kads = setupOptimisticHub()
    startAndDeferStop(kads)
    await connectHub(kads[0], kads[1 ..^ 1])

    kads[0].nsEstimator.seedLinearMeasurements(1)
    let netSize = kads[0].nsEstimator.networkSize().expect("seeded estimate")
    let k = float64(kads[0].config.replication)
    let threshold = gammaIncRegInv(k, 0.1) / float64(netSize)

    # Full buckets reject receivers, and the walk only reaches the hub's table.
    let known =
      kads[1 ..^ 1].filterIt(kads[0].hasKey(it.switch.peerInfo.peerId.toKey()))

    let (key, receivers) =
      known.mineKeyWithTwoReceiversWithin(threshold * 0.9, kads[0].rtable.config.hasher)

    await kads[0].addProvider(key)

    checkUntilTimeout:
      receivers[0].holdsProviderRecord()
      receivers[1].holdsProviderRecord()

  asyncTest "Optimistic provide falls back to the mean distance of the k closest":
    let kads = setupOptimisticHub()
    startAndDeferStop(kads)
    await connectHub(kads[0], kads[1 ..^ 1])

    # A large network puts every receiver outside the individual threshold.
    kads[0].nsEstimator.seedLinearMeasurements(1000)

    await kads[0].addProvider(randomServiceId())

    checkUntilTimeout:
      kads[1 ..^ 1].countIt(it.holdsProviderRecord()) == 2

suite "KadDHT - Republish By Keyspace Region":
  teardown:
    checkTrackers()

  proc provideWithoutAnnouncing(kad: KadDHT, count: int): seq[Key] =
    ## Seed the store directly, so only the republish loop advertises the keys.
    let keys = Key.makeKeys(count)
    for key in keys:
      kad.providerManager.providedKeys.provided[key] = Moment.now()
    keys

  asyncTest "Provided keys are grouped into keyspace regions":
    let kad = setupKad(testKadConfig(republishRegionBits = Opt.some(1)))
    startAndDeferStop(@[kad])

    let keys = kad.provideWithoutAnnouncing(8)
    let regions = kad.providedKeyRegions()
    let hasher = kad.rtable.config.hasher

    check:
      regions.len < keys.len
      # 1 prefix bit splits the keyspace in two, so the keys land in 2 regions at most.
      regions.len <= 2
      regions.concat().toHashSet() == keys.toHashSet()

    for region in regions:
      check region.allIt(
        RegionPrefix.init(it, 1, hasher) == RegionPrefix.init(region[0], 1, hasher)
      )

  asyncTest "Each key gets its own region while the network size is unknown":
    let kad = setupKad()
    startAndDeferStop(@[kad])

    check kad.rtable.regionBits().isNone()

    let keys = kad.provideWithoutAnnouncing(4)
    let regions = kad.providedKeyRegions()

    check:
      regions.len == keys.len
      regions.concat().toHashSet() == keys.toHashSet()

  asyncTest "A single region walk advertises every key it holds":
    let senderKad = setupKad(
      testKadConfig(
        republishRegionBits = Opt.some(0), providerExpirationInterval = 30.seconds
      )
    )
    let receiverKad = setupKad(testKadConfig(providerExpirationInterval = 30.seconds))

    startAndDeferStop(@[senderKad, receiverKad])
    await connect(senderKad, receiverKad)

    let keys = senderKad.provideWithoutAnnouncing(5)
    check senderKad.providedKeyRegions().len == 1

    checkUntilTimeout:
      receiverKad.providerManager.knownKeys.len == keys.len
      keys.allIt(receiverKad.providerManager.knownKeys.hasKey(it))

suite "KadDHT - ADD_PROVIDER Rejection":
  teardown:
    checkTrackers()

  asyncTest "Receiver rejects ADD_PROVIDER when per-key limit reached":
    # kads[0] is sender, kads[1] is receiver with maxProvidersPerKey = 1
    let senderKad = setupKad(testKadConfig(providerRejection = true))
    var receiverConfig = testKadConfig(providerRejection = true)
    receiverConfig.limits.maxProvidersPerKey = Opt.some(1)
    let receiverKad = setupKad(receiverConfig)

    startAndDeferStop(@[senderKad, receiverKad])

    await connect(senderKad, receiverKad)

    let key = senderKad.rtable.selfId
    check receiverKad.providerManager.providerRecords.len == 0

    # First ADD_PROVIDER: receiver has 0 providers for key → accepted
    await senderKad.addProvider(key.toCid())
    checkUntilTimeout:
      receiverKad.providerManager.providerRecords.len == 1

    # Now add a second sender and have it try to advertise the same key
    let sender2Kad = setupKad(testKadConfig(providerRejection = true))
    startAndDeferStop(@[sender2Kad])
    await connect(sender2Kad, receiverKad)

    # Receiver already has 1 provider for key (= maxProvidersPerKey) → reject
    let cidKey = key.toCid().toKey()
    let status = await sender2Kad.sendAddProviderAndGetStatus(receiverKad, cidKey)
    check status
    check status.value() == AddProviderStatus.rejected

  asyncTest "Existing provider refresh is allowed even at per-key limit":
    # The same provider re-advertising updates the expiry rather than adding new entries.
    # Since addProviderRecord removes then re-adds the same record, the count stays the same
    # so a re-advertisement is not blocked by the per-key limit check.
    let senderKad = setupKad(testKadConfig(providerRejection = true))
    var receiverConfig = testKadConfig(providerRejection = true)
    receiverConfig.limits.maxProvidersPerKey = Opt.some(1)
    let receiverKad = setupKad(receiverConfig)

    startAndDeferStop(@[senderKad, receiverKad])
    await connect(senderKad, receiverKad)

    let key = senderKad.rtable.selfId
    await senderKad.addProvider(key.toCid())
    checkUntilTimeout:
      receiverKad.providerManager.providerRecords.len == 1

    let originalExpiry = receiverKad.providerManager.providerRecords[0].expiresAt

    # Ensure the clock advances so the refreshed expiresAt is strictly greater
    await sleepAsync(10.milliseconds)
    # Same sender re-advertises; knownKeys count stays ≤ maxProvidersPerKey
    await senderKad.addProvider(key.toCid())
    checkUntilTimeout:
      receiverKad.providerManager.providerRecords[0].expiresAt > originalExpiry

  asyncTest "Spillover: stores at farther node when closest node is full":
    # Topology: sender → close (full for key) and far (empty).
    # closeKad is pre-populated with a record so it will reject.
    # senderKad should then store the record at farKad (spillover).
    let senderKad = setupKad(testKadConfig(providerRejection = true))

    var closeConfig = testKadConfig(providerRejection = true)
    closeConfig.limits.maxProvidersPerKey = Opt.some(1)
    let closeKad = setupKad(closeConfig)

    let farKad = setupKad(testKadConfig(providerRejection = true))

    startAndDeferStop(@[senderKad, closeKad, farKad])

    # Connect sender to both close and far
    await connect(senderKad, closeKad)
    await connect(senderKad, farKad)

    let key = senderKad.rtable.selfId

    # Directly inject a record into closeKad to trigger rejection without
    # involving an extra sender (which would also discover and fill farKad).
    let existingPeer = Peer(id: randomPeerId().getBytes())
    closeKad.providerManager.knownKeys[key] = initHashSet[Provider]()
    closeKad.providerManager.knownKeys[key].incl(existingPeer)
    closeKad.providerManager.providerRecords.push(
      ProviderRecord(
        provider: existingPeer, expiresAt: Moment.now() + 1.hours, key: key
      )
    )
    check closeKad.providerManager.providerRecords.len == 1
    check farKad.providerManager.providerRecords.len == 0

    # senderKad advertises; closeKad rejects (maxProvidersPerKey=1, already full),
    # so senderKad spills over to farKad which accepts.
    await senderKad.addProvider(key.toCid())

    checkUntilTimeout:
      farKad.providerManager.providerRecords.len == 1
      farKad.providerManager.providerRecords[0].provider.id.get() ==
        senderKad.switch.peerInfo.peerId.getBytes()

  asyncTest "Normal replication still works when all nodes accept":
    # With unlimited capacity both discovered peers get the record via normal replication.
    let senderKad = setupKad(testKadConfig(providerRejection = true))
    let nodeA = setupKad(testKadConfig(providerRejection = true))
    let nodeB = setupKad(testKadConfig(providerRejection = true))

    startAndDeferStop(@[senderKad, nodeA, nodeB])

    await connect(senderKad, nodeA)
    await connect(senderKad, nodeB)

    let key = senderKad.rtable.selfId

    check nodeA.providerManager.providerRecords.len == 0
    check nodeB.providerManager.providerRecords.len == 0

    await senderKad.addProvider(key.toCid())

    checkUntilTimeout:
      nodeA.providerManager.providerRecords.len == 1
      nodeB.providerManager.providerRecords.len == 1

  asyncTest "providerRejection=false: receiver enforces limit silently":
    # The receiver enforces ``maxProvidersPerKey`` even with rejection disabled,
    # but it does not send a rejection reply, so the sender treats the absence
    # of a reply as accepted.
    let senderKad = setupKad(
      testKadConfig(providerRejection = true, providerExpirationInterval = 30.seconds)
    )
    var receiverConfig =
      testKadConfig(providerRejection = false, providerExpirationInterval = 30.seconds)
    receiverConfig.limits.maxProvidersPerKey = Opt.some(1)
    let receiverKad = setupKad(receiverConfig)

    startAndDeferStop(@[senderKad, receiverKad])
    await connect(senderKad, receiverKad)

    let key = senderKad.rtable.selfId
    await senderKad.addProvider(key.toCid())
    checkUntilTimeout:
      receiverKad.providerManager.providerRecords.len == 1

    # Second sender: receiver is at the per-key cap and drops the record
    # silently (no reply).
    let sender2Kad = setupKad(
      testKadConfig(providerRejection = true, providerExpirationInterval = 30.seconds)
    )
    startAndDeferStop(@[sender2Kad])
    await connect(sender2Kad, receiverKad)

    let status =
      await sender2Kad.sendAddProviderAndGetStatus(receiverKad, key.toCid().toKey())
    check status
    # No reply sent by receiver → sender treats absence of reply as accepted
    check status.value() == AddProviderStatus.accepted
    # Limit enforced silently: still only one record at the receiver.
    # sendAddProviderAndGetStatus already waited for the reply timeout, so the
    # receiver has finished processing by the time we reach this check.
    check receiverKad.providerManager.providerRecords.len == 1

  asyncTest "providerRejection=true: receiver enforces limit and rejects":
    let senderKad = setupKad(testKadConfig(providerRejection = true))
    var receiverConfig = testKadConfig(providerRejection = true)
    receiverConfig.limits.maxProvidersPerKey = Opt.some(1)
    let receiverKad = setupKad(receiverConfig)

    startAndDeferStop(@[senderKad, receiverKad])
    await connect(senderKad, receiverKad)

    let key = senderKad.rtable.selfId
    await senderKad.addProvider(key.toCid())
    checkUntilTimeout:
      receiverKad.providerManager.providerRecords.len == 1

    let sender2Kad = setupKad(testKadConfig(providerRejection = true))
    startAndDeferStop(@[sender2Kad])
    await connect(sender2Kad, receiverKad)

    let status =
      await sender2Kad.sendAddProviderAndGetStatus(receiverKad, key.toCid().toKey())
    check status
    check status.value() == AddProviderStatus.rejected
    # Limit enforced: still only one record
    check receiverKad.providerManager.providerRecords.len == 1

  asyncTest "mixed: sender without rejection ignores reply from rejection-enabled receiver":
    # Sender has providerRejection=false so it never reads replies.
    # Receiver has providerRejection=true and sends rejection replies.
    # The sender stores the key and moves on regardless.
    let senderKad = setupKad(testKadConfig(providerRejection = false))
    var receiverConfig = testKadConfig(providerRejection = true)
    receiverConfig.limits.maxProvidersPerKey = Opt.some(1)
    let receiverKad = setupKad(receiverConfig)

    startAndDeferStop(@[senderKad, receiverKad])
    await connect(senderKad, receiverKad)

    let key = senderKad.rtable.selfId
    # addProvider(key.toCid()) sends msg.key = key.toCid().toKey(), which differs
    # from key for identity-multihash peer IDs (ed25519). Pre-fill must use the
    # same key that will appear in the ADD_PROVIDER message so the rejection check
    # finds the existing record.
    let msgKey = key.toCid().toKey()
    let existingPeer = Peer(id: randomPeerId().getBytes())
    receiverKad.providerManager.knownKeys[msgKey] = initHashSet[Provider]()
    receiverKad.providerManager.knownKeys[msgKey].incl(existingPeer)
    receiverKad.providerManager.providerRecords.push(
      ProviderRecord(
        provider: existingPeer, expiresAt: Moment.now() + 1.hours, key: msgKey
      )
    )
    check receiverKad.providerManager.providerRecords.len == 1

    # Sender calls addProvider (no rejection → no spillover, just fire-and-forget)
    await senderKad.addProvider(key.toCid())

    # Receiver rejects (limit already full); record count stays at 1
    await sleepAsync(200.milliseconds)
    check receiverKad.providerManager.providerRecords.len == 1

  asyncTest "Out-of-bounds key is rejected when providerRejection enabled":
    let senderKad = setupKad(testKadConfig(providerRejection = true))
    # Mock receiver injects an over-length key regardless of what is sent.
    let receiverKad = setupMockKad(
      testKadConfig(providerRejection = true),
      handleAddProviderMessage = Opt.some(
        Message(
          msgType: MessageType.addProvider,
          key: Key.fromBytes(newSeq[byte](MaxProviderKeyLen + 1)),
        )
      ),
    )

    startAndDeferStop(@[senderKad] & receiverKad)
    await connect(senderKad, receiverKad)

    let status = await senderKad.sendAddProviderAndGetStatus(
      receiverKad, senderKad.rtable.selfId.toCid().toKey()
    )
    check:
      status.isOk()
      status.value() == AddProviderStatus.rejected
      receiverKad.providerManager.providerRecords.len == 0
