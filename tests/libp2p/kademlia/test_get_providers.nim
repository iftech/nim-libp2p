# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils, sets, tables
import
  ../../../libp2p/[protocols/kademlia, switch, builders, multicodec, multihash, cid]
import ../../tools/[lifecycle, topology, unittest]
import ./[utils]

suite "KadDHT - Get Providers":
  teardown:
    checkTrackers()

  asyncTest "Get providers uses iterative lookup":
    let kads = setupKadSwitches(
      4,
      cleanupProvidersInterval = 1.seconds(),
      republishProvidedKeysInterval = 1.seconds(),
    )
    startAndDeferStop(kads)

    # topology: kads[0] <-> kads[1] <-> kads[2] <-> kads[3]
    await connectChain(kads)

    let key = kads[0].rtable.selfId

    # Add key to kads[3] providedKeys locally (without broadcasting via addProvider)
    kads[3].providerManager.providedKeys.provided[key] = Moment.now()

    # Verify other nodes don't know about the provider yet
    check:
      kads[0].providerManager.providerRecords.len() == 0
      kads[1].providerManager.providerRecords.len() == 0
      kads[2].providerManager.providerRecords.len() == 0

    # kad0 iteratively queries the network and should find kad3 as a provider
    let providers = await kads[0].getProviders(key)

    # kad3 should be found as the provider
    check:
      providers.len() == 1
      providers.containsPeer(kads[3])

    checkUntilTimeout:
      # Provider records have propagated
      kads[0].providerManager.providerRecords.len() == 1
      kads[1].providerManager.providerRecords.len() == 1
      kads[2].providerManager.providerRecords.len() == 1
      # Other peers have been discovered
      kads[0].hasKey(kads[2].rtable.selfId)
      kads[0].hasKey(kads[3].rtable.selfId)

    # Query for unknown key is handled
    check (await kads[0].getProviders(@[1.byte, 1, 1, 1])).len == 0

  asyncTest "Get providers updates routing table with closerPeers when no providers are returned":
    # kads[2] <---> kads[0] (hub) <---> kads[1]
    let kads = setupKadSwitches(
      3, PermissiveValidator(), CandSelector(), @[], 1.seconds, 1.seconds
    )
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    let key = kads[0].rtable.selfId

    check:
      kads[2].hasKey(kads[0].rtable.selfId)
      not kads[2].hasKey(kads[1].rtable.selfId)

    # When kads[0] doesn't have any providers, handleGetProviders returns only closerPeers
    let providers = await kads[2].getProviders(key)

    # kads[2] should discover kads[1] through the closerPeers in the response
    check providers.len() == 0
    checkUntilTimeout:
      kads[2].hasKey(kads[1].rtable.selfId)

  asyncTest "Get providers updates routing table with closerPeers (with providers)":
    # kads[2] <---> kads[0] (hub) <---> kads[1]
    let kads = setupKadSwitches(
      3, PermissiveValidator(), CandSelector(), @[], 1.seconds, 1.seconds
    )
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    let key = kads[0].rtable.selfId

    # kads[0] is providing the key
    kads[0].providerManager.providedKeys.provided[key] = Moment.now()

    check:
      kads[2].hasKey(kads[0].rtable.selfId)
      not kads[2].hasKey(kads[1].rtable.selfId)

    # When kads[0] has providers, handleGetProviders returns both providers and closerPeers
    let providers = await kads[2].getProviders(key)

    # kads[2] should discover kads[1] through the closerPeers in the response
    check providers.len() == 1
    checkUntilTimeout:
      kads[2].hasKey(kads[1].rtable.selfId)

  asyncTest "Get providers uses multihash for CID convergence":
    # Long republish interval so the background heartbeat doesn't race getProviders dials.
    let kads = setupKadSwitches(2, republishProvidedKeysInterval = chronos.hours(1))
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    # Create two CIDs with same multihash but different codecs
    let
      testData = @[1.byte, 2, 3, 4, 5]
      mhash = MultiHash.digest("sha2-256", testData).get()
      cidDagPb = Cid.init(CIDv1, multiCodec("dag-pb"), mhash).get()
      cidRaw = Cid.init(CIDv1, multiCodec("raw"), mhash).get()
      expectedKey = mhash.toKey()

    # Verify CIDs are different but map to same key
    check:
      cidDagPb.data.buffer != cidRaw.data.buffer
      cidDagPb.toKey() == cidRaw.toKey()

    # kads[1] announces as provider using dag-pb CID key
    kads[1].providerManager.providedKeys.provided[expectedKey] = Moment.now()

    # kads[0] queries using raw CID - should find the same provider
    let providers = await kads[0].getProviders(cidRaw.toKey())

    check:
      providers.len() == 1
      providers.containsPeer(kads[1])

  asyncTest "Get providers includes self when querying node is a provider":
    # Long republish interval so the background heartbeat doesn't race getProviders dials.
    let kads = setupKadSwitches(2, republishProvidedKeysInterval = chronos.hours(1))
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = @[1.byte, 2, 3, 4, 5]

    # kads[0] (the querying node) is a provider for the key
    kads[0].providerManager.providedKeys.provided[key] = Moment.now()
    # kads[1] is also a provider for the key
    kads[1].providerManager.providedKeys.provided[key] = Moment.now()

    let providers = await kads[0].getProviders(key)

    # Both kads[0] (self) and kads[1] should be included
    check:
      providers.len() == 2
      providers.containsPeer(kads[0])
      providers.containsPeer(kads[1])

  asyncTest "Get providers deduplicates provider entries from multiple nodes":
    # Topology: kads[0] <-> kads[1], kads[0] <-> kads[2], kads[3] provider
    let kads = setupKadSwitches(4)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])
    await connect(kads[0], kads[2])

    let key = @[1.byte, 2, 3, 4, 5]
    let provider3 = kads[3].toPeer()

    # Both kads[1] and kads[2] know about kads[3] as a provider
    kads[1].providerManager.knownKeys[key] = initHashSet[Provider]()
    kads[1].providerManager.knownKeys[key].incl(provider3)

    kads[2].providerManager.knownKeys[key] = initHashSet[Provider]()
    kads[2].providerManager.knownKeys[key].incl(provider3)

    let providers = await kads[0].getProviders(key)

    # Result should be deduplicated - only one entry for kads[3]
    check:
      providers.len() == 1
      providers.containsPeer(kads[3])

  asyncTest "Get providers filters out invalid provider IDs":
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = @[1.byte, 2, 3, 4, 5]

    # kads[1] has both valid and invalid providers in its knownKeys
    kads[1].providerManager.knownKeys[key] = initHashSet[Provider]()
    kads[1].providerManager.knownKeys[key].incl(kads[2].toPeer())
    # Invalid provider with malformed peer ID bytes
    kads[1].providerManager.knownKeys[key].incl(Peer(id: @[1.byte, 1, 1]))

    # kads[0] queries - should filter out invalid provider and return only valid one
    let providers = await kads[0].getProviders(key)

    # Only the valid provider should be returned
    check:
      providers.len() == 1
      providers.containsPeer(kads[2])

  asyncTest "Get providers terminates early when sufficient providers found":
    # Use small replication value; beta must stay <= replication
    let kads = setupKadSwitches(8, replication = 2, beta = 2)
    startAndDeferStop(kads)

    # kads[0] <-> kads[1] <-> kads[2]
    await connectChain(kads)

    let key = @[1.byte, 2, 3, 4, 5]

    # kads[1] knows about 3 providers
    # kads[2] knows about additional 2 providers
    kads[1].providerManager.knownKeys[key] = initHashSet[Provider]()
    kads[1].providerManager.knownKeys[key].incl(kads[3].toPeer())
    kads[1].providerManager.knownKeys[key].incl(kads[4].toPeer())
    kads[1].providerManager.knownKeys[key].incl(kads[5].toPeer())

    kads[2].providerManager.knownKeys[key] = initHashSet[Provider]()
    kads[2].providerManager.knownKeys[key].incl(kads[6].toPeer())
    kads[2].providerManager.knownKeys[key].incl(kads[7].toPeer())

    # kads[0] queries and should stop at kad[1] as replication reached
    check:
      (await kads[0].getProviders(key)).len() == 3

    # Increase replication. The shortlist cap is derived from replication
    # (`maxShortlistSize = replication * 2`), so refresh the limits too; otherwise
    # the cap stays sized for the old replication and the lookup can evict kad[2]
    # before it answers, dropping its providers.
    kads[0].config.replication = 6
    kads[0].config.limits = KadDHTLimits.new(6, kads[0].config.quorum)

    # kads[0] queries again and stops only at kad[2]
    check:
      (await kads[0].getProviders(key)).len() == 5

  asyncTest "Get providers returns at most k closest peers":
    # Use small replication value
    const k = 3
    let kads = setupKadSwitches(2, replication = k)
    startAndDeferStop(kads)

    # kads[1] will directly dispatch GET_PROVIDERS to kads[0]
    await connect(kads[0], kads[1])

    # Peers are added directly, not through connect: a bucket holds at most k, so
    # how many of them reach the table would depend on how their ids spread over
    # buckets, and the table could end up holding no more than k.
    kads[0].addPeersWithAddrs(2 * k)
    check kads[0].rtable.allKeys().len() > k

    let key = @[1.byte, 2, 3, 4, 5]

    # Directly call dispatchGetProviders to capture the raw response
    let response =
      await kads[1].dispatchGetProviders(kads[0].switch.peerInfo.peerId, key)

    let
      hasher = kads[0].rtable.config.hasher
      expected = kads[0]
        .getPeersFromRoutingTable()
        .filterIt(it != kads[1].switch.peerInfo.peerId)
        .sortPeers(key, hasher)[0 ..< k]

    # kads[0] knows more than k peers but should only return the k closest ones
    check:
      response.get().closerPeers.len() == k
      response.get().closerPeers.toPeerIds().sortPeers(key, hasher) == expected

  asyncTest "Get providers aggregates providers from multiple peers":
    # Topology: kads[0] <-> kads[1] <-> kads[2] <-> kads[3] <-> kads[4]
    # Use a long republishProvidedKeysInterval so the background republish heartbeat
    # doesn't fire during the test and race with getProviders dials.
    let kads = setupKadSwitches(5, republishProvidedKeysInterval = chronos.hours(1))
    startAndDeferStop(kads)

    await connectChain(kads)

    let key = @[1.byte, 2, 3, 4, 5]

    # kads[1 .. 4] are providers
    kads[1].providerManager.providedKeys.provided[key] = Moment.now()
    kads[2].providerManager.providedKeys.provided[key] = Moment.now()
    kads[3].providerManager.providedKeys.provided[key] = Moment.now()
    kads[4].providerManager.providedKeys.provided[key] = Moment.now()

    let providers = await kads[0].getProviders(key)

    # Result should contain all providers
    check:
      providers.len() == 4
      providers.containsPeer(kads[1])
      providers.containsPeer(kads[2])
      providers.containsPeer(kads[3])
      providers.containsPeer(kads[4])

  asyncTest "provider listen addresses are advertised in closerPeers":
    let
      a = setupKad(config = testKadConfig(providerRejection = true))
      b = setupKad()
      c = setupKad()
    startAndDeferStop(@[a, b, c])

    let
      bId = b.switch.peerInfo.peerId
      bListenAddrs = b.switch.peerInfo.addrs
      providerKey = @[1.byte, 2, 3, 4, 5]

    await b.switch.connect(a.switch)
    discard (await b.dispatchFindNode(a.switch.peerInfo.peerId, bId.toKey())).expect(
      "FIND_NODE reply"
    )
    check a.switch.peerStore[AddressBook][bId].allIt(it in bListenAddrs)

    discard (await sendAddProviderAndGetStatus(b, a, providerKey)).expect(
      "add provider accepted"
    )
    checkUntilTimeout:
      bListenAddrs.allIt(it in a.switch.peerStore[AddressBook][bId])

    await c.switch.connect(a.switch)
    let reply =
      (await c.dispatchGetProviders(a.switch.peerInfo.peerId, providerKey)).value()
    let bProvider =
      reply.providerPeers.filterIt(it.id.isSome and it.id.get() == bId.getBytes())
    let bCloser =
      reply.closerPeers.filterIt(it.id.isSome and it.id.get() == bId.getBytes())
    check:
      bProvider.len == 1
      bCloser.len == 1
      bProvider[0].addrs.anyIt(it in bListenAddrs)
      bCloser.mapIt(it.addrs).concat().allIt(it in bListenAddrs)
