# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../libp2p/protocols/kademlia/memory_store
import ./[kad_store_suite, utils]

proc newMemoryStore(limits: KadStoreLimits): KadStore =
  MemoryKadStore.new(limits)

kadStoreTestSuite("MemoryKadStore", newMemoryStore)

suite "MemoryKadStore default limits":
  test "MemoryKadStore.new() uses the default kademlia capacities":
    check MemoryKadStore.new().limits() ==
      KadStoreLimits(
        maxValues: Opt.some(DefaultMaxLocalRecords),
        maxProviders: Opt.some(DefaultProviderRecordCapacity),
        maxProvided: Opt.some(DefaultProvidedKeyCapacity),
        maxProviderRecordsPerPeer:
          Opt.some(defaultMaxProviderRecordsPerPeer(DefaultProviderRecordCapacity)),
      )

  test "KadDHT defaults to a MemoryKadStore with the caps of its config":
    var config = testKadConfig()
    config.storeLimits = KadStoreLimits.new(
      maxValues = Opt.some(5), maxProviders = Opt.some(7), maxProvided = Opt.some(3)
    )
    let kad = setupKad(config)

    check:
      kad.store of MemoryKadStore
      MemoryKadStore(kad.store).limits() == config.storeLimits

  test "KadDHT uses the store of its config":
    let store = MemoryKadStore.new()
    var config = testKadConfig()
    config.store = Opt.some(KadStore(store))
    let kad = setupKad(config)

    check kad.store == KadStore(store)
