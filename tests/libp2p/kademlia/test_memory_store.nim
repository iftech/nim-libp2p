# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ./kad_store_suite

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
      )
