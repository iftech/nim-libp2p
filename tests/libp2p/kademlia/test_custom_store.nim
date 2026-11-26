# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import ../../../libp2p/[protocols/kademlia, switch]
import ../../../libp2p/protocols/kademlia/[key_value, memory_store]
import ../../tools/[lifecycle, unittest]
import ./utils

proc setupStoreKad(store: MemoryKadStore): KadDHT =
  var config = testKadConfig()
  config.store = Opt.some(KadStore(store))
  setupKad(config)

suite "KadDHT - Application Store":
  teardown:
    checkTrackers()

  asyncTest "Handlers read and write the configured store":
    let store = MemoryKadStore.new()
    let kads = @[setupStoreKad(store), setupKad()]
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    let serviceId = randomServiceId()
    await kads[1].addProvider(serviceId)

    let
      key = kads[0].rtable.selfId
      recordKey = RecordKey.init(key).get()
      value = @[1.byte, 2, 3]
    check (await kads[1].putValue(key, value)) == LPResult[int].ok(1)

    let
      seededRecordKey = RecordKey.init(kads[1].rtable.selfId).get()
      seeded = StoredValue(
        key: seededRecordKey,
        record: EntryRecord(value: Value.init(value), time: Timestamp.now()),
        expiresAt: UnixTimestamp.now() + 60,
      )
    check store.putValue(seeded, UnixTimestamp.now()).get()

    check:
      store.getProviders(serviceId, UnixTimestamp.now(), high(int)).get().len == 1
      store.getValue(recordKey, UnixTimestamp.now()).get().isSome()
      (await kads[1].getProviders(serviceId)).len == 1
      (await kads[1].getValue(seededRecordKey, quorumOverride = Opt.some(1))).get().value ==
        value

  asyncTest "Republish reads the provided keys from the configured store":
    let store = MemoryKadStore.new()
    let kads = @[setupKad(), setupStoreKad(store)]
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    let provided = ProvidedKey.init(makeProvidedCid(1)).get()
    check store.addProvided(provided).get()

    checkUntilTimeout:
      kads[0].hasProvider(provided.toKey(), kads[1].switch.peerInfo.peerId)
