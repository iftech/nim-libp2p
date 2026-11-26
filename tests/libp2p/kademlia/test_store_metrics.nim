# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import ../../../libp2p/[cid, multicodec, multihash, peerid, protocols/kademlia]
import
  ../../../libp2p/protocols/kademlia/
    [memory_store, kademlia_metrics, local_record, provider]
import ../../tools/[crypto, metrics_utils, unittest]
import ./utils

const Sentinel = 42.0

type
  FailingPutStore = ref object of MemoryKadStore

  FailingStatsStore = ref object of MemoryKadStore

method getValue*(
    store: FailingPutStore, key: RecordKey, now: UnixTimestamp
): LPResult[Opt[StoredValue]] {.gcsafe, raises: [].} =
  ok(Opt.none(StoredValue))

method putValue*(
    store: FailingPutStore, value: StoredValue, now: UnixTimestamp
): LPResult[bool] {.gcsafe, raises: [].} =
  err("put failed")

method stats*(
    store: FailingStatsStore, now: UnixTimestamp
): LPResult[KadStoreStats] {.gcsafe, raises: [].} =
  err("stats failed")

proc testCid(): Cid =
  Cid.init(CIDv1, multiCodec("raw"), MultiHash.digest("sha2-256", [1'u8]).get()).get()

proc makeKad(store: KadStore): KadDHT =
  var config = testKadConfig()
  config.store = Opt.some(store)
  setupKad(config)

func testKey(): RecordKey =
  RecordKey.init(Key.fromBytes(@[1'u8])).get()

proc entry(): EntryRecord =
  EntryRecord(value: Value.init(@[1'u8]), time: Timestamp.now())

proc storedProvider(): StoredProvider =
  let peerId = PeerId.random()
  StoredProvider(
    provider: Peer(id: Opt.some(peerId.getBytes())), expiresAt: UnixTimestamp.now() + 60
  )

suite "Kademlia store metrics":
  asyncTest "gauges read the live counts of the store":
    let kad = makeKad(MemoryKadStore.new())

    check kad.putBestLocalRecord(testKey(), entry())
    check kad.store
      .addProvider(testKey().toKey(), storedProvider(), UnixTimestamp.now(), 5)
      .get() == AddProviderOutcome.added
    await kad.startProviding(testCid())
    kad.updateStoreGauges()

    check:
      metricValue(kad_stored_value_records) == 1.0
      metricValue(kad_stored_provider_records) == 1.0
      metricValue(kad_provided_keys) == 1.0

  test "gauges skip an expired record":
    let store = MemoryKadStore.new()
    let kad = makeKad(store)
    let now = UnixTimestamp.now()
    check store
      .putValue(
        StoredValue(key: testKey(), record: entry(), expiresAt: now - 1), now - 10
      )
      .get()

    kad.updateStoreGauges()

    check metricValue(kad_stored_value_records) == 0.0

  test "a failing store method increments kad_store_errors":
    let kad = makeKad(FailingPutStore.new())
    let before = metricValue(kad_store_errors, ["putValue"])

    check not kad.putBestLocalRecord(testKey(), entry())
    check metricValue(kad_store_errors, ["putValue"]) == before + 1

  test "a failing stats call increments kad_store_errors and leaves the gauges":
    let kad = makeKad(FailingStatsStore.new())
    kad_stored_value_records.set(Sentinel)
    let before = metricValue(kad_store_errors, ["stats"])

    kad.updateStoreGauges()

    check:
      metricValue(kad_store_errors, ["stats"]) == before + 1
      metricValue(kad_stored_value_records) == Sentinel

  test "a store without stats leaves the gauges and does not crash":
    let kad = makeKad(KadStore())
    kad_stored_value_records.set(Sentinel)

    kad.updateStoreGauges()

    check metricValue(kad_stored_value_records) == Sentinel
