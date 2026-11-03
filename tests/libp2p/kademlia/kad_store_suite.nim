# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The contract tests of ``KadStore``. Run them for each backend with ``kadStoreTestSuite``.

import std/[algorithm, sequtils]
import chronos, results
import ../../../libp2p/[peerid, protocols/kademlia, protocols/kademlia/memory_store]
import ../../tools/[unittest, crypto]

export sequtils, chronos, results, peerid, kademlia, memory_store, unittest, crypto

const
  Now: UnixTimestamp = 1_000
  Later: UnixTimestamp = Now + 60
  Unlimited = high(int)

type
  RemoveCase = object
    target: Key
    peerId: PeerId

  IdCase = object
    provider: Peer
    cause: string

func recordKey(b: byte): RecordKey =
  RecordKey.init(Key.fromBytes(@[b])).get()

proc storedValue(b: byte, expiresAt = Later): StoredValue =
  StoredValue(
    key: recordKey(b),
    record: EntryRecord(value: Value.init([b]), time: Timestamp.now()),
    expiresAt: expiresAt,
  )

proc storedProvider(peerId: PeerId, expiresAt = Later): StoredProvider =
  StoredProvider(provider: Peer(id: Opt.some(peerId.getBytes())), expiresAt: expiresAt)

func peerOf(p: StoredProvider): PeerId =
  PeerId.init(p.provider.id.get()).get()

proc sameProviders(got, want: seq[StoredProvider]): bool =
  let byPeer = proc(a, b: StoredProvider): int =
    cmp(a.peerOf(), b.peerOf())
  got.sorted(byPeer) == want.sorted(byPeer)

proc valueKeys(values: seq[StoredValue]): seq[Key] =
  var keys: seq[Key]
  for value in values:
    keys.add(value.key.toKey())
  keys

template kadStoreTestSuite*(
    name: string, factory: proc(limits: KadStoreLimits): KadStore
) =
  ## ``factory(limits)`` returns a new empty store that enforces ``limits``.
  suite name & " values":
    asyncTest "putValue then getValue returns the value":
      let store = factory(KadStoreLimits())
      let value = storedValue(1)

      check:
        (await store.putValue(value, Now)).get()
        (await store.getValue(value.key, Now)).get().get() == value
        (await store.getValue(recordKey(2), Now)).get().isNone()

    asyncTest "putValue replaces the value of the key":
      let store = factory(KadStoreLimits())
      let replacement = storedValue(1, Later + 1)

      check:
        (await store.putValue(storedValue(1), Now)).get()
        (await store.putValue(replacement, Now)).get()
        (await store.getValue(replacement.key, Now)).get().get() == replacement

    asyncTest "getValue and listValues hide a value with expiresAt <= now":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1, expiresAt = Now), Now)).get()

      check:
        (await store.getValue(recordKey(1), Now - 1)).get().isSome()
        (await store.getValue(recordKey(1), Now)).get().isNone()
        (await store.listValues(Opt.none(RecordKey), Now, Unlimited)).get().len == 0

    asyncTest "getValue deletes the expired value":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1, expiresAt = Now), Now - 1)).get()

      check:
        (await store.getValue(recordKey(1), Now)).get().isNone()
        (await store.getValue(recordKey(1), Now - 1)).get().isNone()

    asyncTest "listValues deletes the expired values":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1, expiresAt = Now), Now - 1)).get()

      check:
        (await store.listValues(Opt.none(RecordKey), Now, Unlimited)).get().len == 0
        (await store.getValue(recordKey(1), Now - 1)).get().isNone()

    asyncTest "putValue deletes expired values and keeps live ones":
      let store = factory(KadStoreLimits(maxValues: Opt.some(2)))
      check:
        (await store.putValue(storedValue(1, expiresAt = Now), Now - 1)).get()
        (await store.putValue(storedValue(2), Now - 1)).get()

      check:
        (await store.putValue(storedValue(3), Now)).get()
        not (await store.putValue(storedValue(4), Now)).get()
        (await store.getValue(recordKey(1), Now - 1)).get().isNone()
        (await store.getValue(recordKey(2), Now)).get().isSome()

    asyncTest "a full store refuses a new key and accepts a known key":
      let store = factory(KadStoreLimits(maxValues: Opt.some(1)))

      check:
        (await store.putValue(storedValue(1), Now)).get()
        not (await store.putValue(storedValue(2), Now)).get()
        (await store.putValue(storedValue(1, Later + 1), Now)).get()
        (await store.getValue(recordKey(2), Now)).get().isNone()

    asyncTest "a full store drops expired values to accept a new key":
      let store = factory(KadStoreLimits(maxValues: Opt.some(1)))
      check:
        (await store.putValue(storedValue(1, expiresAt = Now), Now - 1)).get()
        (await store.putValue(storedValue(2), Now)).get()
        (await store.getValue(recordKey(1), Now - 1)).get().isNone()

    asyncTest "a full store drops a value stored after an earlier drop":
      let store = factory(KadStoreLimits(maxValues: Opt.some(2)))
      check:
        (await store.putValue(storedValue(1, expiresAt = Now), Now - 1)).get()
        (await store.putValue(storedValue(2), Now - 1)).get()
        (await store.putValue(storedValue(3, expiresAt = Now + 1), Now)).get()
        (await store.putValue(storedValue(4), Now + 1)).get()
        (await store.getValue(recordKey(3), Now)).get().isNone()
        (await store.getValue(recordKey(2), Now + 1)).get().isSome()

    asyncTest "delValue frees capacity":
      let store = factory(KadStoreLimits(maxValues: Opt.some(1)))
      check (await store.putValue(storedValue(1), Now)).get()

      check (await store.delValue(recordKey(1))).isOk()

      check:
        (await store.getValue(recordKey(1), Now)).get().isNone()
        (await store.putValue(storedValue(2), Now)).get()

    asyncTest "listValues pages in key byte order and after is exclusive":
      let store = factory(KadStoreLimits())
      for b in [3'u8, 1, 4, 2]:
        check (await store.putValue(storedValue(b), Now)).get()

      let first = (await store.listValues(Opt.none(RecordKey), Now, 2)).get()
      let second = (await store.listValues(Opt.some(first[^1].key), Now, 2)).get()
      let last = (await store.listValues(Opt.some(second[^1].key), Now, 2)).get()

      check:
        first.valueKeys() == @[recordKey(1).toKey(), recordKey(2).toKey()]
        second.valueKeys() == @[recordKey(3).toKey(), recordKey(4).toKey()]
        last.len == 0

    asyncTest "listValues reflects an overwrite, a delete and a re-add":
      let store = factory(KadStoreLimits())
      for b in [2'u8, 1, 3, 2]:
        check (await store.putValue(storedValue(b), Now)).get()

      check (await store.listValues(Opt.none(RecordKey), Now, Unlimited))
        .get()
        .valueKeys() ==
        @[recordKey(1).toKey(), recordKey(2).toKey(), recordKey(3).toKey()]

      check:
        (await store.delValue(recordKey(2))).isOk()
        (await store.delValue(recordKey(9))).isOk()

      check (await store.listValues(Opt.none(RecordKey), Now, Unlimited))
        .get()
        .valueKeys() == @[recordKey(1).toKey(), recordKey(3).toKey()]

      check (await store.putValue(storedValue(2), Now)).get()

      check (await store.listValues(Opt.none(RecordKey), Now, Unlimited))
        .get()
        .valueKeys() ==
        @[recordKey(1).toKey(), recordKey(2).toKey(), recordKey(3).toKey()]

    asyncTest "listValues orders a key before its extension":
      let store = factory(KadStoreLimits())
      let long = RecordKey.init(Key.fromBytes(@[1'u8, 0])).get()
      check:
        (await store.putValue(StoredValue(key: long, expiresAt: Later), Now)).get()
        (await store.putValue(storedValue(1), Now)).get()

      check (await store.listValues(Opt.none(RecordKey), Now, Unlimited))
        .get()
        .valueKeys() == @[recordKey(1).toKey(), long.toKey()]

    asyncTest "listValues with limit below 1 returns no entries":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1), Now)).get()

      for limit in [0, -1]:
        check (await store.listValues(Opt.none(RecordKey), Now, limit)).get().len == 0

  suite name & " providers":
    let key = Key.init([7'u8])

    proc add(
        store: KadStore,
        k: Key,
        peerId: PeerId,
        expiresAt = Later,
        maxPerKey = Unlimited,
        now = Now,
    ): Future[AddProviderOutcome] {.async: (raises: [CancelledError]).} =
      (await store.addProvider(k, storedProvider(peerId, expiresAt), now, maxPerKey)).get()

    proc providers(
        store: KadStore, k: Key, now = Now
    ): Future[seq[StoredProvider]] {.async.} =
      (await store.getProviders(k, now, Unlimited)).get()

    asyncTest "addProvider adds, then refreshes the same peer":
      let store = factory(KadStoreLimits())
      let peerId = PeerId.random()

      check:
        (await store.add(key, peerId)) == AddProviderOutcome.added
        (await store.add(key, peerId, Later + 1)) == AddProviderOutcome.refreshed
        (await store.providers(key)) == @[storedProvider(peerId, Later + 1)]

    asyncTest "a known provider refreshes when the key is full":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(2)
      for peerId in peers:
        check (await store.add(key, peerId, maxPerKey = 2)) == AddProviderOutcome.added

      check:
        (await store.add(key, peers[0], Later + 1, maxPerKey = 2)) ==
          AddProviderOutcome.refreshed
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[0], Later + 1), storedProvider(peers[1])]
        )

    asyncTest "a new provider gets keyFull at maxPerKey":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(2)
      check (await store.add(key, peers[0], maxPerKey = 1)) == AddProviderOutcome.added

      check:
        (await store.add(key, peers[1], maxPerKey = 1)) == AddProviderOutcome.keyFull
        (await store.add(Key.init([8'u8]), peers[1], maxPerKey = 0)) ==
          AddProviderOutcome.keyFull
        (await store.providers(key)) == @[storedProvider(peers[0])]

    asyncTest "a new provider at the total cap evicts the provider that expires first":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(3)
      check:
        (await store.add(key, peers[0], Later + 1)) == AddProviderOutcome.added
        (await store.add(key, peers[1], Later)) == AddProviderOutcome.added

      check:
        (await store.add(Key.init([8'u8]), peers[2], Later + 2)) ==
          AddProviderOutcome.added
        (await store.providers(key)) == @[storedProvider(peers[0], Later + 1)]
        (await store.providers(Key.init([8'u8]))) ==
          @[storedProvider(peers[2], Later + 2)]

    asyncTest "a refresh moves the provider back in the eviction order":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(3)
      check:
        (await store.add(key, peers[0], Later)) == AddProviderOutcome.added
        (await store.add(key, peers[1], Later + 1)) == AddProviderOutcome.added
        (await store.add(key, peers[0], Later + 2)) == AddProviderOutcome.refreshed

      check:
        (await store.add(key, peers[2], Later + 3)) == AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[0], Later + 2), storedProvider(peers[2], Later + 3)]
        )

    asyncTest "a re-advertisement at the total cap evicts nothing":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(2)
      for peerId in peers:
        check (await store.add(key, peerId)) == AddProviderOutcome.added

      check:
        (await store.add(key, peers[1], Later + 1)) == AddProviderOutcome.refreshed
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[0]), storedProvider(peers[1], Later + 1)]
        )

    asyncTest "a full store evicts nothing for a provider that expires no later":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(1)))
      let peers = PeerId.random(3)
      check (await store.add(key, peers[0])) == AddProviderOutcome.added

      check:
        (await store.add(key, peers[1])) == AddProviderOutcome.storeFull
        (await store.add(key, peers[2], expiresAt = Now)) == AddProviderOutcome.storeFull
        (await store.providers(key)) == @[storedProvider(peers[0])]

    asyncTest "a store with a total cap of 0 gives storeFull":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(0)))

      check:
        (await store.add(key, PeerId.random())) == AddProviderOutcome.storeFull
        (await store.providers(key)).len == 0

    asyncTest "a full store drops expired providers to accept a new one":
      let peers = PeerId.random(2)
      let expired = storedProvider(peers[0], expiresAt = Now)
      let fresh = storedProvider(peers[1])

      let totalCapped = factory(KadStoreLimits(maxProviders: Opt.some(1)))
      check:
        (await totalCapped.addProvider(key, expired, Now - 1, Unlimited)).get() ==
          AddProviderOutcome.added
        (await totalCapped.addProvider(key, fresh, Now, Unlimited)).get() ==
          AddProviderOutcome.added

      let keyCapped = factory(KadStoreLimits())
      check:
        (await keyCapped.addProvider(key, expired, Now - 1, 1)).get() ==
          AddProviderOutcome.added
        (await keyCapped.addProvider(key, fresh, Now, 1)).get() ==
          AddProviderOutcome.added
        (await keyCapped.getProviders(key, Now, Unlimited)).get() == @[fresh]

    asyncTest "a full key drops a provider stored after an earlier drop":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(4)
      check:
        (await store.add(key, peers[0], expiresAt = Now, now = Now - 1)) ==
          AddProviderOutcome.added
        (await store.add(key, peers[1], now = Now - 1)) == AddProviderOutcome.added
        (await store.add(key, peers[2], Now + 1, maxPerKey = 2)) ==
          AddProviderOutcome.added
        (await store.add(key, peers[3], maxPerKey = 2, now = Now + 1)) ==
          AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[3])]
        )

    asyncTest "a full key drops a provider added after a drop at the total cap":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(1)))
      let peers = PeerId.random(3)
      check:
        (await store.add(key, peers[0], expiresAt = Now, now = Now - 1)) ==
          AddProviderOutcome.added
        (await store.add(key, peers[1], Now + 1)) == AddProviderOutcome.added
        (await store.add(key, peers[2], maxPerKey = 1, now = Now + 1)) ==
          AddProviderOutcome.added
        (await store.providers(key)) == @[storedProvider(peers[2])]

    asyncTest "addProvider rejects a provider without a valid id":
      let store = factory(KadStoreLimits())
      let cases = [
        IdCase(provider: Peer(), cause: "provider without id"),
        IdCase(provider: Peer(id: Opt.some(@[1'u8])), cause: "invalid provider id"),
      ]
      for c in cases:
        let res = await store.addProvider(
          key, StoredProvider(provider: c.provider, expiresAt: Later), Now, Unlimited
        )
        check:
          res.isErr()
          res.isOfError(c.cause)

    asyncTest "removeProvider removes only that peer and frees capacity":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(3)
      for peerId in peers[0 .. 1]:
        check (await store.add(key, peerId)) == AddProviderOutcome.added

      check (await store.removeProvider(key, peers[0])).isOk()

      check:
        (await store.providers(key)) == @[storedProvider(peers[1])]
        (await store.add(key, peers[2])) == AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2])]
        )

    asyncTest "getProviders hides expired providers and caps at limit":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(3)
      check:
        (await store.add(key, peers[0], expiresAt = Now, now = Now - 1)) ==
          AddProviderOutcome.added
        (await store.add(key, peers[1], now = Now - 1)) == AddProviderOutcome.added
        (await store.add(key, peers[2], now = Now - 1)) == AddProviderOutcome.added
        (await store.providers(key, Now - 1)).len == 3

      let live = @[storedProvider(peers[1]), storedProvider(peers[2])]
      let one = (await store.getProviders(key, Now, 1)).get()
      check:
        (await store.providers(key)).sameProviders(live)
        one.len == 1
        one[0] in live
        (await store.getProviders(key, Now, 0)).get().len == 0

    asyncTest "getProviders deletes the expired providers":
      let store = factory(KadStoreLimits())
      check (await store.add(key, PeerId.random(), expiresAt = Now, now = Now - 1)) ==
        AddProviderOutcome.added

      check:
        (await store.providers(key)).len == 0
        (await store.providers(key, Now - 1)).len == 0

    asyncTest "a provider refreshed past now stays":
      let store = factory(KadStoreLimits())
      let peerId = PeerId.random()
      check:
        (await store.add(key, peerId, expiresAt = Now, now = Now - 1)) ==
          AddProviderOutcome.added
        (await store.add(key, peerId, now = Now - 1)) == AddProviderOutcome.refreshed

      check (await store.providers(key)) == @[storedProvider(peerId)]

    asyncTest "a refresh to an earlier expiry moves the provider forward in the eviction order":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(3)
      check:
        (await store.add(key, peers[0], Later + 5)) == AddProviderOutcome.added
        (await store.add(key, peers[1], Later + 1)) == AddProviderOutcome.added
        (await store.add(key, peers[0], Later)) == AddProviderOutcome.refreshed

      check:
        (await store.add(key, peers[2], Later + 9)) == AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[1], Later + 1), storedProvider(peers[2], Later + 9)]
        )

    asyncTest "many refreshes keep the eviction order and the pruning exact":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(5)
      check:
        (await store.add(key, peers[0], Later)) == AddProviderOutcome.added
        (await store.add(key, peers[1], Later + 1)) == AddProviderOutcome.added
      for i in 10 .. 20:
        check (await store.add(key, peers[1], Later + i)) == AddProviderOutcome.refreshed

      check:
        (await store.add(key, peers[2], Later + 30)) == AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[1], Later + 20), storedProvider(peers[2], Later + 30)]
        )

      check:
        (await store.providers(key, Later + 20)) ==
          @[storedProvider(peers[2], Later + 30)]
        (await store.providers(key, Now)) == @[storedProvider(peers[2], Later + 30)]
        (await store.add(key, peers[3], Later + 31)) == AddProviderOutcome.added
        (await store.providers(key, Now)).sameProviders(
          @[storedProvider(peers[2], Later + 30), storedProvider(peers[3], Later + 31)]
        )
        (await store.add(key, peers[4], Later + 32)) == AddProviderOutcome.added
        (await store.providers(key, Now)).sameProviders(
          @[storedProvider(peers[3], Later + 31), storedProvider(peers[4], Later + 32)]
        )

    asyncTest "removeProvider of an evicted provider does not free capacity":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let other = Key.init([8'u8])
      let peers = PeerId.random(4)
      check:
        (await store.add(key, peers[0], Later)) == AddProviderOutcome.added
        (await store.add(key, peers[1], Later + 1)) == AddProviderOutcome.added
        (await store.add(other, peers[2], Later + 2)) == AddProviderOutcome.added
      check (await store.removeProvider(key, peers[0])).isOk()

      check:
        (await store.add(other, peers[3], Later + 3)) == AddProviderOutcome.added
        (await store.providers(key)).len == 0
        (await store.providers(other)).sameProviders(
          @[storedProvider(peers[2], Later + 2), storedProvider(peers[3], Later + 3)]
        )

    asyncTest "an expiry after removeProvider does not free capacity twice":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(4)
      check:
        (await store.add(key, peers[0], Now, now = Now - 1)) == AddProviderOutcome.added
        (await store.add(key, peers[1], Later, now = Now - 1)) ==
          AddProviderOutcome.added
      check:
        (await store.removeProvider(key, peers[0])).isOk()
        (await store.add(key, peers[2], Later + 1, now = Now)) ==
          AddProviderOutcome.added

      check:
        (await store.add(key, peers[3], Later + 2)) == AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[2], Later + 1), storedProvider(peers[3], Later + 2)]
        )

    asyncTest "removeProvider of an unknown key or peer leaves the count intact":
      let peers = PeerId.random(2)
      let cases = [
        RemoveCase(target: Key.init([8'u8]), peerId: peers[0]),
        RemoveCase(target: key, peerId: peers[1]),
      ]
      for c in cases:
        let store = factory(KadStoreLimits(maxProviders: Opt.some(1)))
        check (await store.add(key, peers[0])) == AddProviderOutcome.added

        check:
          (await store.removeProvider(c.target, c.peerId)).isOk()
          (await store.providers(key)) == @[storedProvider(peers[0])]
          (await store.add(Key.init([9'u8]), peers[1], Later + 1)) ==
            AddProviderOutcome.added
          (await store.providers(key)).len == 0

    asyncTest "an expired provider drop keeps the live providers and counts them exactly":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(3)))
      let peers = PeerId.random(5)
      check:
        (await store.add(key, peers[0], expiresAt = Now)) == AddProviderOutcome.added
        (await store.add(key, peers[1])) == AddProviderOutcome.added
        (await store.add(key, peers[2], Later + 1)) == AddProviderOutcome.added

      check:
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2], Later + 1)]
        )
        (await store.providers(key, Now - 1)).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2], Later + 1)]
        )
        (await store.add(key, peers[3], Later + 1)) == AddProviderOutcome.added
        (await store.providers(key)).len == 3
        (await store.add(key, peers[4], Later + 1)) == AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[
            storedProvider(peers[2], Later + 1),
            storedProvider(peers[3], Later + 1),
            storedProvider(peers[4], Later + 1),
          ]
        )

    asyncTest "a refreshed provider at the total cap keeps the count unchanged":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(3)
      check:
        (await store.add(key, peers[0])) == AddProviderOutcome.added
        (await store.add(key, peers[1])) == AddProviderOutcome.added
        (await store.add(key, peers[0], Later + 1)) == AddProviderOutcome.refreshed

      check (await store.removeProvider(key, peers[0])).isOk()

      check:
        (await store.add(key, peers[2])) == AddProviderOutcome.added
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2])]
        )

  suite name & " provided keys":
    asyncTest "addProvided is idempotent and refuses a new key when full":
      let store = factory(KadStoreLimits(maxProvided: Opt.some(1)))
      let key = Key.init([1'u8])

      check:
        (await store.addProvided(key)).get()
        (await store.addProvided(key)).get()
        not (await store.addProvided(Key.init([2'u8]))).get()
        (await store.hasProvided(key)).get()
        not (await store.hasProvided(Key.init([2'u8]))).get()

    asyncTest "delProvided removes the key and frees capacity":
      let store = factory(KadStoreLimits(maxProvided: Opt.some(1)))
      check (await store.addProvided(Key.init([1'u8]))).get()

      check (await store.delProvided(Key.init([1'u8]))).isOk()

      check:
        not (await store.hasProvided(Key.init([1'u8]))).get()
        (await store.addProvided(Key.init([2'u8]))).get()

    asyncTest "provided keys do not expire":
      let store = factory(KadStoreLimits())
      let key = Key.init([1'u8])
      check (await store.addProvided(key)).get()

      check:
        (await store.getProviders(key, high(UnixTimestamp), Unlimited)).get().len == 0
        (await store.listValues(Opt.none(RecordKey), high(UnixTimestamp), Unlimited)).get().len ==
          0
        (await store.hasProvided(key)).get()

    asyncTest "listProvided pages in key byte order":
      let store = factory(KadStoreLimits())
      let keys = [3'u8, 1, 2].mapIt(Key.fromBytes(@[it]))
      for key in keys:
        check (await store.addProvided(key)).get()

      let first = (await store.listProvided(Opt.none(Key), 2)).get()

      check:
        first == @[keys[1], keys[2]]
        (await store.listProvided(Opt.some(first[^1]), 2)).get() == @[keys[0]]
        (await store.listProvided(Opt.none(Key), 0)).get().len == 0
