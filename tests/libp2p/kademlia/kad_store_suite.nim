# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The contract tests of ``KadStore``. Run them for each backend with ``kadStoreTestSuite``.

import std/[algorithm, sequtils]
import chronos, results
import ../../../libp2p/[cid, multicodec, multihash, peerid, protocols/kademlia]
import ../../tools/[unittest, crypto]

export sequtils, chronos, results, peerid, kademlia, unittest, crypto

const
  Now: UnixTimestamp = 1_000
  Later: UnixTimestamp = Now + 60
  Unlimited = high(int)
  PageSize = 3

type
  RemoveCase = object
    target: Key
    peerId: PeerId

  IdCase = object
    provider: Peer
    cause: string

func recordKey(b: byte): RecordKey =
  RecordKey.init(Key.fromBytes(@[b])).get()

proc providedKey(b: byte): ProvidedKey =
  let cid =
    Cid.init(CIDv1, multiCodec("raw"), MultiHash.digest("sha2-256", [b]).get()).get()
  ProvidedKey.init(cid).tryGet()

proc storedValue(b: byte, expiresAt = Later): StoredValue =
  StoredValue(
    key: recordKey(b),
    record: EntryRecord(value: Value.init([b]), time: Timestamp.now()),
    expiresAt: expiresAt,
  )

proc storedProvider(peerId: PeerId, expiresAt = Later): StoredProvider =
  StoredProvider(
    provider: Peer(id: Opt.some(peerId.getBytes())),
    expiresAt: expiresAt,
    addrsExpireAt: expiresAt,
  )

func peerOf(p: StoredProvider): PeerId =
  PeerId.init(p.provider.id.get()).get()

proc sameProviders(got, want: seq[StoredProvider]): bool =
  let byPeer = proc(a, b: StoredProvider): int =
    cmp(a.peerOf(), b.peerOf())
  got.sorted(byPeer) == want.sorted(byPeer)

template pk1(): ProvidedKey =
  providedKey(1)

template pk2(): ProvidedKey =
  providedKey(2)

template pk3(): ProvidedKey =
  providedKey(3)

proc pagedKeys(): seq[ProvidedKey] =
  @[7'u8, 2, 9, 4, 1, 8, 3, 6, 5, 10].mapIt(providedKey(it))

template pkNone(): Opt[ProvidedKey] =
  Opt.none(ProvidedKey)

converter toOptInt*(n: int): Opt[int] =
  Opt.some(n)

func `==`*[T](r: LPResult[T], value: T): bool =
  r.isOk() and r.get() == value

template provideAll(store: KadStore, keys: openArray[ProvidedKey]) =
  for key in keys:
    check store.addProvided(key).get()

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
    test "putValue then getValue returns the value":
      let store = factory(KadStoreLimits())
      let value = storedValue(1)

      check:
        store.putValue(value, Now).get()
        store.getValue(value.key, Now).get() == value
        store.getValue(recordKey(2), Now).get().isNone()

    test "putValue replaces the value of the key":
      let store = factory(KadStoreLimits())
      let replacement = storedValue(1, Later + 1)

      check:
        store.putValue(storedValue(1), Now).get()
        store.putValue(replacement, Now).get()
        store.getValue(replacement.key, Now).get() == replacement

    test "getValue and listValues hide a value with expiresAt <= now":
      let store = factory(KadStoreLimits())
      check store.putValue(storedValue(1, expiresAt = Now), Now).get()

      check:
        store.getValue(recordKey(1), Now - 1).get().isSome()
        store.getValue(recordKey(1), Now).get().isNone()
        store.listValues(Opt.none(RecordKey), Now, Unlimited).get().len == 0

    test "getValue deletes the expired value":
      let store = factory(KadStoreLimits())
      check store.putValue(storedValue(1, expiresAt = Now), Now - 1).get()

      check:
        store.getValue(recordKey(1), Now).get().isNone()
        store.getValue(recordKey(1), Now - 1).get().isNone()

    test "listValues deletes the expired values":
      let store = factory(KadStoreLimits())
      check store.putValue(storedValue(1, expiresAt = Now), Now - 1).get()

      check:
        store.listValues(Opt.none(RecordKey), Now, Unlimited).get().len == 0
        store.getValue(recordKey(1), Now - 1).get().isNone()

    test "putValue deletes expired values and keeps live ones":
      let store = factory(KadStoreLimits(maxValues: 2))
      check:
        store.putValue(storedValue(1, expiresAt = Now), Now - 1).get()
        store.putValue(storedValue(2), Now - 1).get()

      check:
        store.putValue(storedValue(3), Now).get()
        not store.putValue(storedValue(4), Now).get()
        store.getValue(recordKey(1), Now - 1).get().isNone()
        store.getValue(recordKey(2), Now).get().isSome()

    test "a full store refuses a new key and accepts a known key":
      let store = factory(KadStoreLimits(maxValues: 1))

      check:
        store.putValue(storedValue(1), Now).get()
        not store.putValue(storedValue(2), Now).get()
        store.putValue(storedValue(1, Later + 1), Now).get()
        store.getValue(recordKey(2), Now).get().isNone()

    test "a full store drops expired values to accept a new key":
      let store = factory(KadStoreLimits(maxValues: 1))
      check:
        store.putValue(storedValue(1, expiresAt = Now), Now - 1).get()
        store.putValue(storedValue(2), Now).get()
        store.getValue(recordKey(1), Now - 1).get().isNone()

    test "a full store drops a value stored after an earlier drop":
      let store = factory(KadStoreLimits(maxValues: 2))
      check:
        store.putValue(storedValue(1, expiresAt = Now), Now - 1).get()
        store.putValue(storedValue(2), Now - 1).get()
        store.putValue(storedValue(3, expiresAt = Now + 1), Now).get()
        store.putValue(storedValue(4), Now + 1).get()
        store.getValue(recordKey(3), Now).get().isNone()
        store.getValue(recordKey(2), Now + 1).get().isSome()

    test "delValue frees capacity":
      let store = factory(KadStoreLimits(maxValues: 1))
      check store.putValue(storedValue(1), Now).get()

      check store.delValue(recordKey(1)).isOk()

      check:
        store.getValue(recordKey(1), Now).get().isNone()
        store.putValue(storedValue(2), Now).get()

    test "listValues pages in key byte order and after is exclusive":
      let store = factory(KadStoreLimits())
      for b in [3'u8, 1, 4, 2]:
        check store.putValue(storedValue(b), Now).get()

      let first = store.listValues(Opt.none(RecordKey), Now, 2).get()
      let second = store.listValues(Opt.some(first[^1].key), Now, 2).get()
      let last = store.listValues(Opt.some(second[^1].key), Now, 2).get()

      check:
        first.valueKeys() == @[recordKey(1).toKey(), recordKey(2).toKey()]
        second.valueKeys() == @[recordKey(3).toKey(), recordKey(4).toKey()]
        last.len == 0

    test "listValues reflects an overwrite, a delete and a re-add":
      let store = factory(KadStoreLimits())
      for b in [2'u8, 1, 3, 2]:
        check store.putValue(storedValue(b), Now).get()

      check store.listValues(Opt.none(RecordKey), Now, Unlimited).get().valueKeys() ==
        @[recordKey(1).toKey(), recordKey(2).toKey(), recordKey(3).toKey()]

      check:
        store.delValue(recordKey(2)).isOk()
        store.delValue(recordKey(9)).isOk()

      check store.listValues(Opt.none(RecordKey), Now, Unlimited).get().valueKeys() ==
        @[recordKey(1).toKey(), recordKey(3).toKey()]

      check store.putValue(storedValue(2), Now).get()

      check store.listValues(Opt.none(RecordKey), Now, Unlimited).get().valueKeys() ==
        @[recordKey(1).toKey(), recordKey(2).toKey(), recordKey(3).toKey()]

    test "listValues orders a key before its extension":
      let store = factory(KadStoreLimits())
      let long = RecordKey.init(Key.fromBytes(@[1'u8, 0])).get()
      check:
        store.putValue(StoredValue(key: long, expiresAt: Later), Now).get()
        store.putValue(storedValue(1), Now).get()

      check store.listValues(Opt.none(RecordKey), Now, Unlimited).get().valueKeys() ==
        @[recordKey(1).toKey(), long.toKey()]

    test "listValues with limit below 1 returns no entries":
      let store = factory(KadStoreLimits())
      check store.putValue(storedValue(1), Now).get()

      for limit in [0, -1]:
        check store.listValues(Opt.none(RecordKey), Now, limit).get().len == 0

  suite name & " providers":
    let key = Key.init([7'u8])

    proc add(
        store: KadStore,
        k: Key,
        peerId: PeerId,
        expiresAt = Later,
        maxPerKey = Unlimited,
        now = Now,
    ): AddProviderOutcome =
      store.addProvider(k, storedProvider(peerId, expiresAt), now, maxPerKey).get()

    proc providers(store: KadStore, k: Key, now = Now): seq[StoredProvider] =
      store.getProviders(k, now, Unlimited).get()

    test "addProvider adds, then refreshes the same peer":
      let store = factory(KadStoreLimits())
      let peerId = PeerId.random()

      check:
        store.add(key, peerId) == AddProviderOutcome.added
        store.add(key, peerId, Later + 1) == AddProviderOutcome.refreshed
        store.providers(key) == @[storedProvider(peerId, Later + 1)]

    test "a known provider refreshes when the key is full":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(2)
      for peerId in peers:
        check store.add(key, peerId, maxPerKey = 2) == AddProviderOutcome.added

      check:
        store.add(key, peers[0], Later + 1, maxPerKey = 2) ==
          AddProviderOutcome.refreshed
        store.providers(key).sameProviders(
          @[storedProvider(peers[0], Later + 1), storedProvider(peers[1])]
        )

    test "a new provider gets keyFull at maxPerKey":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(2)
      check store.add(key, peers[0], maxPerKey = 1) == AddProviderOutcome.added

      check:
        store.add(key, peers[1], maxPerKey = 1) == AddProviderOutcome.keyFull
        store.add(Key.init([8'u8]), peers[1], maxPerKey = 0) ==
          AddProviderOutcome.keyFull
        store.providers(key) == @[storedProvider(peers[0])]

    test "a new provider at the total cap evicts the provider that expires first":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(3)
      check:
        store.add(key, peers[0], Later + 1) == AddProviderOutcome.added
        store.add(key, peers[1], Later) == AddProviderOutcome.added

      check:
        store.add(Key.init([8'u8]), peers[2], Later + 2) == AddProviderOutcome.added
        store.providers(key) == @[storedProvider(peers[0], Later + 1)]
        store.providers(Key.init([8'u8])) == @[storedProvider(peers[2], Later + 2)]

    test "a refresh moves the provider back in the eviction order":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(3)
      check:
        store.add(key, peers[0], Later) == AddProviderOutcome.added
        store.add(key, peers[1], Later + 1) == AddProviderOutcome.added
        store.add(key, peers[0], Later + 2) == AddProviderOutcome.refreshed

      check:
        store.add(key, peers[2], Later + 3) == AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[storedProvider(peers[0], Later + 2), storedProvider(peers[2], Later + 3)]
        )

    test "a re-advertisement at the total cap evicts nothing":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(2)
      for peerId in peers:
        check store.add(key, peerId) == AddProviderOutcome.added

      check:
        store.add(key, peers[1], Later + 1) == AddProviderOutcome.refreshed
        store.providers(key).sameProviders(
          @[storedProvider(peers[0]), storedProvider(peers[1], Later + 1)]
        )

    test "a full store evicts nothing for a provider that expires no later":
      let store = factory(KadStoreLimits(maxProviders: 1))
      let peers = PeerId.random(3)
      check store.add(key, peers[0]) == AddProviderOutcome.added

      check:
        store.add(key, peers[1]) == AddProviderOutcome.storeFull
        store.add(key, peers[2], expiresAt = Now) == AddProviderOutcome.storeFull
        store.providers(key) == @[storedProvider(peers[0])]

    test "a store with a total cap of 0 gives storeFull":
      let store = factory(KadStoreLimits(maxProviders: 0))

      check:
        store.add(key, PeerId.random()) == AddProviderOutcome.storeFull
        store.providers(key).len == 0

    test "a new record of a peer gets peerFull at the cap per peer":
      let store = factory(KadStoreLimits(maxProviderRecordsPerPeer: 1))
      let peerId = PeerId.random()
      let otherKey = Key.init([8'u8])
      check store.add(key, peerId) == AddProviderOutcome.added

      check:
        store.add(otherKey, peerId) == AddProviderOutcome.peerFull
        store.add(key, peerId, Later + 1) == AddProviderOutcome.refreshed
        store.providers(otherKey).len == 0

    test "an expired or removed record frees the quota of its peer":
      let store = factory(KadStoreLimits(maxProviderRecordsPerPeer: 1))
      let peerId = PeerId.random()
      let otherKey = Key.init([8'u8])
      check store.add(key, peerId, expiresAt = Now, now = Now - 1) ==
        AddProviderOutcome.added

      check:
        store.add(otherKey, peerId) == AddProviderOutcome.added
        store.removeProvider(otherKey, peerId).isOk()
        store.add(key, peerId) == AddProviderOutcome.added

    test "a full store drops expired providers to accept a new one":
      let peers = PeerId.random(2)
      let expired = storedProvider(peers[0], expiresAt = Now)
      let fresh = storedProvider(peers[1])

      let totalCapped = factory(KadStoreLimits(maxProviders: 1))
      check:
        totalCapped.addProvider(key, expired, Now - 1, Unlimited) ==
          AddProviderOutcome.added
        totalCapped.addProvider(key, fresh, Now, Unlimited) == AddProviderOutcome.added

      let keyCapped = factory(KadStoreLimits())
      check:
        keyCapped.addProvider(key, expired, Now - 1, 1) == AddProviderOutcome.added
        keyCapped.addProvider(key, fresh, Now, 1) == AddProviderOutcome.added
        keyCapped.getProviders(key, Now, Unlimited) == @[fresh]

    test "a full key drops a provider stored after an earlier drop":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(4)
      check:
        store.add(key, peers[0], expiresAt = Now, now = Now - 1) ==
          AddProviderOutcome.added
        store.add(key, peers[1], now = Now - 1) == AddProviderOutcome.added
        store.add(key, peers[2], Now + 1, maxPerKey = 2) == AddProviderOutcome.added
        store.add(key, peers[3], maxPerKey = 2, now = Now + 1) ==
          AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[3])]
        )

    test "a full key drops a provider added after a drop at the total cap":
      let store = factory(KadStoreLimits(maxProviders: 1))
      let peers = PeerId.random(3)
      check:
        store.add(key, peers[0], expiresAt = Now, now = Now - 1) ==
          AddProviderOutcome.added
        store.add(key, peers[1], Now + 1) == AddProviderOutcome.added
        store.add(key, peers[2], maxPerKey = 1, now = Now + 1) ==
          AddProviderOutcome.added
        store.providers(key) == @[storedProvider(peers[2])]

    test "addProvider rejects a provider without a valid id":
      let store = factory(KadStoreLimits())
      let cases = [
        IdCase(provider: Peer(), cause: "provider without id"),
        IdCase(provider: Peer(id: Opt.some(@[1'u8])), cause: "invalid provider id"),
      ]
      for c in cases:
        let res = store.addProvider(
          key,
          StoredProvider(provider: c.provider, expiresAt: Later, addrsExpireAt: Later),
          Now,
          Unlimited,
        )
        check:
          res.isErr()
          res.isOfError(c.cause)

    test "removeProvider removes only that peer and frees capacity":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(3)
      for peerId in peers[0 .. 1]:
        check store.add(key, peerId) == AddProviderOutcome.added

      check store.removeProvider(key, peers[0]).isOk()

      check:
        store.providers(key) == @[storedProvider(peers[1])]
        store.add(key, peers[2]) == AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2])]
        )

    test "getProviders hides expired providers and caps at limit":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(3)
      check:
        store.add(key, peers[0], expiresAt = Now, now = Now - 1) ==
          AddProviderOutcome.added
        store.add(key, peers[1], now = Now - 1) == AddProviderOutcome.added
        store.add(key, peers[2], now = Now - 1) == AddProviderOutcome.added
        store.providers(key, Now - 1).len == 3

      let live = @[storedProvider(peers[1]), storedProvider(peers[2])]
      let one = store.getProviders(key, Now, 1).get()
      check:
        store.providers(key).sameProviders(live)
        one.len == 1
        one[0] in live
        store.getProviders(key, Now, 0).get().len == 0

    test "getProviders deletes the expired providers":
      let store = factory(KadStoreLimits())
      check store.add(key, PeerId.random(), expiresAt = Now, now = Now - 1) ==
        AddProviderOutcome.added

      check:
        store.providers(key).len == 0
        store.providers(key, Now - 1).len == 0

    test "a provider refreshed past now stays":
      let store = factory(KadStoreLimits())
      let peerId = PeerId.random()
      check:
        store.add(key, peerId, expiresAt = Now, now = Now - 1) ==
          AddProviderOutcome.added
        store.add(key, peerId, now = Now - 1) == AddProviderOutcome.refreshed

      check store.providers(key) == @[storedProvider(peerId)]

    test "a refresh to an earlier expiry moves the provider forward in the eviction order":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(3)
      check:
        store.add(key, peers[0], Later + 5) == AddProviderOutcome.added
        store.add(key, peers[1], Later + 1) == AddProviderOutcome.added
        store.add(key, peers[0], Later) == AddProviderOutcome.refreshed

      check:
        store.add(key, peers[2], Later + 9) == AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[storedProvider(peers[1], Later + 1), storedProvider(peers[2], Later + 9)]
        )

    test "many refreshes keep the eviction order and the pruning exact":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(5)
      check:
        store.add(key, peers[0], Later) == AddProviderOutcome.added
        store.add(key, peers[1], Later + 1) == AddProviderOutcome.added
      for i in 10 .. 20:
        check store.add(key, peers[1], Later + i) == AddProviderOutcome.refreshed

      check:
        store.add(key, peers[2], Later + 30) == AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[storedProvider(peers[1], Later + 20), storedProvider(peers[2], Later + 30)]
        )

      check:
        store.providers(key, Later + 20) == @[storedProvider(peers[2], Later + 30)]
        store.providers(key, Now) == @[storedProvider(peers[2], Later + 30)]
        store.add(key, peers[3], Later + 31) == AddProviderOutcome.added
        store.providers(key, Now).sameProviders(
          @[storedProvider(peers[2], Later + 30), storedProvider(peers[3], Later + 31)]
        )
        store.add(key, peers[4], Later + 32) == AddProviderOutcome.added
        store.providers(key, Now).sameProviders(
          @[storedProvider(peers[3], Later + 31), storedProvider(peers[4], Later + 32)]
        )

    test "removeProvider of an evicted provider does not free capacity":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let other = Key.init([8'u8])
      let peers = PeerId.random(4)
      check:
        store.add(key, peers[0], Later) == AddProviderOutcome.added
        store.add(key, peers[1], Later + 1) == AddProviderOutcome.added
        store.add(other, peers[2], Later + 2) == AddProviderOutcome.added
      check store.removeProvider(key, peers[0]).isOk()

      check:
        store.add(other, peers[3], Later + 3) == AddProviderOutcome.added
        store.providers(key).len == 0
        store.providers(other).sameProviders(
          @[storedProvider(peers[2], Later + 2), storedProvider(peers[3], Later + 3)]
        )

    test "an expiry after removeProvider does not free capacity twice":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(4)
      check:
        store.add(key, peers[0], Now, now = Now - 1) == AddProviderOutcome.added
        store.add(key, peers[1], Later, now = Now - 1) == AddProviderOutcome.added
      check:
        store.removeProvider(key, peers[0]).isOk()
        store.add(key, peers[2], Later + 1, now = Now) == AddProviderOutcome.added

      check:
        store.add(key, peers[3], Later + 2) == AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[storedProvider(peers[2], Later + 1), storedProvider(peers[3], Later + 2)]
        )

    test "removeProvider of an unknown key or peer leaves the count intact":
      let peers = PeerId.random(2)
      let cases = [
        RemoveCase(target: Key.init([8'u8]), peerId: peers[0]),
        RemoveCase(target: key, peerId: peers[1]),
      ]
      for c in cases:
        let store = factory(KadStoreLimits(maxProviders: 1))
        check store.add(key, peers[0]) == AddProviderOutcome.added

        check:
          store.removeProvider(c.target, c.peerId).isOk()
          store.providers(key) == @[storedProvider(peers[0])]
          store.add(Key.init([9'u8]), peers[1], Later + 1) == AddProviderOutcome.added
          store.providers(key).len == 0

    test "an expired provider drop keeps the live providers and counts them exactly":
      let store = factory(KadStoreLimits(maxProviders: 3))
      let peers = PeerId.random(5)
      check:
        store.add(key, peers[0], expiresAt = Now) == AddProviderOutcome.added
        store.add(key, peers[1]) == AddProviderOutcome.added
        store.add(key, peers[2], Later + 1) == AddProviderOutcome.added

      check:
        store.providers(key).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2], Later + 1)]
        )
        store.providers(key, Now - 1).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2], Later + 1)]
        )
        store.add(key, peers[3], Later + 1) == AddProviderOutcome.added
        store.providers(key).len == 3
        store.add(key, peers[4], Later + 1) == AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[
            storedProvider(peers[2], Later + 1),
            storedProvider(peers[3], Later + 1),
            storedProvider(peers[4], Later + 1),
          ]
        )

    test "a refreshed provider at the total cap keeps the count unchanged":
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(3)
      check:
        store.add(key, peers[0]) == AddProviderOutcome.added
        store.add(key, peers[1]) == AddProviderOutcome.added
        store.add(key, peers[0], Later + 1) == AddProviderOutcome.refreshed

      check store.removeProvider(key, peers[0]).isOk()

      check:
        store.add(key, peers[2]) == AddProviderOutcome.added
        store.providers(key).sameProviders(
          @[storedProvider(peers[1]), storedProvider(peers[2])]
        )

  suite name & " provided keys":
    test "addProvided stores the key":
      let store = factory(KadStoreLimits())

      check store.addProvided(pk1).get()

      check:
        store.hasProvided(pk1).get()
        not store.hasProvided(pk2).get()

    test "a re-add refreshes the key without an eviction":
      let store = factory(KadStoreLimits(maxProvided: 2))
      store.provideAll([pk1, pk2, pk2])

      check store.listProvided(pkNone, Unlimited) == @[pk1, pk2].sorted()

      store.provideAll([pk1, pk3])

      check store.listProvided(pkNone, Unlimited) == @[pk1, pk3].sorted()

    test "a new key in a full store evicts the oldest key":
      let store = factory(KadStoreLimits(maxProvided: 2))
      store.provideAll([pk1, pk2, pk3])

      check store.listProvided(pkNone, Unlimited) == @[pk2, pk3].sorted()

    test "delProvided removes the key and frees capacity":
      let store = factory(KadStoreLimits(maxProvided: 2))
      store.provideAll([pk1, pk2])

      check:
        store.delProvided(pk2).isOk()
        store.addProvided(pk3).get()

      check store.listProvided(pkNone, Unlimited) == @[pk1, pk3].sorted()

    test "a store with maxProvided 0 stores no provided key":
      let store = factory(KadStoreLimits(maxProvided: 0))

      check not store.addProvided(pk1).get()

      check not store.hasProvided(pk1).get()

    test "delProvided of an absent key succeeds and keeps the other keys":
      let store = factory(KadStoreLimits())
      store.provideAll([pk1, pk2])

      check store.delProvided(pk3).isOk()

      check store.listProvided(pkNone, Unlimited) == @[pk1, pk2].sorted()

    test "provided keys do not expire":
      let store = factory(KadStoreLimits())
      check store.addProvided(pk1).isOk()

      check:
        store.getProviders(pk1.toKey(), high(UnixTimestamp), Unlimited).get().len == 0
        store.listValues(Opt.none(RecordKey), high(UnixTimestamp), Unlimited).get().len ==
          0
        store.hasProvided(pk1).get()

    test "listProvided returns every key exactly once across pages":
      let store = factory(KadStoreLimits())
      let provided = pagedKeys()
      store.provideAll(provided)

      let keys = provided.sorted()
      let first = store.listProvided(pkNone, PageSize).get()

      check:
        first == keys[0 ..< PageSize]
        store.listProvided(Opt.some(first[^1]), Unlimited) == keys[PageSize ..^ 1]
        store.listProvided(Opt.some(keys[^1]), Unlimited).get().len == 0
        store.listProvided(pkNone, 0).get().len == 0

    test "listProvided pages past keys deleted between pages":
      let store = factory(KadStoreLimits())
      let provided = pagedKeys()
      store.provideAll(provided)

      let first = store.listProvided(pkNone, PageSize).get()
      let rest = provided.sorted()[PageSize ..^ 1]

      check:
        store.delProvided(first[^1]).isOk()
        store.delProvided(rest[0]).isOk()

      check store.listProvided(Opt.some(first[^1]), Unlimited) == rest[1 ..^ 1]
