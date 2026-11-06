# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The contract tests of ``KadStore``. Run them for each backend with ``kadStoreTestSuite``.

import std/[algorithm, sequtils]
import chronos, results
import ../../../libp2p/[peerid, protocols/kademlia]
import ../../tools/[unittest, crypto]

export sequtils, chronos, results, peerid, kademlia, unittest, crypto

const
  Now: UnixTimestamp = 1_000
  Later: UnixTimestamp = Now + 60
  Lifetime = 60.seconds
  Unlimited = high(int)
  PageSize = 3
  ProvidedKeyBytes = [7'u8, 2, 9, 4, 1, 8, 3, 6, 5, 10]

type
  RemoveCase = object
    target: Key
    peerId: PeerId

  IdCase = object
    provider: Peer
    cause: string

func wholeSeconds(d: Duration): int64 =
  doAssert d == d.seconds().seconds(), "sub-second durations truncate: " & $d
  d.seconds()

func `-`(t: UnixTimestamp, d: Duration): UnixTimestamp =
  t - d.wholeSeconds()

func `+`(t: UnixTimestamp, d: Duration): UnixTimestamp =
  t + d.wholeSeconds()

func recordKey(b: byte): RecordKey =
  RecordKey.init(Key.fromBytes(@[b])).get()

proc storedValue(b: byte, ttl = Lifetime): StoredValue =
  StoredValue(
    key: recordKey(b),
    record: EntryRecord(value: Value.init([b]), time: Timestamp.now()),
    ttl: ttl,
  )

proc storedProvider(peerId: PeerId, expiresAt = Later): StoredProvider =
  StoredProvider(provider: Peer(id: Opt.some(peerId.getBytes())), expiresAt: expiresAt)

func peerOf(p: StoredProvider): PeerId =
  PeerId.init(p.provider.id.get()).get()

proc sameProviders(got, want: seq[StoredProvider]): bool =
  let byPeer = proc(a, b: StoredProvider): int =
    cmp(a.peerOf(), b.peerOf())
  got.sorted(byPeer) == want.sorted(byPeer)

func providedKey(b: byte): Key =
  Key.fromBytes(@[b])

const
  pk1 = providedKey(1)
  pk2 = providedKey(2)
  pkNone = Opt.none(Key)

converter toOptInt*(n: int): Opt[int] =
  Opt.some(n)

func `==`*[T](r: LPResult[T], value: T): bool =
  r.isOk() and r.get() == value

template provideAll(store: KadStore, bytes: openArray[byte]) =
  for b in bytes:
    check (await store.addProvided(providedKey(b))).get()

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
        (await store.getValue(value.key, Now)).get() == value
        (await store.getValue(recordKey(2), Now)).get().isNone()

    asyncTest "putValue replaces the value of the key":
      let store = factory(KadStoreLimits())
      # a different ttl tells the replacement from the first value
      let replacement = storedValue(1, Lifetime + 1.seconds)

      check:
        (await store.putValue(storedValue(1), Now)).get()
        (await store.putValue(replacement, Now)).get()
        (await store.getValue(replacement.key, Now)).get() == replacement

    asyncTest "getValue and listValues hide a value once its ttl runs out":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1, ttl = 1.seconds), Now - 1.seconds)).get()

      check:
        (await store.getValue(recordKey(1), Now - 1.seconds)).get().isSome()
        (await store.getValue(recordKey(1), Now)).get().isNone()
        (await store.listValues(Opt.none(RecordKey), Now, Unlimited)).get().len == 0

    asyncTest "getValue deletes the expired value":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1, ttl = 1.seconds), Now - 1.seconds)).get()

      check:
        (await store.getValue(recordKey(1), Now)).get().isNone()
        (await store.getValue(recordKey(1), Now - 1.seconds)).get().isNone()

    asyncTest "listValues deletes the expired values":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1, ttl = 1.seconds), Now - 1.seconds)).get()

      check:
        (await store.listValues(Opt.none(RecordKey), Now, Unlimited)).get().len == 0
        (await store.getValue(recordKey(1), Now - 1.seconds)).get().isNone()

    asyncTest "putValue deletes expired values and keeps live ones":
      let store = factory(KadStoreLimits(maxValues: 2))
      check:
        (await store.putValue(storedValue(1, ttl = 1.seconds), Now - 1.seconds)).get()
        (await store.putValue(storedValue(2), Now - 1.seconds)).get()

      check:
        (await store.putValue(storedValue(3), Now)).get()
        not (await store.putValue(storedValue(4), Now)).get()
        (await store.getValue(recordKey(1), Now - 1.seconds)).get().isNone()
        (await store.getValue(recordKey(2), Now)).get().isSome()

    asyncTest "a full store refuses a new key and accepts a known key":
      let store = factory(KadStoreLimits(maxValues: 1))

      check:
        (await store.putValue(storedValue(1), Now)).get()
        not (await store.putValue(storedValue(2), Now)).get()
        (await store.putValue(storedValue(1, Lifetime + 1.seconds), Now)).get()
        (await store.getValue(recordKey(2), Now)).get().isNone()

    asyncTest "a full store drops expired values to accept a new key":
      let store = factory(KadStoreLimits(maxValues: 1))
      check:
        (await store.putValue(storedValue(1, ttl = 1.seconds), Now - 1.seconds)).get()
        (await store.putValue(storedValue(2), Now)).get()
        (await store.getValue(recordKey(1), Now - 1.seconds)).get().isNone()

    asyncTest "a full store drops a value stored after an earlier drop":
      let store = factory(KadStoreLimits(maxValues: 2))
      check:
        (await store.putValue(storedValue(1, ttl = 1.seconds), Now - 1.seconds)).get()
        (await store.putValue(storedValue(2), Now - 1.seconds)).get()
        (await store.putValue(storedValue(3, ttl = 1.seconds), Now)).get()
        (await store.putValue(storedValue(4), Now + 1.seconds)).get()
        (await store.getValue(recordKey(3), Now)).get().isNone()
        (await store.getValue(recordKey(2), Now + 1.seconds)).get().isSome()

    asyncTest "delValue frees capacity":
      let store = factory(KadStoreLimits(maxValues: 1))
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
        (await store.putValue(StoredValue(key: long, ttl: Lifetime), Now)).get()
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
      let peers = PeerId.random(2)
      for peerId in peers:
        check (await store.add(key, peerId)) == AddProviderOutcome.added

      check:
        (await store.add(key, peers[1], Later + 1)) == AddProviderOutcome.refreshed
        (await store.providers(key)).sameProviders(
          @[storedProvider(peers[0]), storedProvider(peers[1], Later + 1)]
        )

    asyncTest "a full store evicts nothing for a provider that expires no later":
      let store = factory(KadStoreLimits(maxProviders: 1))
      let peers = PeerId.random(3)
      check (await store.add(key, peers[0])) == AddProviderOutcome.added

      check:
        (await store.add(key, peers[1])) == AddProviderOutcome.storeFull
        (await store.add(key, peers[2], expiresAt = Now)) == AddProviderOutcome.storeFull
        (await store.providers(key)) == @[storedProvider(peers[0])]

    asyncTest "a store with a total cap of 0 gives storeFull":
      let store = factory(KadStoreLimits(maxProviders: 0))

      check:
        (await store.add(key, PeerId.random())) == AddProviderOutcome.storeFull
        (await store.providers(key)).len == 0

    asyncTest "a new record of a peer gets peerFull at the cap per peer":
      let store = factory(KadStoreLimits(maxProviderRecordsPerPeer: 1))
      let peerId = PeerId.random()
      let otherKey = Key.init([8'u8])
      check (await store.add(key, peerId)) == AddProviderOutcome.added

      check:
        (await store.add(otherKey, peerId)) == AddProviderOutcome.peerFull
        (await store.add(key, peerId, Later + 1)) == AddProviderOutcome.refreshed
        (await store.providers(otherKey)).len == 0

    asyncTest "an expired or removed record frees the quota of its peer":
      let store = factory(KadStoreLimits(maxProviderRecordsPerPeer: 1))
      let peerId = PeerId.random()
      let otherKey = Key.init([8'u8])
      check (await store.add(key, peerId, expiresAt = Now, now = Now - 1)) ==
        AddProviderOutcome.added

      check:
        (await store.add(otherKey, peerId)) == AddProviderOutcome.added
        (await store.removeProvider(otherKey, peerId)).isOk()
        (await store.add(key, peerId)) == AddProviderOutcome.added

    asyncTest "a full store drops expired providers to accept a new one":
      let peers = PeerId.random(2)
      let expired = storedProvider(peers[0], expiresAt = Now)
      let fresh = storedProvider(peers[1])

      let totalCapped = factory(KadStoreLimits(maxProviders: 1))
      check:
        (await totalCapped.addProvider(key, expired, Now - 1, Unlimited)) ==
          AddProviderOutcome.added
        (await totalCapped.addProvider(key, fresh, Now, Unlimited)) ==
          AddProviderOutcome.added

      let keyCapped = factory(KadStoreLimits())
      check:
        (await keyCapped.addProvider(key, expired, Now - 1, 1)) ==
          AddProviderOutcome.added
        (await keyCapped.addProvider(key, fresh, Now, 1)) == AddProviderOutcome.added
        (await keyCapped.getProviders(key, Now, Unlimited)) == @[fresh]

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
      let store = factory(KadStoreLimits(maxProviders: 1))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
        let store = factory(KadStoreLimits(maxProviders: 1))
        check (await store.add(key, peers[0])) == AddProviderOutcome.added

        check:
          (await store.removeProvider(c.target, c.peerId)).isOk()
          (await store.providers(key)) == @[storedProvider(peers[0])]
          (await store.add(Key.init([9'u8]), peers[1], Later + 1)) ==
            AddProviderOutcome.added
          (await store.providers(key)).len == 0

    asyncTest "an expired provider drop keeps the live providers and counts them exactly":
      let store = factory(KadStoreLimits(maxProviders: 3))
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
      let store = factory(KadStoreLimits(maxProviders: 2))
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
    asyncTest "addProvided stores the key":
      let store = factory(KadStoreLimits())

      check (await store.addProvided(pk1)).get()

      check:
        (await store.hasProvided(pk1)).get()
        not (await store.hasProvided(pk2)).get()

    asyncTest "a re-add refreshes the key without an eviction":
      let store = factory(KadStoreLimits(maxProvided: 2))
      store.provideAll([1'u8, 2, 2])

      check (await store.listProvided(pkNone, Unlimited)) == @[pk1, pk2]

      store.provideAll([1'u8, 3])

      check (await store.listProvided(pkNone, Unlimited)) == @[pk1, providedKey(3)]

    asyncTest "a new key in a full store evicts the oldest key":
      let store = factory(KadStoreLimits(maxProvided: 2))
      store.provideAll([1'u8, 2, 3])

      check (await store.listProvided(pkNone, Unlimited)) == @[pk2, providedKey(3)]

    asyncTest "delProvided removes the key and frees capacity":
      let store = factory(KadStoreLimits(maxProvided: 2))
      store.provideAll([1'u8, 2])

      check:
        (await store.delProvided(pk2)).isOk()
        (await store.addProvided(providedKey(3))).get()

      check (await store.listProvided(pkNone, Unlimited)) == @[pk1, providedKey(3)]

    asyncTest "a store with maxProvided 0 stores no provided key":
      let store = factory(KadStoreLimits(maxProvided: 0))

      check not (await store.addProvided(pk1)).get()

      check not (await store.hasProvided(pk1)).get()

    asyncTest "delProvided of an absent key succeeds and keeps the other keys":
      let store = factory(KadStoreLimits())
      store.provideAll([1'u8, 2])

      check (await store.delProvided(providedKey(3))).isOk()

      check (await store.listProvided(pkNone, Unlimited)) == @[pk1, pk2]

    asyncTest "provided keys do not expire":
      let store = factory(KadStoreLimits())
      check (await store.addProvided(pk1)).isOk()

      check:
        (await store.getProviders(pk1, high(UnixTimestamp), Unlimited)).get().len == 0
        (await store.listValues(Opt.none(RecordKey), high(UnixTimestamp), Unlimited)).get().len ==
          0
        (await store.hasProvided(pk1)).get()

    asyncTest "listProvided returns every key exactly once across pages":
      let store = factory(KadStoreLimits())
      store.provideAll(ProvidedKeyBytes)

      let keys = ProvidedKeyBytes.sorted().mapIt(providedKey(it))
      let first = (await store.listProvided(pkNone, PageSize)).get()

      check:
        first == keys[0 ..< PageSize]
        (await store.listProvided(Opt.some(first[^1]), Unlimited)) ==
          keys[PageSize ..^ 1]
        (await store.listProvided(Opt.some(keys[^1]), Unlimited)).get().len == 0
        (await store.listProvided(pkNone, 0)).get().len == 0

    asyncTest "listProvided pages past keys deleted between pages":
      let store = factory(KadStoreLimits())
      store.provideAll(ProvidedKeyBytes)

      let first = (await store.listProvided(pkNone, PageSize)).get()
      let rest = ProvidedKeyBytes.sorted().mapIt(providedKey(it))[PageSize ..^ 1]

      check:
        (await store.delProvided(first[^1])).isOk()
        (await store.delProvided(rest[0])).isOk()

      check (await store.listProvided(Opt.some(first[^1]), Unlimited)) == rest[1 ..^ 1]
