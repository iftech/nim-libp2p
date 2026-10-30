# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The contract tests of ``KadStore``. Run them for each backend with ``kadStoreTestSuite``.

import std/sequtils
import chronos, results
import ../../../libp2p/[peerid, protocols/kademlia]
import ../../tools/[unittest, crypto]

export sequtils, chronos, results, peerid, kademlia, unittest, crypto

const
  Now*: UnixTimestamp = 1_000
  Later*: UnixTimestamp = Now + 60
  Unlimited* = high(int)

type RemoveCase = object
  target: Key
  peerId: PeerId

func recordKey*(b: byte): RecordKey =
  RecordKey.init(Key.fromBytes(@[b])).get()

proc storedValue*(b: byte, expiresAt = Later): StoredValue =
  StoredValue(
    key: recordKey(b),
    record: EntryRecord(value: Value.init([b]), time: Timestamp.now()),
    expiresAt: expiresAt,
  )

proc storedProvider*(peerId: PeerId, expiresAt = Later): StoredProvider =
  StoredProvider(provider: Peer(id: Opt.some(peerId.getBytes())), expiresAt: expiresAt)

proc valueKeys(values: seq[StoredValue]): seq[Key] =
  var keys: seq[Key]
  for value in values:
    keys.add(value.key.toKey())
  keys

template kadStoreTestSuite*(name: string, factory: untyped) =
  ## ``factory(limits)`` returns a new empty store that enforces ``limits``.
  suite name & " values":
    asyncTest "putValue then getValue returns the value":
      let store = factory(KadStoreLimits())
      let value = storedValue(1)

      check:
        (await store.putValue(value)).get()
        (await store.getValue(value.key, Now)).get() == Opt.some(value)
        (await store.getValue(recordKey(2), Now)).get().isNone()

    asyncTest "putValue replaces the value of the key":
      let store = factory(KadStoreLimits())
      let replacement = storedValue(1, Later + 1)

      check:
        (await store.putValue(storedValue(1))).get()
        (await store.putValue(replacement)).get()
        (await store.getValue(replacement.key, Now)).get() == Opt.some(replacement)

    asyncTest "getValue and listValues hide a value with expiresAt <= now":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1, expiresAt = Now))).get()

      check:
        (await store.getValue(recordKey(1), Now)).get().isNone()
        (await store.getValue(recordKey(1), Now - 1)).get().isSome()
        (await store.listValues(Opt.none(RecordKey), Now, Unlimited)).get().len == 0

    asyncTest "pruneExpired deletes expired values and keeps live ones":
      let store = factory(KadStoreLimits())
      check:
        (await store.putValue(storedValue(1, expiresAt = Now))).get()
        (await store.putValue(storedValue(2))).get()

      check (await store.pruneExpired(Now)).isOk()

      check:
        (await store.getValue(recordKey(1), Now - 1)).get().isNone()
        (await store.getValue(recordKey(2), Now)).get().isSome()

    asyncTest "pruneExpired frees capacity":
      let store = factory(KadStoreLimits(maxValues: Opt.some(1)))
      check (await store.putValue(storedValue(1, expiresAt = Now))).get()

      check (await store.pruneExpired(Now)).isOk()

      check (await store.putValue(storedValue(2))).get()

    asyncTest "a full store refuses a new key and accepts a known key":
      let store = factory(KadStoreLimits(maxValues: Opt.some(1)))

      check:
        (await store.putValue(storedValue(1))).get()
        not (await store.putValue(storedValue(2))).get()
        (await store.putValue(storedValue(1, Later + 1))).get()
        (await store.getValue(recordKey(2), Now)).get().isNone()

    asyncTest "delValue frees capacity":
      let store = factory(KadStoreLimits(maxValues: Opt.some(1)))
      check (await store.putValue(storedValue(1))).get()

      check (await store.delValue(recordKey(1))).isOk()

      check:
        (await store.getValue(recordKey(1), Now)).get().isNone()
        (await store.putValue(storedValue(2))).get()

    asyncTest "listValues pages in key byte order and after is exclusive across a delete":
      let store = factory(KadStoreLimits())
      for b in [3'u8, 1, 4, 2]:
        check (await store.putValue(storedValue(b))).get()

      let first = (await store.listValues(Opt.none(RecordKey), Now, 2)).get()
      check (await store.delValue(first[^1].key)).isOk()
      let second = (await store.listValues(Opt.some(first[^1].key), Now, 2)).get()
      let last = (await store.listValues(Opt.some(second[^1].key), Now, 2)).get()

      check:
        first.valueKeys() == @[recordKey(1).toKey(), recordKey(2).toKey()]
        second.valueKeys() == @[recordKey(3).toKey(), recordKey(4).toKey()]
        last.len == 0

    asyncTest "listValues orders a key before its extension":
      let store = factory(KadStoreLimits())
      let long = RecordKey.init(Key.fromBytes(@[1'u8, 0])).get()
      check:
        (await store.putValue(StoredValue(key: long, expiresAt: Later))).get()
        (await store.putValue(storedValue(1))).get()

      check (await store.listValues(Opt.none(RecordKey), Now, Unlimited))
        .get()
        .valueKeys() == @[recordKey(1).toKey(), long.toKey()]

    asyncTest "listValues with limit below 1 returns no entries":
      let store = factory(KadStoreLimits())
      check (await store.putValue(storedValue(1))).get()

      for limit in [0, -1]:
        check (await store.listValues(Opt.none(RecordKey), Now, limit)).get().len == 0

  suite name & " providers":
    let key = Key.init([7'u8])

    asyncTest "addProvider adds, then refreshes the same peer":
      let store = factory(KadStoreLimits())
      let peerId = PeerId.random()

      check:
        (await store.addProvider(key, storedProvider(peerId), 1)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peerId, Later + 1), 1)).get() ==
          AddProviderOutcome.refreshed
        (await store.getProviders(key, Now, Unlimited)).get() ==
          @[storedProvider(peerId, Later + 1)]

    asyncTest "a known provider refreshes when the key is full":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(2)
      check:
        (await store.addProvider(key, storedProvider(peers[0]), 2)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[1]), 2)).get() ==
          AddProviderOutcome.added

      check (await store.addProvider(key, storedProvider(peers[0]), 2)).get() ==
        AddProviderOutcome.refreshed

    asyncTest "a new provider gets keyFull at maxPerKey":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(2)
      check (await store.addProvider(key, storedProvider(peers[0]), 1)).get() ==
        AddProviderOutcome.added

      check:
        (await store.addProvider(key, storedProvider(peers[1]), 1)).get() ==
          AddProviderOutcome.keyFull
        (await store.addProvider(Key.init([8'u8]), storedProvider(peers[1]), 0)).get() ==
          AddProviderOutcome.keyFull
        (await store.getProviders(key, Now, Unlimited)).get().len == 1

    asyncTest "a new provider gets storeFull at the total cap":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(1)))
      let peers = PeerId.random(2)
      check (await store.addProvider(key, storedProvider(peers[0]), Unlimited)).get() ==
        AddProviderOutcome.added

      check:
        (await store.addProvider(Key.init([8'u8]), storedProvider(peers[1]), Unlimited)).get() ==
          AddProviderOutcome.storeFull
        (await store.addProvider(key, storedProvider(peers[0]), Unlimited)).get() ==
          AddProviderOutcome.refreshed

    asyncTest "addProvider rejects a provider without an id":
      let store = factory(KadStoreLimits())
      let res =
        (await store.addProvider(key, StoredProvider(expiresAt: Later), Unlimited))

      check:
        res.isErr()
        res.isOfError("provider without id")

    asyncTest "removeProvider removes only that peer and frees capacity":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(3)
      for peerId in peers[0 .. 1]:
        check (await store.addProvider(key, storedProvider(peerId), Unlimited)).get() ==
          AddProviderOutcome.added

      check (await store.removeProvider(key, peers[0])).isOk()

      check:
        (await store.getProviders(key, Now, Unlimited)).get() ==
          @[storedProvider(peers[1])]
        (await store.addProvider(key, storedProvider(peers[2]), Unlimited)).get() ==
          AddProviderOutcome.added

    asyncTest "getProviders hides expired providers and caps at limit":
      let store = factory(KadStoreLimits())
      let peers = PeerId.random(3)
      check:
        (
          await store.addProvider(
            key, storedProvider(peers[0], expiresAt = Now), Unlimited
          )
        ).get() == AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[1]), Unlimited)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[2]), Unlimited)).get() ==
          AddProviderOutcome.added

      check:
        (await store.getProviders(key, Now, Unlimited)).get() ==
          @[storedProvider(peers[1]), storedProvider(peers[2])]
        (await store.getProviders(key, Now, 1)).get() == @[storedProvider(peers[1])]
        (await store.getProviders(key, Now, 0)).get().len == 0

    asyncTest "pruneExpired deletes expired providers and frees capacity":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(1)))
      let peers = PeerId.random(2)
      check (
        await store.addProvider(
          key, storedProvider(peers[0], expiresAt = Now), Unlimited
        )
      ).get() == AddProviderOutcome.added

      check (await store.pruneExpired(Now)).isOk()

      check:
        (await store.getProviders(key, Now - 1, Unlimited)).get().len == 0
        (await store.addProvider(key, storedProvider(peers[1]), Unlimited)).get() ==
          AddProviderOutcome.added

    asyncTest "removeProvider of an unknown key or peer leaves the count intact":
      let peers = PeerId.random(2)
      let cases = [
        RemoveCase(target: Key.init([8'u8]), peerId: peers[0]),
        RemoveCase(target: key, peerId: peers[1]),
      ]
      for c in cases:
        let store = factory(KadStoreLimits(maxProviders: Opt.some(1)))
        check (await store.addProvider(key, storedProvider(peers[0]), Unlimited)).get() ==
          AddProviderOutcome.added

        check:
          (await store.removeProvider(c.target, c.peerId)).isOk()
          (await store.getProviders(key, Now, Unlimited)).get() ==
            @[storedProvider(peers[0])]
          (
            await store.addProvider(
              Key.init([9'u8]), storedProvider(peers[1]), Unlimited
            )
          ).get() == AddProviderOutcome.storeFull

    asyncTest "pruneExpired keeps the live providers of a key and counts them exactly":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(3)))
      let peers = PeerId.random(5)
      check:
        (
          await store.addProvider(
            key, storedProvider(peers[0], expiresAt = Now), Unlimited
          )
        ).get() == AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[1]), Unlimited)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[2]), Unlimited)).get() ==
          AddProviderOutcome.added

      check (await store.pruneExpired(Now)).isOk()

      check:
        (await store.getProviders(key, Now - 1, Unlimited)).get() ==
          @[storedProvider(peers[1]), storedProvider(peers[2])]
        (await store.addProvider(key, storedProvider(peers[3]), Unlimited)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[4]), Unlimited)).get() ==
          AddProviderOutcome.storeFull

    asyncTest "a refreshed provider at storeFull keeps the count unchanged":
      let store = factory(KadStoreLimits(maxProviders: Opt.some(2)))
      let peers = PeerId.random(4)
      check:
        (await store.addProvider(key, storedProvider(peers[0]), Unlimited)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[1]), Unlimited)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[0], Later + 1), Unlimited)).get() ==
          AddProviderOutcome.refreshed

      check (await store.removeProvider(key, peers[0])).isOk()

      check:
        (await store.addProvider(key, storedProvider(peers[2]), Unlimited)).get() ==
          AddProviderOutcome.added
        (await store.addProvider(key, storedProvider(peers[3]), Unlimited)).get() ==
          AddProviderOutcome.storeFull

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

    asyncTest "provided keys survive pruneExpired":
      let store = factory(KadStoreLimits())
      check (await store.addProvided(Key.init([1'u8]))).get()

      check (await store.pruneExpired(high(UnixTimestamp))).isOk()

      check (await store.hasProvided(Key.init([1'u8]))).get()

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
