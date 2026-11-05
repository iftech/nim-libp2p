# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Reusable contract tests for AutoTLS storage implementations.

import chronos, results, uri
import ../../../libp2p/autotls/[storage, acme/api]
import ../../tools/unittest

export chronos, results, storage, unittest

proc storageKey(): AutotlsStorageKey =
  AutotlsStorageKey(
    peerLabel: "peer-one",
    acmeDirectoryURL: parseUri("https://acme.example/directory"),
    domainSuffix: "example.test",
  )

proc storedState(): AutotlsStoredState =
  AutotlsStoredState(
    accountKey: @[1.byte, 2, 3],
    accountKid: Kid("https://acme.example/account/1"),
    certificatePem: "certificate",
    certificateKeyPem: "certificate key",
  )

template autotlsStorageTestSuite*(name: string, factory: proc(): AutotlsStorage) =
  ## The factory must return a fresh, empty storage instance for each test.
  suite name:
    asyncTest "a new store has no state":
      let storage = factory()
      check (await storage.load(storageKey())).get().isNone()

    asyncTest "saved state is returned for its key":
      let storage = factory()
      let state = storedState()
      check (await storage.save(storageKey(), state)).isOk()
      let loaded = (await storage.load(storageKey())).get().get()
      check:
        loaded.accountKey == state.accountKey
        loaded.accountKid == state.accountKid
        loaded.certificatePem == state.certificatePem
        loaded.certificateKeyPem == state.certificateKeyPem

    asyncTest "each part of the key identifies the state":
      let storage = factory()
      let key = storageKey()
      check (await storage.save(key, storedState())).isOk()
      var differentPeer = key
      differentPeer.peerLabel = "peer-two"
      var differentDirectory = key
      differentDirectory.acmeDirectoryURL = parseUri("https://other.example/directory")
      var differentSuffix = key
      differentSuffix.domainSuffix = "other.test"
      for differentKey in [differentPeer, differentDirectory, differentSuffix]:
        check (await storage.load(differentKey)).get().isNone()
      check (await storage.load(key)).get().isSome()

    asyncTest "saving again replaces state for the same key":
      let storage = factory()
      let key = storageKey()
      check (await storage.save(key, storedState())).isOk()
      let replacement = AutotlsStoredState(
        accountKey: @[9.byte],
        accountKid: Kid("replacement"),
        certificatePem: "new certificate",
        certificateKeyPem: "new key",
      )
      check (await storage.save(key, replacement)).isOk()
      let loaded = (await storage.load(key)).get().get()
      check:
        loaded.accountKey == replacement.accountKey
        loaded.accountKid == replacement.accountKid
        loaded.certificatePem == replacement.certificatePem
        loaded.certificateKeyPem == replacement.certificateKeyPem

    asyncTest "multiple keys retain independent states when one is replaced":
      let storage = factory()
      let firstKey = storageKey()
      var secondKey = firstKey
      secondKey.peerLabel = "peer-two"
      var thirdKey = firstKey
      thirdKey.acmeDirectoryURL = parseUri("https://other.example/directory")
      var fourthKey = firstKey
      fourthKey.domainSuffix = "other.test"
      let keys = [firstKey, secondKey, thirdKey, fourthKey]
      for i, key in keys:
        var state = storedState()
        state.accountKey = @[byte(i)]
        check (await storage.save(key, state)).isOk()

      var replacement = storedState()
      replacement.accountKey = @[99.byte]
      check (await storage.save(secondKey, replacement)).isOk()
      for i, key in keys:
        let loaded = (await storage.load(key)).get().get()
        check loaded.accountKey == (if i == 1: @[99.byte] else: @[byte(i)])
