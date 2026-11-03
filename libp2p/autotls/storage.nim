# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, tables, uri

import ./acme/api, ../results, ../utils/opt

type AutotlsStorageKey* = object
  ## Identifies state belonging to one AutoTLS identity and ACME deployment.
  peerLabel*: string
  acmeDirectoryURL*: Uri
  domainSuffix*: string

type AutotlsStoredState* = object
  ## Serializable AutoTLS state. Private-key fields contain sensitive material
  ## and storage implementations must protect them appropriately.
  accountKey*: seq[byte] ## RSA private key encoded as DER.
  accountKid*: Kid
  certificatePem*: string
  certificateKeyPem*: string

type AutotlsStorage* = ref object of RootObj
  ## Application-owned persistence for AutoTLS state, indexed by storage key.
  ## Saving a key replaces its previous state without affecting other keys.

proc sameStorageKey*(a, b: AutotlsStorageKey): bool =
  a.peerLabel == b.peerLabel and a.domainSuffix == b.domainSuffix and
    $a.acmeDirectoryURL == $b.acmeDirectoryURL

method load*(
    self: AutotlsStorage, key: AutotlsStorageKey
): Future[LPResult[Opt[AutotlsStoredState]]] {.base, async: (raises: [CancelledError]).} =
  raiseAssert "AutotlsStorage.load must be implemented"

method save*(
    self: AutotlsStorage, key: AutotlsStorageKey, state: AutotlsStoredState
): Future[LPResult[void]] {.base, async: (raises: [CancelledError]).} =
  raiseAssert "AutotlsStorage.save must be implemented"

type AutotlsMemoryStorage* = ref object of AutotlsStorage
  ## A process-local storage implementation, useful for tests and embedders
  ## that want the storage lifecycle to be explicit.
  states:
    Table[tuple[peerLabel, directoryURL, domainSuffix: string], AutotlsStoredState]

proc tableKey(
    key: AutotlsStorageKey
): tuple[peerLabel, directoryURL, domainSuffix: string] =
  (key.peerLabel, $key.acmeDirectoryURL, key.domainSuffix)

proc new*(T: typedesc[AutotlsMemoryStorage]): T =
  T()

method load*(
    self: AutotlsMemoryStorage, key: AutotlsStorageKey
): Future[LPResult[Opt[AutotlsStoredState]]] {.async: (raises: [CancelledError]).} =
  let index = key.tableKey()
  if index in self.states:
    return ok(Opt.some(self.states.getOrDefault(index)))
  ok(Opt.none(AutotlsStoredState))

method save*(
    self: AutotlsMemoryStorage, key: AutotlsStorageKey, state: AutotlsStoredState
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  self.states[key.tableKey()] = state
  ok()
