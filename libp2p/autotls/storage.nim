# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, uri

import
  ./acme/api,
  ../results,
  ../utils/opt

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
  ## Application-owned persistence for AutoTLS state.

type AutotlsMemoryStorage* = ref object of AutotlsStorage
  ## A process-local storage implementation, useful for tests and embedders
  ## that want the storage lifecycle to be explicit.
  key: Opt[AutotlsStorageKey]
  state: Opt[AutotlsStoredState]

method load*(
    self: AutotlsStorage, key: AutotlsStorageKey
): Future[LPResult[Opt[AutotlsStoredState]]] {.base, async: (raises: [CancelledError]).} =
  ok(Opt.none(AutotlsStoredState))

method save*(
    self: AutotlsStorage, key: AutotlsStorageKey, state: AutotlsStoredState
): Future[LPResult[void]] {.base, async: (raises: [CancelledError]).} =
  ok()

proc new*(T: typedesc[AutotlsMemoryStorage]): T =
  T(key: Opt.none(AutotlsStorageKey), state: Opt.none(AutotlsStoredState))

proc sameStorageKey(a, b: AutotlsStorageKey): bool =
  a.peerLabel == b.peerLabel and a.domainSuffix == b.domainSuffix and
    $a.acmeDirectoryURL == $b.acmeDirectoryURL

method load*(
    self: AutotlsMemoryStorage, key: AutotlsStorageKey
): Future[LPResult[Opt[AutotlsStoredState]]] {.async: (raises: [CancelledError]).} =
  if self.key.isSome() and sameStorageKey(self.key.get(), key):
    return ok(self.state)
  ok(Opt.none(AutotlsStoredState))

method save*(
    self: AutotlsMemoryStorage, key: AutotlsStorageKey, state: AutotlsStoredState
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  self.key = Opt.some(key)
  self.state = Opt.some(state)
  ok()
