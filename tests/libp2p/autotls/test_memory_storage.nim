# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../libp2p/autotls/storage
import ./suite_autotiles_storage

proc newMemoryStorage(): AutotlsStorage =
  AutotlsMemoryStorage.new()

autotlsStorageTestSuite("AutoTLS memory storage", newMemoryStorage)
