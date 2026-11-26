# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/os
import chronos
import ../../../../libp2p/results
import ../../../../tests/interop/mdns

when isMainModule:
  let outcome = runMdnsInterop(commandLineParams(), 60.seconds)
  if outcome.isErr:
    quit($outcome.error, 1)
  echo "mDNS interoperability test passed"
