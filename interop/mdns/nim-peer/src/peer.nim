# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import os, strutils, chronos
import ../../../../libp2p/results
import ../../../../tests/interop/mdns

proc run(args: seq[string], timeout: Duration): LPResult[void] =
  if args.len != 1:
    return err("usage: peer EXPECTED_PEERS")

  let expected =
    try:
      parseInt(args[0])
    except ValueError:
      return err("expected peer count must be a positive integer")

  try:
    waitFor mdnsInteropTest(expected, timeout)
  except CancelledError:
    err("mDNS interoperability test cancelled")

when isMainModule:
  let outcome = run(commandLineParams(), 60.seconds)
  if outcome.isErr:
    quit($outcome.error, 1)
  echo "mDNS interoperability test passed"
