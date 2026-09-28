# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import chronicles
import macros
import ./results

export results

{.push raises: [].}

type
  # Base exception type for libp2p
  LPError* = object of CatchableError

func toException*(e: cstring): ref LPError =
  (ref LPError)(msg: $e)

func toException*(e: string): ref LPError =
  (ref LPError)(msg: e)

func `==`*[E: enum](e: ref LPError, failure: E): bool =
  e.msg == $failure

# TODO: could not figure how to make it with a simple template
# sadly nim needs more love for hygienic templates
# so here goes the macro, its based on the proc/template version
# and uses quote do so it's quite readable
# TODO https://github.com/nim-lang/Nim/issues/22936
macro checkFutures*[F](futs: seq[F], exclude: untyped = []): untyped =
  let nexclude = exclude.len
  case nexclude
  of 0:
    quote:
      for res in `futs`:
        logScope:
          topics = "libp2p futures"
        if res.failed:
          let exc = res.error
          # We still don't abort but warn
          trace "Future failed",
            err = exc.msg, errType = exc.name, stack = getStackTrace()
  else:
    quote:
      for res in `futs`:
        logScope:
          topics = "libp2p futures"
        block check:
          if res.failed:
            let exc = res.error
            for i in 0 ..< `nexclude`:
              if exc of `exclude`[i]:
                trace "Future failed", err = exc.msg, errType = exc.name
                break check
            # We still don't abort but warn
            trace "Future failed", err = exc.msg, errType = exc.name
