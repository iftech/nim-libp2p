# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos

proc since*(T: typedesc[Moment], start: Moment): Duration {.inline.} =
  ## The time elapsed from `start` until now.
  Moment.now() - start

func toMilliseconds*(d: Duration): float64 {.inline.} =
  ## `d` in milliseconds, keeping the sub-millisecond part that
  ## `Duration.milliseconds` truncates.
  float64(d.nanoseconds) / 1_000_000.0
