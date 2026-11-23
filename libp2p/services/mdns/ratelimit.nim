# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos

type
  MulticastLimit = object
    pending: bool
    nextResponse: Moment

  MulticastLimits* = object
    families: array[bool, MulticastLimit]

proc acquire*(limits: var MulticastLimits, ipv6: bool, now: Moment): bool =
  if limits.families[ipv6].pending or now < limits.families[ipv6].nextResponse:
    return false
  limits.families[ipv6].pending = true
  true

proc finish*(
    limits: var MulticastLimits, ipv6: bool, sent: bool, now: Moment, interval: Duration
) =
  if sent:
    limits.families[ipv6].nextResponse = now + interval
  limits.families[ipv6].pending = false
