# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import std/tables

type
  MulticastLimit = object
    pending: bool
    nextResponse: Moment

  MulticastLimits* = object
    families: array[bool, MulticastLimit]

  InterfaceLimits* = object
    entries: Table[uint32, ref MulticastLimits]

proc newInterfaceLimits*(): ref InterfaceLimits =
  new(InterfaceLimits)

proc get*(limits: ref InterfaceLimits, index: uint32): ref MulticastLimits =
  var entry = limits.entries.getOrDefault(index)
  if entry.isNil:
    entry = new(MulticastLimits)
    limits.entries[index] = entry
  return entry

proc prune*(limits: ref InterfaceLimits, indices: openArray[uint32]) =
  var removed: seq[uint32]
  for index in limits.entries.keys:
    if index notin indices:
      removed.add(index)
  for index in removed:
    limits.entries.del(index)

proc clear*(limits: ref InterfaceLimits) =
  limits.entries.clear()

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
