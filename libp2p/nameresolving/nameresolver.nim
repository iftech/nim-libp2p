# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils, strutils, tables]
import chronos, chronicles
import ../[multiaddress, multicodec]

logScope:
  topics = "libp2p name-resolution"

const
  MaxDnsLookups* = 32 ## Total resolver calls across all branches of one expansion.
  MaxDnsaddrRecursion* = 4 ## Maximum DNSADDR lookups along one branch.
  MaxDnsaddrRecords* = 16 ## TXT records inspected per response, including invalid ones.
  MaxResolvedAddresses* = 100
    ## Outputs per expansion and IP records inspected per lookup.

type
  NameResolver* = ref object of RootObj

  ResolutionState = ref object
    dnsaddrOnly: bool
    lookups: int
    visited: Table[MultiAddress, int]
    addresses: OrderedSet[MultiAddress]

method start*(self: NameResolver) {.base, gcsafe.} =
  ## Prepare for reuse after stop; resolvers without persistent resources do nothing.
  discard

method stop*(self: NameResolver) {.base, async: (raises: []).} =
  ## Release owned resources. Resolvers without persistent resources do nothing.
  discard

method resolveTxt*(
    self: NameResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]), base.} =
  ## Get TXT record
  raiseAssert "[NameResolver.resolveTxt] abstract method not implemented!"

method resolveIp*(
    self: NameResolver, address: string, port: Port, domain: Domain = Domain.AF_UNSPEC
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError]), base
.} =
  ## Resolve the specified address
  raiseAssert "[NameResolver.resolveIp] abstract method not implemented!"

proc containsDnsComponent*(ma: MultiAddress): bool =
  ## True when any component needs DNS resolution, including behind a prefix.
  for partResult in ma:
    let part = partResult.valueOr:
      return false
    if DNS.match(part):
      return true
  false

proc getHostname*(ma: MultiAddress): string =
  ## Prefer the first DNS name, falling back to the first IP literal.
  ## A prefix may identify a relay rather than the named destination.
  var firstIp = ""
  for partResult in ma:
    let part = partResult.valueOr:
      return ""
    if DNS.match(part):
      return ($part).split('/', 2)[2]
    if firstIp.len == 0 and (IP4.match(part) or IP6.match(part)):
      firstIp = ($part).split('/', 2)[2]
  firstIp

proc expand(
    self: NameResolver, address: MultiAddress, depth: int, state: ResolutionState
) {.async: (raises: [CancelledError, MaError, TransportAddressError]).} =
  if state.addresses.len >= MaxResolvedAddresses:
    return

  var
    prefix, component, suffix: MultiAddress
    suffixLength = 0
  for partResult in address:
    let part = partResult.valueOr:
      raise maErr error
    if not component.isEmpty:
      suffix &= part
      inc suffixLength
    elif (if state.dnsaddrOnly: DNSADDR.match(part)
    else: DNS.match(part)):
      component = part
    else:
      prefix &= part

  if component.isEmpty:
    state.addresses.incl(address)
    return

  let isDnsaddr = DNSADDR.match(component)
  if state.lookups >= MaxDnsLookups or (isDnsaddr and depth >= MaxDnsaddrRecursion):
    return
  # Revisit only when a shorter path leaves more DNSADDR recursion budget.
  # This also cuts cycles and duplicate branches without an expansion queue.
  if state.visited.getOrDefault(address, high(int)) <= depth:
    return
  state.visited[address] = depth
  inc state.lookups
  trace "Resolving DNS component", address = component

  if isDnsaddr:
    let records = await self.resolveTxt("_dnsaddr." & component.getHostname())
    for i in 0 ..< min(records.len, MaxDnsaddrRecords):
      if state.addresses.len >= MaxResolvedAddresses:
        break
      let record = records[i]
      if not record.startsWith("dnsaddr="):
        continue
      let entry = MultiAddress.init(record.substr(8)).valueOr:
        continue
      if entry.isEmpty:
        continue
      if suffixLength > 0:
        let length = entry.len.valueOr:
          raise maErr error
        if length < suffixLength:
          continue
        var tail = entry[length - suffixLength ..< length].valueOr:
          raise maErr error
        if tail != suffix:
          continue
      await self.expand(prefix & entry, depth + 1, state)
  else:
    let domain =
      if DNS4.match(component):
        Domain.AF_INET
      elif DNS6.match(component):
        Domain.AF_INET6
      else:
        Domain.AF_UNSPEC
    # Only the IP component is replaced; the original transport/port stays intact.
    let records = await self.resolveIp(component.getHostname(), Port(0), domain)
    for i in 0 ..< min(records.len, MaxResolvedAddresses):
      if state.addresses.len >= MaxResolvedAddresses:
        break
      let resolved = MultiAddress.init(records[i]).valueOr:
        raise maErr error
      let ip = resolved[0].valueOr:
        raise maErr error
      await self.expand(prefix & ip & suffix, depth, state)

proc resolveDnsAddr*(
    self: NameResolver, ma: MultiAddress, depth: int = 0
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  ## Expand DNSADDR records with exact suffix matching, leaving IP names unresolved.
  ## Preserve answer order, deduplicate outputs, and return partial results at limits.
  let state = ResolutionState(dnsaddrOnly: true)
  await self.expand(ma, depth, state)
  state.addresses.toSeq

proc resolveMAddress*(
    self: NameResolver, address: MultiAddress
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  ## Resolve every DNS component, preserving surrounding protocols and answer order.
  ## All branches share the lookup/output budgets; unresolved branches are omitted.
  let state = ResolutionState()
  await self.expand(address, 0, state)
  state.addresses.toSeq
