# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils, strutils, tables]
import chronos, chronicles
import ../[multiaddress, peerid, results]

logScope:
  topics = "libp2p name-resolution"

const
  MaxDnsLookups* = 32 ## Total resolver calls across all branches of one expansion.
  MaxDnsaddrRecursion* = 4 ## Maximum DNSADDR lookups along one branch.
  MaxDnsaddrRecords* = 16 ## Matching DNSADDR records expanded per response.
  MaxResolvedAddresses* = 100
    ## Outputs per expansion and IP records inspected per lookup.

type
  NameResolver* = ref object of RootObj

  ResolutionState = ref object
    dnsaddrOnly: bool
    expectedPeer: MultiAddress
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

proc matchExpectedPeer(address, expectedPeer: MultiAddress): LPResult[MultiAddress] =
  # Return the peerless address for suffix matching, or empty for another peer.
  if expectedPeer.isEmpty or address.isEmpty:
    return ok(address)
  let last = ?address[^1]
  if not P2PPattern.match(last):
    return ok(address)
  if last != expectedPeer:
    trace "DNSADDR record names another peer", address, expectedPeer
    return ok(MultiAddress())
  address[0 ..^ 2]

proc expand(
    self: NameResolver, address: MultiAddress, depth: int, state: ResolutionState
): Future[LPResult[void]] {.async: (raises: [CancelledError, TransportAddressError]).} =
  if state.addresses.len >= MaxResolvedAddresses:
    trace "Resolution stopped at output limit", address, limit = MaxResolvedAddresses
    return ok()

  var
    prefix, component, suffix: MultiAddress
    suffixLength = 0
  let matchingAddress = ?address.matchExpectedPeer(state.expectedPeer)
  if matchingAddress.isEmpty:
    return ok()
  for partResult in matchingAddress:
    let part = ?partResult
    if not component.isEmpty:
      ?suffix.append(part)
      inc suffixLength
    elif DNSADDR.match(part) or (not state.dnsaddrOnly and DNS.match(part)):
      component = part
    else:
      ?prefix.append(part)

  if component.isEmpty:
    state.addresses.incl(address)
    return ok()

  let isDnsaddr = DNSADDR.match(component)
  if state.lookups >= MaxDnsLookups:
    trace "Resolution stopped at lookup limit",
      address = component, limit = MaxDnsLookups
    return ok()
  if isDnsaddr and depth >= MaxDnsaddrRecursion:
    trace "DNSADDR resolution stopped at recursion limit",
      address = component, limit = MaxDnsaddrRecursion
    return ok()
  # Revisit only when a shorter path leaves more DNSADDR recursion budget.
  # This also cuts cycles and duplicate branches without an expansion queue.
  if state.visited.getOrDefault(address, high(int)) <= depth:
    return ok()
  state.visited[address] = depth
  inc state.lookups
  trace "Resolving DNS component", address = component

  if isDnsaddr:
    let records = await self.resolveTxt("_dnsaddr." & component.getHostname())
    var accepted = 0
    for record in records:
      if state.addresses.len >= MaxResolvedAddresses:
        trace "Resolution stopped at output limit",
          address = component, limit = MaxResolvedAddresses
        break
      if not record.startsWith("dnsaddr="):
        continue
      let entry = MultiAddress.init(record.substr(8)).valueOr:
        continue
      let matchingEntry = ?entry.matchExpectedPeer(state.expectedPeer)
      if matchingEntry.isEmpty:
        continue
      if suffixLength > 0:
        let length = ?matchingEntry.len
        if length < suffixLength:
          trace "DNSADDR suffix mismatch", address = entry, suffix
          continue
        let tail = ?matchingEntry[length - suffixLength ..< length]
        if tail != suffix:
          trace "DNSADDR suffix mismatch", address = entry, suffix
          continue
      if accepted >= MaxDnsaddrRecords:
        trace "DNSADDR resolution stopped at record limit",
          address = component, limit = MaxDnsaddrRecords
        break
      inc accepted
      let expanded = ?concat(prefix, entry)
      ?(await self.expand(expanded, depth + 1, state))
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
    if records.len > MaxResolvedAddresses:
      trace "IP resolution stopped at record limit",
        address = component, limit = MaxResolvedAddresses
    for i in 0 ..< min(records.len, MaxResolvedAddresses):
      if state.addresses.len >= MaxResolvedAddresses:
        trace "Resolution stopped at output limit",
          address = component, limit = MaxResolvedAddresses
        break
      let resolved = ?MultiAddress.init(records[i])
      let ip = ?resolved[0]
      let expanded = ?concat(?concat(prefix, ip), suffix)
      ?(await self.expand(expanded, depth, state))
  ok()

proc resolveDnsAddr*(
    self: NameResolver,
    ma: MultiAddress,
    depth: int = 0,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  ## Expand DNSADDR records with exact suffix matching, leaving IP names unresolved.
  ## When peerId is supplied, skip other peers before recursion and match suffixes
  ## without the terminal peer ID. Records without peer IDs remain eligible.
  ## Preserve answer order, deduplicate outputs, and return partial results at limits.
  let state = ResolutionState(dnsaddrOnly: true)
  if peerId.isSome:
    state.expectedPeer = MultiAddress.init("/p2p/" & $peerId.get()).valueOr:
      raise maErr error
  (await self.expand(ma, depth, state)).onErrorRaise(MaError)
  state.addresses.toSeq

proc resolveMAddress*(
    self: NameResolver, address: MultiAddress
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  ## Resolve every DNS component, preserving surrounding protocols and answer order.
  ## All branches share the lookup/output budgets; unresolved branches are omitted.
  let state = ResolutionState()
  (await self.expand(address, 0, state)).onErrorRaise(MaError)
  state.addresses.toSeq
