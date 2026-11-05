# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import sequtils, chronos
import ../../libp2p/nameresolving/[nameresolver, mockresolver]

export mockresolver

proc default*(T: typedesc[MockResolver]): T =
  let resolver = MockResolver.new()
  resolver.ipResponses[("localhost", false)] = @["127.0.0.1"]
  resolver.ipResponses[("localhost", true)] = @["::1"]
  resolver

type StallingResolver* = ref object of NameResolver
  ## Answers the scripted names, never answers any other, records a cancellation.
  txtResponses*: Table[string, seq[string]]
  cancelled*: bool

proc stall(self: StallingResolver) {.async: (raises: [CancelledError]).} =
  try:
    await sleepAsync(1.hours)
  except CancelledError as e:
    self.cancelled = true
    raise e

method resolveIp*(
    self: StallingResolver,
    address: string,
    port: Port,
    domain: Domain = Domain.AF_UNSPEC,
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError])
.} =
  await self.stall()
  @[]

method resolveTxt*(
    self: StallingResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]).} =
  if address notin self.txtResponses:
    await self.stall()
  self.txtResponses.getOrDefault(address)

proc new*(T: typedesc[StallingResolver]): T =
  T()

type StubNameResolverIpOutcome* {.pure.} = enum
  Resolve
  RaiseAddressError
  RaiseCancelled

type StubNameResolver* = ref object of NameResolver
  ## Answers consecutive lookups of one name, recording what was queried.
  txtScript*: seq[seq[string]]
  ipScript*: seq[StubNameResolverIpOutcome]
  ipAddresses*: seq[string]
  txtQueries*: seq[string]
  ipQueries*: seq[string]

proc responseForCall[T](script: seq[T], callIndex: int): T =
  ## Entries answer consecutive calls, the last entry answers every call after it.
  script[min(callIndex, script.high)]

method resolveIp*(
    self: StubNameResolver,
    address: string,
    port: Port,
    domain: Domain = Domain.AF_UNSPEC,
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError])
.} =
  self.ipQueries.add(address)

  case self.ipScript.responseForCall(self.ipQueries.high)
  of StubNameResolverIpOutcome.RaiseAddressError:
    raise newException(TransportAddressError, "Could not resolve " & address)
  of StubNameResolverIpOutcome.RaiseCancelled:
    raise newException(CancelledError, "Cancelled while resolving " & address)
  of StubNameResolverIpOutcome.Resolve:
    self.ipAddresses.mapIt(initTAddress(it, port))

method resolveTxt*(
    self: StubNameResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]).} =
  self.txtQueries.add(address)
  self.txtScript.responseForCall(self.txtQueries.high)

proc new*(
    T: typedesc[StubNameResolver],
    txtRecords: seq[string] = @[],
    ipAddresses: seq[string] = @[],
): T =
  T(
    txtScript: @[txtRecords],
    ipScript: @[StubNameResolverIpOutcome.Resolve],
    ipAddresses: ipAddresses,
  )
