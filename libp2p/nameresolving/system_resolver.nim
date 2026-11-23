# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Resolve IPs through the OS, including hosts files and search domains.
## Blocking getaddrinfo calls run on worker threads; TXT queries use a fallback
## NameResolver. Call stop() to release workers, and start() to reuse a resolver.

{.push raises: [].}

import chronos, chronos/transports/ipnet, chronicles
import nameresolver, dnsresolver
import ../crypto/rng
import ../results
import ../utils/blockingpool

logScope:
  topics = "libp2p systemresolver"

const MaxSystemAddresses = 100

type
  Lookup = proc(
    address: string, port: Port, domain: Domain, context: pointer
  ): seq[TransportAddress] {.nimcall, gcsafe, raises: [TransportAddressError].}

  ResolveJob = object
    host: array[256, char] # null-terminated, copied at submission
    port: uint16
    domain: Domain
    lookup: Lookup
    lookupContext: pointer
    results: array[MaxSystemAddresses, TransportAddress]
    resultsLen: int

  SystemResolver* = ref object of NameResolver
    ## Resolves names through the OS resolver (getaddrinfo), offloaded to
    ## lazily-created worker threads.
    txtResolver: NameResolver
    pool: BlockingPool[ResolveJob]
    lookup: Lookup
    lookupContext: pointer

proc systemLookup(
    address: string, port: Port, domain: Domain, context: pointer
): seq[TransportAddress] {.gcsafe, raises: [TransportAddressError].} =
  resolveTAddress(address, port, domain)

proc doResolve(j: var ResolveJob): bool {.nimcall, gcsafe, raises: [].} =
  let host = $cast[cstring](addr j.host[0])
  try:
    let resolved = j.lookup(host, Port(j.port), j.domain, j.lookupContext)
    for address in resolved:
      # getaddrinfo can return mapped literals even without AI_V4MAPPED.
      if j.domain == Domain.AF_INET6 and address.isV4Mapped():
        continue
      if j.resultsLen >= MaxSystemAddresses:
        debug "System resolver results truncated", host, limit = MaxSystemAddresses
        break
      j.results[j.resultsLen] = address
      inc j.resultsLen
    true
  except TransportAddressError:
    false

proc new*(
    T: type SystemResolver, rng: Rng, txtResolver: NameResolver = nil, workers: int = 2
): T =
  ## Create a SystemResolver which starts `workers` worker threads on first use.
  ## `txtResolver` handles TXT queries (getaddrinfo cannot); when nil, a
  ## `DnsResolver` over the system nameservers is used. Discovery is synchronous
  ## during construction and can block the calling thread while reading system config.
  T(
    txtResolver:
      if txtResolver.isNil:
        NameResolver(DnsResolver.new(getSystemNameServers(), rng))
      else:
        txtResolver,
    pool: BlockingPool[ResolveJob].new(doResolve, workers),
    lookup: systemLookup,
  )

proc setLookup(self: SystemResolver, lookup: Lookup, context: pointer) =
  # Jobs capture the context at submission, so a replaced context must outlive
  # every job submitted before the swap, including asynchronous shutdown.
  doAssert not lookup.isNil
  self.lookup = lookup
  self.lookupContext = context

when defined(libp2p_testing):
  export setLookup

method resolveIp*(
    self: SystemResolver, address: string, port: Port, domain: Domain = Domain.AF_UNSPEC
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError])
.} =
  if address.len == 0 or address.len > 255 or '\0' in address:
    return @[]

  var job = ResolveJob(
    port: uint16(port),
    domain: domain,
    lookup: self.lookup,
    lookupContext: self.lookupContext,
  )
  copyMem(addr job.host[0], address.cstring, address.len)

  trace "Resolving via getaddrinfo", address, port = uint16(port), domain
  let done = (await self.pool.submit(job)).valueOr:
    if error.kind == PoolErrorKind.StartFailed:
      raise newException(TransportAddressError, error.detail)
    return @[]
  return @(done.results.toOpenArray(0, done.resultsLen - 1))

method resolveTxt*(
    self: SystemResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]).} =
  if self.pool.isStopped():
    return @[]
  return await self.txtResolver.resolveTxt(address)

method start*(self: SystemResolver) {.gcsafe.} =
  ## Worker resources are created lazily by the next IP resolution.
  self.pool.start()

method stop*(self: SystemResolver) {.async: (raises: []).} =
  ## Wait for active OS lookups, discard queued lookups, and release workers.
  ## Concurrent callers await the same cleanup; the event loop stays responsive.
  await self.pool.stop()
