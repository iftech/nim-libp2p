# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Choose a DNS resolver with explicit servers or an OS-backed resolver:
##
## ```nim
## let resolver = newNameResolver(rng)
## let addresses = await resolver.resolveMAddress(address)
## await resolver.stop()
## ```
##
## Passing a resolver to `SwitchBuilder.withNameResolver` keeps its lifecycle
## caller-managed. Stop dependent switches before awaiting `SystemResolver.stop()`.
##
## The OS resolver requires threads. Its TXT queries use discovered system DNS
## servers, with DefaultDnsServers as a fallback when discovery finds none.

{.push raises: [].}

import chronos
import ./nameresolving/[nameresolver, dnsresolver, systemresolver]
import ./crypto/rng

export nameresolver, dnsresolver, systemresolver

proc newNameResolver*(rng: Rng, nameServers: seq[TransportAddress]): DnsResolver =
  ## Use only the supplied DNS servers. An empty list produces no DNS results.
  DnsResolver.new(nameServers, rng)

proc newNameResolver*(rng: Rng): SystemResolver =
  ## Resolve IPs through the OS. Discovers TXT nameservers synchronously during
  ## construction, which can block the calling thread while reading system config.
  ## Requires threads. The caller must await stop() to release its workers.
  SystemResolver.new(rng)
