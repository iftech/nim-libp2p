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
## Pass a resolver to `SwitchBuilder.withNameResolver` to let the switch manage
## its lifecycle. Standalone callers must await `stop()` themselves.
##
## The OS resolver requires threads. Its TXT queries use discovered system DNS
## servers, with DefaultDnsServers as a fallback when discovery finds none.

{.push raises: [].}

import chronos
import ./nameresolving/[nameresolver, dnsresolver, systemresolver]
import ./crypto/rng

export nameresolver, dnsresolver, systemresolver

proc newNameResolver*(
    rng: Rng, nameServers: seq[TransportAddress] = @[]
): NameResolver =
  ## Use explicit DNS servers when supplied; otherwise resolve IPs through the OS.
  ## Requires threads. Outside a switch, call stop() to release its workers.
  if nameServers.len > 0:
    DnsResolver.new(nameServers, rng)
  else:
    SystemResolver.new(rng)
