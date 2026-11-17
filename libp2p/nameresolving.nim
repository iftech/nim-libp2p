# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Choose a DNS resolver with explicit servers or an OS-backed resolver:
##
## ```nim
## let resolver = SystemResolver.new(rng)
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

import ./nameresolving/[nameresolver, dnsresolver, system_resolver]

export nameresolver, dnsresolver, system_resolver
