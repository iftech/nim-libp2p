# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/importutils
import chronos
import ../../libp2p/[switch, nameresolving/dnsresolver, nameresolving/mockresolver]
import ../tools/[unittest, multiaddress, switch_builder]

privateAccess(Dialer)

suite "Switch builder resolver configuration":
  teardown:
    checkTrackers()

  asyncTest "build preserves default resolver configuration":
    let builder = makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver()
    let first = builder.build()
    let second = builder.build()
    check:
      first.ownsNameResolver
      second.ownsNameResolver
      first.nameResolver of DnsResolver
      second.nameResolver of DnsResolver
      first.nameResolver != second.nameResolver
      first.dialer.nameResolver == first.nameResolver
      second.dialer.nameResolver == second.nameResolver
      DnsResolver(first.nameResolver).nameServers.len > 0
    await first.stop()
    await second.stop()

  asyncTest "last resolver configuration wins":
    let resolver = MockResolver.new()
    let builder = makeStandardSwitchBuilder(TcpAutoAddress)
    let disabled = builder.build()
    check disabled.nameResolver.isNil
    let injected = builder.withNameResolver().withNameResolver(resolver).build()
    check:
      injected.nameResolver == resolver
      not injected.ownsNameResolver
    let owned = builder.withNameResolver().build()
    check:
      owned.nameResolver of DnsResolver
      owned.ownsNameResolver
    let cleared = builder.withNameResolver(nil).build()
    check:
      cleared.nameResolver.isNil
      not cleared.ownsNameResolver
    for node in [disabled, injected, owned, cleared]:
      await node.stop()
