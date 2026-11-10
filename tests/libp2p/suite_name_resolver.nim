# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../../libp2p/nameresolving/nameresolver
import ../tools/[unittest, multiaddress]

template nameResolverSuite*(name: string, resolver, setup, cleanup: untyped) =
  suite name:
    teardown:
      checkTrackers()

    asyncTest "requested family and port are preserved":
      setup
      defer:
        cleanup
      let ipv4 = await resolver.resolveIp("127.0.0.1", 4001.Port, Domain.AF_INET)
      let ipv6 = await resolver.resolveIp("::1", 4002.Port, Domain.AF_INET6)
      check:
        ipv4 == @[initTAddress("127.0.0.1:4001")]
        ipv6 == @[initTAddress("[::1]:4002")]

    asyncTest "multiaddress resolution preserves the transport and suffix":
      setup
      defer:
        cleanup
      check (await resolver.resolveMAddress(ma("/dns4/127.0.0.1/tcp/443/tls/ws"))) ==
        @[ma("/ip4/127.0.0.1/tcp/443/tls/ws")]
      check (await resolver.resolveMAddress(ma("/dns6/::1/udp/4001/quic-v1"))) ==
        @[ma("/ip6/::1/udp/4001/quic-v1")]

    asyncTest "DNS components resolve behind a prefix and without a port":
      setup
      defer:
        cleanup
      check (await resolver.resolveMAddress(ma("/dns4/127.0.0.1"))) ==
        @[ma("/ip4/127.0.0.1")]
      check (await resolver.resolveMAddress(ma("/p2p-circuit/dns6/::1/tcp/4001"))) ==
        @[ma("/p2p-circuit/ip6/::1/tcp/4001")]
