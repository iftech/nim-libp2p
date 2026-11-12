# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/sequtils
import ../../libp2p/builders
import ../../libp2p/services/[mdns, wildcardresolverservice, identify_pusher]
import ../tools/[unittest, crypto]

proc tcpBuilder(): SwitchBuilder =
  SwitchBuilder
    .new()
    .withAddress(MultiAddress.init("/ip4/127.0.0.1/tcp/0").get())
    .withRng(rng())
    .withTcpTransport()
    .withMplex()
    .withNoise()

suite "SwitchBuilder":
  teardown:
    checkTrackers()

  test "default services include wildcard resolution and exclude opt-in services":
    let node = tcpBuilder().build()
    check:
      node.services.anyIt(it of WildcardAddressResolverService)
      not node.services.anyIt(it of MdnsService)
      not node.services.anyIt(it of IdentifyPusher)

  test "enabling mDNS adds service":
    let node = tcpBuilder().withMdns().build()
    check node.services.anyIt(it of MdnsService)

  test "mDNS rejects query intervals outside its supported range":
    expect AssertionDefect:
      discard tcpBuilder().withMdns(queryInterval = MdnsMinQueryInterval - 1.seconds)
    expect AssertionDefect:
      discard tcpBuilder().withMdns(queryInterval = MdnsMaxQueryInterval + 1.seconds)

  test "disabling mDNS after enabling it prevents service creation":
    let node = tcpBuilder().withMdns().withMdns(enabled = false).build()
    check not node.services.anyIt(it of MdnsService)
