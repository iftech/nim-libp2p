# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, net
import ../../../libp2p/[multiaddress, utils/ipaddr]
import ../../tools/[unittest, multiaddress]

suite "IpAddr Utils":
  teardown:
    checkTrackers()

  test "ipAddrMatches":
    # same ip address
    check ipAddrMatches(ma("/ip4/127.0.0.1/tcp/4041"), @[ma("/ip4/127.0.0.1/tcp/4040")])
    # different ip address
    check not ipAddrMatches(
      ma("/ip4/127.0.0.2/tcp/4041"), @[ma("/ip4/127.0.0.1/tcp/4040")]
    )
    # same ipv6 address
    check ipAddrMatches(
      ma("/ip6/2001:db8::1/tcp/4041"), @[ma("/ip6/2001:db8::1/tcp/4040")]
    )
    # different ipv6 address
    check not ipAddrMatches(
      ma("/ip6/2001:db8::2/tcp/4041"), @[ma("/ip6/2001:db8::1/tcp/4040")]
    )
    # different family
    check not ipAddrMatches(ma("/ip6/::1/tcp/4041"), @[ma("/ip4/127.0.0.1/tcp/4040")])

  test "ipSupport":
    check ipSupport(@[ma("/ip4/127.0.0.1/tcp/4040")]) == (true, false)
    check ipSupport(@[ma("/ip6/::1/tcp/4040")]) == (false, true)
    check ipSupport(@[ma("/ip6/::1/tcp/4040"), ma("/ip4/127.0.0.1/tcp/4040")]) ==
      (true, true)
    check ipSupport(@[ma("/dns4/example.com/tcp/4040")]) == (false, false)

  test "isGlobalIP accepts a public address of either family":
    check isGlobalIP(parseIpAddress("1.1.1.1"))
    check isGlobalIP(parseIpAddress("8.8.8.8"))
    check isGlobalIP(parseIpAddress("172.15.0.1"))
    check isGlobalIP(parseIpAddress("172.32.0.1"))
    check isGlobalIP(parseIpAddress("185.199.108.153"))
    check isGlobalIP(parseIpAddress("2606:4700::1111"))
    check isGlobalIP(parseIpAddress("2a00:1450:4001:800::200e"))

  test "isGlobalIP rejects a non-global address of either family":
    check not isGlobalIP(parseIpAddress("192.168.1.100"))
    check not isGlobalIP(parseIpAddress("10.0.0.25"))
    check not isGlobalIP(parseIpAddress("172.16.0.1"))
    check not isGlobalIP(parseIpAddress("172.31.200.8"))
    check not isGlobalIP(parseIpAddress("127.0.0.1"))
    check not isGlobalIP(parseIpAddress("169.254.12.34"))
    # CGNAT (100.64.0.0/10)
    check not isGlobalIP(parseIpAddress("100.64.0.1"))
    # IPv4-mapped IPv6 loopback
    check not isGlobalIP(parseIpAddress("::ffff:127.0.0.1"))
    # documentation (2001:db8::/32)
    check not isGlobalIP(parseIpAddress("2001:db8::1"))
    # ULA (fc00::/7)
    check not isGlobalIP(parseIpAddress("fd00::1"))
    # link-local (fe80::/10)
    check not isGlobalIP(parseIpAddress("fe80::1"))
    check not isGlobalIP(parseIpAddress("::1"))
    check not isGlobalIP(parseIpAddress("::"))

  test "firstGlobalIP picks the first global address":
    let
      privateV4 = parseIpAddress("192.168.1.100")
      publicV4 = parseIpAddress("1.1.1.1")
      publicV6 = parseIpAddress("2606:4700::1111")
      linkLocalV6 = parseIpAddress("fe80::1")
    check firstGlobalIP(newSeq[IpAddress]()) == Opt.none(IpAddress)
    check firstGlobalIP([privateV4, linkLocalV6]) == Opt.none(IpAddress)
    check firstGlobalIP([privateV4, publicV6]) == publicV6
    check firstGlobalIP([publicV4, publicV6]) == publicV4

  test "isIPv4, isIPv6":
    let ipv4 = parseIpAddress("1.2.3.4")
    let ipv6 = parseIpAddress("2001:db8::1")
    check ipv4.isIPv4()
    check not ipv4.isIPv6()
    check ipv6.isIPv6()
    check not ipv6.isIPv4()
