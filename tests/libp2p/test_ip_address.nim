# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/net
import pkg/chronicles
import ../../libp2p/ip_address
import ../tools/unittest

{.push raises: [].}

suite "IP address":
  const
    ipv4: Ipv4Address = [192'u8, 0, 2, 255]
    ipv6: Ipv6Address =
      [0x20'u8, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0xff]
    subnet4: Ipv4Subnet24 = [192'u8, 0, 2]
    subnet6: Ipv6Subnet64 = [0x20'u8, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34]

  test "convert IPv4 and IPv6 to std/net addresses":
    let
      ip4 = ipv4.toIpAddress()
      ip6 = ipv6.toIpAddress()
    check:
      ip4.family == IpAddressFamily.IPv4
      ip4.address_v4 == ipv4
      ip6.family == IpAddressFamily.IPv6
      ip6.address_v6 == ipv6

  test "extract IPv4 /24 and IPv6 /64 subnet prefixes":
    check:
      ipv4.subnetOf() == subnet4
      ipv6.subnetOf() == subnet6

  test "format addresses and subnets for Chronicles":
    check:
      chroniclesFormatItIMPL(ipv4) == "192.0.2.255"
      chroniclesFormatItIMPL(ipv6) == "2001:db8:abcd:1234::ff"
      chroniclesFormatItIMPL(subnet4) == "192.0.2.0/24"
      chroniclesFormatItIMPL(subnet6) == "2001:db8:abcd:1234::/64"
