# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/nameresolving/dnsresolver
import ../tools/unittest

suite "System nameserver discovery":
  test "parse IPv4 and IPv6 nameservers in order":
    check parseNameServers(
      """
# ignored
search example.com
nameserver 10.0.0.2 # local resolver
nameserver fd00::2
options ndots:5
"""
    ) == @[initTAddress("10.0.0.2:53"), initTAddress("[fd00::2]:53")]

  test "skip malformed and scoped nameservers":
    check parseNameServers(
      """
nameserver
nameserver not-an-address
nameserver fe80::1%eth0
nameserver 10.0.0.2
"""
    ) == @[initTAddress("10.0.0.2:53")]

  test "use at most three nameservers":
    check parseNameServers(
      """
nameserver 10.0.0.1
nameserver 10.0.0.2
nameserver 10.0.0.3
nameserver 10.0.0.4
"""
    ) ==
      @[
        initTAddress("10.0.0.1:53"),
        initTAddress("10.0.0.2:53"),
        initTAddress("10.0.0.3:53"),
      ]

  test "empty configuration and platform fallback":
    check:
      parseNameServers("").len == 0
      parseNameServers("search example.com\n").len == 0
      getSystemNameServers().len > 0
