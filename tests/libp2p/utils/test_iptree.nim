# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/net
import ../../../libp2p/utils/iptree
import ../../tools/unittest

func ip4(a, b, c, d: uint8): IpAddress =
  IpAddress(family: IpAddressFamily.IPv4, address_v4: [a, b, c, d])

func ip6(a, b: uint8, rest: uint8 = 0): IpAddress =
  var addr_v6 = [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  addr_v6[0] = a
  addr_v6[1] = b
  addr_v6[15] = rest
  IpAddress(family: IpAddressFamily.IPv6, address_v6: addr_v6)

# IP Similarity Score Semantics:
# - Score range: 0.0 to 1.0
# - HIGH score (close to 1.0) = HIGH SIMILARITY = many IPs share prefixes = potential Sybil attack
# - LOW score (close to 0.0) = LOW SIMILARITY = IPs well-distributed = normal behaviour
#
# The score is used to rate-limit advertisements from the same subnet.
# A high similarity score triggers increased waiting times for registration.

suite "IpTree":
  test "new IpTree has root counter set to 0":
    let tree = IpTree.new()
    check tree.root.counter == 0
    check tree.root.left.isNil
    check tree.root.right.isNil
    check tree.root6.counter == 0
    check tree.root6.left.isNil
    check tree.root6.right.isNil
    check tree.ipsLen == 0

  test "insertIps / removeIps / ipsMaxScore / ipsLen":
    let tree = IpTree.new()
    let ips = @[ip4(192, 168, 1, 1), ip4(192, 168, 1, 2), ip6(0x20, 0x01, 1)]
    tree.insertIps(ips)
    check tree.ipsLen == 3
    check tree.ipsMaxScore(@[ip4(192, 168, 1, 3)]) > 0.7
    check tree.ipsMaxScore(@[ip4(10, 0, 0, 1)]) < 0.3
    check tree.ipsMaxScore(@[]) == 1.0
    tree.removeIps(@[ip4(192, 168, 1, 1), ip6(0x20, 0x01, 1)])
    check tree.ipsLen == 1
    tree.removeIps(@[ip4(192, 168, 1, 2)])
    check tree.ipsLen == 0

  test "insertIp creates correct tree structure":
    let tree = IpTree.new()

    # 64.0.0.1 = 01000000 ... → first bit 0 → goes LEFT
    let ip1 = ip4(64, 0, 0, 1)
    tree.insertIp(ip1)
    check tree.root.counter == 1
    check not tree.root.left.isNil
    check tree.root.right.isNil

    # 192.168.1.1 = 11000000 ... → first bit 1 → goes RIGHT
    let ip2 = ip4(192, 168, 1, 1)
    tree.insertIp(ip2)
    check tree.root.counter == 2
    check tree.root.left.counter == 1
    check tree.root.right.counter == 1

    # 128.0.0.1 = 10000000 ... → RIGHT then LEFT
    let ip3 = ip4(128, 0, 0, 1)
    tree.insertIp(ip3)
    check tree.root.counter == 3
    check tree.root.right.counter == 2
    check tree.root.right.left.counter == 1

    # Inserting the same IP again increments counters again
    tree.insertIp(ip1)
    check tree.root.counter == 4
    check tree.root.left.counter == 2

  test "removeIp decrements counters correctly":
    let tree = IpTree.new()
    let ip1 = ip4(64, 0, 0, 1)
    let ip2 = ip4(192, 168, 1, 1)
    let ip3 = ip4(128, 0, 0, 1)

    tree.insertIp(ip1)
    tree.insertIp(ip1)
    tree.insertIp(ip2)
    tree.insertIp(ip3)
    check tree.root.counter == 4

    tree.removeIp(ip1)
    check tree.root.counter == 3
    check tree.root.left.counter == 1

    tree.removeIp(ip3)
    check tree.root.counter == 2
    check tree.root.right.left.isNil

    tree.removeIp(ip1)
    tree.removeIp(ip2)
    check tree.root.counter == 0

  test "removeIp fully clears the leaf, not just ancestors":
    let tree = IpTree.new()
    let ipA = ip4(10, 0, 0, 1)
    let ipB = ip4(192, 168, 1, 1)

    tree.insertIp(ipA)
    tree.insertIp(ipB)
    tree.removeIp(ipA)

    check tree.root.counter == 1
    check tree.ipScore(ipA) == 0.0

  test "removeIp prunes dead branches but keeps branches still in use":
    let tree = IpTree.new()
    # 10.0.0.1 and 10.0.0.2 share every bit except the last.
    let ipA = ip4(10, 0, 0, 1)
    let ipB = ip4(10, 0, 0, 2)

    tree.insertIp(ipA)
    tree.insertIp(ipB)
    tree.removeIp(ipA)

    # The shared prefix is still needed by ipB, so it must stay linked.
    check not tree.root.left.isNil
    check tree.ipScore(ipB) > 0.9

    tree.removeIp(ipB)

    # Nothing left using this branch: fully pruned back to the root.
    check tree.root.counter == 0
    check tree.root.left.isNil
    check tree.root.right.isNil

  test "removeIp should not affect tree if IP was never inserted":
    let tree = IpTree.new()
    tree.insertIp(ip4(192, 168, 1, 1))
    tree.insertIp(ip4(192, 168, 1, 2))
    check tree.root.counter == 2

    tree.removeIp(ip4(10, 0, 0, 1))

    check tree.root.counter == 2

  test "removeIp on empty tree should not allow negative counters":
    let tree = IpTree.new()
    tree.removeIp(ip4(192, 168, 1, 1))
    check tree.root.counter == 0

  test "removeIp should not allow counters to go below zero":
    let tree = IpTree.new()
    let ip = ip4(192, 168, 1, 1)

    tree.insertIp(ip)
    check tree.root.counter == 1

    tree.removeIp(ip)
    check tree.root.counter == 0

    tree.removeIp(ip)
    check tree.root.counter == 0

  test "insertIp on IPv6 grows the IPv6 tree, not the IPv4 tree":
    let tree = IpTree.new()

    # 2001:... = 0010000000000001... → first bit 0 → goes LEFT
    tree.insertIp(ip6(0x20, 0x01))
    check tree.root6.counter == 1
    check not tree.root6.left.isNil
    check tree.root6.right.isNil

    check tree.root.counter == 0
    check tree.root.left.isNil
    check tree.root.right.isNil

  test "removeIp on IPv6 decrements counters correctly":
    let tree = IpTree.new()
    let ipA = ip6(0x20, 0x01, 1)
    let ipB = ip6(0xfe, 0x80, 1)

    tree.insertIp(ipA)
    tree.insertIp(ipA)
    tree.insertIp(ipB)
    check tree.root6.counter == 3

    tree.removeIp(ipA)
    check tree.root6.counter == 2

    tree.removeIp(ipA)
    tree.removeIp(ipB)
    check tree.root6.counter == 0

  test "removeIp on IPv6 should not allow counters to go below zero":
    let tree = IpTree.new()
    let ip = ip6(0x20, 0x01)

    tree.insertIp(ip)
    check tree.root6.counter == 1

    tree.removeIp(ip)
    check tree.root6.counter == 0

    tree.removeIp(ip)
    check tree.root6.counter == 0

  test "ipScore returns 0.0 for empty IPv6 tree":
    let tree = IpTree.new()
    check tree.ipScore(ip6(0x20, 0x01)) == 0.0

  test "ipScore returns high score for exact same IPv6 address":
    let tree = IpTree.new()
    let ip = ip6(0x20, 0x01, 1)
    tree.insertIp(ip)
    check tree.ipScore(ip) > 0.9

  test "ipScore detects IPv6 prefix similarity":
    let tree = IpTree.new()
    tree.insertIp(ip6(0x20, 0x01, 10))
    check tree.ipScore(ip6(0x20, 0x01, 20)) > 0.7

  test "ipScore returns low score for completely different IPv6 addresses":
    let tree = IpTree.new()
    # 0x20 = 00100000, 0xf0 = 11110000 — first bits differ
    tree.insertIp(ip6(0x20, 0x01, 1))
    check tree.ipScore(ip6(0xf0, 0x00, 1)) < 0.2

  test "IPv4 and IPv6 trees are tracked independently":
    let tree = IpTree.new()
    tree.insertIp(ip4(192, 168, 1, 1))
    tree.insertIp(ip6(0x20, 0x01, 1))

    check tree.root.counter == 1
    check tree.root6.counter == 1

    # A never-seen IPv6 address scores 0 even though the (unrelated) IPv4
    # tree is populated.
    check tree.ipScore(ip6(0xf0, 0x00, 1)) == 0.0
    # An IPv6 address matching the one inserted still scores high.
    check tree.ipScore(ip6(0x20, 0x01, 1)) > 0.9

  test "ipScore returns 0.0 for empty tree":
    let tree = IpTree.new()
    check tree.ipScore(ip4(192, 168, 1, 1)) == 0.0

  test "ipScore returns high score for exact same IP":
    let tree = IpTree.new()
    let ip = ip4(192, 168, 1, 1)
    tree.insertIp(ip)
    check tree.ipScore(ip) > 0.9

  test "ipScore detects /24 subnet similarity":
    let tree = IpTree.new()
    tree.insertIp(ip4(192, 168, 1, 10))
    check tree.ipScore(ip4(192, 168, 1, 20)) > 0.7

  test "ipScore detects /16 subnet similarity":
    let tree = IpTree.new()
    tree.insertIp(ip4(192, 168, 1, 10))
    let score = tree.ipScore(ip4(192, 168, 2, 20))
    check score > 0.4 and score < 0.8

  test "ipScore detects /8 subnet similarity":
    let tree = IpTree.new()
    tree.insertIp(ip4(192, 168, 1, 10))
    let score = tree.ipScore(ip4(192, 255, 255, 255))
    check score > 0.1 and score < 0.5

  test "ipScore returns low score for completely different IPs":
    let tree = IpTree.new()
    # 192 = 11000000, 10 = 00001010 — first bits differ
    tree.insertIp(ip4(192, 168, 1, 1))
    check tree.ipScore(ip4(10, 0, 0, 1)) < 0.2

  test "ipScore demonstrates graduated similarity across prefix lengths":
    let tree = IpTree.new()
    let base = ip4(192, 168, 1, 100)
    tree.insertIp(base)

    check tree.ipScore(base) > 0.9
    check tree.ipScore(ip4(192, 168, 1, 200)) > 0.7

    let score16 = tree.ipScore(ip4(192, 168, 255, 255))
    check score16 > 0.4 and score16 <= 0.7

    let score8 = tree.ipScore(ip4(192, 255, 255, 255))
    check score8 > 0.1 and score8 <= 0.4

    check tree.ipScore(ip4(10, 0, 0, 1)) < 0.1

  test "insert and remove maintains scoring consistency":
    let tree = IpTree.new()
    let ip = ip4(192, 168, 1, 1)

    tree.insertIp(ip)
    check tree.ipScore(ip) > 0.9

    tree.removeIp(ip)
    check tree.ipScore(ip) == 0.0

  test "similar IPs with single bit difference":
    # 192.168.1.0 and 192.168.1.1 differ only in the last bit
    let tree = IpTree.new()
    tree.insertIp(ip4(192, 168, 1, 0))
    check tree.ipScore(ip4(192, 168, 1, 1)) > 0.9

  test "diverse IP distribution yields low individual scores":
    let tree = IpTree.new()
    tree.insertIp(ip4(10, 0, 0, 1))
    tree.insertIp(ip4(172, 16, 0, 1))
    tree.insertIp(ip4(192, 168, 0, 1))
    tree.insertIp(ip4(8, 8, 8, 8))
    tree.insertIp(ip4(1, 1, 1, 1))
    check tree.root.counter == 5

    # Same /8 as 10.0.0.1 → moderate score
    check tree.ipScore(ip4(10, 0, 0, 2)) > 0.7
    # Different from all existing IPs → low score
    check tree.ipScore(ip4(11, 0, 0, 1)) < 0.3

  test "threshold calculation at different tree depths":
    let tree = IpTree.new()
    for i in 1'u8 .. 8'u8:
      tree.insertIp(ip4(192, 168, 1, i))
    check tree.root.counter == 8

    # All 8 IPs share the same /24 prefix, so the shared-path counters are
    # well above the threshold at every depth → high score
    check tree.ipScore(ip4(192, 168, 1, 200)) > 0.7
