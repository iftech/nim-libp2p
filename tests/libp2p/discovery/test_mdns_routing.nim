# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

include ../../../libp2p/services/mdns/network
import ../../tools/unittest
import ./mdns_fixtures

suite "mDNS ingress routing":
  test "unpinned sockets fall back when source subnets overlap or do not match":
    for ipv6 in [false, true]:
      let
        local = if ipv6: LocalSubnet6 else: LocalSubnet4
        remote = if ipv6: SubnetPeer6 else: SubnetPeer4
        receiver = new(MdnsInterface)
        other = new(MdnsInterface)
        network = MdnsNetwork.new()
      receiver.index = 1
      other.index = 2
      if ipv6:
        network.interfaces6 = @[receiver, other]
      else:
        network.interfaces4 = @[receiver, other]
      for index in [1'u32, 2'u32]:
        network.localAddresses.add(
          MdnsLocalAddress(
            index: index, address: InterfaceAddress.init(local, if ipv6: 64 else: 24)
          )
        )
      check network.sourceInterfaceIndex(remote) == 0
      check network.receivingInterface(receiver, remote) == receiver
      check network.receivingInterface(other, remote) == other
      network.localAddresses = @[]
      check network.receivingInterface(receiver, remote) == receiver

  test "unique subnet matches require an available socket in the source family":
    for ipv6 in [false, true]:
      let
        local = if ipv6: LocalSubnet6 else: LocalSubnet4
        remote = if ipv6: SubnetPeer6 else: SubnetPeer4
        receiver = new(MdnsInterface)
        matched = new(MdnsInterface)
        network = MdnsNetwork.new()
      receiver.index = 1
      matched.index = 2
      network.localAddresses = @[
        MdnsLocalAddress(
          index: 2, address: InterfaceAddress.init(local, if ipv6: 64 else: 24)
        )
      ]
      network.interfaces4 = @[receiver, matched]
      network.interfaces6 = @[receiver, matched]
      check network.receivingInterface(receiver, remote) == matched
      receiver.ingressPinned = true
      check network.receivingInterface(receiver, remote) == receiver
      receiver.ingressPinned = false
      if ipv6:
        network.interfaces6 = @[receiver]
      else:
        network.interfaces4 = @[receiver]
      check network.sourceInterfaceIndex(remote) == 2
      check network.receivingInterface(receiver, remote) == receiver

  test "IPv6 link-local sources retain the receiving socket association":
    let
      network = MdnsNetwork.new()
      receiver = new(MdnsInterface)
    check network.receivingInterface(receiver, LinkLocalPeer6) == receiver
