# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos

# Addresses shared by the mDNS discovery, network and routing tests.
const
  FixturePort* = 12345
  FixtureAddress* = "/ip4/192.168.1.2/tcp/" & $FixturePort
  PrivateAddress* = "/ip4/192.168.1.2/tcp/4001"
  AlternatePrivateAddress* = "/ip4/10.0.0.1/tcp/4001"
  PrivateIpv6Address* = "/ip6/fd00::1/tcp/4001"
  WildcardAddress* = "/ip4/0.0.0.0/tcp/4001"
  EphemeralWildcardAddress* = "/ip4/0.0.0.0/tcp/0"
  InterfaceIp* = "10.20.30.40"
  AnnouncementAddress* = "/ip4/" & InterfaceIp & "/tcp/4001"
  UnboundAnnouncementAddress* = "/ip4/" & InterfaceIp & "/tcp/0"
  PrivateQuic6Address* = "/ip6/fd00::1/udp/4001/quic-v1"
  LinkLocal4Address* = "/ip4/169.254.1.2/tcp/4001"
  LinkLocal6Address* = "/ip6/fe80::1/tcp/4001"
  Public4Address* = "/ip4/8.8.8.8/tcp/4001"
  Public6Address* = "/ip6/2606:4700::1111/tcp/4001"
  Loopback4Address* = "/ip4/127.0.0.1/tcp/4001"
  Loopback6Address* = "/ip6/::1/tcp/4001"
  MappedLoopback6Address* = "/ip6/::ffff:127.0.0.1/tcp/4001"
  Multicast4Address* = "/ip4/224.0.0.1/tcp/4001"
  Dns4Address* = "/dns4/example.com/tcp/4001"
  EphemeralPrivate4Address* = "/ip4/10.0.0.1/tcp/0"
  Wildcard6Address* = "/ip6/::/tcp/4001"
  WebSocketAddress* = "/ip4/192.168.1.2/tcp/4001/ws"
  RelayAddress* = "/ip4/192.168.1.2/tcp/4001/p2p-circuit"
  UnboundPrivate4Address* = "/ip4/192.168.1.2/tcp/0"
  UnboundQuic6Address* = "/ip6/2001:db8::1/udp/0/quic-v1"
  PreviousPeerAddress* = "/ip4/192.168.1.3/tcp/4001"
  WildcardQuic6Address* = "/ip6/::/udp/4001/quic-v1"
  PrivateQuic4Address* = "/ip4/10.0.0.1/udp/4001/quic-v1"
  AlternatePortAddress* = "/ip4/192.168.1.2/tcp/5000"
  LoopbackIp4* = "127.0.0.1"
  LoopbackIp6* = "::1"
  Loopback4Prefix* = "/ip4/127."
  Loopback6Prefix* = "/ip6/::1/"
  FixtureTcpPrefix* = "/ip4/192.168.1.2/tcp/"

const
  AnnouncementInterface4* = initTAddress(InterfaceIp & ":0")
  LocalSubnet4* = initTAddress("192.168.10.1:0")
  LocalSubnet6* = initTAddress("[fd12:3456::1]:0")
  OverlappingSubnet4* = initTAddress("192.168.10.2:0")
  DownInterface4* = initTAddress("10.2.0.1:0")
  SubnetPeer4* = initTAddress("192.168.10.42:5353")
  SubnetPeer6* = initTAddress("[fd12:3456::42]:5353")
  AdjacentSubnetPeer4* = initTAddress("192.168.11.42:5353")
  DownSubnetPeer4* = initTAddress("10.2.0.42:5353")
  AdjacentSubnetPeer6* = initTAddress("[fd12:3457::42]:5353")
  WildcardMdns4* = initTAddress("0.0.0.0:5353")
  MulticastMdns4* = initTAddress("224.0.0.251:5353")
  UnmatchedSubnetPeer4* = initTAddress("10.0.0.1:5353")
  ExpansionInterface4* = initTAddress("10.0.0.1:0")
  ExpansionInterface6* = initTAddress("[fd00::1]:0")
  MissingInterface4* = initTAddress("192.0.2.1:0")
  LinkLocalPeer6* = initTAddress("[fe80::42]:5353")
  MulticastMdns6* = initTAddress("[ff02::fb]:5353")
