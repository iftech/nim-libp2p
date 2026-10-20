# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../libp2p/[multiaddress, wire]
import ../tools/[unittest, multiaddress]

suite "Wire":
  test "initTAddress returns ok and correct result for a Unix domain address":
    let res = initTAddress(ma("/unix/tmp/socket"))
    var address_un: array[108, uint8]
    let unixPath = "/tmp/socket"
    for i in 0 ..< len(unixPath):
      address_un[i] = uint8(unixPath[i])
    let expected = TransportAddress(
      family: AddressFamily.Unix, address_un: address_un, port: Port(1)
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv4/TCP address":
    let res = initTAddress(ma("/ip4/127.0.0.1/tcp/1234"))
    let expected = TransportAddress(
      family: AddressFamily.IPv4,
      address_v4: [127'u8, 0, 0, 1], # IPv4 address 127.0.0.1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv6/TCP address":
    let res = initTAddress(ma("/ip6/::1/tcp/1234"))
    let expected = TransportAddress(
      family: AddressFamily.IPv6,
      address_v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        # IPv6 address ::1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv4/UDP address":
    let res = initTAddress(ma("/ip4/127.0.0.1/udp/1234"))
    let expected = TransportAddress(
      family: AddressFamily.IPv4,
      address_v4: [127'u8, 0, 0, 1], # IPv4 address 127.0.0.1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv6/UDP address":
    let res = initTAddress(ma("/ip6/::1/udp/1234"))
    let expected = TransportAddress(
      family: AddressFamily.IPv6,
      address_v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        # IPv6 address ::1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv4/TCP/WS address":
    let res = initTAddress(ma("/ip4/127.0.0.1/tcp/1234/ws"))
    let expected = TransportAddress(
      family: AddressFamily.IPv4,
      address_v4: [127'u8, 0, 0, 1], # IPv4 address 127.0.0.1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv6/TCP/WS address":
    let res = initTAddress(ma("/ip6/::1/tcp/1234/ws"))
    let expected = TransportAddress(
      family: AddressFamily.IPv6,
      address_v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        # IPv6 address ::1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv4/TCP/WSS address":
    let res = initTAddress(ma("/ip4/127.0.0.1/tcp/1234/wss"))
    let expected = TransportAddress(
      family: AddressFamily.IPv4,
      address_v4: [127'u8, 0, 0, 1], # IPv4 address 127.0.0.1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns ok and correct result for an IPv6/TCP/WSS address":
    let res = initTAddress(ma("/ip6/::1/tcp/1234/wss"))
    let expected = TransportAddress(
      family: AddressFamily.IPv6,
      address_v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        # IPv6 address ::1
      port: Port(1234),
    )
    check res.isOk
    check res.get() == expected

  test "initTAddress returns error for a DNS/TCP/ws address":
    let res = initTAddress(ma("/dns4/localhost/tcp/1234/ws"))
    check res.isErr

  test "initTAddress returns error for a DNS/TCP/wss address":
    let res = initTAddress(ma("/dns4/localhost/tcp/1234/wss"))
    check res.isErr

  test "initTAddress returns error for a DNS/TCP address":
    let res = initTAddress(ma("/dns4/localhost/tcp/1234"))
    check res.isErr

  test "initTAddress returns error for a DNS/UDP address":
    let res = initTAddress(ma("/dns4/localhost/udp/1234"))
    check res.isErr

  test "initTAddress returns error for an Onion3/TCP address":
    let res = initTAddress(
      MultiAddress
        .init("/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234")
        .get()
    )
    check res.isErr

  test "initTAddress returns error for a HTTP WebRTCDirect address":
    let res = initTAddress(ma("/ip4/127.0.0.1/http/p2p-webrtc-direct"))
    check res.isErr

  test "initTAddress returns error for a HTTPS WebRTCDirect address":
    let res = initTAddress(ma("/ip4/127.0.0.1/https/p2p-webrtc-direct"))
    check res.isErr

  test "initTAddress returns error for a p2p-circuit address":
    let res = initTAddress(ma("/ip4/127.0.0.1/tcp/1234/p2p-circuit"))
    check res.isErr

suite "isFilterablePrivateMA":
  test "RFC1918 addresses are filterable":
    check not isPublicMA(ma("/ip4/10.0.0.1/tcp/4001"))
    check not isPublicMA(ma("/ip4/172.16.0.1/tcp/4001"))
    check not isPublicMA(ma("/ip4/172.31.255.255/tcp/4001"))
    check not isPublicMA(ma("/ip4/192.168.1.5/tcp/4001"))

  test "loopback addresses are filterable":
    check not isPublicMA(ma("/ip4/127.0.0.1/tcp/4001"))
    check not isPublicMA(ma("/ip6/::1/tcp/4001"))
    check isLoopbackMA(ma("/ip4/127.0.0.1/tcp/4001"))
    check isLoopbackMA(ma("/ip6/::1/tcp/4001"))

  test "link-local addresses are filterable":
    check not isPublicMA(ma("/ip4/169.254.1.1/tcp/4001"))
    check not isPublicMA(ma("/ip6/fe80::1/tcp/4001"))

  test "public IPv4 addresses are not filterable":
    check isPublicMA(ma("/ip4/1.1.1.1/tcp/4001"))
    check isPublicMA(ma("/ip4/8.8.8.8/tcp/53"))

  test "DNS addresses are not filterable":
    check isPublicMA(ma("/dns4/example.com/tcp/4001"))
    check isPublicMA(ma("/dns/example.com/tcp/4001"))

  test "circuit relay addresses are not filterable even with private relay IP":
    check isCircuitRelayMA(
      ma(
        "/ip4/192.168.1.5/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit"
      )
    )
    check isCircuitRelayMA(
      ma(
        "/ip4/127.0.0.1/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit"
      )
    )

suite "isGlobalMA":
  test "accepts a global wire address of either family":
    check isGlobalMA(ma("/ip4/1.1.1.1/tcp/4001"))
    check isGlobalMA(ma("/ip6/2606:4700::1111/tcp/4001"))
    check isGlobalMA(ma("/ip4/1.1.1.1/udp/4001/quic-v1"))

  test "rejects a non-global wire address of either family":
    check not isGlobalMA(ma("/ip4/192.168.1.5/tcp/4001"))
    check not isGlobalMA(ma("/ip4/127.0.0.1/tcp/4001"))
    check not isGlobalMA(ma("/ip6/::1/tcp/4001"))
    check not isGlobalMA(ma("/ip6/fd00::1/tcp/4001"))
    check not isGlobalMA(ma("/ip6/fe80::1/tcp/4001"))

  test "rejects a name":
    check not isGlobalMA(ma("/dns4/example.com/tcp/4001"))
    check not isGlobalMA(ma("/dns/example.com/tcp/4001"))

suite "isDialableMA":
  test "wildcard bind hosts are not dialable":
    check not isDialableMA(ma("/ip4/0.0.0.0/tcp/60000"))
    check not isDialableMA(ma("/ip6/::/tcp/60000"))
    check not isDialableMA(ma("/ip6/::ffff:0.0.0.0/tcp/60000"))

  test "an unresolved ephemeral port is not dialable":
    check not isDialableMA(ma("/ip4/127.0.0.1/tcp/0"))
    check not isDialableMA(ma("/ip4/1.1.1.1/tcp/0"))
    check not isDialableMA(ma("/ip4/1.1.1.1/udp/0/quic-v1"))
    check not isDialableMA(ma("/dns4/example.com/tcp/0"))

  test "a terminal peer id does not hide the host or the port":
    check not isDialableMA(
      ma("/ip4/0.0.0.0/tcp/60000/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
    )
    check not isDialableMA(
      ma("/ip4/1.1.1.1/tcp/0/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
    )
    check isDialableMA(
      ma("/ip4/1.1.1.1/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
    )

  test "private and loopback addresses stay dialable":
    check isDialableMA(ma("/ip4/127.0.0.1/tcp/4001"))
    check isDialableMA(ma("/ip4/192.168.1.87/tcp/59203"))
    check isDialableMA(ma("/ip4/1.1.1.1/tcp/4001"))

  test "non-wire addresses pass through":
    check isDialableMA(ma("/dns4/example.com/tcp/4001"))
    check isDialableMA(ma("/unix/tmp/socket"))
    check isDialableMA(
      ma(
        "/ip4/0.0.0.0/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit"
      )
    )
