# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/net
import pkg/chronicles

{.push raises: [].}

type
  Ipv4Address* = array[4, byte]
  Ipv6Address* = array[16, byte]
  Ipv4Subnet24* = array[3, byte]
  Ipv6Subnet64* = array[8, byte]

func toIpAddress*(ip: Ipv4Address): IpAddress =
  IpAddress(family: IpAddressFamily.IPv4, address_v4: ip)

func toIpAddress*(ip: Ipv6Address): IpAddress =
  IpAddress(family: IpAddressFamily.IPv6, address_v6: ip)

func subnetOf*(ip: Ipv4Address): Ipv4Subnet24 =
  var subnet: Ipv4Subnet24
  subnet[0] = ip[0]
  subnet[1] = ip[1]
  subnet[2] = ip[2]
  subnet

func subnetOf*(ip: Ipv6Address): Ipv6Subnet64 =
  var subnet: Ipv6Subnet64
  for i in 0 ..< subnet.len:
    subnet[i] = ip[i]
  subnet

chronicles.formatIt(Ipv4Address):
  net.`$`(toIpAddress(it))

chronicles.formatIt(Ipv6Address):
  net.`$`(toIpAddress(it))

chronicles.formatIt(Ipv4Subnet24):
  let ip: Ipv4Address = [it[0], it[1], it[2], 0'u8]
  net.`$`(toIpAddress(ip)) & "/24"

chronicles.formatIt(Ipv6Subnet64):
  var ip: Ipv6Address
  for i in 0 ..< it.len:
    ip[i] = it[i]
  net.`$`(toIpAddress(ip)) & "/64"
