# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[nativesockets, os, winlean]

# Winsock IP and IPv6 multicast options (ws2ipdef.h).
const
  ipv4Protocol* = 0.cint
  ipv4MulticastInterface* = 9.cint
  ipv4MulticastTtl* = 10.cint
  ipv4AddMembership* = 12.cint
  ipv4DropMembership* = 13.cint
  ipv6Protocol* = 41.cint
  ipv6MulticastInterface* = 9.cint
  ipv6MulticastHops* = 10.cint
  ipv6JoinGroup* = 12.cint
  ipv6LeaveGroup* = 13.cint

type MulticastTtl* = cint

template toSocketHandle*(fd: untyped): winlean.SocketHandle =
  winlean.SocketHandle(fd)

proc setSocketOption*[T](
    socket: winlean.SocketHandle, level, option: cint, value: var T
): cint =
  winlean.setsockopt(socket, level, option, addr value, winlean.SockLen(sizeof(value)))

proc socketLastError*(): OSErrorCode =
  OSErrorCode(winlean.wsaGetLastError())

proc bindToInterface*(socket: winlean.SocketHandle, index: uint32, ipv6: bool): cint =
  # IFLIST filters incoming datagrams; UNICAST_IF alone only affects sends.
  # These options have the same numbers at both protocol levels on Windows.
  const ifList = 28.cint
  const addIfList = 29.cint
  const unicastIf = 31.cint
  let level = if ipv6: ipv6Protocol else: ipv4Protocol
  var enabled = 1'u32
  let filterStatus = setSocketOption(socket, level, ifList, enabled)
  if filterStatus != 0 or index == 0:
    return filterStatus
  var receiveIndex = index
  let listStatus = setSocketOption(socket, level, addIfList, receiveIndex)
  if listStatus != 0:
    return listStatus
  var sendIndex =
    if ipv6:
      index
    else:
      htonl(index)
  setSocketOption(socket, level, unicastIf, sendIndex)
