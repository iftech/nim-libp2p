# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[os, winlean]

# Winsock IP and IPv6 multicast options (ws2ipdef.h).
const
  ipv4Protocol* = cint(0)
  ipv4MulticastInterface* = cint(9)
  ipv4MulticastTtl* = cint(10)
  ipv4AddMembership* = cint(12)
  ipv4DropMembership* = cint(13)
  ipv6Protocol* = cint(41)
  ipv6MulticastInterface* = cint(9)
  ipv6MulticastHops* = cint(10)
  ipv6JoinGroup* = cint(12)
  ipv6LeaveGroup* = cint(13)

type MulticastTtl* = cint

template toSocketHandle*(fd: untyped): winlean.SocketHandle =
  winlean.SocketHandle(fd)

proc setSocketOption*[T](
    socket: winlean.SocketHandle, level, option: cint, value: var T
): cint =
  winlean.setsockopt(socket, level, option, addr value, winlean.SockLen(sizeof(value)))

proc socketLastError*(): OSErrorCode =
  OSErrorCode(winlean.wsaGetLastError())
