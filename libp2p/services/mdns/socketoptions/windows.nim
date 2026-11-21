# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[os, winlean]

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
