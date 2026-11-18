# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[os, posix]

const (
  ipv4AddMembership*, ipv4MulticastTtl*, ipv4MulticastInterface*, ipv4DropMembership*
) =
  when declared(posix.IP_ADD_MEMBERSHIP) and declared(posix.IP_MULTICAST_TTL):
    (
      posix.IP_ADD_MEMBERSHIP, posix.IP_MULTICAST_TTL, posix.IP_MULTICAST_IF,
      posix.IP_DROP_MEMBERSHIP,
    )
  elif defined(linux) or defined(android):
    (cint(35), cint(33), cint(32), cint(36))
  elif defined(macosx) or defined(ios) or defined(bsd):
    (cint(12), cint(10), cint(9), cint(13))
  else:
    {.error: "mDNS IPv4 multicast socket options are unavailable on this platform".}

# Some POSIX targets expose these C constants as imported variables in Nim.
# Templates preserve those native definitions without evaluating them in Nim.
template ipv4Protocol*(): cint =
  posix.IPPROTO_IP

template ipv6Protocol*(): cint =
  posix.IPPROTO_IPV6

template ipv6MulticastInterface*(): cint =
  posix.IPV6_MULTICAST_IF

template ipv6MulticastHops*(): cint =
  posix.IPV6_MULTICAST_HOPS

template ipv6JoinGroup*(): cint =
  posix.IPV6_JOIN_GROUP

template ipv6LeaveGroup*(): cint =
  posix.IPV6_LEAVE_GROUP

when defined(linux) or defined(android):
  type MulticastTtl* = cint
else:
  # Darwin and BSD require a one-byte value for IP_MULTICAST_TTL.
  type MulticastTtl* = uint8

template toSocketHandle*(fd: untyped): posix.SocketHandle =
  posix.SocketHandle(fd)

proc setSocketOption*[T](
    socket: posix.SocketHandle, level, option: cint, value: var T
): cint =
  posix.setsockopt(socket, level, option, addr value, posix.SockLen(sizeof(value)))

proc socketLastError*(): OSErrorCode =
  osLastError()
