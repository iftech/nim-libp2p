# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[os, posix]
import results
import ./types

export types

const (
  ipv4AddMembership*, ipv4DropMembership*, ipv4MulticastTtl*, ipv4MulticastInterface*
) =
  when declared(posix.IP_ADD_MEMBERSHIP) and declared(posix.IP_MULTICAST_TTL):
    (
      posix.IP_ADD_MEMBERSHIP, posix.IP_DROP_MEMBERSHIP, posix.IP_MULTICAST_TTL,
      posix.IP_MULTICAST_IF,
    )
  elif defined(linux) or defined(android):
    (35.cint, 36.cint, 33.cint, 32.cint)
  elif defined(macosx) or defined(ios) or defined(bsd):
    (12.cint, 13.cint, 10.cint, 9.cint)
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

proc restrictMulticastReception*(socket: posix.SocketHandle): cint =
  ## Restrict multicast reception to this socket's memberships where needed.
  when defined(linux) or defined(android):
    # Linux otherwise delivers traffic for memberships on other sockets.
    const ipMulticastAll = 49.cint
    var enabled = 0.cint
    setSocketOption(socket, ipv4Protocol, ipMulticastAll, enabled)
  else:
    0

proc bindToInterface*(
    socket: posix.SocketHandle, index: uint32, ipv6: bool
): InterfaceBindingResult =
  ## Pin ingress to an interface, or report unavailable pinning or an OS error.
  ## Index zero returns ok(false) without changing the socket.
  if index == 0:
    return ok(false)
  when defined(linux) or defined(android):
    # IPv6 membership checks do not distinguish the receiving interface.
    # Bind the socket so both multicast and unicast retain ingress.
    # SO_BINDTOIFINDEX pins reception as well as transmission. Unlike changing
    # an existing binding, the initial binding needs no privilege on Linux 5.7+.
    const soBindToIfIndex = 62.cint
    var interfaceIndex = index.cint
    let status =
      setSocketOption(socket, posix.SOL_SOCKET, soBindToIfIndex, interfaceIndex)
    if status != 0:
      let error = socketLastError()
      # ENOPROTOOPT: the socket option is unsupported at this protocol level.
      # EPERM: the operation is not permitted.
      # EACCES: permission is denied.
      if error.int in [ENOPROTOOPT.int, EPERM.int, EACCES.int]:
        return ok(false)
      return err(error)
    ok(true)
  elif defined(macosx):
    # Interface pinning is unavailable here; callers must filter received packets.
    ok(false)
  else:
    ok(false)
