# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import net, chronicles, results, strutils
import chronos

import ../multiaddress, ../multicodec

logScope:
  topics = "libp2p ip-address"

const RouteProbes = [parseIpAddress("8.8.8.8"), parseIpAddress("2001:4860:4860::8888")]

proc isIPv4*(ip: IpAddress): bool =
  ip.family == IpAddressFamily.IPv4

proc isIPv6*(ip: IpAddress): bool =
  ip.family == IpAddressFamily.IPv6

proc isGlobalIP*(ip: IpAddress): bool {.raises: [].} =
  ## Globally routable address of either family, so an IPv6 ULA is not global.
  initTAddress(ip, Port(0)).isGlobal()

proc primaryIPAddrTo(probe: IpAddress): Result[IpAddress, string] {.raises: [].} =
  ## Source address the routing table picks for ``probe``. No traffic is sent.
  try:
    ok(getPrimaryIPAddr(probe))
  except CatchableError as e:
    err(e.msg)
  except Defect as e:
    raise e
  except Exception as e: # on windows getPrimaryIPAddr has untracked effects
    err(e.msg)

func firstGlobalIP*(candidates: openArray[IpAddress]): Opt[IpAddress] =
  for ip in candidates:
    if ip.isGlobalIP():
      return Opt.some(ip)
  Opt.none(IpAddress)

proc getPublicIPAddress*(): Result[IpAddress, string] {.raises: [].} =
  ## Public address of the host, IPv4 first. A v6-only host reaches the v6 probe only.
  var candidates: seq[IpAddress]
  var failures: seq[string]
  for probe in RouteProbes:
    let ip = primaryIPAddrTo(probe).valueOr:
      failures.add($probe & ": " & error)
      continue
    candidates.add(ip)

  let address = firstGlobalIP(candidates)

  debug "Public IP address lookup finished",
    probes = RouteProbes.len,
    resolved = candidates.len,
    failed = RouteProbes.len - candidates.len,
    address

  let globalIp = address.valueOr:
    if candidates.len == 0:
      return err("could not determine a source IP address: " & failures.join("; "))
    return err("no globally routable source IP address found" & failures.join("; "))
  ok(globalIp)

func ipAddrMatches*(lookup: MultiAddress, addrs: openArray[MultiAddress]): bool =
  ## Returns true when the ip4 or ip6 component of ``lookup`` equals that of any addr

  let lookupIp = lookup.getPart(multiCodec("ip4")).valueOr:
    lookup.getPart(multiCodec("ip6")).valueOr:
      return false

  for ma in addrs:
    ma[0].ifValue(ipAddr):
      if ipAddr == lookupIp:
        return true
  false

proc ipSupport*(addrs: seq[MultiAddress]): (bool, bool) =
  ## Returns ipv4 and ipv6 support status of a list of MultiAddresses

  var ipv4 = false
  var ipv6 = false

  for ma in addrs:
    ma[0].ifValue(addrIp):
      if IP4.match(addrIp):
        ipv4 = true
      elif IP6.match(addrIp):
        ipv6 = true

  (ipv4, ipv6)
