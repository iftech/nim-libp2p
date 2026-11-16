# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/strutils, chronos

when not defined(windows):
  import stew/io2

proc parseNameServers*(conf: string): seq[TransportAddress] =
  ## Extracts nameserver addresses from resolv.conf-formatted content.
  ## resolv.conf(5): at most 3 nameservers are used.
  var servers: seq[TransportAddress]
  for line in conf.splitLines():
    let parts = line.splitWhitespace()
    if parts.len >= 2 and parts[0] == "nameserver":
      # TransportAddress cannot represent an IPv6 interface scope.
      let host = parts[1]
      if '%' in host:
        continue
      try:
        let server = initTAddress((if ':' in host: "[" & host & "]" else: host) & ":53")
        if server.family == AddressFamily.IPv6 and server.isLinkLocal():
          continue
        servers.add(server)
      except TransportAddressError:
        discard
    if servers.len >= 3:
      break
  return servers

when not defined(windows):
  proc getNameServers*(): seq[TransportAddress] =
    let conf = io2.readAllChars("/etc/resolv.conf").valueOr:
      ""
    parseNameServers(conf)
