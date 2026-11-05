# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos
import ./nameservers/posix

when defined(windows):
  import ./nameservers/windows

export posix.parseNameServers

const DefaultDnsServers* = @[
  initTAddress("1.1.1.1:53"),
  initTAddress("1.0.0.1:53"),
  initTAddress("[2606:4700:4700::1111]:53"),
]

proc getSystemNameServers*(): seq[TransportAddress] =
  ## Best-effort system nameserver discovery, falling back to
  ## `DefaultDnsServers` when the platform configuration has no usable entries.
  let servers = getNameServers()
  if servers.len == 0:
    return DefaultDnsServers
  servers
