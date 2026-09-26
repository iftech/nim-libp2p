# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/net
import chronos
import ../../errors

type
  MapProto* = enum
    mpTcp
    mpUdp

  MappedPort* = object ## External address the NAT device assigned.
    externalIp*: IpAddress
    externalPort*: Port

  PortMapper* = ref object of RootObj ## Abstract async NAT port-mapping client.

method map*(
    self: PortMapper, internalPort: Port, externalPort: Port, proto: MapProto
): Future[LPResult[MappedPort]] {.base, async: (raises: [CancelledError]), gcsafe.} =
  raiseAssert "PortMapper.map not implemented"

method unmap*(
    self: PortMapper, externalPort: Port, proto: MapProto
): Future[LPResult[void]] {.base, async: (raises: [CancelledError]), gcsafe.} =
  raiseAssert "PortMapper.unmap not implemented"

method close*(self: PortMapper) {.base, async: (raises: []), gcsafe.} =
  discard
