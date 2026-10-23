# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/[stream/connection, stream/bufferstream]
import ../../tools/[unittest]

type WrappedConnection = ref object of Connection
  wrapped: Connection

method getWrapped(s: WrappedConnection): Connection =
  s.wrapped

suite "Connection":
  test "underlying connection":
    let
      transport = WrappedConnection()
      inner = WrappedConnection(wrapped: transport)
      outer = WrappedConnection(wrapped: inner)
    check outer.getUnderlying() == transport
    transport.wrapped = transport
    check outer.getUnderlying() == transport
    transport.wrapped = nil
    check Connection(nil).getUnderlying() == nil

  asyncTest "close":
    var conn = BufferStream.new()
    await conn.close()
    check:
      conn.closed == true
