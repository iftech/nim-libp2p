# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/net
import chronos, results
import ../../../libp2p/services/nat/[portmapper, plum_mapper]
import ../../tools/unittest

suite "PlumMapper":
  teardown:
    checkTrackers()

  asyncTest "create + close is clean (no mapping in between)":
    let m = PlumMapper.new().get()
    await m.close()

  asyncTest "double close is a no-op":
    let m = PlumMapper.new().get()
    await m.close()
    await m.close()

  asyncTest "map after close returns 'closed' error":
    let m = PlumMapper.new().get()
    await m.close()

    let r = await m.map(Port(9000), Port(9000), mpTcp)
    check r.isErr()
    check r.error() == "PlumMapper closed"

  asyncTest "unmap after close returns 'closed' error":
    let m = PlumMapper.new().get()
    await m.close()

    let r = await m.unmap(Port(9000), mpTcp)
    check r.isErr()
    check r.error() == "PlumMapper closed"

  asyncTest "unmap without a prior map returns 'no known mapping' error":
    # no recorded mapping id, so there is nothing to destroy.
    let m = PlumMapper.new().get()
    defer:
      await m.close()

    let r = await m.unmap(Port(9000), mpTcp)
    check r.isErr()
    check r.error() == "plum unmap: no known mapping for external port (9000)"

  asyncTest "a second mapper shares the ref-counted libplum instance":
    # overlapping mappers must not double-init or tear down the shared singleton.
    let a = PlumMapper.new().get()
    let b = PlumMapper.new().get()
    await a.close()
    await b.close()
