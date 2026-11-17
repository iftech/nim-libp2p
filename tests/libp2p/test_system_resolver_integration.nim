# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/nameresolving/system_resolver
import ../tools/[unittest, crypto, multiaddress, switch_builder]

suite "System resolver switch integration":
  teardown:
    checkTrackers()

  asyncTest "switch dials DNS addresses and leaves resolver ownership to the caller":
    let resolver = SystemResolver.new(rng())
    let source =
      makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver).build()
    let destination = makeStandardSwitch(TcpAutoAddress)
    defer:
      await source.stop()
      await destination.stop()
      await resolver.stop()
    await destination.start()
    await source.start()
    let address =
      ma("/dns4/localhost") & destination.peerInfo.addrs[0][1 ..^ 1].tryGet()
    await source.connect(destination.peerInfo.peerId, @[address])
    check source.isConnected(destination.peerInfo.peerId)
    await source.stop()
    check (await resolver.resolveIp("localhost", 4001.Port)).len > 0
