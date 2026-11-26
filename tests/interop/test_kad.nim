# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/[switch, builders, peerid, protocols/kademlia, wire]
import ../tools/[crypto, unittest, multiaddress]
import ./kad

proc createSwitch(mountKad = true): Switch =
  let switch = SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[TcpAutoAddress])
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

  if mountKad:
    let kad = KadDHT.new(
      switch, bootstrapNodes = @[], config = KadDHTConfig.new(quorum = 2), rng = rng()
    )
    switch.mount(kad)

  switch

suite "KadDHT Interop Tests with Nim nodes":
  const ourAddress = "/ip4/127.0.0.1/tcp/0"

  teardown:
    checkTrackers()

  asyncTest "Happy path":
    let switch = createSwitch()

    await switch.start()
    defer:
      await switch.stop()

    check await kadInteropTest(
      ourAddress, $switch.peerInfo.addrs[0], switch.peerInfo.peerId
    )

  asyncTest "Fails when peer lacks KadDHT protocol":
    # No KadDHT mounted
    let switch = createSwitch(false)

    await switch.start()
    defer:
      await switch.stop()

    check not await kadInteropTest(
      ourAddress, $switch.peerInfo.addrs[0], switch.peerInfo.peerId, timeout = 3.seconds
    )

  asyncTest "Fails when peer is unreachable":
    const unreachableAddress = "/ip4/127.0.0.1/tcp/59999"
    let fakePeerId = PeerId.random()

    check not await kadInteropTest(ourAddress, unreachableAddress, fakePeerId)
