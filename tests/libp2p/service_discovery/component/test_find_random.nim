# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, sequtils
import ../../../../libp2p/protocols/service_discovery
import ../../../../libp2p/protocols/kademlia/ping
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

suite "Service Discovery Component - Find Random":
  teardown:
    checkTrackers()

  asyncTest "Simple find random node":
    let discos = setupServiceDiscoveryNodes(5)
    startAndDeferStop(discos)

    await connectStar(discos)

    let records = await discos[1].lookupRandom()

    check records.len == 4
    let peerIds = discos.mapIt(it.switch.peerInfo.peerId)
    for record in records:
      check record.peerId in peerIds

  asyncTest "lookupRandom completes when there are no peers to query":
    # With an empty routing table the shortlist is empty, so the lookup returns
    # immediately and lookupRandom must complete rather than hang.
    let discos = setupServiceDiscoveryNodes(1)
    startAndDeferStop(discos)

    check await discos[0].lookupRandom().withTimeout(5.seconds)

  asyncTest "lookupRandom can be cancelled while the lookup is in flight":
    # Cancelling lookupRandom must propagate the cancellation cleanly without
    # leaking transport resources, which teardown's checkTrackers verifies.
    let discos = setupServiceDiscoveryNodes(3)
    startAndDeferStop(discos)
    await connectStar(discos)

    let fut = discos[0].lookupRandom()
    await sleepAsync(1.millis)
    await fut.cancelAndWait()

  asyncTest "a disco node answers a ping on its own codec":
    let discos = setupServiceDiscoveryNodes(2)
    startAndDeferStop(discos)

    check await discos[0].ping(
      discos[1].switch.peerInfo.peerId, discos[1].switch.peerInfo.addrs
    )
