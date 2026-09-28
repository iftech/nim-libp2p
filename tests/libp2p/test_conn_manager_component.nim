# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils, tables]
import
  ../../libp2p/[
    switch,
    connmanager,
    peerinfo,
    stream/connection,
    protocols/pubsub/gossipsub,
    protocols/pubsub/pubsub,
  ]
import ../tools/[lifecycle, unittest, switch_builder, crypto, multiaddress]

proc newWatermarkSwitch(
    lowWater: int,
    highWater: int,
    gracePeriod: Duration = 0.seconds,
    silencePeriod: Duration = 0.seconds,
    outboundBonus: int = 0,
    decayResolution: Duration = 1.minutes,
    maxConnections: int = 0,
): Switch {.raises: [LPError].} =
  var builder = makeStandardSwitchBuilder()
    .withWatermarkPolicy(lowWater, highWater, gracePeriod, silencePeriod)
    .withPeerScoring(
      PeerScoring(outboundBonus: outboundBonus, decayResolution: decayResolution)
    )
  if maxConnections > 0:
    builder = builder.withMaxConnections(maxConnections)
  builder.build()

proc newSwitches(count: int): seq[Switch] {.raises: [LPError].} =
  (0 ..< count).mapIt(makeStandardSwitch())

proc connect(dialer, listener: Switch) {.async.} =
  await dialer.connect(listener.peerInfo.peerId, listener.peerInfo.addrs)
  # short wait between connects
  await sleepAsync(50.millis)

proc peerCount(s: Switch): int =
  s.connManager.getConnections().len

suite "Connection Manager Watermark/Scoring Component":
  teardown:
    checkTrackers()

  asyncTest "watermark trims node down to lowWater":
    # peers[0] is the oldest peer, the first to be trimmed.
    const
      lowWater = 2
      highWater = 4
    let node = newWatermarkSwitch(lowWater, highWater)
    # one peer over highWater so the last dial triggers the only trim cycle
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers:
      await connect(peer, node)

    # the trim settles at lowWater with peers[0] pruned as the oldest peer
    checkUntilTimeout:
      node.peerCount == lowWater

    check not node.isConnected(peers[0].peerInfo.peerId)

  asyncTest "grace period exempts newly connected peers":
    const
      lowWater = 1
      highWater = 2
    # long grace period so every peer is too young to be trimmed
    let node = newWatermarkSwitch(lowWater, highWater, gracePeriod = 1.hours)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers:
      await connect(peer, node)

    # the trim fires but finds no eligible candidates, so all peers stay connected
    await sleepAsync(200.millis)
    check node.peerCount == peers.len

  asyncTest "grace period exempts recent peers but trims older ones":
    # peers[0] connects first and is past the grace period when the trim runs.
    # peers[1] and peers[2] are still within the grace period, so the trim skips them.
    # only peers[0] can be pruned, so the count settles above lowWater.
    const
      lowWater = 1
      highWater = 2
      gracePeriod = 1.seconds
    let node = newWatermarkSwitch(lowWater, highWater, gracePeriod = gracePeriod)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    # peers[0] moves past the grace period before the other peers connect
    await connect(peers[0], node)
    await sleepAsync(gracePeriod + 500.millis)

    # peers[1] and peers[2] connect within the grace period, peers[2] triggers the trim
    await connect(peers[1], node)
    await connect(peers[2], node)

    # the trim prunes the peer past the grace period and skips the two within it
    checkUntilTimeout:
      node.peerCount == 2

    check:
      not node.isConnected(peers[0].peerInfo.peerId)
      node.isConnected(peers[1].peerInfo.peerId)
      node.isConnected(peers[2].peerInfo.peerId)

  asyncTest "silence period throttles back-to-back trims":
    # the first trim settles the node at lowWater and starts the silence period.
    # the second batch pushes the count back over highWater within the silence period.
    # the silence period throttles the trim, so the count stays above lowWater.
    const
      lowWater = 1
      highWater = 2
    # long silence period so the second batch cannot trigger a second trim
    let node = newWatermarkSwitch(lowWater, highWater, silencePeriod = 1.hours)
    # the first batch is one over highWater, the second pushes back over it
    let firstBatch = newSwitches(highWater + 1)
    let secondBatch = newSwitches(highWater)
    let all = @[node] & firstBatch & secondBatch

    startAndDeferStop(all)

    # the first batch triggers the only trim, settling the node at lowWater
    for peer in firstBatch:
      await connect(peer, node)
    checkUntilTimeout:
      node.peerCount == lowWater

    # the second batch pushes the count back over highWater
    for peer in secondBatch:
      await connect(peer, node)

    # the silence period is still active, so the trim never runs
    # the count stays at the post-batch total instead of dropping to lowWater
    await sleepAsync(200.millis)
    check node.peerCount == lowWater + secondBatch.len

  asyncTest "protected peer survives trim":
    # peers[0] is the oldest peer, the first to be trimmed.
    # protection keeps it connected through the trim.
    const
      lowWater = 2
      highWater = 3
    let node = newWatermarkSwitch(lowWater, highWater)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers[0 ..< ^1]:
      await connect(peer, node)

    # protect peers[0] before the trim-triggering dial
    node.connManager.protect(peers[0].peerInfo.peerId, "keep")

    await connect(peers[^1], node)

    # the trim settles at lowWater with peers[0] still connected
    checkUntilTimeout:
      node.peerCount == lowWater

    check:
      node.isConnected(peers[0].peerInfo.peerId)

  asyncTest "higher-scored peer survives trim":
    # peers[0] is the oldest peer, the first to be trimmed.
    # a high static score keeps it connected through the trim.
    const
      lowWater = 2
      highWater = 3
    let node = newWatermarkSwitch(lowWater, highWater)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    await connect(peers[0], node)
    # give peers[0] a high static score before the trim-triggering dial
    node.connManager.tagPeer(peers[0].peerInfo.peerId, "important", 500)
    for peer in peers[1 .. ^1]:
      await connect(peer, node)

    # the trim settles at lowWater with peers[0] still connected
    checkUntilTimeout:
      node.peerCount == lowWater

    check node.isConnected(peers[0].peerInfo.peerId)

  asyncTest "outbound peer survives trim over inbound peers":
    # peers[0] is the oldest peer, the first to be trimmed.
    # the node dialed it, so outboundBonus keeps it connected through the trim.
    const
      lowWater = 2
      highWater = 3
    let node = newWatermarkSwitch(lowWater, highWater, outboundBonus = 500)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    # the node dials peers[0], so that connection is outbound from the node
    await connect(node, peers[0])
    # the rest dial the node, so those connections are inbound on the node
    for peer in peers[1 .. ^1]:
      await connect(peer, node)

    # the trim settles at lowWater with peers[0] still connected
    checkUntilTimeout:
      node.peerCount == lowWater

    check node.isConnected(peers[0].peerInfo.peerId)

  asyncTest "unprotect re-exposes a peer to trimming":
    # peers[0] is the oldest peer, the first to be trimmed.
    # protection keeps it through the first trim.
    # once unprotected the second trim drops it.
    const
      lowWater = 2
      highWater = 3
    let node = newWatermarkSwitch(lowWater, highWater)
    # twice highWater peers so a second batch can trigger a second trim
    let peers = newSwitches(2 * highWater)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers[0 ..< highWater]:
      await connect(peer, node)

    # protect peers[0] before the trim-triggering dial
    node.connManager.protect(peers[0].peerInfo.peerId, "keep")

    await connect(peers[highWater], node)

    # the first trim settles at lowWater with protected peers[0] still connected
    checkUntilTimeout:
      node.peerCount == lowWater
    check node.isConnected(peers[0].peerInfo.peerId)

    # remove the protection, then drive a second trim with the remaining peers
    check node.connManager.unprotect(peers[0].peerInfo.peerId, "keep") == false
    for peer in peers[highWater + 1 ..< peers.len]:
      await connect(peer, node)

    # the second trim prunes peers[0] now that it is unprotected
    checkUntilTimeout:
      node.peerCount == lowWater

    check not node.isConnected(peers[0].peerInfo.peerId)

  asyncTest "multi-tag protection holds until all tags are removed":
    # peers[0] is the oldest peer, the first to be trimmed.
    # two protection tags keep it through the first trim.
    # the second trim drops it only once both tags are removed.
    const
      lowWater = 2
      highWater = 3
      tagA = "tag-a"
      tagB = "tag-b"
    let node = newWatermarkSwitch(lowWater, highWater)
    let peers = newSwitches(2 * highWater)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers[0 ..< highWater]:
      await connect(peer, node)

    let protectedId = peers[0].peerInfo.peerId
    node.connManager.protect(protectedId, tagA)
    node.connManager.protect(protectedId, tagB)

    # removing one of two tags leaves the peer protected
    check:
      node.connManager.unprotect(protectedId, tagA) == true
      node.connManager.isProtected(protectedId)

    await connect(peers[highWater], node)

    # the first trim settles at lowWater with protected peers[0] still connected
    checkUntilTimeout:
      node.peerCount == lowWater

    check node.isConnected(protectedId)

    # removing the last tag clears protection
    check:
      node.connManager.unprotect(protectedId, tagB) == false
      not node.connManager.isProtected(protectedId)

    for peer in peers[highWater + 1 ..< peers.len]:
      await connect(peer, node)

    # the second trim prunes peers[0] now that it is unprotected
    checkUntilTimeout:
      node.peerCount == lowWater

    check not node.isConnected(protectedId)

  asyncTest "decaying tag keeps a peer until it decays":
    # peers[0] is the oldest peer, the first to be trimmed.
    # a decaying tag keeps it through the first trim.
    # once the tag value decays to zero the second trim drops it.
    const
      lowWater = 2
      highWater = 3
    let node = newWatermarkSwitch(lowWater, highWater, decayResolution = 100.millis)
    let peers = newSwitches(2 * highWater)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers[0 ..< highWater]:
      await connect(peer, node)

    # the tag value decays by 20 every 100ms
    let taggedId = peers[0].peerInfo.peerId
    node.connManager.tagPeerDecaying(taggedId, "boost", 100, 100.millis, decayFixed(20))

    await connect(peers[highWater], node)

    # the first trim settles at lowWater with the tagged peers[0] still connected
    checkUntilTimeout:
      node.peerCount == lowWater

    check node.isConnected(taggedId)

    # wait for the tag value to decay to zero
    checkUntilTimeout:
      node.connManager.peerScore(taggedId) == 0

    for peer in peers[highWater + 1 ..< peers.len]:
      await connect(peer, node)

    # the second trim prunes peers[0] now that the tag has decayed away
    checkUntilTimeout:
      node.peerCount == lowWater

    check not node.isConnected(taggedId)

  asyncTest "trim stops when more than lowWater peers are protected":
    # protecting more than lowWater peers leaves the trim unable to reach lowWater.
    # it drops every unprotected peer and then stops.
    const
      lowWater = 2
      highWater = 4
    let node = newWatermarkSwitch(lowWater, highWater)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    # peers[2 .. ^1] are protected, which is more than lowWater
    # protect before connecting so the trigger-dial peers are already exempt when the trim runs
    let protectedPeers = peers[2 .. ^1]
    for peer in protectedPeers:
      node.connManager.protect(peer.peerInfo.peerId, "keep")

    for peer in peers:
      await connect(peer, node)

    # the trim drops both unprotected peers but cannot pass the protected ones
    # so it settles at the protected count, above lowWater
    checkUntilTimeout:
      node.peerCount == protectedPeers.len

    for peer in protectedPeers:
      check node.isConnected(peer.peerInfo.peerId)

  asyncTest "hard cap and watermark run together":
    # the semaphore caps total connections while the watermark trims toward lowWater.
    # dropping peers below the cap releases their slots, freeing inbound slots again.
    const
      lowWater = 2
      highWater = 4
      maxConnections = 6
    let node = newWatermarkSwitch(lowWater, highWater, maxConnections = maxConnections)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers:
      await connect(peer, node)

    # both guards run at once: the watermark trims to lowWater, the semaphore tracks the cap
    # the trimmed connections release their slots back to the semaphore
    # the accept loop does not reserve a slot before a connection arrives
    checkUntilTimeout:
      node.peerCount == lowWater
      node.connManager.availableSlots(Direction.In) == maxConnections - lowWater

  asyncTest "hard cap rejects new connections when the trim cannot free slots":
    # every peer is protected, so the trim has nothing to prune
    # the cap stays full at maxConnections
    # the semaphore then rejects further connections: an inbound slot blocks, an outbound slot fails
    const
      lowWater = 2
      highWater = 3
      maxConnections = 4
    let node = newWatermarkSwitch(lowWater, highWater, maxConnections = maxConnections)
    let peers = newSwitches(maxConnections)
    let all = @[node] & peers

    startAndDeferStop(all)

    # protect every peer so the trim has no candidates to prune
    for peer in peers:
      node.connManager.protect(peer.peerInfo.peerId, "keep")
    for peer in peers:
      await connect(peer, node)

    # more peers than highWater are connected, but the trim can drop none of them
    # so the cap stays full at maxConnections with no inbound slots left
    checkUntilTimeout:
      node.peerCount == maxConnections
      node.connManager.availableSlots(Direction.In) == 0

    # with the cap full the semaphore rejects new connections
    check not (await node.connManager.getIncomingSlot().withTimeout(100.millis))
    check node.connManager.getOutgoingSlot().isErr()

  asyncTest "cap rejection retries watermark trimming after grace":
    const
      lowWater = 1
      highWater = 2
      maxConnections = 3
      gracePeriod = 1.seconds
    let node = newWatermarkSwitch(
      lowWater, highWater, gracePeriod = gracePeriod, maxConnections = maxConnections
    )
    let peers = newSwitches(maxConnections + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    for peer in peers[0 ..< maxConnections]:
      await connect(peer, node)

    checkUntilTimeout:
      node.peerCount == maxConnections
      node.connManager.availableSlots(Direction.In) == 0

    await sleepAsync(gracePeriod)
    let rejectedDial = peers[^1].connect(node.peerInfo.peerId, node.peerInfo.addrs)
    defer:
      await rejectedDial.cancelAndWait()

    checkUntilTimeout:
      node.peerCount == lowWater

  asyncTest "dial fails when the trim prunes the new connection":
    # reaching lowWater can force the trim to drop the dialing peer's own freshly stored connection
    # the dial then fails with DialFailedError instead of connecting and being trimmed cleanly later
    const
      lowWater = 1
      highWater = 2
    let node = newWatermarkSwitch(lowWater, highWater)
    let peers = newSwitches(highWater + 1)
    let all = @[node] & peers

    startAndDeferStop(all)

    # protect peers[0] so it is the only peer the trim is allowed to keep
    await connect(peers[0], node)
    await connect(peers[1], node)
    node.connManager.protect(peers[0].peerInfo.peerId, "keep")

    # peers[2] triggers the trim, but reaching lowWater forces it to drop both unprotected peers
    # that includes peers[2]'s own just-stored connection
    expect DialFailedError:
      await connect(peers[2], node)

  asyncTest "gossipsub drops peers pruned after Joined is emitted":
    # When the trim prunes a just-stored connection, gossipsub must observe Joined
    # before Left so it does not keep a pruned peer subscribed.
    const
      lowWater = 1
      highWater = 2
      connectedHandlerDelay = 200.millis
    let node = newWatermarkSwitch(lowWater, highWater)
    let gossip =
      GossipSub.init(switch = node, rng = rng(), parameters = GossipSubParams.init())
    node.mount(gossip)
    let peers = newSwitches(highWater + 1)
    let prunedId = peers[2].peerInfo.peerId
    let all = @[node] & peers

    startAndDeferStop(all)

    proc connectedHandler(
        peerId: PeerId, event: ConnEvent
    ) {.async: (raises: [CancelledError]).} =
      # Simulates a Connected handler with I/O that used to delay Joined past the prune.
      if peerId == prunedId:
        await sleepAsync(connectedHandlerDelay)

    node.connManager.addConnEventHandler(connectedHandler, ConnEventKind.Connected)

    # protect peers[0] so it is the only peer the trim is allowed to keep
    await connect(peers[0], node)
    await connect(peers[1], node)
    node.connManager.protect(peers[0].peerInfo.peerId, "keep")

    # peers[2] triggers the trim, which prunes its own just-stored connection.
    await connect(peers[2], node)

    # Joined is handled before Left, so the prune removes the peer from gossipsub.
    checkUntilTimeout:
      not node.isConnected(prunedId)
      prunedId notin gossip.peers

  asyncTest "score and protection are persisted between disconnections":
    let node = newWatermarkSwitch(1, 2)
    let peer = newSwitches(1)[0]
    let all = @[node, peer]

    startAndDeferStop(all)

    await connect(node, peer)

    let peerId = peer.peerInfo.peerId
    const value = 500
    node.connManager.tagPeer(peerId, "important", value)
    node.connManager.protect(peerId, "keep")

    await node.disconnect(peerId)
    checkUntilTimeout:
      not node.isConnected(peerId)

    check:
      node.connManager.peerScore(peerId) == value
      node.connManager.isProtected(peerId)
