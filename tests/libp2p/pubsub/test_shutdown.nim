# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./utils
import ../../../libp2p/connmanager
import ../../../libp2p/protocols/pubsub/[pubsub, pubsubpeer, floodsub, gossipsub]
import ../../tools/[unittest, switch_builder, bufferstream, multiaddress, lifecycle]

suite "PubSub shutdown":
  teardown:
    checkTrackers()

  asyncTest "switch cancels pubsub connectors before stopping connections":
    let
      sw = makeStandardSwitch()
      gossip = GossipSub.init(sw, rng = rng())
      dialing = newAsyncEvent()
      never = newAsyncEvent()
    var
      attempts = 0
      cancelled = false
      connectionsRunningAtCancellation = false

    proc getStream(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      inc attempts
      dialing.fire()
      try:
        await never.wait()
      finally:
        cancelled = true
        connectionsRunningAtCancellation = sw.connManager.isRunning()

    let peer = PubSubPeer.new(
      randomPeerId(), getStream, nil, GossipSubCodec_12, 1024, voidPeerHandler
    )
    gossip.peers[peer.peerId] = peer
    sw.mount(gossip)
    await sw.start()
    peer.connect()
    await dialing.wait()
    await sw.stop()

    check:
      cancelled
      connectionsRunningAtCancellation
      gossip.peers.len == 0
    peer.connect()
    check attempts == 1

  asyncTest "FloodSub stop cancels peers and rejects late peer events until restart":
    let
      sw = makeStandardSwitch()
      flood = FloodSub.init(sw, rng = rng())
      never = newAsyncEvent()
    var cancelled = false

    proc getStream(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      try:
        await never.wait()
      finally:
        cancelled = true

    let peer = PubSubPeer.new(
      randomPeerId(), getStream, nil, FloodSubCodec, 1024, voidPeerHandler
    )
    flood.peers[peer.peerId] = peer
    await flood.start()
    peer.connect()
    await flood.stop()
    check:
      cancelled
      flood.peers.len == 0
    flood.subscribePeer(randomPeerId())
    check flood.peers.len == 0
    let lateStream = TestBufferStream.new(noop)
    await flood.handleConn(lateStream, FloodSubCodec)
    check:
      lateStream.closed
      flood.peers.len == 0
    await flood.start()
    let nextPeer = PubSubPeer.new(
      randomPeerId(), getStream, nil, FloodSubCodec, 1024, voidPeerHandler
    )
    flood.peers[nextPeer.peerId] = nextPeer
    cancelled = false
    flood.subscribePeer(nextPeer.peerId)
    await flood.stop()
    check cancelled
    await sw.stop()

  asyncTest "pubsub refuses new dials while a registered upgrade drains":
    let
      server = makeStandardSwitch(MemoryAutoAddress())
      client = makeStandardSwitch(MemoryAutoAddress())
      gossip = GossipSub.init(server, rng = rng())
      remoteGossip = GossipSub.init(client, rng = rng())
      registered = newAsyncEvent()
      releaseUpgrade = newAsyncEvent()

    proc onConnected(
        peerId: PeerId, event: ConnEvent
    ) {.async: (raises: [CancelledError]).} =
      registered.fire()
      await releaseUpgrade.wait()

    server.addConnEventHandler(onConnected, ConnEventKind.Connected)
    server.mount(gossip)
    client.mount(remoteGossip)
    startAndDeferStop(@[server, client])
    defer:
      releaseUpgrade.fire()

    let connecting = client.connect(server)
    await registered.wait()
    await connecting
    let peer = gossip.getOrCreatePeer(client.peerInfo.peerId, @[GossipSubCodec_12])
    peer.connect()
    checkUntilTimeout:
      peer.connected
    let stream = peer.sendStream

    let stopped = server.stop()
    let reconnect = peer.getStream()
    check reconnect.cancelled
    await noCancel reconnect.cancelAndWait()

    let latePeer = randomPeerId()
    gossip.subscribePeer(latePeer)
    check latePeer notin gossip.peers
    let directDial = gossip.addDirectPeer(latePeer, client.peerInfo.addrs)
    check directDial.completed
    await noCancel directDial.cancelAndWait()

    await stream.close()
    await stopped

  asyncTest "stop waits for cleanup of an already removed peer":
    let
      sw = makeStandardSwitch()
      flood = FloodSub.init(sw, rng = rng())
      never = newAsyncEvent()
      cleaningUp = newAsyncEvent()
      releaseCleanup = newAsyncEvent()
    var cleanupFinished = false

    proc getStream(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      try:
        await never.wait()
      finally:
        cleaningUp.fire()
        await noCancel releaseCleanup.wait()
        cleanupFinished = true

    let peer = PubSubPeer.new(
      randomPeerId(), getStream, nil, FloodSubCodec, 1024, voidPeerHandler
    )
    flood.peers[peer.peerId] = peer
    peer.connect()
    flood.unsubscribePeer(peer.peerId)
    let
      peerStopped = peer.stopTasks()
      stopped = flood.stop()
    await cleaningUp.wait()
    check:
      flood.peers.len == 0
      not peerStopped.finished
      not stopped.finished
    releaseCleanup.fire()
    await stopped
    await peerStopped
    check cleanupFinished
    await sw.stop()

  asyncTest "overlapping GossipSub stops wait for pending cleanup, even before start":
    for started in [false, true]:
      let
        sw = makeStandardSwitch()
        gossip = GossipSub.init(sw, rng = rng())
        never = newAsyncEvent()
        cleaningUp = newAsyncEvent()
        releaseCleanup = newAsyncEvent()
      var cleanupFinished = false

      proc pendingTask() {.async: (raises: [CancelledError]).} =
        try:
          await never.wait()
        finally:
          cleaningUp.fire()
          await noCancel releaseCleanup.wait()
          cleanupFinished = true

      if started:
        await gossip.start()
      gossip.pendingTasks.add(pendingTask())
      let firstStop = gossip.stop()
      await cleaningUp.wait()
      let secondStop = gossip.stop()
      check:
        not firstStop.finished
        not secondStop.finished
      releaseCleanup.fire()
      await firstStop
      await secondStop
      check cleanupFinished
      await sw.stop()
