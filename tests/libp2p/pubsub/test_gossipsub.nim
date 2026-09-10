# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, chronos/rateLimit, stew/byteutils, utils, sequtils
import ../../../libp2p/[muxers/muxer, connmanager, switch]
import ../../../libp2p/stream/[bufferstream, connection]
import ../../../libp2p/utils/future
import
  ../../../libp2p/protocols/pubsub/[
    floodsub,
    gossipsub,
    gossipsub/extensions,
    gossipsub/partial_message,
    mcache,
    peertable,
    pubsubpeer,
    rpc/message,
    rpc/protobuf,
    timedcache,
  ]
import ../../tools/[unittest, bufferstream, crypto, switch_builder, multiaddress]

func withSubs*(T: type RPCMsg, topics: openArray[string], subscribe: bool): RPCMsg =
  RPCMsg.withSubscriptions(topics.mapIt(SubOpts(subscribe: subscribe, topic: it)))

suite "GossipSub":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "onNewPeer - sets peer stats and budgets and disconnects if bad score":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
      peerStats = PeerStats(
        score: gossipSub.parameters.graylistThreshold - 1.0,
        appScore: 10.0,
        slowPeerPenalty: 3.0,
        behaviourPenalty: 5.0,
      )
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And existing peer stats are set
    gossipSub.peerStats[peer.peerId] = peerStats

    # And the peer is connected
    await gossipSub.switch.connManager.storeMuxer(Muxer(connection: conns[0]))
    check:
      gossipSub.switch.isConnected(peer.peerId)

    # When onNewPeer is called
    gossipSub.parameters.disconnectBadPeers = true
    gossipSub.onNewPeer(peer)

    # Then peer stats are updated
    check:
      peer.score == peerStats.score
      peer.appScore == peerStats.appScore
      peer.slowPeerPenalty == peerStats.slowPeerPenalty
      peer.behaviourPenalty == peerStats.behaviourPenalty

    # And peer budgets are set to default values
    check:
      peer.iHaveBudget == IHavePeerBudget

    # And peer is disconnected because score < graylistThreshold
    checkUntilTimeout:
      not gossipSub.switch.isConnected(peer.peerId)

  asyncTest "onPubSubPeerEvent - StreamClosed removes peer from mesh and fanout":
    # Given a GossipSub instance with one peer in both mesh and fanout
    let
      (gossipSub, conns, peers) =
        setupGossipSubWithPeers(1, topic, populateMesh = true, populateFanout = true)
      peer = peers[0]
      event = PubSubPeerEvent(kind: PubSubPeerEventKind.StreamClosed)
    defer:
      await teardownGossipSub(gossipSub, conns)

    check:
      gossipSub.mesh.hasPeerId(topic, peer.peerId)
      gossipSub.fanout.hasPeerId(topic, peer.peerId)

    # When StreamClosed event is handled
    gossipSub.onPubSubPeerEvent(peer, event)

    # Then peer is removed from both mesh and fanout
    check:
      not gossipSub.mesh.hasPeerId(topic, peer.peerId)
      not gossipSub.fanout.hasPeerId(topic, peer.peerId)

  asyncTest "onPubSubPeerEvent - DisconnectionRequested disconnects peer":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(
        1, topic, populateGossipsub = true, populateMesh = true, populateFanout = true
      )
      peer = peers[0]
      event = PubSubPeerEvent(kind: PubSubPeerEventKind.DisconnectionRequested)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And the peer is connected
    await gossipSub.switch.connManager.storeMuxer(Muxer(connection: conns[0]))
    check:
      gossipSub.switch.isConnected(peer.peerId)
      gossipSub.mesh.hasPeerId(topic, peer.peerId)
      gossipSub.fanout.hasPeerId(topic, peer.peerId)
      gossipSub.gossipsub.hasPeerId(topic, peer.peerId)

    # When DisconnectionRequested event is handled
    gossipSub.onPubSubPeerEvent(peer, event)

    # Then peer should be disconnected
    checkUntilTimeout:
      not gossipSub.switch.isConnected(peer.peerId)
      not gossipSub.mesh.hasPeerId(topic, peer.peerId)
      not gossipSub.fanout.hasPeerId(topic, peer.peerId)
      not gossipSub.gossipsub.hasPeerId(topic, peer.peerId)

  asyncTest "drop during Connected handlers does not leave stale pubsub peer":
    let
      gossipSub = TestGossipSub.init(makeStandardSwitch(), rng = rng())
      connMngr = gossipSub.switch.connManager
      peerId = randomPeerId()
      muxer = Muxer(connection: Connection.new(peerId, Direction.In))
      unblockConnected = newAsyncEvent()
      connectedStartedFut = newFuture[void]("connectedStarted")

    defer:
      await gossipSub.switch.stop()

    proc connectedHandler(
        handlerPeerId: PeerId, event: ConnEvent
    ) {.async: (raises: [CancelledError]).} =
      if handlerPeerId == peerId:
        connectedStartedFut.completeOnce()
        await unblockConnected.wait()

    connMngr.addConnEventHandler(connectedHandler, ConnEventKind.Connected)

    let storeFut = connMngr.storeMuxer(muxer)
    await connectedStartedFut

    check:
      peerId in connMngr
      peerId notin gossipSub.peers

    await connMngr.dropPeer(peerId)
    checkUntilTimeout:
      peerId notin connMngr
      peerId notin gossipSub.peers

    unblockConnected.fire()
    await storeFut

    check:
      peerId notin connMngr
      peerId notin gossipSub.peers

  asyncTest "unsubscribePeer - handles nil peer gracefully":
    # Given a GossipSub instance
    let (gossipSub, conns, _) = setupGossipSubWithPeers(0, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And a non-existent peer ID
    let nonExistentPeerId = randomPeerId()

    # When unsubscribePeer is called with non-existent peer
    gossipSub.unsubscribePeer(nonExistentPeerId)

    # Then no errors occur (method returns early for nil peers)
    check:
      true

  asyncTest "unsubscribeAll does not crash when peers table is mutated during iteration":
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(3, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # An onSend hook fires synchronously from within the peers-table iteration
    # in onTopicSubscription (via sendSubs -> send -> sendObservers). We use it
    # to mutate `gossipSub.peers` mid-iteration, standing in for an incoming
    # subscription arriving on the network path.
    let extraPeerId = randomPeerId()
    let extraPeer = peers[0]

    var injected = false
    proc onSend(p: PubSubPeer, msg: var RPCMsg) {.gcsafe, raises: [].} =
      # Only inject during the unsubscribe subscription message (which carries
      # `subscriptions`), not during unrelated control-message broadcasts.
      if not injected and msg.subscriptions.len > 0:
        injected = true
        gossipSub.peers[extraPeerId] = extraPeer

    let observers = new(seq[PubSubObserver])
    observers[].add(PubSubObserver(onSend: onSend))
    for peer in peers:
      peer.observers = observers

    gossipSub.unsubscribeAll(topic)

    check injected

  asyncTest "unsubscribePeer - removes peer from mesh, gossipsub, fanout and subscribedDirectPeers":
    # Given a GossipSub instance with one peer in mesh
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(
        1, topic, populateGossipsub = true, populateMesh = true, populateFanout = true
      )
      peer = peers[0]
      peerId = peer.peerId
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer is configured as a direct peer
    gossipSub.parameters.directPeers[peerId] = @[]
    discard gossipSub.subscribedDirectPeers.addPeer(topic, peer)

    check:
      gossipSub.mesh.hasPeerId(topic, peerId)
      gossipSub.gossipsub.hasPeerId(topic, peerId)
      gossipSub.fanout.hasPeerId(topic, peerId)
      gossipSub.subscribedDirectPeers.hasPeerId(topic, peerId)

    # When unsubscribePeer is called
    gossipSub.unsubscribePeer(peerId)

    # Then peer is removed from mesh
    check:
      not gossipSub.mesh.hasPeerId(topic, peerId)
      not gossipSub.gossipsub.hasPeerId(topic, peerId)
      not gossipSub.fanout.hasPeerId(topic, peerId)
      not gossipSub.subscribedDirectPeers.hasPeerId(topic, peerId)

  asyncTest "unsubscribePeer - resets firstMessageDeliveries in peerStats":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
      peerId = peer.peerId
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer stats with firstMessageDeliveries set
    gossipSub.peerStats[peerId] = PeerStats()
    gossipSub.peerStats[peerId].topicInfos[topic] =
      TopicInfo(firstMessageDeliveries: 5.0)
    check:
      gossipSub.peerStats[peerId].topicInfos[topic].firstMessageDeliveries == 5.0

    # When unsubscribePeer is called
    gossipSub.unsubscribePeer(peerId)

    # Then firstMessageDeliveries is reset to 0
    gossipSub.peerStats.withValue(peerId, stats):
      check:
        stats[].topicInfos[topic].firstMessageDeliveries == 0.0

  asyncTest "unsubscribePeer - removes peer from peersInIP":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
      peerId = peer.peerId
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer has an address and is in peersInIP
    let testAddress = TcpAutoAddress
    peer.address = Opt.some(testAddress)
    gossipSub.peersInIP[testAddress] = initHashSet[PeerId]()
    gossipSub.peersInIP[testAddress].incl(peerId)

    # And verify peer is initially in peersInIP
    check:
      peerId in gossipSub.peersInIP[testAddress]

    # When unsubscribePeer is called
    gossipSub.unsubscribePeer(peerId)

    # Then peer is removed from peersInIP
    check:
      testAddress notin gossipSub.peersInIP

  asyncTest "handleSubscribe via rpcHandler - subscribe and unsubscribe with direct peer":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And the peer is configured as a direct peer
    gossipSub.parameters.directPeers[peer.peerId] = @[]

    # When a subscribe message is sent via RPC handler
    await gossipSub.rpcHandler(peer, RPCMsg.withSubs(@[topic], true).encode(false))

    # Then the peer is added to gossipsub for the topic
    # And the peer is added to subscribedDirectPeers
    check:
      gossipSub.gossipsub.hasPeer(topic, peer)
      gossipSub.subscribedDirectPeers.hasPeer(topic, peer)

    # When Peer is added to the mesh and fanout
    discard gossipSub.mesh.addPeer(topic, peer)
    discard gossipSub.fanout.addPeer(topic, peer)

    # And an unsubscribe message is sent via RPC handler
    await gossipSub.rpcHandler(peer, RPCMsg.withSubs(@[topic], false).encode(false))

    # Then the peer is removed from gossipsub, mesh and fanout
    # And the peer is removed from subscribedDirectPeers
    check:
      not gossipSub.gossipsub.hasPeer(topic, peer)
      not gossipSub.mesh.hasPeer(topic, peer)
      not gossipSub.fanout.hasPeer(topic, peer)
      not gossipSub.subscribedDirectPeers.hasPeer(topic, peer)

  asyncTest "handleSubscribe via rpcHandler - subscribe unknown peer":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer is not in gossipSub.peers
    let nonExistentPeerId = randomPeerId()
    peer.peerId = nonExistentPeerId # override PeerId

    # When a subscribe message is sent via RPC handler
    await gossipSub.rpcHandler(peer, RPCMsg.withSubs(@[topic], true).encode(false))

    # Then the peer is ignored
    check:
      not gossipSub.gossipsub.hasPeer(topic, peer)

  asyncTest "getOrCreatePeer removes peer created without a live connection":
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    let disconnectedPeer = randomPeerId()
    let pubSubPeer = gossipSub.getOrCreatePeer(disconnectedPeer, @[], GossipSubCodec_12)

    check:
      not pubSubPeer.handler.isNil
      disconnectedPeer notin gossipSub.peers
      # peers created by other means are untouched
      peers[0].peerId in gossipSub.peers

  test "PubSubPeer requires a non-nil handler":
    expect AssertionDefect:
      discard
        PubSubPeer.new(randomPeerId(), nil, nil, GossipSubCodec_12, 1024 * 1024, nil)

  asyncTest "runHandleLoop dispatches the first message":
    var handled = false

    proc handler(
        peer: PubSubPeer, data: sink seq[byte]
    ) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
      handled = data == @[byte 0]

    let
      stream = TestBufferStream.new(noop)
      peer = PubSubPeer.new(
        randomPeerId(), nil, nil, GossipSubCodec_12, 1024 * 1024, handler = handler
      )
    defer:
      await peer.stopTasks()
      await stream.close()

    let handleFut = peer.runHandleLoop(stream)
    await stream.pushData(@[byte 1, 0])
    await stream.pushEof()
    await handleFut

    check handled

  asyncTest "subscribe and unsubscribeAll":
    let (gossipSub, conns, _) =
      setupGossipSubWithPeers(15, topic, populateGossipsub = true, populateMesh = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # test via dynamic dispatch
    gossipSub.PubSub.subscribe(topic, voidTopicHandler)

    check:
      gossipSub.topics.contains(topic)
      gossipSub.gossipsub[topic].len() > 0
      gossipSub.mesh[topic].len() > 0

    # test via dynamic dispatch
    gossipSub.PubSub.unsubscribeAll(topic)

    check:
      topic notin gossipSub.topics # not in local topics
      topic notin gossipSub.mesh # not in mesh
      topic in gossipSub.gossipsub # but still in gossipsub table (for fanning out)

  asyncTest "rpcHandler - drop messages of topics without subscription":
    var (gossipSub, conns, peers) = setupGossipSubWithPeers(30, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # generate messages
    var seqno = 0'u64
    for i in 0 .. 5:
      let conn = conns[i]
      let peer = peers[i]
      inc seqno
      let msg =
        Message.init(conn.peerId, ("bar" & $i).toBytes(), topic, Opt.some(seqno))
      let msgId = gossipSub.salt(gossipSub.msgIdProvider(msg).get())
      await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))
      check msgId notin gossipSub.seen

    check gossipSub.mcache.msgs.len == 0

  test "seen cache uses configured maximum size":
    let
      params = GossipSubParams.init(seenMaxSize = 3)
      gossipSub =
        TestGossipSub.init(makeStandardSwitch(), parameters = params, rng = rng())

    for i in 0 .. 3:
      discard gossipSub.addSeen(gossipSub.salt(($i).toBytes()))

    check:
      gossipSub.seen.len == 3
      gossipSub.salt("0".toBytes()) notin gossipSub.seen

  asyncTest "rpcHandler - subscription limits":
    let gossipSub = TestGossipSub.init(makeStandardSwitch(), rng = rng())
    gossipSub.topicsHigh = 10

    var tooManyTopics: seq[string]
    for i in 0 .. gossipSub.topicsHigh + 10:
      tooManyTopics &= topic & $i
    let lotOfSubs = RPCMsg.withSubs(tooManyTopics, true)

    let conn = TestBufferStream.new(noop)
    let peerId = randomPeerId()
    conn.peerId = peerId
    let peer = gossipSub.getPubSubPeer(peerId)

    await gossipSub.rpcHandler(peer, encode(lotOfSubs, false))

    check:
      gossipSub.gossipsub.len == gossipSub.topicsHigh
      peer.behaviourPenalty > 0.0

    await conn.close()

  asyncTest "rpcHandler - cumulative subscription limit across messages":
    let gossipSub = TestGossipSub.init(makeStandardSwitch(), rng = rng())
    gossipSub.topicsHigh = 10

    let conn = TestBufferStream.new(noop)
    let peerId = randomPeerId()
    conn.peerId = peerId
    let peer = gossipSub.getPubSubPeer(peerId)

    for i in 0 .. gossipSub.topicsHigh + 10:
      let sub = RPCMsg.withSubs(@[topic & $i], true)
      await gossipSub.rpcHandler(peer, encode(sub, false))

    check:
      gossipSub.gossipsub.len == gossipSub.topicsHigh
      peer.subscribedTopics == gossipSub.topicsHigh
      not gossipSub.gossipsub.hasKey(topic & $gossipSub.topicsHigh)
      peer.behaviourPenalty > 0.0

    let unsub = RPCMsg.withSubs(@[topic & "0"], false)
    await gossipSub.rpcHandler(peer, encode(unsub, false))
    check peer.subscribedTopics == gossipSub.topicsHigh - 1

    let lateSub = RPCMsg.withSubs(@[topic & "late"], true)
    await gossipSub.rpcHandler(peer, encode(lateSub, false))
    check:
      peer.subscribedTopics == gossipSub.topicsHigh
      gossipSub.gossipsub.hasKey(topic & "late")

    await conn.close()

  asyncTest "rpcHandler - extensions only see accepted subscriptions":
    proc unionPartsMetadata(
        a, b: PartsMetadata
    ): Result[PartsMetadata, string] {.gcsafe, raises: [].} =
      ok(a & b)

    proc materializeParts(
        topic: string, groupId: GroupId, metadata: PartsMetadata
    ): Result[PartsData, string] {.gcsafe, raises: [].} =
      ok(newSeq[byte]())

    proc validateRPC(
        rpc: PartialMessageExtensionRPC
    ): Result[void, string] {.gcsafe, raises: [].} =
      ok()

    proc onIncomingRPC(
        peer: PeerId, rpc: PartialMessageExtensionRPC
    ) {.gcsafe, raises: [].} =
      discard

    let gossipSub = TestGossipSub.init(
      makeStandardSwitch(),
      rng = rng(),
      parameters = GossipSubParams.init(
        partialMessageExtensionConfig = Opt.some(
          PartialMessageExtensionConfig(
            unionPartsMetadata: unionPartsMetadata,
            materializeParts: materializeParts,
            validateRPC: validateRPC,
            onIncomingRPC: onIncomingRPC,
            heartbeatsTillEviction: 1,
          )
        )
      ),
    )
    gossipSub.topicsHigh = 2

    let peerId = randomPeerId()
    let peer = gossipSub.getPubSubPeer(peerId)

    var subs: seq[SubOpts]
    for i in 0 .. gossipSub.topicsHigh:
      subs.add(
        SubOpts(subscribe: true, topic: topic & $i, requestsPartial: Opt.some(true))
      )

    await gossipSub.rpcHandler(peer, encode(RPCMsg.withSubscriptions(subs), false))

    check:
      gossipSub.extensionsState.peerRequestsPartial(peerId, topic & "0")
      not gossipSub.extensionsState.peerRequestsPartial(
        peerId, topic & $gossipSub.topicsHigh
      )

  asyncTest "rpcHandler - invalid message bytes":
    let gossipSub = TestGossipSub.init(makeStandardSwitch(), rng = rng())

    let peerId = randomPeerId()
    let peer = gossipSub.getPubSubPeer(peerId)

    expect PeerMessageDecodeError:
      await gossipSub.rpcHandler(peer, @[byte 1, 2, 3])

  asyncTest "rateLimit - records lightweight overhead metrics without a limiter":
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    check peer.overheadRateLimitOpt.isNone()

    gossipSub.overheadMetricsWindowStart = Moment.now()
    peer.overheadSecondWindowStart = Moment.now()

    await gossipSub.rateLimit(peer, 1024)
    await gossipSub.rateLimit(peer, 4096)

    check:
      gossipSub.rpcOverheadBytesMax == 4096
      gossipSub.peerOverheadBytesPerSecondMax == 5120

    gossipSub.overheadMetricsWindowStart = Moment.now() - 1.minutes
    peer.overheadSecondWindowStart = Moment.now() - 1.seconds
    peer.overheadBytesInSecondWindow = 1024

    await gossipSub.rateLimit(peer, 2048)

    check:
      gossipSub.rpcOverheadBytesMax == 2048
      gossipSub.peerOverheadBytesPerSecondMax == 2048
      peer.overheadBytesInSecondWindow == 2048

  asyncTest "rpcHandler - peer is disconnected and rate limit is hit when overhead rate limit is exceeded":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
      rateLimitHits = currentRateLimitHits("unknown")
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification disabled to avoid message being dropped
    gossipSub.verifySignature = false

    # And peer disconnection is enabled when rate limit is exceeded
    gossipSub.parameters.disconnectPeerAboveRateLimit = true

    # And low overheadRateLimit is set
    const
      bytes = 1
      interval = 1.millis
      overheadRateLimit = Opt.some(RateLimit(bytes: bytes, interval: interval))

    gossipSub.parameters.overheadRateLimit = overheadRateLimit
    peer.overheadRateLimitOpt = Opt.some(TokenBucket.new(bytes, interval))

    # And a message is created that will exceed the overhead rate limit
    var msg = Message.init(peer.peerId, ("bar").toBytes(), topic, Opt.some(1'u64))

    # When the GossipSub processes the message
    # Then it throws an exception due to peer disconnection
    expect PeerRateLimitError:
      await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    # And the rate limit hit counter is incremented
    check:
      currentRateLimitHits("unknown") == rateLimitHits + 1

  asyncTest "rpcHandler - peer is disconnected and rate limit is hit when overhead rate limit is exceeded when decode fails":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
      rateLimitHits = currentRateLimitHits("unknown")
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer disconnection is enabled when rate limit is exceeded
    gossipSub.parameters.disconnectPeerAboveRateLimit = true

    # And low overheadRateLimit is set
    const
      bytes = 1
      interval = 1.millis
      overheadRateLimit = Opt.some(RateLimit(bytes: bytes, interval: interval))

    gossipSub.parameters.overheadRateLimit = overheadRateLimit
    peer.overheadRateLimitOpt = Opt.some(TokenBucket.new(bytes, interval))

    # When invalid RPC data is sent that fails to decode
    expect PeerRateLimitError:
      await gossipSub.rpcHandler(peer, @[byte 1, 2, 3])

    # And the rate limit hit counter is incremented
    check:
      currentRateLimitHits("unknown") == rateLimitHits + 1

  asyncTest "rpcHandler - peer is punished and rate limit is hit when overhead rate limit is exceeded when decode fails":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
      rateLimitHits = currentRateLimitHits("unknown")
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer disconnection is disabled when rate limit is exceeded to not raise PeerRateLimitError
    gossipSub.parameters.disconnectPeerAboveRateLimit = false

    # And low overheadRateLimit is set
    const
      bytes = 1
      interval = 1.millis
      overheadRateLimit = Opt.some(RateLimit(bytes: bytes, interval: interval))

    gossipSub.parameters.overheadRateLimit = overheadRateLimit
    peer.overheadRateLimitOpt = Opt.some(TokenBucket.new(bytes, interval))

    # And initial behavior penalty is zero
    check:
      peer.behaviourPenalty == 0.0

    # When invalid RPC data is sent that fails to decode
    expect PeerMessageDecodeError:
      await gossipSub.rpcHandler(peer, @[byte 1, 2, 3])

    # And the rate limit hit counter is incremented
    check:
      currentRateLimitHits("unknown") == rateLimitHits + 1
      peer.behaviourPenalty == 0.1

  asyncTest "rpcHandler - peer is punished when decode fails":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And initial behavior penalty is zero
    check:
      peer.behaviourPenalty == 0.0

    # When invalid RPC data is sent that fails to decode
    expect PeerMessageDecodeError:
      await gossipSub.rpcHandler(peer, @[byte 1, 2, 3])

    # Then the peer is penalized with behavior penalty
    check:
      peer.behaviourPenalty == 0.1

  asyncTest "rpcHandler - message already seen - valid message dropped when ID already in seenMsgs":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification disabled to focus on seen message logic
    gossipSub.verifySignature = false

    # And a message is created
    let msg = Message.init(peer.peerId, "bar".toBytes, topic, Opt.some(1'u64))
    let data = RPCMsg.withMessages(msg).encode(false)

    # And the message ID is marked as already seen
    let messageId = gossipSub.msgIdProvider(msg).get
    let saltedMessageId = gossipSub.salt(messageId)
    check:
      not gossipSub.addSeen(saltedMessageId)

    # When the message is processed again
    await gossipSub.rpcHandler(peer, data)

    # Then the message should be dropped (not cached)
    check:
      gossipSub.mcache.msgs.len == 0

  asyncTest "rpcHandler - peer is punished when message contains invalid sequence number":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification disabled to avoid message being dropped
    gossipSub.verifySignature = false

    # And a message is created with invalid sequence number
    var msg = Message.init(peer.peerId, ("bar").toBytes(), topic, Opt.some(1'u64))
    msg.seqno = ("1").toBytes()

    # When the GossipSub processes the message
    await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    # Then the peer's invalidMessageDeliveries counter is incremented 
    check:
      gossipSub.getPeerTopicInfo(peer.peerId, topic).invalidMessageDeliveries == 1.0

  asyncTest "rpcHandler - peer is punished when message id generation fails":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification disabled to avoid message being dropped
    gossipSub.verifySignature = false

    # And a custom msgIdProvider is set that always returns an error
    func customMsgIdProvider(m: Message): Result[MessageId, ValidationResult] =
      err(ValidationResult.Reject)
    gossipSub.msgIdProvider = customMsgIdProvider

    # And a message is created
    var msg = Message.init(peer.peerId, ("bar").toBytes(), topic, Opt.some(1'u64))

    # When the GossipSub processes the message
    await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    # Then the peer's invalidMessageDeliveries counter is incremented
    check:
      gossipSub.getPeerTopicInfo(peer.peerId, topic).invalidMessageDeliveries == 1.0

  asyncTest "rpcHandler - peer is punished when signature verification fails":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification enabled
    gossipSub.verifySignature = true

    # And a message without signature is created
    var msg = Message.init(peer.peerId, ("bar").toBytes(), topic, Opt.some(1'u64))

    # When the GossipSub processes the message
    await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    # Then the peer's invalidMessageDeliveries counter is incremented
    check:
      gossipSub.getPeerTopicInfo(peer.peerId, topic).invalidMessageDeliveries == 1.0

  asyncTest "rpcHandler - peer is punished when message validation is rejected":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification disabled to avoid message being dropped earlier
    gossipSub.verifySignature = false

    # And a custom validator that always rejects messages
    proc rejectingValidator(
        topic: string, message: Message
    ): Future[ValidationResult] {.async.} =
      return ValidationResult.Reject

    # Register the rejecting validator for the topic
    gossipSub.addValidator(topic, rejectingValidator)

    # And a message is created
    var msg = Message.init(peer.peerId, ("bar").toBytes(), topic, Opt.some(1'u64))

    # When the GossipSub processes the message
    await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    # Then the peer's invalidMessageDeliveries counter is incremented
    check:
      gossipSub.getPeerTopicInfo(peer.peerId, topic).invalidMessageDeliveries == 1.0

  asyncTest "rpcHandler - message validation ignore drops message":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification disabled to avoid message being dropped
    gossipSub.verifySignature = false

    # And a custom validator that ignores messages
    proc ignoringValidator(
        topic: string, message: Message
    ): Future[ValidationResult] {.async.} =
      return ValidationResult.Ignore

    gossipSub.addValidator(topic, ignoringValidator)

    # And a message is created
    let msg = Message.init(peer.peerId, ("bar").toBytes(), topic, Opt.some(1'u64))
    let msgId = gossipSub.msgIdProvider(msg).tryGet()

    # When the message is processed via rpcHandler
    await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    # Then the message should not be cached
    check:
      gossipSub.mcache.get(msgId).isNone

    # And the peer should not be punished
    check:
      gossipSub.getPeerTopicInfo(peer.peerId, topic).invalidMessageDeliveries == 0.0

  asyncTest "rpcHandler - message validation accept and successful relay":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) =
        setupGossipSubWithPeers(5, topic, populateGossipsub = true, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And signature verification disabled to avoid message being dropped
    gossipSub.verifySignature = false

    # And a custom validator that accepts messages
    proc acceptingValidator(
        topic: string, message: Message
    ): Future[ValidationResult] {.async.} =
      return ValidationResult.Accept

    gossipSub.addValidator(topic, acceptingValidator)

    # And a message is created
    let msg = Message.init(peer.peerId, ("bar").toBytes(), topic, Opt.some(1'u64))
    let msgId = gossipSub.msgIdProvider(msg).tryGet()

    # When the message is processed via rpcHandler
    await gossipSub.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    # Then the message should be cached
    checkUntilTimeout:
      gossipSub.mcache.get(msgId).isSome

    # And the peer should be rewarded for delivery
    check:
      gossipSub.getPeerTopicInfo(peer.peerId, topic).firstMessageDeliveries == 1.0

  asyncTest "onTopicSubscription - subscribe removes topic from fanout and rebalances mesh":
    # Given a GossipSub instance with peers in gossipsub and fanout
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(5, topic, populateGossipsub = true, populateFanout = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And the topic is in fanout with peers
    check:
      gossipSub.fanout[topic].len == peers.len
      gossipSub.mesh[topic].len == 0

    # When onTopicSubscription is called with subscribed = true
    gossipSub.onTopicSubscription(topic, true)

    check:
      # Then the topic should be removed from fanout
      topic notin gossipSub.fanout
      # And mesh should be populated with peers (rebalanced)
      gossipSub.mesh[topic].len == peers.len

  asyncTest "onTopicSubscription - unsubscribe removes topic from mesh":
    # Given a GossipSub instance with peers in mesh
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(3, topic, populateGossipsub = true, populateMesh = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    check:
      gossipSub.mesh[topic].len == peers.len

    # When onTopicSubscription is called with subscribed = false
    gossipSub.onTopicSubscription(topic, false)

    # Then the topic should be removed from mesh
    check:
      topic notin gossipSub.mesh
