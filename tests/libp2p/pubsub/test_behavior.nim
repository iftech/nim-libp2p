# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils, tables], stew/byteutils, utils, chronicles, results
import ../../../libp2p/[routing_record, crypto/crypto, multiaddress]
import
  ../../../libp2p/protocols/pubsub/[floodsub, gossipsub, mcache, peertable, rpc/message]
import ../../tools/[unittest, crypto, multiaddress]

suite "GossipSub Behavior":
  const
    topic = "foobar"
    MsgIdSuccess = "msg id gen success"

  teardown:
    checkTrackers()

  asyncTest "grafted - updates peer stats":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And no peer stats initially
    check:
      not gossipSub.peerStats[peer.peerId].topicInfos.hasKey(topic)

    # When peer is grafted 
    gossipSub.grafted(peer, topic)

    # Then peer stats are updated
    let stats = gossipSub.peerStats[peer.peerId]
    let topicInfo = stats.topicInfos[topic]

    check:
      topicInfo.inMesh
      topicInfo.meshTime == 0.seconds
      topicInfo.graftTime <= Moment.now()
      not topicInfo.meshMessageDeliveriesActive

  asyncTest "pruned - updates peer stats, applies penalty, and sets backoff":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer is grafted and in mesh initially
    gossipSub.grafted(peer, topic)

    # And message deliveries are active but below threshold
    gossipSub.topicParams[topic] = TopicParams.init()
    gossipSub.topicParams[topic].meshMessageDeliveriesThreshold = 10
    gossipSub.withPeerStats(peer.peerId) do(stats: var PeerStats):
      var info = stats.topicInfos.getOrDefault(topic)
      info.meshMessageDeliveriesActive = true
      info.meshMessageDeliveries = 5
      stats.topicInfos[topic] = info

    # And no backoff is set initially
    check:
      topic notin gossipSub.backingOff

    # When pruned is called 
    gossipSub.pruned(peer, topic, setBackoff = true)

    # Then peer stats are updated
    let stats = gossipSub.peerStats[peer.peerId]
    let topicInfo = stats.topicInfos[topic]

    check:
      not topicInfo.inMesh
      topicInfo.meshFailurePenalty == 25.0
      # And backoff should be set
      peer.peerId in gossipSub.backingOff[topic]

  asyncTest "handleBackingOff - removes expired backoff entries":
    # Given a GossipSub instance with some peers
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(2, topic)
      peer1 = peers[0]
      peer2 = peers[1]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And backoff table
    let now = Moment.now()
    gossipSub.backingOff[topic] = initTable[PeerId, Moment]()
    gossipSub.backingOff[topic][peer1.peerId] = now - 1.minutes # Expired
    gossipSub.backingOff[topic][peer2.peerId] = now + 5.minutes # Non-expired

    # And initially all peers are in backoff table
    check:
      gossipSub.backingOff[topic].len == 2
      peer1.peerId in gossipSub.backingOff[topic]
      peer2.peerId in gossipSub.backingOff[topic]

    # When handleBackingOff is called
    handleBackingOff(gossipSub.backingOff, topic)

    # Then expired entries should be removed and non-expired should remain
    check:
      gossipSub.backingOff[topic].len == 1
      peer1.peerId notin gossipSub.backingOff[topic]
      peer2.peerId in gossipSub.backingOff[topic]

  asyncTest "peerExchangeList - returns empty list when PX disabled":
    # Given a GossipSub instance with peers
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(3, topic, populateGossipsub = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer exchange is disabled
    gossipSub.parameters.enablePX = false

    # And peers have good scores
    for peer in peers:
      peer.score = 10.0

    # When peerExchangeList is called
    let peerList = gossipSub.peerExchangeList(topic)

    # Then empty list should be returned
    check peerList.len == 0

  asyncTest "peerExchangeList - returns filtered peers with SPR data":
    # Given a GossipSub instance with multiple peers
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(4, topic, populateGossipsub = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer exchange is enabled
    gossipSub.parameters.enablePX = true

    # And peers have mixed scores
    # Good peers
    peers[0].score = 10.0 # with SPR
    peers[1].score = 5.0 # without SPR
    peers[2].score = 0.0 # with SPR
    # Bad peer
    peers[3].score = -1.0

    # And some peers have signed peer records in the SPRBook
    let
      mockPrivKey0 = PrivateKey.random(ECDSA, rng()).tryGet()
      mockPrivKey2 = PrivateKey.random(ECDSA, rng()).tryGet()
      peerRecord0 = PeerRecord.init(peers[0].peerId, @[TcpAutoAddress], 1)
      peerRecord2 = PeerRecord.init(peers[2].peerId, @[TcpAutoAddress], 1)
      mockRecord0 = SignedPeerRecord.init(mockPrivKey0, peerRecord0).tryGet()
      mockRecord2 = SignedPeerRecord.init(mockPrivKey2, peerRecord2).tryGet()
    gossipSub.switch.peerStore[SPRBook][peers[0].peerId] = mockRecord0.envelope
    gossipSub.switch.peerStore[SPRBook][peers[2].peerId] = mockRecord2.envelope

    # When peerExchangeList is called 
    let peerInfoList = gossipSub.peerExchangeList(topic)

    # Then the list should contain only peers with non-negative scores
    check:
      peerInfoList.len == 3
      peerInfoList.allIt(it.peerId != peers[3].peerId)

    # And peers with SPRs should have non-empty signedPeerRecord
    let
      peer0Info = peerInfoList.filterIt(it.peerId == peers[0].peerId)[0]
      peer1Info = peerInfoList.filterIt(it.peerId == peers[1].peerId)[0]
      peer2Info = peerInfoList.filterIt(it.peerId == peers[2].peerId)[0]

    check:
      peer0Info.signedPeerRecord == mockRecord0.envelope.encode()
      peer1Info.signedPeerRecord.isNone
      peer2Info.signedPeerRecord == mockRecord2.envelope.encode()

  asyncTest "handleIHave - peers with no budget should not request messages":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And an IHAVE message
    let id = @[0'u8, 1, 2, 3]
    let msg = ControlIHave(topicID: topic, messageIDs: @[id])

    # And the peer has no budget to request messages
    peer.iHaveBudget = 0

    # When IHave is handled
    let iwants = gossipSub.handleIHave(peer, @[msg])

    # Then gossipSub should not generate an IWANT message due to budget constraints
    check:
      iwants.messageIDs.len == 0

  asyncTest "handleIHave - peers with budget should request messages":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And an IHAVE message that contains the same message ID three times
    # If ids are repeated, only one request should be generated
    let id = @[0'u8, 1, 2, 3]
    let msg = ControlIHave(topicID: topic, messageIDs: @[id, id, id])

    # Given the peer has budget to request messages
    check:
      peer.iHaveBudget > 0

    # When IHave is handled
    let iwants = gossipSub.handleIHave(peer, @[msg])

    # Then gossipSub should generate an IWANT message for the message
    check:
      iwants.messageIDs.len == 1

  asyncTest "handleIHave - do not handle IHave if peer score is below GossipThreshold threshold":
    const gossipThreshold = -100.0
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # Given peer with score below GossipThreshold
    gossipSub.parameters.gossipThreshold = gossipThreshold
    peer.score = gossipThreshold - 100.0

    # and IHave message
    let id = @[0'u8, 1, 2, 3]
    let msg = ControlIHave(topicID: topic, messageIDs: @[id])

    # When IHave is handled
    let iWant = gossipSub.handleIHave(peer, @[msg])

    # Then IHave is ignored
    check:
      iWant.messageIDs.len == 0

  asyncTest "handleIHave - do not handle IHave when message already in cache":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And an IHAVE message
    let id = @[0'u8, 1, 2, 3]
    let msg = ControlIHave(topicID: topic, messageIDs: @[id])

    # And message has already been seen
    check:
      not gossipSub.addSeen(gossipSub.salt(id))

    # When IHave is handled
    let iWant = gossipSub.handleIHave(peer, @[msg])

    # Then no IWANT should be generated
    check:
      iWant.messageIDs.len == 0

  asyncTest "handleIWant - message is handled when in cache and with sent IHave":
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # Add message to `gossipSub`'s message cache
    let id = @[0'u8, 1, 2, 3]
    gossipSub.mcache.put(id, Message())
    peer.sentIHaves[^1].incl(id)

    # Build an IWANT message that contains the same message ID three times
    # If ids are repeated, only one request should be generated
    let msg = ControlIWant(messageIDs: @[id, id, id])

    # When a peer makes an IWANT request for the a message that `gossipSub` has
    let (messages, _) = gossipSub.handleIWant(peer, @[msg])

    # Then `gossipSub` should return the message
    check:
      messages.len == 1
      gossipSub.mcache.msgs.len == 1

  asyncTest "handleIWant - do not handle IWant if peer score is below GossipThreshold threshold":
    const gossipThreshold = -100.0
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # Given peer with score below GossipThreshold
    gossipSub.parameters.gossipThreshold = gossipThreshold
    peer.score = gossipThreshold - 100.0

    # and IWant message with MsgId in mcache and sentIHaves
    let id = @[0'u8, 1, 2, 3]
    gossipSub.mcache.put(id, Message())
    peer.sentIHaves[0].incl(id)
    let msg = ControlIWant(messageIDs: @[id])

    # When IWant is handled
    let (messages, _) = gossipSub.handleIWant(peer, @[msg])

    # Then IWant is ignored
    check:
      messages.len == 0

  asyncTest "handleIWant - message not handled without sent IHave":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And message in message cache but not in sentIHaves 
    let id = @[0'u8, 1, 2, 3]
    gossipSub.mcache.put(id, Message())
    check:
      peer.sentIHaves.allIt(id notin it)

    # And an IWANT message 
    let msg = ControlIWant(messageIDs: @[id])

    # When IWANT is handled
    let (messages, _) = gossipSub.handleIWant(peer, @[msg])

    # Then IWant is ignored
    check:
      messages.len == 0

  asyncTest "handleIWant - message not handled when not in cache":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And message in sentIHaves but not in cache
    let id = @[0'u8, 1, 2, 3]
    peer.sentIHaves[0].incl(id)
    check:
      gossipSub.mcache.msgs.len == 0

    # And an IWANT message 
    let msg = ControlIWant(messageIDs: @[id])

    # When IWANT is handled
    let (messages, _) = gossipSub.handleIWant(peer, @[msg])

    # Then IWant is ignored
    check:
      messages.len == 0

  asyncTest "handleIWant - stops processing after 21 invalid requests":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And multiple message IDs
    var messageIds: seq[MessageId]
    for i in 0 ..< 25:
      let id = @[i.uint8, 1, 2, 3]
      messageIds.add(id)
      gossipSub.mcache.put(id, Message())
      # And the last 4 message IDs valid with sent IHaves
      if i > 20:
        peer.sentIHaves[0].incl(id)

    # First 21 message IDs are invalid (not in sentIHaves)
    # This means canAskIWant will return false for them
    check:
      peer.sentIHaves[0].len == 4

    # And an IWANT message with 21 invalid + 4 valid requests
    let msg = ControlIWant(messageIDs: messageIds)

    # When IWANT is handled
    let (messages, _) = gossipSub.handleIWant(peer, @[msg])

    # Then processing stops after 21 invalid requests
    # so the last 4 valid messages are not processed
    check:
      messages.len == 0

  asyncTest "handleIDontWant - Max IDONTWANT messages per heartbeat per peer":
    # Given GossipSub node with 1 peer
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    let peer = peers[0]

    # And sequence of iDontWants with more messages than max number (1200)
    proc generateMessageIds(count: int): seq[MessageId] =
      return (0 ..< count).mapIt(("msg_id_" & $it & $Moment.now()).toBytes())

    let iDontWants = @[
      ControlIWant(messageIDs: generateMessageIds(600)),
      ControlIWant(messageIDs: generateMessageIds(600)),
    ]

    # When node handles iDontWants
    gossipSub.handleIDontWant(peer, iDontWants)

    # Then it saves max IDontWantMaxCount messages in the history and the rest is dropped
    check:
      peer.iDontWants[0].len == IDontWantMaxCount

  asyncTest "handlePrune - peer is pruned and backoff is set":
    # Given a GossipSub instance with one peer in mesh
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And mesh contains peer initially
    check:
      gossipSub.mesh[topic].len == 1
      peer in gossipSub.mesh[topic]

    # And a Prune message with backoff > 0
    let pruneMsg = ControlPrune(
      topicID: topic, peers: @[], backoff: 300'u64 # 5 minutes backoff
    )

    # When handlePrune is called
    gossipSub.handlePrune(peer, @[pruneMsg])

    # Then peer is removed from mesh
    check:
      gossipSub.mesh.getOrDefault(topic).len == 0

    # And backoff is set correctly
    # Expected backoff calculation: prune.backoff (300s) + BackoffSlackTime (2s) = 302s
    let expectedBackoffSeconds = 302'u64
    let expectedBackoffTime = Moment.fromNow(expectedBackoffSeconds.int64.seconds)

    # And backoff table is properly populated
    check:
      topic in gossipSub.backingOff
      peer.peerId in gossipSub.backingOff[topic]

    # And backoff time is approximately the expected time (within 1 second tolerance)
    let actualBackoffTime = gossipSub.backingOff[topic][peer.peerId]
    let timeDifference = abs((actualBackoffTime - expectedBackoffTime).nanoseconds)
    check:
      timeDifference < 1.seconds.nanoseconds

  asyncTest "handlePrune - max backoff does not wrap around":
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    gossipSub.handlePrune(peer, @[ControlPrune(topicID: topic, backoff: high(uint64))])

    check gossipSub.backingOff.getOrDefault(topic).getOrDefault(peer.peerId) >
      Moment.fromNow(23.hours)

  asyncTest "handlePrune - ignores unsubscribed topics":
    const unknownTopic = "not-subscribed"
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    var routingRecordsCalled = false
    gossipSub.routingRecordsHandler.add(
      proc(peer: PeerId, tag: string, peers: seq[RoutingRecordsPair]) =
        routingRecordsCalled = true
    )

    gossipSub.handlePrune(
      peer,
      @[
        ControlPrune(
          topicID: unknownTopic,
          peers: @[PeerInfoMsg(peerId: peer.peerId)],
          backoff: 300'u64,
        )
      ],
    )

    check:
      unknownTopic notin gossipSub.backingOff
      peer in gossipSub.mesh[topic]
      gossipSub.mesh[topic].len == 1
      routingRecordsCalled == false

  asyncTest "handlePrune - unsolicited prune from peer outside mesh is ignored":
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    gossipSub.handlePrune(peer, @[ControlPrune(topicID: topic, backoff: 300'u64)])

    check:
      topic notin gossipSub.backingOff
      peer notin gossipSub.mesh[topic]

  asyncTest "handlePrune - peer outside mesh after our GRAFT: backoff is set, the rest is ignored":
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    var routingRecordsCalled = false
    gossipSub.routingRecordsHandler.add(
      proc(peer: PeerId, tag: string, peers: seq[RoutingRecordsPair]) =
        routingRecordsCalled = true
    )
    gossipSub.withPeerStats(peer.peerId) do(stats: var PeerStats):
      stats.topicInfos.mgetOrPut(topic).lastGraftSent = Moment.now()

    gossipSub.handlePrune(
      peer,
      @[
        ControlPrune(
          topicID: topic, peers: @[PeerInfoMsg(peerId: peer.peerId)], backoff: 300'u64
        )
      ],
    )

    check:
      peer.peerId in gossipSub.backingOff.getOrDefault(topic)
      gossipSub.peerStats[peer.peerId].topicInfos[topic].lastGraftSent == Moment()
      peer notin gossipSub.mesh[topic]
      gossipSub.mesh[topic].len == 0
      routingRecordsCalled == false

  asyncTest "handlePrune - backoff 0 sets the default pruneBackoff":
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    gossipSub.handlePrune(peer, @[ControlPrune(topicID: topic, backoff: 0'u64)])

    let
      expected =
        Moment.fromNow(gossipSub.parameters.pruneBackoff + BackoffSlackTime.seconds)
      actual = gossipSub.backingOff.getOrDefault(topic).getOrDefault(peer.peerId)
    check:
      peer notin gossipSub.mesh.getOrDefault(topic)
      abs((actual - expected).nanoseconds) < 1.seconds.nanoseconds

  asyncTest "handlePrune - do not trigger PeerExchange on Prune if peer score is below GossipThreshold threshold":
    const gossipThreshold = -100.0
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # Given peer with score below GossipThreshold
    gossipSub.parameters.gossipThreshold = gossipThreshold
    peer.score = gossipThreshold - 100.0

    # and RoutingRecordsHandler added
    var routingRecordsFut = newFuture[void]()
    gossipSub.routingRecordsHandler.add(
      proc(peer: PeerId, tag: string, peers: seq[RoutingRecordsPair]) =
        routingRecordsFut.complete()
    )

    # and Prune message
    let msg = ControlPrune(
      topicID: topic, peers: @[PeerInfoMsg(peerId: peer.peerId)], backoff: 123'u64
    )

    # When Prune is handled
    gossipSub.handlePrune(peer, @[msg])

    # Then handler is not triggered
    # Wait some time before asserting
    await sleepAsync(300.milliseconds)
    check:
      routingRecordsFut.finished() == false

  asyncTest "handleGraft - peer joins mesh for subscribed topic":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) =
        setupGossipSubWithPeers(1, topic, populateFanout = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer is not in mesh, but it is in fanout
    check:
      peer notin gossipSub.mesh[topic]
      peer in gossipSub.fanout[topic]

    # When peer sends GRAFT for the topic
    let graftMsg = ControlGraft(topicID: topic)
    let pruneResult = gossipSub.handleGraft(peer, @[graftMsg])

    # Then peer should be added to mesh, removed from fanout and no PRUNE sent
    check:
      peer in gossipSub.mesh[topic]
      peer notin gossipSub.fanout.getOrDefault(topic)
      pruneResult.len == 0

  asyncTest "handleGraft - do not graft if peer already in mesh":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And peer is already in mesh
    check:
      peer in gossipSub.mesh[topic]

    # When peer sends GRAFT for the topic
    let graftMsg = ControlGraft(topicID: topic)
    let pruneResult = gossipSub.handleGraft(peer, @[graftMsg])

    # Then graft is skipped and no PRUNE sent
    check:
      peer in gossipSub.mesh[topic]
      pruneResult.len == 0

  asyncTest "handleGraft - reject peer when mesh at dHigh threshold":
    # Given a GossipSub instance with mesh at dHigh threshold
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(6, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And configure dHigh to current mesh size
    gossipSub.parameters.dHigh = 5

    # And initially mesh has 5 peers, which equals dHigh
    gossipSub.mesh.removePeer(topic, peer)
    check:
      gossipSub.mesh[topic].len == gossipSub.parameters.dHigh
      peer notin gossipSub.mesh[topic]

    # When peer sends GRAFT
    let graftMsg = ControlGraft(topicID: topic)
    let prunes = gossipSub.handleGraft(peer, @[graftMsg])

    # Then peer should be rejected with PRUNE
    check:
      peer notin gossipSub.mesh[topic]
      gossipSub.mesh[topic].len == gossipSub.parameters.dHigh
      prunes.len == 1

  asyncTest "handleGraft - accept outbound peer when mesh at dHigh but below dOut threshold":
    # Given a GossipSub instance with mesh at dHigh threshold but lacking outbound peers
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(6, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    for peer in peers:
      peer.sendStream.transportDir = Direction.In

    # And configure dHigh to current mesh size, dOut higher than current outbound count
    gossipSub.parameters.dHigh = 5
    gossipSub.parameters.dOut = 2

    # And Peer to graft is outbound and not in the mesh
    gossipSub.mesh.removePeer(topic, peer)
    peer.sendStream.transportDir = Direction.Out

    # And initially mesh has 5 peers at dHigh, but 0 outbound peers < dOut (2)
    check:
      gossipSub.mesh[topic].len == gossipSub.parameters.dHigh
      gossipSub.mesh.outboundPeers(topic) < gossipSub.parameters.dOut
      peer notin gossipSub.mesh[topic]

    # When outbound peer sends GRAFT
    let graftMsg = ControlGraft(topicID: topic)
    let prunes = gossipSub.handleGraft(peer, @[graftMsg])

    # Then peer should be accepted despite mesh being at dHigh
    check:
      peer in gossipSub.mesh[topic]
      gossipSub.mesh[topic].len == gossipSub.parameters.dHigh + 1
      prunes.len == 0

  asyncTest "handleGraft - reject outbound peer when mesh at dHigh and dOut threshold met":
    # Given a GossipSub instance with mesh at dHigh and dOut thresholds
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(6, topic, populateMesh = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # Configure some existing peers as outbound to meet dOut threshold, peer to graft + 2 in the mesh
    for i in 0 ..< 3:
      peers[i].sendStream.transportDir = Direction.Out
    # Rest as inbound
    for i in 3 ..< 6:
      peers[i].sendStream.transportDir = Direction.In

    # And configure dHigh to current mesh size, dOut to current outbound count
    gossipSub.parameters.dHigh = 5
    gossipSub.parameters.dOut = 2

    # Initially mesh has 5 peers at dHigh, and 2 outbound peers meeting dOut (2)
    gossipSub.mesh.removePeer(topic, peer)
    check:
      gossipSub.mesh[topic].len == gossipSub.parameters.dHigh
      gossipSub.mesh.outboundPeers(topic) == gossipSub.parameters.dOut
      peer notin gossipSub.mesh[topic]

    # When outbound peer sends GRAFT
    let graftMsg = ControlGraft(topicID: topic)
    let prunes = gossipSub.handleGraft(peer, @[graftMsg])

    # Then peer should be rejected with PRUNE
    check:
      peer notin gossipSub.mesh[topic]
      prunes.len == 1

  asyncTest "handleGraft - do not graft when peer score below PublishThreshold threshold":
    const publishThreshold = -100.0
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # Given peer with score below publishThreshold
    gossipSub.parameters.publishThreshold = publishThreshold
    peer.score = publishThreshold - 100.0

    # and Graft message
    let msg = ControlGraft(topicID: topic)

    # When Graft is handled
    let prunes = gossipSub.handleGraft(peer, @[msg])

    # Then peer is ignored and not added to prunes
    check:
      gossipSub.mesh[topic].len == 0
      prunes.len == 0

  asyncTest "handleGraft - penalizes direct peer attempting to graft":
    # Given a GossipSub instance with one direct peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And the peer is configured as a direct peer
    gossipSub.parameters.directPeers[peer.peerId] = @[]

    # And initial behavior penalty is zero
    check:
      peer.behaviourPenalty == 0.0

    # When a GRAFT message is handled
    let graftMsg = ControlGraft(topicID: topic)
    let prunes = gossipSub.handleGraft(peer, @[graftMsg])

    # Then the peer is penalized with behavior penalty
    # And receives PRUNE in response
    check:
      peer.behaviourPenalty == 0.1
      prunes.len == 1

  asyncTest "handleGraft - penalizes peer for grafting during backoff period":
    # Given a GossipSub instance with one peer
    let
      (gossipSub, conns, peers) = setupGossipSubWithPeers(1, topic)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And the peer is in backoff period for the topic
    gossipSub.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[peer.peerId] =
      Moment.now() + 1.hours

    # And initial behavior penalty is zero
    check:
      peer.behaviourPenalty == 0.0

    # When a GRAFT message is handled
    let graftMsg = ControlGraft(topicID: topic)
    let prunes = gossipSub.handleGraft(peer, @[graftMsg])

    # Then the peer is penalized with behavior penalty
    # And receives PRUNE in response
    check:
      peer.behaviourPenalty == 0.1
      prunes.len == 1

  asyncTest "replenishFanout - Degree Lo":
    let (gossipSub, conns, _) =
      setupGossipSubWithPeers(15, topic, populateGossipsub = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    check gossipSub.gossipsub[topic].len == 15
    gossipSub.replenishFanout(topic)
    check gossipSub.fanout[topic].len == gossipSub.parameters.d

  asyncTest "dropFanoutPeers - drop expired fanout topics":
    let (gossipSub, conns, _) =
      setupGossipSubWithPeers(6, topic, populateGossipsub = true, populateFanout = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    gossipSub.lastFanoutPubSub[topic] = Moment.fromNow(1.millis)
    await sleepAsync(5.millis) # allow the topic to expire 

    check gossipSub.fanout[topic].len == gossipSub.parameters.d

    gossipSub.dropFanoutPeers()
    check topic notin gossipSub.fanout

  asyncTest "dropFanoutPeers - leave unexpired fanout topics":
    const
      topic1 = "foobar1"
      topic2 = "foobar2"
    let (gossipSub, conns, _) = setupGossipSubWithPeers(
      6, @[topic1, topic2], populateGossipsub = true, populateFanout = true
    )
    defer:
      await teardownGossipSub(gossipSub, conns)

    gossipSub.lastFanoutPubSub[topic1] = Moment.fromNow(1.millis)
    gossipSub.lastFanoutPubSub[topic2] = Moment.fromNow(1.minutes)
    await sleepAsync(5.millis) # allow first topic to expire 

    check gossipSub.fanout[topic1].len == gossipSub.parameters.d
    check gossipSub.fanout[topic2].len == gossipSub.parameters.d

    gossipSub.dropFanoutPeers()
    check topic1 notin gossipSub.fanout
    check topic2 in gossipSub.fanout

  asyncTest "makeGossipControlMessages - should gather up to degree D non intersecting peers":
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(45, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # generate mesh and fanout peers 
    for i in 0 ..< 30:
      let peer = peers[i]
      if i mod 2 == 0:
        gossipSub.fanout[topic].incl(peer)
      else:
        gossipSub.grafted(peer, topic)
        gossipSub.mesh[topic].incl(peer)

    # generate gossipsub (free standing) peers
    for i in 30 ..< 45:
      let peer = peers[i]
      gossipSub.gossipsub[topic].incl(peer)

    # generate messages
    var seqno = 0'u64
    for i in 0 .. 5:
      let conn = conns[i]
      inc seqno
      let msg =
        Message.init(conn.peerId, ("HELLO" & $i).toBytes(), topic, Opt.some(seqno))
      gossipSub.mcache.put(gossipSub.msgIdProvider(msg).expect(MsgIdSuccess), msg)

    check gossipSub.fanout[topic].len == 15
    check gossipSub.mesh[topic].len == 15
    check gossipSub.gossipsub[topic].len == 15

    let gossipPeers = gossipSub.makeGossipControlMessages()
    check gossipPeers.len == gossipSub.parameters.d
    for p in gossipPeers.keys:
      check not gossipSub.fanout.hasPeerId(topic, p.peerId)
      check not gossipSub.mesh.hasPeerId(topic, p.peerId)

  asyncTest "makeGossipControlMessages - should not crash on missing topics in mesh":
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(30, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # generate mesh and fanout peers 
    for i, peer in peers:
      if i mod 2 == 0:
        gossipSub.fanout[topic].incl(peer)
      else:
        gossipSub.gossipsub[topic].incl(peer)

    # generate messages
    var seqno = 0'u64
    for i in 0 .. 5:
      let conn = conns[i]
      inc seqno
      let msg =
        Message.init(conn.peerId, ("HELLO" & $i).toBytes(), topic, Opt.some(seqno))
      gossipSub.mcache.put(gossipSub.msgIdProvider(msg).expect(MsgIdSuccess), msg)

    let gossipPeers = gossipSub.makeGossipControlMessages()
    check gossipPeers.len == gossipSub.parameters.d

  asyncTest "makeGossipControlMessages - should not crash on missing topics in fanout":
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(30, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # generate mesh and fanout peers 
    for i, peer in peers:
      if i mod 2 == 0:
        gossipSub.mesh[topic].incl(peer)
        gossipSub.grafted(peer, topic)
      else:
        gossipSub.gossipsub[topic].incl(peer)

    # generate messages
    var seqno = 0'u64
    for i in 0 .. 5:
      let conn = conns[i]
      inc seqno
      let msg =
        Message.init(conn.peerId, ("HELLO" & $i).toBytes(), topic, Opt.some(seqno))
      gossipSub.mcache.put(gossipSub.msgIdProvider(msg).expect(MsgIdSuccess), msg)

    let gossipPeers = gossipSub.makeGossipControlMessages()
    check gossipPeers.len == gossipSub.parameters.d

  asyncTest "makeGossipControlMessages - should not crash on missing topics in gossip":
    let (gossipSub, conns, peers) = setupGossipSubWithPeers(30, topic)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # generate mesh and fanout peers 
    for i, peer in peers:
      if i mod 2 == 0:
        gossipSub.mesh[topic].incl(peer)
        gossipSub.grafted(peer, topic)
      else:
        gossipSub.fanout[topic].incl(peer)

    # generate messages
    var seqno = 0'u64
    for i in 0 .. 5:
      let conn = conns[i]
      inc seqno
      let msg =
        Message.init(conn.peerId, ("HELLO" & $i).toBytes(), topic, Opt.some(seqno))
      gossipSub.mcache.put(gossipSub.msgIdProvider(msg).expect(MsgIdSuccess), msg)

    let gossipPeers = gossipSub.makeGossipControlMessages()
    check gossipPeers.len == 0

  asyncTest "makeGossipControlMessages - no IHAVE for a subscribed topic once PRUNE removes its last mesh peer":
    # TODO: vacp2p/nim-libp2p#3237
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(2, topic, populateGossipsub = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    # A subscribed topic has no fanout entry
    gossipSub.fanout.del(topic)
    gossipSub.grafted(peers[0], topic)
    gossipSub.mesh[topic].incl(peers[0])

    let msg = Message.init(peers[1].peerId, "HELLO".toBytes(), topic, Opt.some(1'u64))
    gossipSub.mcache.put(gossipSub.msgIdProvider(msg).expect(MsgIdSuccess), msg)

    gossipSub.handlePrune(peers[0], @[ControlPrune(topicID: topic, backoff: 60'u64)])

    check:
      topic in gossipSub.topics
      gossipSub.gossipsub.hasPeerId(topic, peers[1].peerId)
      gossipSub.mcache.window(topic).len == 1
      topic notin gossipSub.mesh
      topic notin gossipSub.fanout
      gossipSub.makeGossipControlMessages().len == 0

  asyncTest "makeGossipControlMessages - do not select peer for IHave broadcast if peer score is below GossipThreshold threshold":
    const gossipThreshold = -100.0
    let
      (gossipSub, conns, peers) =
        setupGossipSubWithPeers(1, topic, populateGossipsub = true)
      peer = peers[0]
    defer:
      await teardownGossipSub(gossipSub, conns)

    # Given peer with score below GossipThreshold
    gossipSub.parameters.gossipThreshold = gossipThreshold
    peer.score = gossipThreshold - 100.0

    # and message in cache
    let id = @[0'u8, 1, 2, 3]
    gossipSub.mcache.put(id, Message(topic: topic))

    # When Node selects peers for IHave broadcast
    let gossipPeers = gossipSub.makeGossipControlMessages()

    # Then peer is not selected
    check:
      gossipPeers.len == 0

  asyncTest "rebalanceMesh - Degree Lo":
    let (gossipSub, conns, _) =
      setupGossipSubWithPeers(15, topic, populateGossipsub = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    check gossipSub.peers.len == 15
    gossipSub.rebalanceMesh(topic)
    check gossipSub.mesh[topic].len == gossipSub.parameters.d

  asyncTest "rebalanceMesh - bad peers":
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(15, topic, populateGossipsub = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    var scoreLow = -11'f64
    for peer in peers:
      peer.score = scoreLow
      scoreLow += 1.0

    check gossipSub.peers.len == 15
    gossipSub.rebalanceMesh(topic)
    # low score peers should not be in mesh, that's why the count must be 4
    check gossipSub.mesh[topic].len == 4
    for peer in gossipSub.mesh[topic]:
      check peer.score >= 0.0

  asyncTest "rebalanceMesh - Degree Hi":
    let (gossipSub, conns, _) =
      setupGossipSubWithPeers(15, topic, populateGossipsub = true, populateMesh = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    check gossipSub.mesh[topic].len == 15
    gossipSub.rebalanceMesh(topic)
    check gossipSub.mesh[topic].len ==
      gossipSub.parameters.d + gossipSub.parameters.dScore

  asyncTest "rebalanceMesh - fail due to backoff":
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(15, topic, populateGossipsub = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    for peer in peers:
      gossipSub.backingOff.mgetOrPut(topic, initTable[PeerId, Moment]())[peer.peerId] =
        Moment.now() + 1.hours
      let prunes = gossipSub.handleGraft(peer, @[ControlGraft(topicID: topic)])
      # there must be a control prune due to violation of backoff
      check prunes.len != 0

    check gossipSub.peers.len == 15
    gossipSub.rebalanceMesh(topic)
    # expect 0 since they are all backing off
    check gossipSub.mesh[topic].len == 0

  asyncTest "rebalanceMesh - fail due to backoff - remote":
    let (gossipSub, conns, peers) =
      setupGossipSubWithPeers(15, topic, populateGossipsub = true, populateMesh = true)
    defer:
      await teardownGossipSub(gossipSub, conns)

    check gossipSub.peers.len == 15
    gossipSub.rebalanceMesh(topic)
    check gossipSub.mesh[topic].len != 0

    for peer in peers:
      gossipSub.handlePrune(
        peer,
        @[
          ControlPrune(
            topicID: topic,
            peers: @[],
            backoff: gossipSub.parameters.pruneBackoff.seconds.uint64,
          )
        ],
      )

    # expect topic cleaned up since they are all pruned
    check topic notin gossipSub.mesh

  asyncTest "rebalanceMesh - Degree Hi - audit scenario":
    const
      numInPeers = 6
      numOutPeers = 7
      totalPeers = numInPeers + numOutPeers

    let (gossipSub, conns, peers) = setupGossipSubWithPeers(
      totalPeers, topic, populateGossipsub = true, populateMesh = true
    )
    defer:
      await teardownGossipSub(gossipSub, conns)

    gossipSub.parameters.dScore = 4
    gossipSub.parameters.d = 6
    gossipSub.parameters.dOut = 3
    gossipSub.parameters.dHigh = 12
    gossipSub.parameters.dLow = 4

    for i in 0 ..< numInPeers:
      let conn = conns[i]
      let peer = peers[i]
      conn.transportDir = Direction.In
      peer.score = 40.0

    for i in numInPeers ..< totalPeers:
      let conn = conns[i]
      let peer = peers[i]
      conn.transportDir = Direction.Out
      peer.score = 10.0

    check gossipSub.mesh[topic].len == 13
    gossipSub.rebalanceMesh(topic)
    # ensure we are above dlow
    check gossipSub.mesh[topic].len > gossipSub.parameters.dLow
    var outbound = 0
    for peer in gossipSub.mesh[topic]:
      if peer.sendStream.transportDir == Direction.Out:
        inc outbound
    # ensure we give priority and keep at least dOut outbound peers
    check outbound >= gossipSub.parameters.dOut

  asyncTest "rebalanceMesh - Degree Hi - dScore controls number of peers to retain by score when pruning":
    # Given GossipSub node starting with 13 peers in mesh
    const totalPeers = 13
    let (gossipSub, conns, _) = setupGossipSubWithPeers(
      totalPeers, topic, populateGossipsub = true, populateMesh = true
    )
    defer:
      await teardownGossipSub(gossipSub, conns)

    # And mesh is larger than dHigh
    gossipSub.parameters.dLow = 4
    gossipSub.parameters.d = 6
    gossipSub.parameters.dHigh = 8
    gossipSub.parameters.dOut = 3
    gossipSub.parameters.dScore = 13

    check gossipSub.mesh[topic].len == totalPeers

    # When mesh is rebalanced
    gossipSub.rebalanceMesh(topic)

    # Then prunning is not triggered when mesh is not larger than dScore
    check gossipSub.mesh[topic].len == totalPeers
