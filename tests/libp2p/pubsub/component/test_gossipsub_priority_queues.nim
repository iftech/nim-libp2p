# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/[sequtils, strutils], stew/byteutils
import
  ../../../../libp2p/protocols/pubsub/[gossipsub, pubsubpeer, peertable, rpc/messages]
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

type MockSendStream* = ref object of Connection
  ## Records every write in order. The first `stallCount` writes stay pending.
  ## Later writes complete at once. Closing fails any pending write.
  writes*: seq[seq[byte]] # messages written, in order
  pendingWrites: seq[Future[void].Raising([CancelledError, LPStreamError])]
  stallCount: int

method writeLp*(
    s: MockSendStream, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  s.writes.add(@msg)
  let fut =
    Future[void].Raising([CancelledError, LPStreamError]).init("MockSendStream.writeLp")
  if s.pendingWrites.len >= s.stallCount:
    fut.complete()
  else:
    s.pendingWrites.add(fut)
  fut

method getWrapped*(s: MockSendStream): Connection =
  s

method closeImpl*(s: MockSendStream) {.async: (raises: []).} =
  for fut in s.pendingWrites:
    if not fut.finished:
      fut.fail(newLPStreamClosedError())
  await procCall Connection(s).closeImpl()

proc releasePendingWrites*(s: MockSendStream) {.raises: [].} =
  for fut in s.pendingWrites:
    if not fut.finished:
      fut.complete()

proc stallSendStream*(
    node: GossipSub, topic: string, peerId: PeerId, stallCount: int = int.high
): MockSendStream =
  ## Point `node`'s send stream for `peerId` at a stall stream so its outbound queues fill up.
  ## The replaced stream is left open on purpose: if it closed, the peer would
  ## dial a new stream and overwrite the stall stream. It is closed at teardown.
  let mock =
    MockSendStream(dir: Direction.Out, timeout: 0.milliseconds, stallCount: stallCount)
  mock.initStream()
  node.getPeerByPeerId(topic, peerId).sendStream = mock
  mock

proc message(n: byte): seq[byte] =
  @[n, n, n]

func carries(writes: seq[seq[byte]], data: seq[byte]): bool =
  let needle = string.fromBytes(data)
  writes.anyIt(string.fromBytes(it).contains(needle))

suite "GossipSub Component - Priority Queues":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "High-priority queue overflow disconnects the peer":
    let nodes = generateNodes(2, gossip = true).toGossipSub()
    # Small cap so two pending high messages fill the high-priority queue.
    nodes[0].parameters.maxHighPriorityQueueLen = 2

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[1].peerInfo.peerId
    let mock = stallSendStream(nodes[0], topic, peerId)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)
    let penaltyBefore = peer.slowPeerPenalty

    let msg = message(1)
    # Two pending high messages fill the high-priority queue to its cap.
    var msg1 = msg
    let f1 = peer.sendEncoded(move(msg1), MessagePriority.High)
    var msg2 = msg
    let f2 = peer.sendEncoded(move(msg2), MessagePriority.High)
    check:
      f1.finished
      f2.finished
    # The third high message finds the queue full and disconnects the peer.
    var msg3 = msg
    await peer.sendEncoded(move(msg3), MessagePriority.High)

    # Only the first two high messages were written; the third disconnected instead.
    check:
      mock.writes.len == 2
      peer.slowPeerPenalty == penaltyBefore
    checkUntilTimeout:
      not nodes[0].switch.isConnected(peerId)
      not nodes[0].gossipsub.hasPeerId(topic, peerId)
      not nodes[0].mesh.hasPeerId(topic, peerId)

  asyncTest "Medium-priority queue overflow drops the message but keeps the peer":
    let nodes = generateNodes(2, gossip = true).toGossipSub()
    nodes[0].parameters.maxMediumPriorityQueueLen = 2

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[1].peerInfo.peerId
    checkUntilTimeout:
      nodes[0].mesh.hasPeerId(topic, peerId)

    let mock = stallSendStream(nodes[0], topic, peerId)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)
    let penaltyBefore = peer.slowPeerPenalty

    # A pending high message keeps the high-priority queue non-empty, so the
    # medium messages are queued rather than sent at once.
    check peer.sendEncoded(message(9), MessagePriority.High).finished

    # maxMedium = 2: the first two are queued, the third overflows and is dropped.
    for i in 0 ..< 3:
      check peer.sendEncoded(message(byte(i)), MessagePriority.Medium).finished

    check:
      # Only the high message was written; the medium messages were queued or dropped.
      mock.writes.len == 1
      peer.slowPeerPenalty == penaltyBefore + 1.0 # one message dropped
      peer.connected
      nodes[0].switch.isConnected(peerId)
      nodes[0].mesh.hasPeerId(topic, peerId)

  asyncTest "Low-priority queue overflow drops the message but keeps the peer":
    let nodes = generateNodes(2, gossip = true).toGossipSub()
    nodes[0].parameters.maxLowPriorityQueueLen = 2

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[1].peerInfo.peerId
    checkUntilTimeout:
      nodes[0].mesh.hasPeerId(topic, peerId)

    let mock = stallSendStream(nodes[0], topic, peerId)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)
    let penaltyBefore = peer.slowPeerPenalty

    # A pending high message keeps the high-priority queue non-empty, so the
    # low messages are queued rather than sent at once.
    check peer.sendEncoded(message(9), MessagePriority.High).finished

    # maxLow = 2: the first two are queued, the third overflows and is dropped.
    for i in 0 ..< 3:
      check peer.sendEncoded(message(byte(i)), MessagePriority.Low).finished

    check:
      # Only the high message was written; the low messages were queued or dropped.
      mock.writes.len == 1
      peer.slowPeerPenalty == penaltyBefore + 1.0 # one message dropped
      peer.connected
      nodes[0].switch.isConnected(peerId)
      nodes[0].mesh.hasPeerId(topic, peerId)

  asyncTest "Messages are sent in priority order: high, then medium, then low":
    let nodes = generateNodes(2, gossip = true).toGossipSub()
    # Caps high enough that nothing overflows, only ordering is tested.
    nodes[0].parameters.maxMediumPriorityQueueLen = 4
    nodes[0].parameters.maxLowPriorityQueueLen = 4

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[1].peerInfo.peerId
    checkUntilTimeout:
      nodes[0].mesh.hasPeerId(topic, peerId)

    let mock = stallSendStream(nodes[0], topic, peerId, stallCount = 1)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)

    let highMsgs = @[message(0), message(1)]
    let mediumMsgs = @[message(10), message(11)]
    let lowMsgs = @[message(20), message(21)]

    # A pending high message keeps the high-priority queue non-empty, so the
    # medium and low messages are queued rather than sent at once.
    var highMsg0 = highMsgs[0]
    check peer.sendEncoded(move(highMsg0), MessagePriority.High).finished

    check mock.writes == @[highMsgs[0]]

    # Interleave the sends so the order proves priority precedence, not send order.
    var
      mediumMsg0 = mediumMsgs[0]
      lowMsg0 = lowMsgs[0]
      mediumMsg1 = mediumMsgs[1]
      lowMsg1 = lowMsgs[1]
    check:
      peer.sendEncoded(move(mediumMsg0), MessagePriority.Medium).finished
      peer.sendEncoded(move(lowMsg0), MessagePriority.Low).finished
      peer.sendEncoded(move(mediumMsg1), MessagePriority.Medium).finished
      peer.sendEncoded(move(lowMsg1), MessagePriority.Low).finished

    # A further high message is written ahead of the queued medium and low messages.
    var highMsg1 = highMsgs[1]
    check peer.sendEncoded(move(highMsg1), MessagePriority.High).finished

    check mock.writes == highMsgs

    # Releasing the high message lets the queues drain: all medium, then all low.
    mock.releasePendingWrites()

    checkUntilTimeout:
      mock.writes == highMsgs & mediumMsgs & lowMsgs

  asyncTest "A copy from the peer cancels the relay still queued for it":
    # Anonymous, so the cancel cannot lean on the `fromPeer` exclusion.
    let nodes = generateNodes(
        3, gossip = true, sign = false, verifySignature = false, anonymize = true
      )
      .toGossipSub()
    nodes[0].parameters.maxLowPriorityQueueLen = 4

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[2].peerInfo.peerId
    checkUntilTimeout:
      nodes[0].mesh.hasPeerId(topic, peerId)
      nodes[2].mesh.hasPeerId(topic, nodes[0].peerInfo.peerId)

    let mock = stallSendStream(nodes[0], topic, peerId, stallCount = 1)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)

    # A pending high message keeps the queue non-empty, so the relay is queued.
    check peer.sendEncoded(message(9), MessagePriority.High).finished

    let msgData = "relay me once".toBytes()
    var copiesAtNode0 = 0
    nodes[0].addOnRecvObserver(
      proc(p: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].} =
        for m in msgs.messages:
          if m.data == msgData:
            copiesAtNode0.inc()
    )

    tryPublish await nodes[1].publish(topic, msgData), 2

    # Node 1 publishes to both peers, so node 2 sends its copy on to node 0.
    checkUntilTimeout:
      copiesAtNode0 == 2

    # Queued behind the relay, so its write proves the queue drained past it.
    let sentinel = message(7)
    check peer.sendEncoded(sentinel, MessagePriority.Low).finished

    mock.releasePendingWrites()

    checkUntilTimeout:
      sentinel in mock.writes
    check not mock.writes.carries(msgData)

  asyncTest "Persistently slow peer is penalized and pruned":
    let nodes =
      generateNodes(2, gossip = true, decayInterval = 20.milliseconds).toGossipSub()
    # Aggressive slow-peer scoring so any penalty drives the score negative.
    for node in nodes:
      node.parameters.slowPeerPenaltyWeight = -10.0
      node.parameters.slowPeerPenaltyThreshold = 0.0
      node.parameters.slowPeerPenaltyDecay = 0.9
    # Small cap so the medium queue overflows quickly.
    nodes[0].parameters.maxMediumPriorityQueueLen = 2

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[1].peerInfo.peerId
    # The peer must be in the mesh first, so the later prune is a real removal.
    checkUntilTimeout:
      nodes[0].mesh.hasPeerId(topic, peerId)

    let mock = stallSendStream(nodes[0], topic, peerId)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)

    # A pending high message keeps the high-priority queue non-empty,
    # so the medium messages are queued rather than sent at once.
    check peer.sendEncoded(message(9), MessagePriority.High).finished

    # the first two are queued, the next three are dropped
    for i in 0 ..< 5:
      check peer.sendEncoded(message(byte(i)), MessagePriority.Medium).finished
    check peer.slowPeerPenalty == 3.0

    # The penalty makes the peer's score negative, so it is pruned from the mesh.
    checkUntilTimeout:
      nodes[0].getPeerScore(peerId) < 0.0
      not nodes[0].mesh.hasPeerId(topic, peerId)

  asyncTest "Transiently slow peer recovers and is not pruned":
    let nodes =
      generateNodes(2, gossip = true, decayInterval = 20.milliseconds).toGossipSub()
    for node in nodes:
      node.parameters.slowPeerPenaltyWeight = -10.0
      # Threshold above the transient penalty, so it never affects the score.
      node.parameters.slowPeerPenaltyThreshold = 2.0
      node.parameters.slowPeerPenaltyDecay = 0.5
    nodes[0].parameters.maxMediumPriorityQueueLen = 2

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[1].peerInfo.peerId

    let mock = stallSendStream(nodes[0], topic, peerId)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)

    # A pending high message keeps the high-priority queue non-empty,
    # so the medium messages are queued rather than sent at once.
    check peer.sendEncoded(message(9), MessagePriority.High).finished

    # the first two are queued, the third is dropped
    for i in 0 ..< 3:
      check peer.sendEncoded(message(byte(i)), MessagePriority.Medium).finished
    check peer.slowPeerPenalty == 1.0

    # The penalty stays below the threshold, so it never affects the score, and
    # decay returns it to zero over heartbeats. The peer is never pruned.
    checkUntilTimeout:
      peer.slowPeerPenalty == 0.0
    check nodes[0].mesh.hasPeerId(topic, peerId)

  asyncTest "Slow-peer penalty with zero weight never prunes the peer":
    let nodes =
      generateNodes(2, gossip = true, decayInterval = 20.milliseconds).toGossipSub()
    # Same as the pruning test, but with zero weight the penalty never affects
    # the score.
    for node in nodes:
      node.parameters.slowPeerPenaltyWeight = 0.0
      node.parameters.slowPeerPenaltyThreshold = 0.0
      node.parameters.slowPeerPenaltyDecay = 0.9
    nodes[0].parameters.maxMediumPriorityQueueLen = 2

    startAndDeferStop(nodes)
    await connectStar(nodes)
    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    let peerId = nodes[1].peerInfo.peerId
    checkUntilTimeout:
      nodes[0].mesh.hasPeerId(topic, peerId)

    let mock = stallSendStream(nodes[0], topic, peerId)
    defer:
      await mock.close()
    let peer = nodes[0].getPeerByPeerId(topic, peerId)

    # A pending high message keeps the high-priority queue non-empty,
    # so the medium messages are queued rather than sent at once.
    check peer.sendEncoded(message(9), MessagePriority.High).finished

    # the first two are queued, the next three are dropped
    for i in 0 ..< 5:
      check peer.sendEncoded(message(byte(i)), MessagePriority.Medium).finished
    check peer.slowPeerPenalty == 3.0

    # Recompute the score over several scoring heartbeats, then run a mesh
    # heartbeat that would prune a low-scoring peer.
    await nodes[0].waitForScoringHeartbeatByEvent(3)
    await nodes[0].waitForNextHeartbeat()

    check:
      # The penalty stays above the threshold, but with zero weight it never
      # affects the score, so the score stays non-negative and the peer is not
      # pruned.
      peer.slowPeerPenalty > nodes[0].parameters.slowPeerPenaltyThreshold
      nodes[0].getPeerScore(peerId) >= 0.0
      nodes[0].mesh.hasPeerId(topic, peerId)
