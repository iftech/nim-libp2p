# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import sequtils, tables, sets, chronos, stew/byteutils
import chronos/ratelimit
import
  ../utils,
  ../../../../libp2p/[
    switch,
    stream/connection,
    protocols/pubsub/pubsub,
    protocols/pubsub/floodsub,
    protocols/pubsub/timedcache,
    protocols/pubsub/rpc/message,
    protocols/pubsub/rpc/messages,
    protocols/pubsub/rpc/protobuf,
    protocols/pubsub/peertable,
    protocols/pubsub/pubsubpeer,
  ]
import ../../../../libp2p/protocols/pubsub/errors as pubsub_errors
import ../../../tools/[lifecycle, topology, unittest, futures]

proc addRateLimitedPeer(f: FloodSub, bucket: TokenBucket): PubSubPeer =
  let peerId = randomPeerId()
  proc getStream(): Future[Stream] {.
      async: (raises: [CancelledError, GetStreamDialError])
  .} =
    raise (ref GetStreamDialError)(msg: "unused")

  let peer =
    PubSubPeer.new(peerId, getStream, nil, FloodSubCodec, 1024 * 1024, voidPeerHandler)
  peer.overheadRateLimitOpt = Opt.some(bucket)
  f.peers[peerId] = peer

  peer

func failingMsgIdProvider(m: Message): Result[MessageId, ValidationResult] =
  err(ValidationResult.Reject)

suite "FloodSub Component":
  const topic = "foobar"

  teardown:
    checkTrackers()

  asyncTest "FloodSub basic publish/subscribe A -> B":
    let (handlerFut, handler) = createCompleteHandler()

    let nodes = generateNodes(2).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[1].subscribe(topic, handler)
    waitSubscribe(nodes[0], nodes[1], topic)

    check (await nodes[0].publish(topic, "Hello!".toBytes())) > 0
    check (await handlerFut) == true

    when defined(libp2p_agents_metrics):
      let
        agentA = nodes[0].peers[nodes[1].switch.peerInfo.peerId].shortAgent
        agentB = nodes[1].peers[nodes[0].switch.peerInfo.peerId].shortAgent
      check:
        agentA == "nim-libp2p"
        agentB == "nim-libp2p"

  asyncTest "FloodSub basic publish/subscribe B -> A":
    let (handlerFut, handler) = createCompleteHandler()

    let nodes = generateNodes(2).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[0].subscribe(topic, handler)
    waitSubscribe(nodes[1], nodes[0], topic)

    check (await nodes[1].publish(topic, "Hello!".toBytes())) > 0
    check (await handlerFut) == true

  asyncTest "FloodSub validation should succeed":
    let (handlerFut, handler) = createCompleteHandler()

    let nodes = generateNodes(2).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[1].subscribe(topic, handler)
    waitSubscribe(nodes[0], nodes[1], topic)

    var validatorFut = newFuture[bool]()
    proc validator(
        topic: string, message: Message
    ): Future[ValidationResult] {.async.} =
      check topic == topic
      validatorFut.complete(true)
      ValidationResult.Accept

    nodes[1].addValidator(topic, validator)

    check (await nodes[0].publish(topic, "Hello!".toBytes())) > 0
    check (await handlerFut) == true

  asyncTest "FloodSub validation should fail":
    proc handler(topic: string, data: seq[byte]) {.async.} =
      raiseAssert "Handler should not be called when validation fails"

    let nodes = generateNodes(2).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[1].subscribe(topic, handler)
    waitSubscribe(nodes[0], nodes[1], topic)

    var validatorFut = newFuture[bool]()
    proc validator(
        topic: string, message: Message
    ): Future[ValidationResult] {.async.} =
      validatorFut.complete(true)
      ValidationResult.Reject

    nodes[1].addValidator(topic, validator)

    discard await nodes[0].publish(topic, "Hello!".toBytes())

  asyncTest "FloodSub validation one fails and one succeeds":
    const
      topicFoo = "foo"
      topicBar = "bar"
    var handlerFut = newFuture[bool]()
    proc handler(topic: string, data: seq[byte]) {.async.} =
      check topic == topicFoo
      handlerFut.complete(true)

    let nodes = generateNodes(2).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    nodes[1].subscribe(topicFoo, handler)
    waitSubscribe(nodes[0], nodes[1], topicFoo)
    nodes[1].subscribe(topicBar, handler)
    waitSubscribe(nodes[0], nodes[1], topicBar)

    proc validator(
        topic: string, message: Message
    ): Future[ValidationResult] {.async.} =
      if topic == topicFoo: ValidationResult.Accept else: ValidationResult.Reject

    nodes[1].addValidator(topicFoo, topicBar, validator)

    check (await nodes[0].publish(topicFoo, "Hello!".toBytes())) > 0
    check (await nodes[0].publish(topicBar, "Hello!".toBytes())) > 0

  asyncTest "FloodSub multiple peers, no self trigger":
    const numberOfNodes = 10

    var futs = newSeq[(Future[void], TopicHandler, ref int)](numberOfNodes)
    for i in 0 ..< numberOfNodes:
      closureScope:
        var
          fut = newFuture[void]()
          counter = new int
        futs[i] = (
          fut,
          (
            proc(handlerTopic: string, data: seq[byte]) {.async.} =
              check handlerTopic == topic
              inc counter[]
              if counter[] == numberOfNodes - 1:
                fut.complete()
          ),
          counter,
        )

    let nodes = generateNodes(numberOfNodes, triggerSelf = false).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, futs.mapIt(it[1]))
    # A full star of numberOfNodes needs numberOfNodes * (numberOfNodes - 1)
    # pubsub streams to be dialed and negotiated; give this more headroom
    # than the 30s default on loaded CI runners (see #2798).
    waitSubscribeStar(nodes, topic, timeout = 90.seconds)

    var pubs: seq[Future[int]]
    for i in 0 ..< numberOfNodes:
      pubs &= nodes[i].publish(topic, ("Hello!" & $i).toBytes())
    await allFuturesRaising(pubs)

    await allFuturesRaising(futs.mapIt(it[0]))

  asyncTest "FloodSub multiple peers, with self trigger":
    const numberOfNodes = 10

    var futs = newSeq[(Future[void], TopicHandler, ref int)](numberOfNodes)
    for i in 0 ..< numberOfNodes:
      closureScope:
        var
          fut = newFuture[void]()
          counter = new int
        futs[i] = (
          fut,
          (
            proc(handlerTopic: string, data: seq[byte]) {.async.} =
              check handlerTopic == topic
              inc counter[]
              if counter[] == numberOfNodes - 1:
                fut.complete()
          ),
          counter,
        )

    let nodes = generateNodes(numberOfNodes, triggerSelf = true).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, futs.mapIt(it[1]))
    waitSubscribeStar(nodes, topic, timeout = 90.seconds)

    var pubs: seq[Future[int]]
    for i in 0 ..< numberOfNodes:
      pubs &= nodes[i].publish(topic, ("Hello!" & $i).toBytes())
    await allFuturesRaising(pubs)

    # wait the test task
    await allFuturesRaising(futs.mapIt(it[0]))

    # test calling unsubscribeAll for coverage
    #
    # This assertion must run synchronously, immediately after unsubscribeAll.
    # `unsubscribeAll` broadcasts "unsubscribe" RPC messages to every connected 
    # peer. If we polled/awaited here (e.g. via checkUntilTimeout), earlier nodes'
    # broadcasts could reach later nodes before they're checked, eventually removing
    #  their `floodsub[topic]` entry and crashing with an unhandled KeyError.
    for node in nodes:
      node.unsubscribeAll(topic)
      check:
        node.floodsub.getOrDefault(topic).len == numberOfNodes - 1
          # we keep the peers in table
        node.topics.len == 0 # remove the topic tho

  asyncTest "FloodSub message size validation":
    var messageReceived = 0
    proc handler(topic: string, data: seq[byte]) {.async.} =
      check data.len < 50
      inc(messageReceived)

    let
      bigNode = generateNodes(1).toFloodSub()[0]
      smallNode = generateNodes(1, maxMessageSize = 200).toFloodSub()[0]
      nodes = @[bigNode, smallNode]

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, handler)
    waitSubscribeStar(nodes, topic)

    let
      bigMessage = newSeq[byte](1000)
      smallMessage1 = @[1.byte]
      smallMessage2 = @[3.byte]

    # Need two different messages, otherwise they are the same when anonymized
    check (await smallNode.publish(topic, smallMessage1)) > 0
    check (await bigNode.publish(topic, smallMessage2)) > 0

    checkUntilTimeout:
      messageReceived == 2

    # Publishing a message larger than the configured maxMessageSize will not publish.
    check (await smallNode.publish(topic, bigMessage)) == 0

    # The larger node can still publish, but the smaller node cannot receive it
    # because its maxMessageSize is exceeded on the wire.
    check (await bigNode.publish(topic, bigMessage)) > 0

    await sleepAsync(300.milliseconds) # Wait before checking
    check:
      messageReceived == 2

  asyncTest "FloodSub message size validation 2":
    var messageReceived = 0
    proc handler(topic: string, data: seq[byte]) {.async.} =
      inc(messageReceived)

    let nodes = generateNodes(2, maxMessageSize = 20000000).toFloodSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, handler)
    waitSubscribeStar(nodes, topic)

    let bigMessage = newSeq[byte](19000000)

    check (await nodes[0].publish(topic, bigMessage)) > 0

    # Large message transfer (19MB over QUIC) can take longer than the default 30s timeout,
    # especially on slow CI machines (e.g. Windows runners).
    checkUntilTimeoutCustom(120.seconds, 500.milliseconds):
      messageReceived == 1

  asyncTest "FloodSub cumulative subscription limit across messages":
    let node = generateNodes(1).toFloodSub()[0]
    node.topicsHigh = 10

    let peerId = randomPeerId()
    proc getStream(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      raise (ref GetStreamDialError)(msg: "unused")

    let peer = PubSubPeer.new(
      peerId, getStream, nil, FloodSubCodec, 1024 * 1024, voidPeerHandler
    )
    node.peers[peerId] = peer

    for i in 0 .. node.topicsHigh + 10:
      let sub = RPCMsg.withSubscriptions(@[SubOpts(subscribe: true, topic: topic & $i)])
      await node.rpcHandler(peer, encode(sub, false))

    check:
      node.floodsub.len == node.topicsHigh
      peer.subscribedTopics == node.topicsHigh
      not node.floodsub.hasKey(topic & $node.topicsHigh)

    let unsub =
      RPCMsg.withSubscriptions(@[SubOpts(subscribe: false, topic: topic & "0")])
    await node.rpcHandler(peer, encode(unsub, false))
    check peer.subscribedTopics == node.topicsHigh - 1

    let lateSub =
      RPCMsg.withSubscriptions(@[SubOpts(subscribe: true, topic: topic & "late")])
    await node.rpcHandler(peer, encode(lateSub, false))
    check:
      peer.subscribedTopics == node.topicsHigh
      node.floodsub.hasKey(topic & "late")

  asyncTest "FloodSub unsubscribePeer clears emptied topics":
    let node = generateNodes(1).toFloodSub()[0]

    let peerId = randomPeerId()
    proc getStream(): Future[Stream] {.
        async: (raises: [CancelledError, GetStreamDialError])
    .} =
      raise (ref GetStreamDialError)(msg: "unused")

    let peer = PubSubPeer.new(
      peerId, getStream, nil, FloodSubCodec, 1024 * 1024, voidPeerHandler
    )
    node.peers[peerId] = peer

    for i in 0 ..< 5:
      let sub = RPCMsg.withSubscriptions(@[SubOpts(subscribe: true, topic: topic & $i)])
      await node.rpcHandler(peer, encode(sub, false))
    check node.floodsub.len == 5

    node.unsubscribePeer(peerId)
    check node.floodsub.len == 0

  asyncTest "FloodSub charges the overhead budget when message id generation fails":
    const budget = 1024

    let
      node = generateNodes(1).toFloodSub()[0]
      peer = node.addRateLimitedPeer(TokenBucket.new(budget, 1.hours))

    node.msgIdProvider = failingMsgIdProvider

    let msg = Message.init(peer.peerId, "bar".toBytes(), topic, Opt.some(1'u64))
    await node.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

    let bucket = peer.overheadRateLimitOpt.get()
    check:
      bucket.tryConsume(budget - msg.byteSize())
      not bucket.tryConsume(1)

  asyncTest "FloodSub disconnects a peer above the overhead budget":
    let
      node = generateNodes(1).toFloodSub()[0]
      peer = node.addRateLimitedPeer(TokenBucket.new(1, 1.millis))

    node.msgIdProvider = failingMsgIdProvider
    node.disconnectPeerAboveRateLimit = true

    let msg = Message.init(peer.peerId, "bar".toBytes(), topic, Opt.some(1'u64))

    expect PeerRateLimitError:
      await node.rpcHandler(peer, RPCMsg.withMessages(msg).encode(false))

  asyncTest "FloodSub gives a new peer a bucket built from overheadRateLimit":
    let node = generateNodes(1).toFloodSub()[0]
    node.overheadRateLimit = Opt.some(RateLimit(bytes: 10, interval: 1.hours))

    let peer = node.getOrCreatePeer(randomPeerId(), @[FloodSubCodec])
    check peer.overheadRateLimitOpt.isSome()

  asyncTest "FloodSub keeps the bucket a known peer already spent":
    let
      node = generateNodes(1).toFloodSub()[0]
      peer = node.addRateLimitedPeer(TokenBucket.new(10, 1.hours))
    node.overheadRateLimit = Opt.some(RateLimit(bytes: 10, interval: 1.hours))

    check peer.tryCharge(10)
    discard node.getOrCreatePeer(peer.peerId, @[FloodSubCodec])

    check not peer.tryCharge(1)

  asyncTest "FloodSub ignores an overheadRateLimit that refuses every charge":
    let node = generateNodes(1).toFloodSub()[0]
    node.overheadRateLimit = Opt.some(RateLimit(bytes: 0, interval: 1.hours))

    let peer = node.getOrCreatePeer(randomPeerId(), @[FloodSubCodec])
    check:
      peer.overheadRateLimitOpt.isNone()
      peer.tryCharge(1024)

  asyncTest "FloodSub caps the entry count of the seen cache":
    let node = generateNodes(1).toFloodSub()[0]
    check node.seen.maxSize == FloodSubSeenMaxSize
