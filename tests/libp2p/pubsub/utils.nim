# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import
  metrics,
  hashes,
  random,
  tables,
  sets,
  sequtils,
  chronos,
  results,
  stew/byteutils,
  chronos/ratelimit
import
  ../../../libp2p/[
    switch,
    protocols/pubsub/errors,
    protocols/pubsub/pubsub,
    protocols/pubsub/pubsubpeer,
    protocols/pubsub/peertable,
    protocols/pubsub/gossipsub,
    protocols/pubsub/gossipsub/extensions,
    protocols/pubsub/floodsub,
    protocols/pubsub/rpc/messages,
  ]
import
  ../../tools/[unittest, crypto, bufferstream, futures, switch_builder, multiaddress]
import ./converters

export switch, converters, crypto

randomize()

const connectWarmup = 200.milliseconds
  # the delay needed for node to open all streams, start handlers after connecting it to other node
const TEST_GOSSIPSUB_HEARTBEAT_INTERVAL* = 60.milliseconds

proc waitForHeartbeatByEvent*[T: PubSub](node: T, multiplier: int = 1) {.async.} =
  for _ in 0 ..< multiplier:
    let evnt = newAsyncEvent()
    node.heartbeatEvents &= evnt
    try:
      await evnt.wait()
    finally:
      let i = node.heartbeatEvents.find(evnt)
      if i != -1:
        node.heartbeatEvents.delete(i)

proc waitForNextHeartbeat*[T: PubSub](node: T) {.async.} =
  await node.waitForHeartbeatByEvent(1)

proc waitForScoringHeartbeatByEvent*(node: GossipSub, multiplier: int = 1) {.async.} =
  for _ in 0 ..< multiplier:
    let evnt = newAsyncEvent()
    node.scoringHeartbeatEvents &= evnt
    try:
      await evnt.wait()
    finally:
      let i = node.scoringHeartbeatEvents.find(evnt)
      if i != -1:
        node.scoringHeartbeatEvents.delete(i)

type
  TestGossipSub* = ref object of GossipSub
  DValues* = object
    d*: Opt[int]
    dLow*: Opt[int]
    dHigh*: Opt[int]
    dScore*: Opt[int]
    dOut*: Opt[int]
    dLazy*: Opt[int]

proc noop*(data: sink seq[byte]) {.async: (raises: [CancelledError, LPStreamError]).} =
  discard

proc voidTopicHandler*(topic: string, data: seq[byte]) {.async.} =
  discard

proc voidPeerHandler*(
    peer: PubSubPeer, data: sink seq[byte]
) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
  discard

proc getPubSubPeer*(p: TestGossipSub, peerId: PeerId): PubSubPeer =
  proc getStream(): Future[Stream] {.
      async: (raises: [CancelledError, GetStreamDialError])
  .} =
    try:
      return await p.switch.dial(peerId, GossipSubCodec_12)
    except DialFailedError as e:
      raise (ref GetStreamDialError)(parent: e, msg: e.msg)

  let pubSubPeer = PubSubPeer.new(
    peerId, getStream, nil, GossipSubCodec_12, 1024 * 1024, voidPeerHandler
  )

  p.peers[peerId] = pubSubPeer

  onNewPeer(p, pubSubPeer)
  pubSubPeer

proc setupGossipSubWithPeers*(
    numPeers: int,
    topics: seq[string],
    populateGossipsub: bool = false,
    populateMesh: bool = false,
    populateFanout: bool = false,
): (TestGossipSub, seq[Stream], seq[PubSubPeer]) =
  let gossipSub = TestGossipSub.init(makeStandardSwitch(), rng = rng())

  for topic in topics:
    gossipSub.subscribe(topic, voidTopicHandler)
    gossipSub.topicParams[topic] = TopicParams.init()
    gossipSub.mesh[topic] = initHashSet[PubSubPeer]()
    gossipSub.gossipsub[topic] = initHashSet[PubSubPeer]()
    gossipSub.fanout[topic] = initHashSet[PubSubPeer]()

  var conns = newSeq[Stream]()
  var peers = newSeq[PubSubPeer]()
  for i in 0 ..< numPeers:
    let conn = TestBufferStream.new(noop)
    conns &= conn
    let peerId = randomPeerId()
    conn.peerId = peerId
    let peer = gossipSub.getPubSubPeer(peerId)
    peer.sendStream = conn
    peers &= peer
    for topic in topics:
      if (populateGossipsub):
        gossipSub.gossipsub[topic].incl(peer)
      if (populateMesh):
        gossipSub.grafted(peer, topic)
        gossipSub.mesh[topic].incl(peer)
      if (populateFanout):
        gossipSub.fanout[topic].incl(peer)

  return (gossipSub, conns, peers)

proc setupGossipSubWithPeers*(
    numPeers: int,
    topic: string,
    populateGossipsub: bool = false,
    populateMesh: bool = false,
    populateFanout: bool = false,
): (TestGossipSub, seq[Stream], seq[PubSubPeer]) =
  return setupGossipSubWithPeers(
    numPeers, @[topic], populateGossipsub, populateMesh, populateFanout
  )

proc teardownGossipSub*(gossipSub: TestGossipSub, conns: seq[Stream]) {.async.} =
  await allFuturesRaising(conns.mapIt(it.close()))

func defaultMsgIdProvider*(m: Message): Result[MessageId, ValidationResult] =
  let mid =
    if m.seqno.len > 0 and m.fromPeer.data.len > 0:
      byteutils.toHex(m.seqno) & $m.fromPeer
    else:
      # This part is irrelevant because it's not standard,
      # We use it exclusively for testing basically and users should
      # implement their own logic in the case they use anonymization
      $m.data.hash & $m.topic.hash
  ok mid.toBytes()

proc applyDValues*(parameters: var GossipSubParams, dValues: Opt[DValues]) =
  if dValues.isNone:
    return
  let values = dValues.get
  # Apply each value if it exists
  if values.d.isSome:
    parameters.d = values.d.get
  if values.dLow.isSome:
    parameters.dLow = values.dLow.get
  if values.dHigh.isSome:
    parameters.dHigh = values.dHigh.get
  if values.dScore.isSome:
    parameters.dScore = values.dScore.get
  if values.dOut.isSome:
    parameters.dOut = values.dOut.get
  if values.dLazy.isSome:
    parameters.dLazy = values.dLazy.get

proc generateNodes*(
    num: int,
    address: MultiAddress = QuicAutoAddress,
    msgIdProvider: MsgIdProvider = defaultMsgIdProvider,
    gossip: bool = false,
    triggerSelf: bool = false,
    sign: bool = true,
    verifySignature: bool = true,
    anonymize: bool = false,
    sendSignedPeerRecord = false,
    unsubscribeBackoff = 1.seconds,
    pruneBackoff = 1.minutes,
    fanoutTTL = 1.minutes,
    maxMessageSize: int = 1024 * 1024,
    enablePX: bool = false,
    overheadRateLimit: Opt[RateLimit] = Opt.none(RateLimit),
    codecs: seq[string] = @[],
    sendIDontWantOnPublish: bool = false,
    heartbeatInterval: Duration = TEST_GOSSIPSUB_HEARTBEAT_INTERVAL,
    floodPublish: bool = false,
    dValues: Opt[DValues] = Opt.none(DValues),
    gossipFactor: Opt[float] = Opt.none(float),
    opportunisticGraftThreshold: float = 0.0,
    historyLength = 20,
    historyGossip = 5,
    gossipThreshold = -100.0,
    decayInterval = 1.seconds,
    publishThreshold = -1000.0,
    graylistThreshold = -10000.0,
    disconnectBadPeers: bool = false,
    maxConcurrentValidations = GossipSubMaxConcurrentValidations,
    testExtensionConfig: Opt[TestExtensionConfig] = Opt.none(TestExtensionConfig),
    partialMessageExtensionConfig: Opt[PartialMessageExtensionConfig] =
      Opt.none(PartialMessageExtensionConfig),
    pingpongExtensionConfig: Opt[PingPongExtensionConfig] =
      Opt.none(PingPongExtensionConfig),
    preambleExtensionConfig: Opt[PreambleExtensionConfig] =
      Opt.none(PreambleExtensionConfig),
): seq[PubSub] =
  var pubsubs: seq[PubSub]
  for i in 0 ..< num:
    let switch = makeStandardSwitchBuilder(address)
      .withSignedPeerRecord(sendSignedPeerRecord)
      .build()
    let pubsub =
      if gossip:
        let g = GossipSub.init(
          rng = rng(),
          switch = switch,
          triggerSelf = triggerSelf,
          verifySignature = verifySignature,
          sign = sign,
          msgIdProvider = msgIdProvider,
          anonymize = anonymize,
          maxMessageSize = maxMessageSize,
          parameters = (
            var p = GossipSubParams.init()
            p.heartbeatInterval = heartbeatInterval
            p.floodPublish = floodPublish
            p.historyLength = historyLength
            p.historyGossip = historyGossip
            p.unsubscribeBackoff = unsubscribeBackoff
            p.pruneBackoff = pruneBackoff
            p.fanoutTTL = fanoutTTL
            p.enablePX = enablePX
            p.overheadRateLimit = overheadRateLimit
            p.sendIDontWantOnPublish = sendIDontWantOnPublish
            p.opportunisticGraftThreshold = opportunisticGraftThreshold
            p.gossipThreshold = gossipThreshold
            p.decayInterval = decayInterval
            p.publishThreshold = publishThreshold
            p.graylistThreshold = graylistThreshold
            p.disconnectBadPeers = disconnectBadPeers
            p.maxConcurrentValidations = maxConcurrentValidations
            p.testExtensionConfig = testExtensionConfig
            p.partialMessageExtensionConfig = partialMessageExtensionConfig
            p.pingpongExtensionConfig = pingpongExtensionConfig
            p.preambleExtensionConfig = preambleExtensionConfig
            if gossipFactor.isSome: p.gossipFactor = gossipFactor.get
            applyDValues(p, dValues)
            p
          ),
        )
        if codecs.len != 0:
          g.codecs = codecs
        g.PubSub
      else:
        FloodSub.init(
          rng = rng(),
          switch = switch,
          triggerSelf = triggerSelf,
          verifySignature = verifySignature,
          sign = sign,
          msgIdProvider = msgIdProvider,
          maxMessageSize = maxMessageSize,
          anonymize = anonymize,
        ).PubSub

    switch.mount(pubsub)
    pubsubs.add(pubsub)
  pubsubs

proc toFloodSub*(nodes: seq[PubSub]): seq[FloodSub] =
  nodes.mapIt(FloodSub(it))

proc toGossipSub*(nodes: seq[PubSub]): seq[GossipSub] =
  nodes.mapIt(GossipSub(it))

proc setDefaultTopicParams*(nodes: seq[GossipSub], topic: string): void =
  for node in nodes:
    node.topicParams.mgetOrPut(topic, TopicParams.init()).topicWeight = 1.0

proc getNodeByPeerId*[T: PubSub](nodes: seq[T], peerId: PeerId): GossipSub =
  let filteredNodes = nodes.filterIt(it.peerInfo.peerId == peerId)
  check:
    filteredNodes.len == 1
  return filteredNodes[0]

proc getPeerByPeerId*[T: PubSub](node: T, topic: string, peerId: PeerId): PubSubPeer =
  let filteredPeers =
    node.gossipsub.getOrDefault(topic).toSeq().filterIt(it.peerId == peerId)
  check:
    filteredPeers.len == 1
  return filteredPeers[0]

proc getPeerStats*(node: GossipSub, peerId: PeerId): PeerStats =
  node.peerStats.withValue(peerId, stats):
    return stats[]

proc getPeerScore*(node: GossipSub, peerId: PeerId): float64 =
  return node.getPeerStats(peerId).score

proc getPeerTopicInfo*(node: GossipSub, peerId: PeerId, topic: string): TopicInfo =
  return node.getPeerStats(peerId).topicInfos.getOrDefault(topic)

proc connect*[T: PubSub](dialer: T, target: T) {.async.} =
  doAssert dialer.switch.peerInfo.peerId != target.switch.peerInfo.peerId,
    "Could not connect same peer"
  await dialer.switch.connect(target.switch)
  await sleepAsync(connectWarmup)

template waitSubscribeChain*[T: PubSub](nodes: seq[T], topic: string): untyped =
  ## Chain: 1-2-3-4-5
  ## 
  checkUntilTimeout:
    nodes[0].gossipsub.getOrDefault(topic).len == 1
    nodes[1 .. ^2].allIt(it.gossipsub.getOrDefault(topic).len == 2)
    nodes[^1].gossipsub.getOrDefault(topic).len == 1

template waitSubscribeRing*[T: PubSub](nodes: seq[T], topic: string): untyped =
  ## Ring: 1-2-3-4-5-1
  ## 
  checkUntilTimeout:
    nodes.allIt(it.gossipsub.getOrDefault(topic).len == 2)

template waitSubscribeHub*[T: PubSub](hub: T, nodes: seq[T], topic: string): untyped =
  ## Hub: hub-1, hub-2, hub-3,...
  ## 
  checkUntilTimeout:
    hub.gossipsub.getOrDefault(topic).len == nodes.len
    nodes.allIt(it.gossipsub.getOrDefault(topic).len == 1)

template waitSubscribeStar*[T: PubSub](
    nodes: seq[T], topic: string, timeout: Duration = 30.seconds
): untyped =
  ## Star: 1-2; 1-3; 2-1; 2-3, 3-1, 3-2
  when T is GossipSub:
    checkUntilTimeoutCustom(timeout, 50.milliseconds):
      nodes.allIt(it.gossipsub.getOrDefault(topic).len == nodes.len - 1)
  elif T is FloodSub:
    checkUntilTimeoutCustom(timeout, 50.milliseconds):
      nodes.allIt(it.floodsub.getOrDefault(topic).len == nodes.len - 1)
  else:
    {.error: "not implemented for this PubSub type".}

template waitSubscribe*[T: PubSub](dialer, receiver: T, topic: string): untyped =
  if dialer.switch.peerInfo.peerId == receiver.switch.peerInfo.peerId:
    return
  let peerId = receiver.peerInfo.peerId

  when T is GossipSub:
    checkUntilTimeout:
      dialer.gossipsub.hasKey(topic)
      dialer.gossipsub.hasPeerId(topic, peerId)
  elif T is FloodSub:
    checkUntilTimeout:
      dialer.floodsub.hasKey(topic)
      dialer.floodsub.hasPeerId(topic, peerId)
  else:
    {.error: "not implemented for this PubSub type".}

proc waitSubGraph*[T: PubSub](nodes: seq[T], key: string) {.async.} =
  proc isGraphConnected(): bool =
    var
      nodesMesh: Table[PeerId, seq[PeerId]]
      seen: HashSet[PeerId]
    for n in nodes:
      nodesMesh[n.peerInfo.peerId] =
        toSeq(n.mesh.getOrDefault(key).items()).mapIt(it.peerId)
    var ok = 0
    for n in nodes:
      seen.clear()
      proc explore(p: PeerId) =
        if p in seen:
          return
        seen.incl(p)
        for peer in nodesMesh.getOrDefault(p):
          explore(peer)

      explore(n.peerInfo.peerId)
      if seen.len == nodes.len:
        ok.inc()

    return ok == nodes.len

  checkUntilTimeout:
    isGraphConnected()

template waitForNotSubscribed*[T: PubSub](nodes: seq[T], topic: string): untyped =
  checkUntilTimeout:
    nodes.allIt(topic notin it.topics)
    nodes.allIt(topic notin it.mesh)
    nodes.allIt(topic notin it.gossipsub)

template subscribeAllNodes*[T: PubSub](
    nodes: seq[T], topic: string, topicHandler: TopicHandler
): untyped =
  for node in nodes:
    node.subscribe(topic, topicHandler)

template unsubscribeAllNodes*[T: PubSub](
    nodes: seq[T], topic: string, topicHandler: TopicHandler, wait: bool = true
) =
  for node in nodes:
    node.unsubscribe(topic, topicHandler)

  if wait:
    waitForNotSubscribed(nodes, topic)

proc subscribeAllNodes*[T: PubSub](
    nodes: seq[T], topic: string, topicHandlers: seq[TopicHandler]
) =
  if nodes.len != topicHandlers.len:
    raise (ref CatchableError)(msg: "nodes and topicHandlers count needs to match!")

  for i in 0 ..< nodes.len:
    nodes[i].subscribe(topic, topicHandlers[i])

template tryPublish*(
    call: untyped, require: int, wait = 10.milliseconds, timeout = 10.seconds
): untyped =
  var
    expiration = Moment.now() + timeout
    pubs = 0
  while pubs < require and Moment.now() < expiration:
    pubs = pubs + call
    await sleepAsync(wait)

  doAssert pubs >= require, "Failed to publish!"

proc createCompleteHandler*(): (
  Future[bool], proc(topic: string, data: seq[byte]) {.async.}
) =
  var fut = newFuture[bool]()
  proc handler(topic: string, data: seq[byte]) {.async.} =
    fut.complete(true)

  return (fut, handler)

proc createCheckForMessages*(): (
  ref seq[Message], proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
) =
  var messages = new seq[Message]
  let checkForMessage = proc(
      peer: PubSubPeer, msgs: var RPCMsg
  ) {.gcsafe, raises: [].} =
    for message in msgs.messages:
      messages[].add(message)

  return (messages, checkForMessage)

proc createCheckForIHave*(): (
  ref seq[ControlIHave], proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
) =
  var messages = new seq[ControlIHave]
  let checkForMessage = proc(
      peer: PubSubPeer, msgs: var RPCMsg
  ) {.gcsafe, raises: [].} =
    if msgs.control.isSome:
      for msg in msgs.control.get.ihave:
        messages[].add(msg)

  return (messages, checkForMessage)

proc createCheckForIWant*(): (
  ref seq[ControlIWant], proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
) =
  var messages = new seq[ControlIWant]
  let checkForMessage = proc(
      peer: PubSubPeer, msgs: var RPCMsg
  ) {.gcsafe, raises: [].} =
    if msgs.control.isSome:
      for msg in msgs.control.get.iwant:
        messages[].add(msg)

  return (messages, checkForMessage)

proc createCheckForIDontWant*(): (
  ref seq[ControlIWant], proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
) =
  var messages = new seq[ControlIWant]
  let checkForMessage = proc(
      peer: PubSubPeer, msgs: var RPCMsg
  ) {.gcsafe, raises: [].} =
    if msgs.control.isSome:
      for msg in msgs.control.get.idontwant:
        messages[].add(msg)

  return (messages, checkForMessage)

proc addOnRecvObserver*[T: PubSub](
    node: T, handler: proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
) =
  let pubsubObserver = PubSubObserver(onRecv: handler)
  node.addObserver(pubsubObserver)

proc addIHaveObservers*[T: PubSub](nodes: seq[T]): (ref seq[ref seq[ControlIHave]]) =
  let numberOfNodes = nodes.len
  var allMessages = new seq[ref seq[ControlIHave]]
  allMessages[].setLen(numberOfNodes)

  for i in 0 ..< numberOfNodes:
    var (messages, checkForMessage) = createCheckForIHave()
    nodes[i].addOnRecvObserver(checkForMessage)
    allMessages[i] = messages

  return allMessages

proc addIDontWantObservers*[T: PubSub](
    nodes: seq[T]
): (ref seq[ref seq[ControlIWant]]) =
  let numberOfNodes = nodes.len
  var allMessages = new seq[ref seq[ControlIWant]]
  allMessages[].setLen(numberOfNodes)

  for i in 0 ..< numberOfNodes:
    var (messages, checkForMessage) = createCheckForIDontWant()
    nodes[i].addOnRecvObserver(checkForMessage)
    allMessages[i] = messages

  return allMessages

proc findAndUnsubscribePeers*[T: PubSub](
    nodes: seq[T], peers: seq[PeerId], topic: string, handler: TopicHandler
) =
  for i in 0 ..< nodes.len:
    let node = nodes[i]
    if peers.anyIt(it == node.peerInfo.peerId):
      node.unsubscribe(topic, voidTopicHandler)

proc clearMCache*[T: PubSub](node: T) =
  node.mcache.msgs.clear()
  for i in 0 ..< node.mcache.history.len:
    node.mcache.history[i].setLen(0)
  node.mcache.pos = 0

proc `$`*(peer: PubSubPeer): string =
  shortLog(peer)

proc currentRateLimitHits*(label: string = "nim-libp2p"): float64 =
  try:
    libp2p_gossipsub_peers_rate_limit_hits.valueByName(
      "libp2p_gossipsub_peers_rate_limit_hits_total", @[label]
    )
  except KeyError:
    0

proc currentGraylistedRpcs*(label: string = "nim-libp2p"): float64 =
  try:
    libp2p_gossipsub_graylisted_rpcs.valueByName(
      "libp2p_gossipsub_graylisted_rpcs_total", @[label]
    )
  except KeyError:
    0

proc addDirectPeer*[T: PubSub](node: T, target: T) {.async.} =
  doAssert node.switch.peerInfo.peerId != target.switch.peerInfo.peerId,
    "Could not add same peer"
  await node.addDirectPeer(target.switch.peerInfo.peerId, target.switch.peerInfo.addrs)
  await sleepAsync(connectWarmup)

proc addDirectPeerStar*[T: PubSub](nodes: seq[T]) {.async.} =
  var futs: seq[Future[void]]

  for node in nodes:
    for target in nodes:
      if node.switch.peerInfo.peerId != target.switch.peerInfo.peerId:
        futs.add(addDirectPeer(node, target))

  await allFuturesRaising(futs)

proc pluckPeerId*[T: PubSub](nodes: seq[T]): seq[PeerId] =
  nodes.mapIt(it.peerInfo.peerId)
