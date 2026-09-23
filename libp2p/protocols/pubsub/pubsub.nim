# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Base interface for pubsub protocols
##
## You can `subscribe<#subscribe%2CPubSub%2Cstring%2CTopicHandler>`_ to a topic,
## `publish<#publish.e%2CPubSub%2Cstring%2Cseq%5Bbyte%5D>`_ something on it,
## and eventually `unsubscribe<#unsubscribe%2CPubSub%2Cstring%2CTopicHandler>`_ from it.

{.push raises: [].}

import std/[tables, sequtils, sets, strutils]
import chronos, chronicles, metrics, results
import
  ./errors as pubsub_errors,
  ./pubsubpeer,
  ./rpc/[message, messages, protobuf],
  ../../switch,
  ../protocol,
  ../../crypto/crypto,
  ../../stream/connection,
  ../../peerid,
  ../../peerinfo,
  ../../errors,
  ../../utils/opt,
  ../../utils/future

export tables, sets, results, chronicles
export PubSubPeer, PubSubObserver, RateLimit, protocol, pubsub_errors

logScope:
  topics = "libp2p pubsub"

const
  KnownLibP2PTopics* {.strdefine.} = ""
  KnownLibP2PTopicsSeq* = KnownLibP2PTopics.toLowerAscii().split(",")
  DefaultTopicsHigh* = 1024 ## max topics a single peer may subscribe to
  DefaultPubSubMaxMessageSize* = 1024 * 1024 ## max size of a single pubsub message

declareGauge(libp2p_pubsub_peers, "pubsub peer instances")
declareGauge(libp2p_pubsub_topics, "pubsub subscribed topics")
declareCounter(libp2p_pubsub_subscriptions, "pubsub subscription operations")
declareCounter(libp2p_pubsub_unsubscriptions, "pubsub unsubscription operations")
declareGauge(
  libp2p_pubsub_topic_handlers,
  "pubsub subscribed topics handlers count",
  labels = ["topic"],
)

declareCounter(
  libp2p_pubsub_validation_success, "pubsub successfully validated messages"
)
declareCounter(libp2p_pubsub_validation_failure, "pubsub failed validated messages")
declareCounter(libp2p_pubsub_validation_ignore, "pubsub ignore validated messages")

declarePublicCounter(
  libp2p_pubsub_messages_published, "published messages", labels = ["topic"]
)
declarePublicCounter(
  libp2p_pubsub_messages_published_partial,
  "published partial messages",
  labels = ["topic"],
)
declarePublicCounter(
  libp2p_pubsub_messages_rebroadcasted, "re-broadcasted messages", labels = ["topic"]
)

declarePublicCounter(
  libp2p_pubsub_broadcast_subscriptions,
  "pubsub broadcast subscriptions",
  labels = ["topic"],
)
declarePublicCounter(
  libp2p_pubsub_broadcast_unsubscriptions,
  "pubsub broadcast unsubscriptions",
  labels = ["topic"],
)
declarePublicCounter(
  libp2p_pubsub_broadcast_messages, "pubsub broadcast messages", labels = ["topic"]
)

declarePublicCounter(
  libp2p_pubsub_received_subscriptions,
  "pubsub received subscriptions",
  labels = ["topic"],
)
declarePublicCounter(
  libp2p_pubsub_received_unsubscriptions,
  "pubsub received subscriptions",
  labels = ["topic"],
)
declarePublicCounter(
  libp2p_pubsub_received_messages, "pubsub received messages", labels = ["topic"]
)

declarePublicCounter(libp2p_pubsub_broadcast_iwant, "pubsub broadcast iwant")

declarePublicCounter(
  libp2p_pubsub_broadcast_ihave, "pubsub broadcast ihave", labels = ["topic"]
)
declarePublicCounter(
  libp2p_pubsub_broadcast_graft, "pubsub broadcast graft", labels = ["topic"]
)
declarePublicCounter(
  libp2p_pubsub_broadcast_prune, "pubsub broadcast prune", labels = ["topic"]
)

declarePublicCounter(libp2p_pubsub_received_iwant, "pubsub broadcast iwant")

declarePublicCounter(
  libp2p_pubsub_received_ihave, "pubsub broadcast ihave", labels = ["topic"]
)
declarePublicCounter(
  libp2p_pubsub_received_graft, "pubsub broadcast graft", labels = ["topic"]
)
declarePublicCounter(
  libp2p_pubsub_received_prune, "pubsub broadcast prune", labels = ["topic"]
)

type
  InitializationError* = object of LPError

  PeerMessageDecodeError* = object of CatchableError

  TopicHandler* =
    proc(topic: string, data: seq[byte]): Future[void] {.gcsafe, raises: [].}

  ValidatorHandler* = proc(topic: string, message: Message): Future[ValidationResult] {.
    gcsafe, raises: []
  .}

  TopicPair* = tuple[topic: string, handler: TopicHandler]

  MsgIdProvider* = proc(m: Message): Result[MessageId, ValidationResult] {.
    noSideEffect, raises: [], gcsafe
  .}

  SubscriptionValidator* = proc(topic: string): bool {.raises: [], gcsafe.}
    ## Every time a peer send us a subscription (even to an unknown topic),
    ## we have to store it, which may be an attack vector.
    ## This callback can be used to reject topic we're not interested in

  PublishParams* = object
    ## Used to indicate whether a message will be broadcasted using a custom stream
    ## defined when instantiating Pubsub, or if it will use the normal send stream
    useCustomStream*: bool

    ## Can be used to avoid having the node reply to IWANT messages when initially 
    ## broadcasting a message, it's only after relaying its own message that the
    ## node will reply to IWANTs
    skipMCache*: bool

    ## Determines whether an IDontWant message will be sent for the current message
    ## when it is published if it's a large message. 
    skipIDontWant*: bool

    ## Determines whether a Preamble message will be sent for the current message
    ## when it is published if it's a large message
    skipPreamble*: bool

  TopicData* = ref object
    handlers: seq[TopicHandler]
    requestsPartial*: bool
    supportsSendingPartial*: bool

  PubSub* = ref object of LPProtocol
    stopping: bool
    peerStopFuts: seq[Future[void].Raising([])] # cleanup outlives removal from peers
    switch*: Switch # the switch used to dial/connect to peers
    peerInfo*: PeerInfo # this peer's info
    topics*: Table[string, TopicData] # the topics that _we_ are interested in
    peers*: Table[PeerId, PubSubPeer]
      #\
      # Peers that we are interested to gossip with (but not necessarily
      # yet connected to)
    triggerSelf*: bool ## trigger own local handler on publish
    verifySignature*: bool ## enable signature verification
    sign*: bool ## enable message signing
    validators*: Table[string, HashSet[ValidatorHandler]]
    observers: ref seq[PubSubObserver] # ref as in smart_ptr
    msgIdProvider*: MsgIdProvider ## Turn message into message id (not nil)
    msgSeqno*: uint64
    anonymize*: bool ## if we omit fromPeer and seqno from RPC messages we send
    subscriptionValidator*: SubscriptionValidator
      # callback used to validate subscriptions
    topicsHigh*: int ## the maximum number of topics a peer is allowed to subscribe to
    maxMessageSize*: int
      ##\
      ## the maximum raw message size we'll globally allow
      ## for finer tuning, check message size on topic validator
      ##
      ## sending a big message to a peer with a lower size limit can
      ## lead to issues, from descoring to connection drops
      ##
      ## defaults to 1mB
    rng*: Rng

    knownTopics*: HashSet[string]
    customStreamCallbacks*: Opt[CustomStreamCallbacks]

proc topicLabel*(p: PubSub, topic: string | Opt[string]): string =
  ## returns value to be used for `topic` labels.
  let t =
    when topic is Opt[string]:
      if topic.isSome:
        topic.get()
      else:
        return "unset"
    else:
      topic

  if p.knownTopics.contains(t): t else: "generic"

method unsubscribePeer*(p: PubSub, peerId: PeerId) {.base, gcsafe.} =
  ## handle peer disconnects
  ##

  trace "unsubscribing pubsub peer", peerId
  p.peers.withValue(peerId, peer):
    let stopped = peer[].stopTasks()
    if p.stopping:
      # Shutdown drains the whole batch; pruning on each removal is quadratic.
      p.peerStopFuts.add(stopped)
    else:
      p.peerStopFuts.trackFut(stopped)
  p.peers.del(peerId)

  libp2p_pubsub_peers.set(p.peers.len.int64)

proc send*(
    p: PubSub,
    peer: PubSubPeer,
    msg: RPCMsg,
    priority: MessagePriority,
    useCustomStream: bool = false,
) {.raises: [].} =
  ## Sends an application-published `msg` (of type `RPCMsg`) to the specified
  ## remote peer in the PubSub network.
  ##
  ## The message is sent as-is, without splitting - the application is
  ## responsible for ensuring the message fits within `maxMessageSize`.
  ##
  ## Parameters:
  ## - `p`: The `PubSub` instance.
  ## - `peer`: An instance of `PubSubPeer` representing the peer to whom the message should be sent.
  ## - `msg`: The `RPCMsg` instance that contains the message to be sent.
  ## - `priority`: The message priority level (`High`, `Medium`, or `Low`).
  ##   High priority messages are sent immediately, medium and low priority messages are queued
  ##   and sent only after all high priority messages have been sent.

  trace "sending pubsub message to peer", peer, msg
  peer.send(msg, p.anonymize, priority, useCustomStream)

proc countBroadcastMetrics*(
    p: PubSub,
    sendPeers: openArray[PubSubPeer] | seq[PubSubPeer] | HashSet[PubSubPeer],
    msg: RPCMsg,
) {.raises: [].} =
  ## Increments the broadcast-related metrics for an outgoing RPC message.
  let npeers = sendPeers.len.int64
  for sub in msg.subscriptions:
    if sub.isSubscribe:
      libp2p_pubsub_broadcast_subscriptions.inc(
        npeers, labelValues = [p.topicLabel(sub.topic)]
      )
    else:
      libp2p_pubsub_broadcast_unsubscriptions.inc(
        npeers, labelValues = [p.topicLabel(sub.topic)]
      )

  for smsg in msg.messages:
    libp2p_pubsub_broadcast_messages.inc(
      npeers, labelValues = [p.topicLabel(smsg.topic)]
    )

  msg.control.ifValue(control):
    libp2p_pubsub_broadcast_iwant.inc(npeers * control.iwant.len.int64)

    for ihave in control.ihave:
      libp2p_pubsub_broadcast_ihave.inc(
        npeers, labelValues = [p.topicLabel(ihave.topicID)]
      )
    for graft in control.graft:
      libp2p_pubsub_broadcast_graft.inc(
        npeers, labelValues = [p.topicLabel(graft.topicID)]
      )
    for prune in control.prune:
      libp2p_pubsub_broadcast_prune.inc(
        npeers, labelValues = [p.topicLabel(prune.topicID)]
      )

proc broadcast*(
    p: PubSub,
    sendPeers: openArray[PubSubPeer] | seq[PubSubPeer] | HashSet[PubSubPeer],
    msg: RPCMsg,
    priority: MessagePriority,
    useCustomStream: bool = false,
) {.raises: [].} =
  ## Sends an application-published `msg` (of type `RPCMsg`) to a specified
  ## group of peers in the PubSub network.
  ##
  ## Parameters:
  ## - `p`: The `PubSub` instance.
  ## - `sendPeers`: A sequence of `PubSubPeer` instances to which the message should be sent.
  ## - `msg`: The `RPCMsg` instance that contains the message to be broadcast.
  ## - `priority`: The message priority level (`High`, `Medium`, or `Low`).
  ##   High priority messages are sent immediately, medium and low priority messages are queued
  ##   and sent only after all high priority messages have been sent.

  countBroadcastMetrics(p, sendPeers, msg)

  trace "broadcasting messages to peers", peersCount = sendPeers.len, msg

  if anyIt(sendPeers, it.hasObservers):
    for peer in sendPeers:
      p.send(peer, msg, priority, useCustomStream)
  else:
    # Fast path that only encodes message once
    let encoded = msg.encode(p.anonymize)
    if encoded.len > p.maxMessageSize:
      warn "message exceeds maximum message size; message will not be broadcasted",
        encodedSize = encoded.len, maxMessageSize = p.maxMessageSize
      return

    for peer in sendPeers:
      var peerEncoded = encoded
      peer.trackSend(peer.sendEncoded(move(peerEncoded), priority, useCustomStream))

proc sendSubs*(
    p: PubSub, peer: PubSubPeer, subTopics: openArray[string], subscribe: bool
) =
  ## send subscriptions to remote peer

  var subscriptions = newSeq[SubOpts]()
  for topic in subTopics:
    var subOpt = SubOpts(subscribe: Opt.some(subscribe), topic: Opt.some(topic))
    if subscribe:
      p.topics.withValue(topic, topicData):
        subOpt.requestsPartial = Opt.some(topicData[].requestsPartial)
        subOpt.supportsSendingPartial = Opt.some(topicData[].supportsSendingPartial)
    subscriptions.add(subOpt)

  peer.sendResponse(
    RPCMsg.withSubscriptions(subscriptions), p.anonymize, MessagePriority.High
  )

  for topic in subTopics:
    if subscribe:
      libp2p_pubsub_broadcast_subscriptions.inc(labelValues = [p.topicLabel(topic)])
    else:
      libp2p_pubsub_broadcast_unsubscriptions.inc(labelValues = [p.topicLabel(topic)])

proc updateMetrics*(p: PubSub, rpcMsg: RPCMsg) =
  for i in 0 ..< min(rpcMsg.subscriptions.len, p.topicsHigh):
    template sub(): untyped =
      rpcMsg.subscriptions[i]

    if sub.isSubscribe:
      libp2p_pubsub_received_subscriptions.inc(labelValues = [p.topicLabel(sub.topic)])
    else:
      libp2p_pubsub_received_unsubscriptions.inc(
        labelValues = [p.topicLabel(sub.topic)]
      )

  for m in rpcMsg.messages:
    libp2p_pubsub_received_messages.inc(labelValues = [p.topicLabel(m.topic)])

  rpcMsg.control.ifValue(control):
    libp2p_pubsub_received_iwant.inc(control.iwant.len.int64)
    for ihave in control.ihave:
      libp2p_pubsub_received_ihave.inc(labelValues = [p.topicLabel(ihave.topicID)])
    for graft in control.graft:
      libp2p_pubsub_received_graft.inc(labelValues = [p.topicLabel(graft.topicID)])
    for prune in control.prune:
      libp2p_pubsub_received_prune.inc(labelValues = [p.topicLabel(prune.topicID)])

method rpcHandler*(
    p: PubSub, peer: PubSubPeer, data: sink seq[byte]
): Future[void] {.
    base, async: (raises: [CancelledError, PeerMessageDecodeError, PeerRateLimitError])
.} =
  ## Handler that must be overridden by concrete implementation
  raiseAssert "Unimplemented"

method onNewPeer(p: PubSub, peer: PubSubPeer) {.base, gcsafe.} =
  discard

method onPubSubPeerEvent*(
    p: PubSub, peer: PubSubPeer, event: PubSubPeerEvent
) {.base, gcsafe.} =
  # Peer event is raised for the send stream in particular
  case event.kind
  of PubSubPeerEventKind.StreamOpened:
    if p.topics.len > 0:
      p.sendSubs(peer, toSeq(p.topics.keys), true)
  of PubSubPeerEventKind.StreamClosed:
    discard
  of PubSubPeerEventKind.DisconnectionRequested:
    discard

method getOrCreatePeer*(
    p: PubSub, peerId: PeerId, protosToDial: seq[string], protoNegotiated: string = ""
): PubSubPeer {.base, gcsafe.} =
  p.peers.withValue(peerId, peer):
    if peer[].codec == "":
      peer[].codec = protoNegotiated
    return peer[]

  let protos =
    if protoNegotiated != "":
      @[protoNegotiated]
    else:
      protosToDial

  proc getStream(): Future[Stream] {.
      async: (raises: [CancelledError, GetStreamDialError])
  .} =
    if p.stopping or p.switch.isStopping:
      raise newException(CancelledError, "pubsub is stopping")
    try:
      return await p.switch.dial(peerId, protos)
    except DialFailedError as e:
      raise (ref GetStreamDialError)(parent: e, msg: e.msg)

  proc onEvent(peer: PubSubPeer, event: PubSubPeerEvent) {.gcsafe.} =
    p.onPubSubPeerEvent(peer, event)

  proc peerHandler(
      peer: PubSubPeer, data: sink seq[byte]
  ): Future[void] {.async: (raises: [CancelledError, PeerRateLimitError]).} =
    try:
      await p.rpcHandler(peer, move(data))
    except PeerMessageDecodeError as e:
      trace "failed to decode message in peerHandler", err = e.msg, peerId = peer
      # loop continues and invalid messages are swallowed

  # create new pubsub peer
  let pubSubPeer = PubSubPeer.new(
    peerId,
    getStream,
    onEvent,
    protoNegotiated,
    p.maxMessageSize,
    customStreamCallbacks = p.customStreamCallbacks,
    handler = peerHandler,
  )
  trace "created new pubsub peer", peerId

  p.peers[peerId] = pubSubPeer
  pubSubPeer.observers = p.observers

  p.onNewPeer(pubSubPeer)

  # metrics
  libp2p_pubsub_peers.set(p.peers.len.int64)

  if not p.switch.isConnected(peerId):
    # The peer was dropped while this stream was being negotiated, so
    # `PeerEvent.Left` has already fired (or never will for this peer) and
    # nothing else would remove the peer.
    debug "created pubsub peer for disconnected peer, removing", peerId
    p.unsubscribePeer(peerId)

  return pubSubPeer

proc disconnectPeer*(
    p: PubSub, peer: PubSubPeer
) {.async: (raises: [CancelledError]).} =
  await p.switch.disconnect(peer.peerId)

template punishOverBudget*(
    p: PubSub, punished: PubSubPeer, invalidBytesSent: int, disconnectAboveLimit: bool
) =
  # a template, so that only the disconnect path allocates a future
  debug "Peer sent application data above the rate limit",
    peer = punished, overhead = invalidBytesSent, willDisconnect = disconnectAboveLimit
  if disconnectAboveLimit:
    await p.disconnectPeer(punished)
    raise newException(
      PeerRateLimitError, "Peer disconnected because it's above rate limit."
    )

proc handleData*(
    p: PubSub, topic: string, data: seq[byte]
): Future[void] {.async: (raises: [], raw: true).} =
  # Start work on all data handlers without copying data into closure like
  # happens on {.async.} transformation
  if topic notin p.topics:
    return newFutureCompleted[void]()

  var futs = newSeq[Future[void]]()
  var handlers = 0
  let handleData =
    try:
      p.topics[topic]
    except KeyError:
      raiseAssert "checked with if"

  for handler in handleData.handlers:
    if handler != nil: # allow nil handlers
      handlers.inc()
      let fut = handler(topic, data)
      if not fut.completed(): # Fast path for successful sync handlers
        futs.add(fut)

  if futs.len() == 0:
    # Fast path - futures finished synchronously or nobody cared about data
    trace "Topic handlers finished",
      topic, handlers, succeeded = handlers, failed = 0, cancelled = 0, pending = 0
    return newFutureCompleted[void]()

  proc waiter(): Future[void] {.async: (raises: []).} =
    # slow path - we have to wait for the handlers to complete
    try:
      futs = await allFinished(futs)
    except CancelledError:
      # propagate cancellation
      futs.cancelSoon()

    var failed, cancelled, pending: int
    # check for errors in futures
    for fut in futs:
      if fut.cancelled():
        cancelled.inc()
      elif fut.failed:
        failed.inc()
        trace "Error in topic handler", topic, err = fut.error().msg
      elif not fut.finished():
        pending.inc()

    trace "Topic handlers finished",
      topic,
      handlers,
      succeeded = handlers - failed - cancelled - pending,
      failed,
      cancelled,
      pending

  return waiter()

template handleSelfPublishing*(p: PubSub, topic: string, data: seq[byte]) =
  if p.triggerSelf:
    await handleData(p, topic, data)

method start*(p: PubSub) {.async: (raises: [CancelledError]).} =
  p.stopping = false
  await procCall LPProtocol(p).start()

method stop*(p: PubSub) {.async: (raises: []).} =
  p.stopping = true
  p.started = false
  for peerId in toSeq(p.peers.keys):
    p.unsubscribePeer(peerId)
  await noCancel allFutures(p.peerStopFuts)
  p.peerStopFuts = @[]

method handleConn*(
    p: PubSub, stream: Stream, proto: string
) {.base, async: (raises: [CancelledError]).} =
  ## handle incoming connections
  ##
  ## this proc will:
  ## 1) register a new PubSubPeer for the connection
  ## 2) handle RPC messages received on this stream
  ##

  if p.stopping or p.switch.isStopping:
    await stream.close()
    return

  let peer = p.getOrCreatePeer(stream.peerId, @[], proto)
  peer.connect()

  try:
    await peer.runHandleLoop(stream)
  except CancelledError as exc:
    raise exc
  finally:
    await stream.closeWithEOF()

method subscribePeer*(p: PubSub, peer: PeerId) {.base, gcsafe.} =
  ## subscribe to remote peer to receive/send pubsub
  ## messages
  ##

  if p.stopping or p.switch.isStopping:
    return

  let pubSubPeer = p.getOrCreatePeer(peer, p.codecs)
  pubSubPeer.connect()

proc updateTopicMetrics(p: PubSub, topic: string) =
  # metrics
  libp2p_pubsub_topics.set(p.topics.len.int64)

  if p.knownTopics.contains(topic):
    p.topics.withValue(topic, topicData):
      libp2p_pubsub_topic_handlers.set(
        topicData[].handlers.len.int64, labelValues = [topic]
      )
    do:
      libp2p_pubsub_topic_handlers.set(0, labelValues = [topic])
  else:
    var others: int64 = 0
    for key, _ in p.topics:
      if key notin p.knownTopics:
        others += 1

    libp2p_pubsub_topic_handlers.set(others, labelValues = ["other"])

method onTopicSubscription*(
    p: PubSub, topic: string, subscribed: bool
) {.base, gcsafe.} =
  # Called when subscribe is called the first time for a topic or unsubscribe
  # removes the last handler

  if subscribed:
    debug "subscribed to topic", topic
  else:
    debug "unsubscribed from topic", topic

  # Notify others that we are no longer interested in the topic.
  for peer in toSeq(p.peers.values):
    # If we don't have a sendStream yet, we will
    # send the full sub list when we get the sendStream,
    # so no need to send it here
    if peer.hasSendStream:
      p.sendSubs(peer, [topic], subscribed)

  if subscribed:
    libp2p_pubsub_subscriptions.inc()
  else:
    libp2p_pubsub_unsubscriptions.inc()

proc unsubscribe*(p: PubSub, topic: string, handler: TopicHandler) =
  ## unsubscribe from a ``topic`` string
  ##
  p.topics.withValue(topic, topicData):
    topicData[].handlers.keepItIf(it != handler)

    if topicData[].handlers.len() == 0:
      p.topics.del(topic)

      p.onTopicSubscription(topic, false)

    p.updateTopicMetrics(topic)

proc unsubscribe*(p: PubSub, topics: openArray[TopicPair]) =
  ## unsubscribe from a list of ``topic`` handlers
  for t in topics:
    p.unsubscribe(t.topic, t.handler)

proc unsubscribeAll*(p: PubSub, topic: string) {.gcsafe.} =
  ## unsubscribe every `handler` from `topic`
  if topic notin p.topics:
    trace "unsubscribeAll called for an unknown topic", topic
  else:
    p.topics.del(topic)

    p.onTopicSubscription(topic, false)

    p.updateTopicMetrics(topic)

proc subscribe*(
    p: PubSub,
    topic: string,
    handler: TopicHandler,
    requestsPartial: bool = false,
    supportsSendingPartial: bool = false,
) =
  ## subscribe to a topic
  ##
  ## ``topic``   - a string topic to subscribe to
  ##
  ## ``handler`` - user provided proc that will be triggered on 
  ##  every received message
  ## 
  ## ``requestsPartial`` - this node requests partial messages 
  ## for this topic, instead of full messages.
  ## 
  ## ``supportsSendingPartial`` - this node supports sending 
  ## partial messages for this topic.

  # Check that this is an allowed topic
  if p.subscriptionValidator != nil and p.subscriptionValidator(topic) == false:
    warn "trying to subscribe to a topic not passing validation", topic
    return

  p.topics.withValue(topic, topicData):
    # Already subscribed, just adding another handler
    # requestsPartial and supportsSendingPartial must be ignored because
    # node has allready sent subscription.
    topicData[].handlers.add(handler)
  do:
    trace "subscribing to topic", topic
    p.topics[topic] = TopicData(
      handlers: @[handler],
      requestsPartial: requestsPartial,
      supportsSendingPartial: supportsSendingPartial,
    )

    # Notify on first handler
    p.onTopicSubscription(topic, true)

  p.updateTopicMetrics(topic)

method publish*(
    p: PubSub,
    topic: string,
    data: sink seq[byte],
    publishParams: Opt[PublishParams] = Opt.none(PublishParams),
): Future[int] {.base, async: (raises: []).} =
  ## publish to a ``topic``
  ##
  ## The return value is the number of neighbours that we attempted to send the
  ## message to, excluding self. Note that this is an optimistic number of
  ## attempts - the number of peers that actually receive the message might
  ## be lower.
  handleSelfPublishing(p, topic, data)

  return 0

{.push hint[XCannotRaiseY]: off.}
  # Base initPubSub keeps `raises: [InitializationError]` to match overrides.
method initPubSub*(p: PubSub) {.base, raises: [InitializationError].} =
  ## perform pubsub initialization
  p.observers = new(seq[PubSubObserver])
  if p.msgIdProvider == nil:
    p.msgIdProvider = defaultMsgIdProvider

{.pop.}

method addValidator*(
    p: PubSub, topic: varargs[string], hook: ValidatorHandler
) {.base, gcsafe.} =
  ## Add a validator to a `topic`. Each new message received in this
  ## will be sent to `hook`. `hook` can return either `Accept`,
  ## `Ignore` or `Reject` (which can descore the peer)
  for t in topic:
    trace "adding validator for topic", topic = t
    p.validators.mgetOrPut(t, HashSet[ValidatorHandler]()).incl(hook)

method removeValidator*(
    p: PubSub, topic: varargs[string], hook: ValidatorHandler
) {.base, gcsafe.} =
  for t in topic:
    p.validators.withValue(t, validators):
      validators[].excl(hook)
      if validators[].len() == 0:
        p.validators.del(t)

method validate*(
    p: PubSub, message: Message
): Future[ValidationResult] {.async: (raises: [CancelledError]), base.} =
  var pending: seq[Future[ValidationResult]]
  let topic = message.topic

  if topic in p.validators:
    trace "running validators for topic", topic
    p.validators.withValue(topic, validators):
      for validator in validators[]:
        pending.add(validator(topic, message))
  var valResult = ValidationResult.Accept
  let futs = await allFinished(pending)
  for fut in futs:
    if fut.failed:
      valResult = ValidationResult.Reject
      break
    try:
      let res = fut.read()
      if res != ValidationResult.Accept:
        valResult = res
        if res == ValidationResult.Reject:
          break
    except CatchableError as e:
      trace "validator for message could not be executed, ignoring", err = e.msg, topic
      valResult = ValidationResult.Ignore

  case valResult
  of ValidationResult.Accept:
    libp2p_pubsub_validation_success.inc()
  of ValidationResult.Reject:
    libp2p_pubsub_validation_failure.inc()
  of ValidationResult.Ignore:
    libp2p_pubsub_validation_ignore.inc()

  valResult

proc init*[PubParams: object | bool](
    P: typedesc[PubSub],
    switch: Switch,
    triggerSelf: bool = false,
    anonymize: bool = false,
    verifySignature: bool = true,
    sign: bool = true,
    msgIdProvider: MsgIdProvider = defaultMsgIdProvider,
    subscriptionValidator: SubscriptionValidator = nil,
    maxMessageSize: int = DefaultPubSubMaxMessageSize,
    rng: Rng,
    parameters: PubParams = false,
    customStreamCallbacks: Opt[CustomStreamCallbacks] = Opt.none(CustomStreamCallbacks),
): P {.raises: [InitializationError].} =
  let pubsub =
    when PubParams is bool:
      P(
        switch: switch,
        peerInfo: switch.peerInfo,
        triggerSelf: triggerSelf,
        anonymize: anonymize,
        verifySignature: verifySignature,
        sign: sign,
        msgIdProvider: msgIdProvider,
        subscriptionValidator: subscriptionValidator,
        maxMessageSize: maxMessageSize,
        rng: rng,
        topicsHigh: DefaultTopicsHigh,
        customStreamCallbacks: customStreamCallbacks,
      )
    else:
      P(
        switch: switch,
        peerInfo: switch.peerInfo,
        triggerSelf: triggerSelf,
        anonymize: anonymize,
        verifySignature: verifySignature,
        sign: sign,
        msgIdProvider: msgIdProvider,
        subscriptionValidator: subscriptionValidator,
        parameters: parameters,
        maxMessageSize: maxMessageSize,
        rng: rng,
        topicsHigh: DefaultTopicsHigh,
        customStreamCallbacks: customStreamCallbacks,
      )

  proc peerEventHandler(
      peerId: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    case event.kind
    of PeerEventKind.Joined:
      pubsub.subscribePeer(peerId)
    of PeerEventKind.Left:
      pubsub.unsubscribePeer(peerId)
    of PeerEventKind.Identified:
      # Identified events are handled by IdentifyPusher service
      discard

  switch.addPeerEventHandler(peerEventHandler, PeerEventKind.Joined)
  switch.addPeerEventHandler(peerEventHandler, PeerEventKind.Left)

  pubsub.knownTopics = KnownLibP2PTopicsSeq.toHashSet()

  pubsub.initPubSub()

  return pubsub

proc addObserver*(p: PubSub, observer: PubSubObserver) =
  p.observers[] &= observer

proc removeObserver*(p: PubSub, observer: PubSubObserver) =
  let idx = p.observers[].find(observer)
  if idx != -1:
    p.observers[].del(idx)
