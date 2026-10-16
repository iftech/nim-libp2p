# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sequtils, tables, hashes, sets, deques]
import results
import chronos, chronicles, nimcrypto/sha2, metrics
import chronos/ratelimit
import
  rpc/[messages, message, protobuf],
  ../../peerid,
  ../../peerinfo,
  ../../stream/connection,
  ../../crypto/crypto,
  ../../utils/shortlog,
  ../../utils/future

export peerid, connection, deques

logScope:
  topics = "libp2p pubsubpeer"

when defined(libp2p_expensive_metrics):
  declareCounter(
    libp2p_pubsub_sent_messages, "number of messages sent", labels = ["id", "topic"]
  )
  declareCounter(
    libp2p_pubsub_skipped_received_messages,
    "number of received skipped messages",
    labels = ["id"],
  )
  declareCounter(
    libp2p_pubsub_skipped_sent_messages,
    "number of sent skipped messages",
    labels = ["id"],
  )

when defined(pubsubpeer_queue_metrics):
  declareGauge(
    libp2p_gossipsub_high_priority_queue_size,
    "the number of in-flight high-priority sends",
    labels = ["id"],
  )
  declareGauge(
    libp2p_gossipsub_medium_priority_queue_size,
    "the number of messages in the medium-priority queue",
    labels = ["id"],
  )
  declareGauge(
    libp2p_gossipsub_low_priority_queue_size,
    "the number of messages in the low-priority queue",
    labels = ["id"],
  )

  declareCounter(
    libp2p_pubsub_disconnects_over_high_priority_queue_limit,
    "number of peers disconnected due to high-priority queue overflow",
  )
  declareCounter(
    libp2p_pubsub_medium_priority_queue_drops,
    "number of messages dropped from medium-priority queue due to overflow",
  )
  declareCounter(
    libp2p_pubsub_low_priority_queue_drops,
    "number of messages dropped from low-priority queue due to overflow",
  )

const
  MaxInboundStreamsPerPeer* = 4
  DefaultMaxHighPriorityQueueLen* = 256
  DefaultMaxMediumPriorityQueueLen* = 512
  DefaultMaxLowPriorityQueueLen* = 1024

type
  PeerRateLimitError* = object of CatchableError

  GetStreamDialError* = object of CatchableError

  PubSubObserver* = ref object
    onRecv*: proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
    onSend*: proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
    onValidated*:
      proc(peer: PubSubPeer, msg: Message, msgId: MessageId) {.gcsafe, raises: [].}

  MessagePriority* {.pure.} = enum
    High
      ## Protocol-critical messages: subscriptions, GRAFT, PRUNE, IHAVE,
      ## IDontWant, control responses. Sent immediately. If max is exceeded
      ## we drop the peer.
    Medium
      ## Locally published messages. Sent before low priority traffic.
      ## They are dropped if exceeded max. Peer is not disconnected.
    Low
      ## Relayed messages and IWANT replies
      ## They are dropped if exceeded max. Peer is not disconnected.

  QueueAction* = object
    priority*: MessagePriority
    send*: bool
      # if true msg should be sent respecting priority, if false it means drop/disconnect
    slowPeerPenaltyDelta*: float64

  PubSubPeerEventKind* {.pure.} = enum
    StreamOpened
    StreamClosed
    DisconnectionRequested
      # tells gossipsub that the transport connection to the peer should be closed

  PubSubPeerEvent* = object
    kind*: PubSubPeerEventKind

  GetStream* =
    proc(): Future[Stream] {.async: (raises: [CancelledError, GetStreamDialError]).}
  DropStream* = proc(peer: PubSubPeer) {.gcsafe, raises: [].}
    # have to pass peer as it's unknown during init
  OnEvent* = proc(peer: PubSubPeer, event: PubSubPeerEvent) {.gcsafe, raises: [].}

  QueuedMessage = object
    # Messages sent as medium/low priority are queued and sent on a
    # separate routine.
    data: seq[byte]
    useCustomStream: bool

  RpcMessageQueue* = ref object
    # Tracks async tasks for sending high-priority peer-published messages.
    sendPriorityQueue: Deque[Future[void]]
    # Queue for local published messages
    mediumPriorityQueue: Deque[QueuedMessage]
    # Queue for lower-priority messages, like "IWANT" replies and relay messages.
    lowPriorityQueue: Deque[QueuedMessage]
    # Triggered when a message is added to medium or low queue.
    dataAvailableEvent: AsyncEvent
    # Task for processing non-priority message queue.
    sendNonHighPriorityTask: Future[void]

  CustomStreamCreationProc* = proc(
    destAddr: Opt[MultiAddress], destPeerId: PeerId, codec: string
  ): Stream {.gcsafe, raises: [].}

  CustomPeerSelectionProc* = proc(
    allPeers: HashSet[PubSubPeer],
    directPeers: HashSet[PubSubPeer],
    meshPeers: HashSet[PubSubPeer],
    fanoutPeers: HashSet[PubSubPeer],
  ): HashSet[PubSubPeer] {.gcsafe, raises: [].}

  CustomStreamCallbacks* = object
    customStreamCreationCB*: CustomStreamCreationProc
    customPeerSelectionCB*: CustomPeerSelectionProc

  RecvStream = object
    stream: Stream
    loop: Future[void].Raising([CancelledError])

  PubSubPeer* = ref object of RootObj
    getStream*: GetStream # callback to establish a new send stream
    onEvent*: OnEvent # Connectivity updates for peer
    codec*: string # the protocol that this peer joined from
    recvStreams: seq[RecvStream]
    sendStream*: Stream # cached send stream
    connectedFut: Future[void]
    address*: Opt[MultiAddress]
    peerId*: PeerId
    handler*: RPCHandler
    observers*: ref seq[PubSubObserver] # ref as in smart_ptr
    score*: float64
    subscribedTopics*: int # distinct topics this peer is tracked as subscribed to
    sentIHaves*: Deque[HashSet[MessageId]]
    iDontWants*: Deque[HashSet[SaltedId]]
      ## IDONTWANT contains unvalidated message id:s which may be long and/or
      ## expensive to look up, so we apply the same salting to them as during
      ## unvalidated message processing
    iHaveBudget*: int
    maxMessageSize: int
    appScore*: float64 # application specific score
    slowPeerPenalty*: float64 # penalty from repeated medium/low queue overflow drops
    behaviourPenalty*: float64 # the eventual penalty score
    overheadRateLimitOpt*: Opt[TokenBucket]
    overheadSecondWindowStart*: Moment
    overheadBytesInSecondWindow*: int
    rpcmessagequeue: RpcMessageQueue
    maxHighPriorityQueueLen*: int
    maxMediumPriorityQueueLen*: int
    maxLowPriorityQueueLen*: int
    stopped: bool
    customStreamCallbacks*: Opt[CustomStreamCallbacks]
    connectFut: Future[void]
    sendFuts: seq[Future[void]]

  RPCHandler* = proc(peer: PubSubPeer, data: sink seq[byte]): Future[void] {.
    async: (raises: [CancelledError, PeerRateLimitError])
  .}

when defined(libp2p_agents_metrics):
  func shortAgent*(p: PubSubPeer): string =
    if p.sendStream.isNil or p.sendStream.getWrapped().isNil:
      "unknown"
    else:
      #TODO the sendStream is setup before identify,
      #so we have to read the parents short agent..
      p.sendStream.getWrapped().shortAgent

proc getAgent*(peer: PubSubPeer): string =
  return
    when defined(libp2p_agents_metrics):
      if peer.shortAgent.len > 0: peer.shortAgent else: "unknown"
    else:
      "unknown"

proc `$`*(p: PubSubPeer): string =
  $p.peerId

func hash*(p: PubSubPeer): Hash =
  p.peerId.hash

func `==`*(a, b: PubSubPeer): bool =
  a.peerId == b.peerId

func shortLog*(p: PubSubPeer): string =
  if p.isNil:
    "PubSubPeer(nil)"
  else:
    shortLog(p.peerId)
chronicles.formatIt(PubSubPeer):
  shortLog(it)

proc connected*(p: PubSubPeer): bool =
  not p.sendStream.isNil and not (p.sendStream.closed or p.sendStream.atEof)

proc hasObservers*(p: PubSubPeer): bool =
  p.observers != nil and anyIt(p.observers[], it != nil)

func outbound*(p: PubSubPeer): bool =
  # gossipsub 1.1 spec requires us to know if the transport is outgoing
  # in order to give priotity to connections we make
  # https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md#outbound-mesh-quotas
  # This behaviour is presrcibed to counter sybil attacks and ensures that a coordinated inbound attack can never fully take over the mesh
  if not p.sendStream.isNil and p.sendStream.transportDir == Direction.Out:
    true
  else:
    false

func determineQueueAction*(
    priority: MessagePriority,
    sendPriorityQueueLen, mediumPriorityQueueLen, lowPriorityQueueLen: int,
    maxHighPriorityQueueLen, maxMediumPriorityQueueLen, maxLowPriorityQueueLen: int,
): QueueAction =
  let emptyQueues =
    sendPriorityQueueLen == 0 and mediumPriorityQueueLen == 0 and
    lowPriorityQueueLen == 0

  var send = true
  var slowPeerPenaltyDelta = 0.0
  var priority = priority

  if priority == MessagePriority.High or emptyQueues:
    # If queues are empty, we can send medium/low messages immediatly
    # thus setting the priority of the message to high
    priority = MessagePriority.High

    if sendPriorityQueueLen >= maxHighPriorityQueueLen:
      send = false
  elif priority == MessagePriority.Medium:
    if mediumPriorityQueueLen >= maxMediumPriorityQueueLen:
      send = false
      slowPeerPenaltyDelta = 1.0
  else:
    if lowPriorityQueueLen >= maxLowPriorityQueueLen:
      slowPeerPenaltyDelta = 1.0
      send = false

  QueueAction(
    priority: priority, send: send, slowPeerPenaltyDelta: slowPeerPenaltyDelta
  )

func determineQueueAction*(
    priority: MessagePriority,
    rpcmessagequeue: RpcMessageQueue,
    maxHighPriorityQueueLen, maxMediumPriorityQueueLen, maxLowPriorityQueueLen: int,
): QueueAction =
  determineQueueAction(
    priority, rpcmessagequeue.sendPriorityQueue.len,
    rpcmessagequeue.mediumPriorityQueue.len, rpcmessagequeue.lowPriorityQueue.len,
    maxHighPriorityQueueLen, maxMediumPriorityQueueLen, maxLowPriorityQueueLen,
  )

proc recvObservers*(p: PubSubPeer, msg: var RPCMsg) =
  # trigger hooks
  if not (isNil(p.observers)) and p.observers[].len > 0:
    for obs in p.observers[]:
      if not (isNil(obs)): # TODO: should never be nil, but...
        if not (isNil(obs.onRecv)):
          obs.onRecv(p, msg)

proc validatedObservers*(p: PubSubPeer, msg: Message, msgId: MessageId) =
  # trigger hooks
  if not (isNil(p.observers)) and p.observers[].len > 0:
    for obs in p.observers[]:
      if not (isNil(obs.onValidated)):
        obs.onValidated(p, msg, msgId)

proc sendObservers(p: PubSubPeer, msg: var RPCMsg) =
  # trigger hooks
  if not (isNil(p.observers)) and p.observers[].len > 0:
    for obs in p.observers[]:
      if not (isNil(obs)): # TODO: should never be nil, but...
        if not (isNil(obs.onSend)):
          obs.onSend(p, msg)

proc runHandleLoop*(
    p: PubSubPeer, stream: Stream
) {.async: (raises: [CancelledError]).} =
  debug "starting pubsub read loop", stream, peer = p, closed = stream.closed
  defer:
    debug "exiting pubsub read loop", stream, peer = p, closed = stream.closed

  while not p.stopped and not stream.atEof:
    trace "waiting for data", stream, peer = p, closed = stream.closed

    var data =
      try:
        await stream.readLp(p.maxMessageSize)
      except LPStreamEOFError:
        return
      except LPStreamError as e:
        debug "Exception occurred reading message PubSubPeer.handle",
          stream, peer = p, closed = stream.closed, description = e.msg
        return

    if p.stopped:
      return

    trace "read data from peer",
      stream, peer = p, closed = stream.closed, data = data.shortLog

    if p.handler.isNil:
      debug "Ignoring pubsub message without handler", stream, peer = p
      continue

    try:
      await p.handler(p, move(data))
    except PeerRateLimitError as e:
      trace "peer rate limit exceeded in peerHandler",
        description = e.msg, stream, peer = p
      await stream.closeWithEOF()
      return

proc stop(recv: RecvStream) {.async: (raises: []).} =
  await recv.stream.reset()
  await recv.loop.cancelAndWait()

proc handleRecvStream*(
    p: PubSubPeer, stream: Stream
) {.async: (raises: [CancelledError]).} =
  # Release the old reader before admitting another; recheck after each await.
  while not p.stopped and p.recvStreams.len >= MaxInboundStreamsPerPeer:
    let oldest = p.recvStreams[0]
    await oldest.stop()
    p.recvStreams.keepItIf(it.stream != oldest.stream)

  if p.stopped:
    await stream.reset()
    return

  let loop = p.runHandleLoop(stream)
  p.recvStreams.add(RecvStream(stream: stream, loop: loop))
  try:
    await loop
  finally:
    p.recvStreams.keepItIf(it.stream != stream)

proc closeSendStream(
    p: PubSubPeer, event: PubSubPeerEventKind
) {.async: (raises: [CancelledError]).} =
  if p.sendStream != nil:
    trace "Removing send stream", p, stream = p.sendStream
    await p.sendStream.close()
    p.sendStream = nil

  p.connectedFut.completeOnce()

  try:
    if p.onEvent != nil:
      p.onEvent(p, PubSubPeerEvent(kind: event))
  except CancelledError as exc:
    raise exc
  # don't cleanup p.address else we leak some gossip stat table

proc connectOnce(
    p: PubSubPeer
): Future[void] {.async: (raises: [CancelledError, GetStreamDialError]).} =
  try:
    if p.connectedFut.finished:
      p.connectedFut = newFuture[void]()
    let newStream =
      try:
        await p.getStream().wait(5.seconds)
      except AsyncTimeoutError:
        raise newException(GetStreamDialError, "establishing stream timed out")
    if p.stopped:
      await newStream.close()
      return

    # When the send channel goes up, subscriptions need to be sent to the
    # remote peer - if we had multiple channels up and one goes down, all
    # stop working so we make an effort to only keep a single channel alive

    trace "Get new send stream", p, newStream

    # Careful to race conditions here.
    # Topic subscription relies on either connectedFut
    # to be completed, or onEvent to be called later
    p.sendStream = newStream
    p.address =
      if p.sendStream.observedAddr.isSome:
        Opt.some(p.sendStream.observedAddr.get)
      else:
        Opt.none(MultiAddress)

    if p.codec == "":
      # if codec was not know, it can be retrieved from newly established stream
      p.codec = newStream.protocol

    p.connectedFut.completeOnce()
    if p.onEvent != nil:
      p.onEvent(p, PubSubPeerEvent(kind: PubSubPeerEventKind.StreamOpened))

    await p.runHandleLoop(newStream)
  finally:
    await p.closeSendStream(PubSubPeerEventKind.StreamClosed)

proc connectImpl(p: PubSubPeer) {.async: (raises: []).} =
  try:
    # Keep trying to establish a stream while it's possible to do so - the
    # send stream might get disconnected due to a timeout or an unrelated
    # issue so we try to get a new one
    while true:
      if p.stopped:
        p.connectedFut.completeOnce()
        return
      await connectOnce(p)
  except CancelledError:
    discard
  except GetStreamDialError as exc:
    debug "Could not establish send stream", description = exc.msg

proc connect*(p: PubSubPeer) =
  if p.stopped or p.connected:
    return
  if not p.connectFut.isNil() and not p.connectFut.finished():
    return

  p.connectFut = connectImpl(p)

proc trackSend*(p: PubSubPeer, fut: Future[void]) =
  ## Take ownership of an in-flight send future on this peer.
  p.sendFuts.trackFut(fut)

proc hasSendStream*(p: PubSubPeer): bool =
  p.sendStream != nil

template sendMetrics(msg: RPCMsg): untyped =
  when defined(libp2p_expensive_metrics):
    for x in msg.messages:
      # metrics
      libp2p_pubsub_sent_messages.inc(labelValues = [$p.peerId, x.topic])

proc clearSendPriorityQueue(p: PubSubPeer) =
  if p.rpcmessagequeue.sendPriorityQueue.len == 0:
    return # fast path

  while p.rpcmessagequeue.sendPriorityQueue.len > 0 and
      p.rpcmessagequeue.sendPriorityQueue[0].finished:
    discard p.rpcmessagequeue.sendPriorityQueue.popFirst()

  while p.rpcmessagequeue.sendPriorityQueue.len > 0 and
      p.rpcmessagequeue.sendPriorityQueue[^1].finished:
    discard p.rpcmessagequeue.sendPriorityQueue.popLast()

  when defined(pubsubpeer_queue_metrics):
    libp2p_gossipsub_high_priority_queue_size.set(
      value = p.rpcmessagequeue.sendPriorityQueue.len.int64, labelValues = [$p.peerId]
    )

proc sendMsgContinue(
    stream: Stream, msgFut: Future[void].Raising([CancelledError, LPStreamError])
) {.async: (raises: [CancelledError]).} =
  # Continuation for a pending transport write from below
  try:
    await msgFut
    trace "sent pubsub message to remote", stream
  except CancelledError as exc:
    trace "sendMsgContinue cancelled", stream, description = exc.msg
    raise exc
  except LPStreamError as exc:
    trace "Unexpected exception in sendMsgContinue", stream, description = exc.msg
    # Next time sendStream is used, it will be have its close flag set and thus
    # will be recycled
    await stream.close() # This will clean up the send stream

proc sendMsgSlow(
    p: PubSubPeer, msg: sink seq[byte]
) {.async: (raises: [CancelledError]).} =
  # Slow path where msg is held in memory while send stream is being set up.
  if p.sendStream == nil:
    # Wait for a send stream to be setup. `connectOnce` will
    # complete this even if the sendStream setup failed
    discard await race(p.connectedFut)

  var stream = p.sendStream
  if stream == nil or stream.closed():
    debug "No send stream", p, encoded = shortLog(msg)
    return

  trace "sending encoded msg to peer", stream, encoded = shortLog(msg)
  await sendMsgContinue(stream, stream.writeLp(msg))

proc sendMsg(
    p: PubSubPeer, msg: sink seq[byte], useCustomStream: bool = false
): Future[void] {.async: (raises: [CancelledError]).} =
  ## Starts a transport write and returns its lifecycle future for internal
  ## queue accounting. Do not await this from receive-handler paths.
  type StreamType = enum
    ctCustom
    ctSend
    ctSlow

  var slowPath = false
  let (stream, streamType) =
    if useCustomStream and p.customStreamCallbacks.isSome:
      let address = p.address
      (
        p.customStreamCallbacks.get().customStreamCreationCB(address, p.peerId, p.codec),
        ctCustom,
      )
    elif p.sendStream != nil and not p.sendStream.closed():
      (p.sendStream, ctSend)
    else:
      slowPath = true
      (nil, ctSlow)

  if not slowPath:
    trace "sending encoded msg to peer",
      streamType = $streamType, stream = stream, encoded = shortLog(msg)
    let f = stream.writeLp(msg)
    await sendMsgContinue(stream, f)
  else:
    trace "sending encoded msg to peer via slow path"
    await sendMsgSlow(p, move(msg))

proc disconnectPeer(p: PubSubPeer): Future[void] =
  if not p.stopped:
    p.stopped = true
    when defined(pubsubpeer_queue_metrics):
      libp2p_pubsub_disconnects_over_high_priority_queue_limit.inc()
    return p.closeSendStream(PubSubPeerEventKind.DisconnectionRequested)

  return newFutureCompleted[void]()

proc sendHighPriorityMessage(
    p: PubSubPeer, msg: sink seq[byte], useCustomStream: bool
): Future[void] =
  let f = p.sendMsg(move(msg), useCustomStream)
  if not f.finished:
    p.rpcmessagequeue.sendPriorityQueue.addLast(f)
    when defined(pubsubpeer_queue_metrics):
      libp2p_gossipsub_high_priority_queue_size.inc(labelValues = [$p.peerId])
  return newFutureCompleted[void]()

proc enqueueNonHighPriorityMessage(
    p: PubSubPeer, msg: sink seq[byte], useCustomStream: bool, priority: MessagePriority
): Future[void] =
  let queuedMsg = QueuedMessage(data: move(msg), useCustomStream: useCustomStream)
  case priority
  of MessagePriority.Medium:
    p.rpcmessagequeue.mediumPriorityQueue.addLast(queuedMsg)
    when defined(pubsubpeer_queue_metrics):
      libp2p_gossipsub_medium_priority_queue_size.inc(labelValues = [$p.peerId])
  of MessagePriority.Low:
    p.rpcmessagequeue.lowPriorityQueue.addLast(queuedMsg)
    when defined(pubsubpeer_queue_metrics):
      libp2p_gossipsub_low_priority_queue_size.inc(labelValues = [$p.peerId])
  of MessagePriority.High:
    raiseAssert "high-priority messages are not enqueued"
  p.rpcmessagequeue.dataAvailableEvent.fire()

  return newFutureCompleted[void]()

proc dropNonHighPriorityMessage(
    p: PubSubPeer, slowPeerPenaltyDelta: float64, priority: MessagePriority
): Future[void] =
  p.slowPeerPenalty += slowPeerPenaltyDelta
  case priority
  of MessagePriority.Medium:
    when defined(pubsubpeer_queue_metrics):
      libp2p_pubsub_medium_priority_queue_drops.inc()
    trace "medium priority queue full, dropping message", p
  of MessagePriority.Low:
    when defined(pubsubpeer_queue_metrics):
      libp2p_pubsub_low_priority_queue_drops.inc()
    trace "low priority queue full, dropping message", p
  of MessagePriority.High:
    raiseAssert "high-priority messages are not dropped via queue overflow scoring"
  return newFutureCompleted[void]()

proc sendEncoded*(
    p: PubSubPeer,
    msg: sink seq[byte],
    priority: MessagePriority,
    useCustomStream: bool = false,
): Future[void] =
  ## Asynchronously sends an encoded message to a specified `PubSubPeer` according to its priority.
  ##
  ## Parameters:
  ## - `p`: The `PubSubPeer` instance to which the message is to be sent.
  ## - `msg`: The message to be sent, encoded as a sequence of bytes (`seq[byte]`).
  ## - `priority`:
  ##   - `High` or any priority when all queues are empty: sent immediately
  ##   - `Medium`: queued in `mediumPriorityQueue`. Dropped when full.
  ##   - `Low`: queued in `lowPriorityQueue`. Dropped when full.
  ## - `useCustomStream`: boolean used to indicate if a custom stream is going to
  ##   be used for sending this message
  ## Low and medium priority messages are queued and sent only after all high
  ## priority messages have been sent.
  doAssert(not isNil(p), "pubsubpeer nil!")

  if p.stopped:
    return newFutureCompleted[void]()

  p.clearSendPriorityQueue()

  if msg.len <= 0:
    debug "empty message, skipping", p, encoded = shortLog(msg)
    newFutureCompleted[void]()
  elif msg.len > p.maxMessageSize:
    info "trying to send a msg too big for pubsub",
      maxSize = p.maxMessageSize, msgSize = msg.len
    newFutureCompleted[void]()
  else:
    let action = determineQueueAction(
      priority, p.rpcmessagequeue, p.maxHighPriorityQueueLen,
      p.maxMediumPriorityQueueLen, p.maxLowPriorityQueueLen,
    )

    case action.priority
    of High:
      if action.send:
        p.sendHighPriorityMessage(move(msg), useCustomStream)
      else:
        p.disconnectPeer()
    of Medium, Low:
      if action.send:
        p.enqueueNonHighPriorityMessage(move(msg), useCustomStream, action.priority)
      else:
        p.dropNonHighPriorityMessage(action.slowPeerPenaltyDelta, action.priority)

iterator splitRPCMsg(
    peer: PubSubPeer, rpcMsg: RPCMsg, maxSize: int, anonymize: bool
): seq[byte] =
  ## This iterator takes an `RPCMsg` and sequentially repackages its Messages into new `RPCMsg` instances.
  ## Each new `RPCMsg` accumulates Messages until reaching the specified `maxSize`. If a single Message
  ## exceeds the `maxSize` when trying to fit into an empty `RPCMsg`, the latter is skipped as too large to send.
  ## Every constructed `RPCMsg` is then encoded, optionally anonymized, and yielded as a sequence of bytes.

  var currentRPCMsg = RPCMsg()
  var currentSize = 0

  for msg in rpcMsg.messages:
    let msgSize = byteSize(msg)

    # Check if adding the next message will exceed maxSize
    if currentSize + msgSize > maxSize:
      if msgSize > maxSize:
        warn "message too big to sent", peer, rpcMsg = shortLog(msg)
        continue # Skip this message

      trace "sending msg to peer", peer, rpcMsg = shortLog(currentRPCMsg)
      yield encode(currentRPCMsg, anonymize)
      currentRPCMsg = RPCMsg()
      currentSize = 0

    currentRPCMsg.messages.add(msg)
    currentSize += msgSize

  # Check if there is a non-empty currentRPCMsg left to be added
  if currentRPCMsg.messages.len > 0:
    trace "sending msg to peer", peer, rpcMsg = shortLog(currentRPCMsg)
    yield encode(currentRPCMsg, anonymize)

proc send*(
    p: PubSubPeer,
    msg: RPCMsg,
    anonymize: bool,
    priority: MessagePriority,
    useCustomStream: bool = false,
) {.raises: [].} =
  ## Asynchronously sends an `RPCMsg` to a specified `PubSubPeer` with an option for anonymization.
  ##
  ## Parameters:
  ## - `p`: The `PubSubPeer` instance to which the message is to be sent.
  ## - `msg`: The `RPCMsg` instance representing the message to be sent.
  ## - `anonymize`: A boolean flag indicating whether the message should be sent with anonymization.
  ## - `priority`: The message priority level (`High`, `Medium`, or `Low`).
  ##   High priority messages are sent immediately, medium and low priority messages are queued
  ##   and sent only after all high priority messages have been sent.
  # When sending messages, we take care to re-encode them with the right
  # anonymization flag to ensure that we're not penalized for sending invalid
  # or malicious data on the wire - in particular, re-encoding protects against
  # some forms of valid but redundantly encoded protobufs with unknown or
  # duplicated fields
  var encoded =
    if p.hasObservers():
      var mm = msg
      # trigger send hooks
      p.sendObservers(mm)
      sendMetrics(mm)
      encode(mm, anonymize)
    else:
      # If there are no send hooks, we redundantly re-encode the message to
      # protobuf for every peer - this could easily be improved!
      sendMetrics(msg)
      encode(msg, anonymize)

  # Messages should not exceed 90% of maxMessageSize. Guessing 10% protobuf overhead.
  let maxEncodedMsgSize = (p.maxMessageSize * 90) div 100

  if encoded.len > maxEncodedMsgSize and msg.messages.len > 1:
    for encodedSplitMsg in splitRPCMsg(p, msg, maxEncodedMsgSize, anonymize):
      var ownedEncodedSplitMsg = encodedSplitMsg
      p.trackSend(p.sendEncoded(move(ownedEncodedSplitMsg), priority, useCustomStream))
  else:
    # If the message size is within limits, send it as is
    trace "sending msg to peer", peer = p, rpcMsg = shortLog(msg)
    p.trackSend(p.sendEncoded(move(encoded), priority, useCustomStream))

proc canAskIWant*(p: PubSubPeer, msgId: MessageId): bool =
  for sentIHave in p.sentIHaves.mitems():
    if msgId in sentIHave:
      sentIHave.excl(msgId)
      return true
  return false

proc sendNonHighPriorityTask(p: PubSubPeer) {.async: (raises: [CancelledError]).} =
  while true:
    # we send non-priority messages only if there are no pending priority messages
    while p.rpcmessagequeue.mediumPriorityQueue.len == 0 and
        p.rpcmessagequeue.lowPriorityQueue.len == 0:
      await p.rpcmessagequeue.dataAvailableEvent.wait()
      p.rpcmessagequeue.dataAvailableEvent.clear()

    var priority = MessagePriority.Low
    var msg =
      if p.rpcmessagequeue.mediumPriorityQueue.len != 0:
        priority = MessagePriority.Medium
        p.rpcmessagequeue.mediumPriorityQueue.popFirst()
      elif p.rpcmessagequeue.lowPriorityQueue.len != 0:
        p.rpcmessagequeue.lowPriorityQueue.popFirst()
      else:
        continue

    while p.rpcmessagequeue.sendPriorityQueue.len > 0:
      p.clearSendPriorityQueue()
      # waiting for the last future minimizes the number of times we have to
      # wait for something (each wait = performance cost) -
      # clearSendPriorityQueue ensures we're not waiting for an already-finished
      # future
      if p.rpcmessagequeue.sendPriorityQueue.len > 0:
        # `race` prevents `p.rpcmessagequeue.sendPriorityQueue[^1]` from being
        # cancelled when this task is cancelled
        discard await race(p.rpcmessagequeue.sendPriorityQueue[^1])
    when defined(pubsubpeer_queue_metrics):
      if priority == MessagePriority.Medium:
        libp2p_gossipsub_medium_priority_queue_size.dec(labelValues = [$p.peerId])
      else:
        libp2p_gossipsub_low_priority_queue_size.dec(labelValues = [$p.peerId])

    let useCustomStream = msg.useCustomStream
    await p.sendMsg(move(msg.data), useCustomStream)

proc startSendNonHighPriorityTask(p: PubSubPeer) =
  debug "starting sendNonHighPriorityTask", p
  if p.rpcmessagequeue.sendNonHighPriorityTask.isNil:
    p.rpcmessagequeue.sendNonHighPriorityTask = p.sendNonHighPriorityTask()

proc stopTasks*(p: PubSubPeer) {.async: (raises: []).} =
  ## Prevents further work, cancels peer tasks, and waits for cleanup to finish.
  p.stopped = true
  var pending = p.sendFuts
  let receiving = p.recvStreams
  var stopping: seq[Future[void]]
  for recv in receiving:
    stopping.add(recv.stop())
  if not p.connectFut.isNil:
    pending.add(p.connectFut)
  if not p.rpcmessagequeue.sendNonHighPriorityTask.isNil:
    trace "stopping sendNonHighPriorityTask", peer = p
    pending.add(p.rpcmessagequeue.sendNonHighPriorityTask)
  for fut in p.rpcmessagequeue.sendPriorityQueue:
    pending.add(fut)

  # Retain task handles until cancellation finishes, including for repeated stops.
  stopping.add(chronos.cancelAndWait(pending))
  await noCancel allFutures(stopping)
  p.connectFut = nil
  p.sendFuts = @[]
  p.rpcmessagequeue.sendNonHighPriorityTask = nil
  p.rpcmessagequeue.sendPriorityQueue.clear()
  p.rpcmessagequeue.mediumPriorityQueue.clear()
  p.rpcmessagequeue.lowPriorityQueue.clear()

  when defined(pubsubpeer_queue_metrics):
    libp2p_gossipsub_high_priority_queue_size.set(labelValues = [$p.peerId], value = 0)
    libp2p_gossipsub_medium_priority_queue_size.set(
      labelValues = [$p.peerId], value = 0
    )
    libp2p_gossipsub_low_priority_queue_size.set(labelValues = [$p.peerId], value = 0)

proc new(T: typedesc[RpcMessageQueue]): T =
  return T(
    sendPriorityQueue: initDeque[Future[void]](),
    mediumPriorityQueue: initDeque[QueuedMessage](),
    lowPriorityQueue: initDeque[QueuedMessage](),
    dataAvailableEvent: newAsyncEvent(),
  )

proc new*(
    T: typedesc[PubSubPeer],
    peerId: PeerId,
    getStream: GetStream,
    onEvent: OnEvent,
    codec: string,
    maxMessageSize: int,
    handler: RPCHandler,
    maxHighPriorityQueueLen: int = DefaultMaxHighPriorityQueueLen,
    maxMediumPriorityQueueLen: int = DefaultMaxMediumPriorityQueueLen,
    maxLowPriorityQueueLen: int = DefaultMaxLowPriorityQueueLen,
    overheadRateLimitOpt: Opt[TokenBucket] = Opt.none(TokenBucket),
    customStreamCallbacks: Opt[CustomStreamCallbacks] = Opt.none(CustomStreamCallbacks),
): T =
  doAssert not handler.isNil, "RPC handler must be set"
  let response = T(
    getStream: getStream,
    onEvent: onEvent,
    codec: codec,
    peerId: peerId,
    connectedFut: newFuture[void](),
    maxMessageSize: maxMessageSize,
    handler: handler,
    overheadRateLimitOpt: overheadRateLimitOpt,
    overheadSecondWindowStart: Moment.now(),
    rpcmessagequeue: RpcMessageQueue.new(),
    maxHighPriorityQueueLen: maxHighPriorityQueueLen,
    maxMediumPriorityQueueLen: maxMediumPriorityQueueLen,
    maxLowPriorityQueueLen: maxLowPriorityQueueLen,
    customStreamCallbacks: customStreamCallbacks,
  )
  response.sentIHaves.addFirst(default(HashSet[MessageId]))
  response.iDontWants.addFirst(default(HashSet[SaltedId]))
  response.startSendNonHighPriorityTask()

  response
