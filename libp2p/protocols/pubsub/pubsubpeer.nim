# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sequtils, tables, hashes, sets, deques, lists]
import results
import chronos, chronicles, nimcrypto/sha2, metrics
import chronos/ratelimit
import
  rpc/[messages, message, protobuf],
  gossipsub/extensions,
  outboundqueue,
  ../../peerid,
  ../../peerinfo,
  ../../stream/connection,
  ../../crypto/crypto,
  ../../logging,
  ../../utils/shortlog,
  ../../utils/future

export peerid, connection, deques, extensions, outboundqueue

logScope:
  topics = "libp2p pubsub"

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
  declareCounter(
    libp2p_pubsub_outbound_queue_dropped_messages,
    "outbound pubsub messages dropped from queues",
    labels = ["priority", "reason"],
  )
  declareCounter(
    libp2p_pubsub_outbound_queue_dropped_bytes,
    "encoded outbound pubsub bytes dropped from queues",
    labels = ["priority", "reason"],
  )

declareCounter(
  libp2p_pubsub_send_stream_opens,
  "send stream open attempts by outcome",
  labels = ["result"],
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
  DefaultSendStreamRetryBaseDelay* = 1.seconds
  DefaultSendStreamRetryMaxDelay* = 16.seconds
  SendStreamRetryJitter = 0.2
  MaxUnknownSendStreamFailures = 5
  DefaultMaxOutboundQueueBytes* = 16 * 1024 * 1024
  HighPriorityQueueReserveDivisor = 16

type
  PeerRateLimitError* = object of CatchableError

  GetStreamDialError* = object of CatchableError

  PubSubObserver* = ref object
    onRecv*: proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
    onSend*: proc(peer: PubSubPeer, msgs: var RPCMsg) {.gcsafe, raises: [].}
    onValidated*:
      proc(peer: PubSubPeer, msg: Message, msgId: MessageId) {.gcsafe, raises: [].}

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
    relayedSaltedId: Opt[SaltedId]
      ## Id of the one relayed message this RPC carries, when it was not split.

  RelayQueue = object
    messages: DoublyLinkedList[QueuedMessage]
    count: int
    # Each ID bucket follows FIFO order; cancellation removes the whole bucket.
    byId: Table[SaltedId, Deque[DoublyLinkedNode[QueuedMessage]]]

  RpcMessageQueue* = ref object
    # Tracks async tasks for sending high-priority peer-published messages.
    sendPriorityQueue: Deque[Future[void]]
    # Admission and byte accounting shared with the peer's topic streams.
    budget: OutboundQueue
    # Queue for local published messages
    mediumPriorityQueue: Deque[QueuedMessage]
    # Queue for lower-priority messages, like "IWANT" replies and relay messages.
    lowPriorityQueue: RelayQueue
    # Triggered when a message is added to medium or low queue.
    dataAvailableEvent: AsyncEvent
    # Task for processing non-priority message queue.
    sendNonHighPriorityTask: Future[void]

  ## Opens the requested codec. Topic-stream peers use /gsts/v0beta for
  ## payloads and the GossipSub codec for control RPCs. Custom topic writers
  ## reuse the stream until it closes or the topic is unsubscribed.
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

  RateLimit* = object
    bytes*: int
    interval*: Duration

  RecvStream = object
    stream: Stream
    loop: Future[void].Raising([CancelledError])

  PubSubPeer* = ref object of RootObj
    extensionsState*: ExtensionsState
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
    subscribedTopicBytes*: int
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
    sendStreamRetryBaseDelay*: Duration
    sendStreamRetryMaxDelay*: Duration
      ## Caps retry backoff and sets the stream lifetime required to reset it.
    protocolSupported*: bool
      ## Evidence from advertised protocols or inbound negotiation, not an optimistic open.
    unknownSendStreamFailures: int # Persists across connect() calls.
    sendStreamWarnings: LogRateLimit
    rng: Rng
    validationSlots*: AsyncSemaphore
    maxOutboundQueueBytes*: int
    stopped: bool
    customStreamCallbacks*: Opt[CustomStreamCallbacks]
    connectFut: Future[void]
    sendFuts: seq[Future[void]]
    stoppingTopicStreams: Future[void].Raising([])

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

func len(q: RelayQueue): int =
  q.count

proc addLast(q: var RelayQueue, msg: sink QueuedMessage) =
  let node = newDoublyLinkedNode(move(msg))
  node.value.relayedSaltedId.ifValue(id):
    q.byId.mgetOrPut(id).addLast(node)
  q.messages.append(node)
  inc q.count

proc popFirst(q: var RelayQueue): QueuedMessage =
  let node = q.messages.head
  node.value.relayedSaltedId.ifValue(id):
    q.byId.withValue(id, entries):
      discard entries[].popFirst()
      if entries[].len == 0:
        q.byId.del(id)
  q.messages.remove(node)
  node.prev = nil
  node.next = nil
  dec q.count

  move(node.value)

proc clear(q: var RelayQueue) =
  while q.count > 0:
    discard q.popFirst()

proc getAgent*(peer: PubSubPeer): string =
  return
    when defined(libp2p_agents_metrics):
      if peer.shortAgent.len > 0: peer.shortAgent else: "unknown"
    else:
      "unknown"

proc newOverheadBucket*(overheadRateLimit: Opt[RateLimit]): Opt[TokenBucket] =
  overheadRateLimit.ifValue(limit):
    if limit.bytes <= 0 or limit.interval <= ZeroDuration:
      # such a bucket refuses every charge, which would disconnect every peer
      warn "ignoring an unusable overhead rate limit", limit
      return Opt.none(TokenBucket)

    return Opt.some(TokenBucket.new(limit.bytes, limit.interval))

  Opt.none(TokenBucket)

proc tryCharge*(peer: PubSubPeer, overhead: int): bool =
  ## Charges `overhead` bytes of useless data to the peer, false when it cannot pay.
  if overhead <= 0:
    return true

  peer.overheadRateLimitOpt.ifValue(overheadRateLimit):
    return overheadRateLimit.tryConsume(overhead)

  true

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

func fitsWithin(currentBytes, messageBytes, maxBytes: int): bool =
  currentBytes <= maxBytes and messageBytes <= maxBytes - currentBytes

func highPriorityQueueReservedBytes*(maxOutboundQueueBytes: int): int =
  maxOutboundQueueBytes div HighPriorityQueueReserveDivisor

func determineQueueAction*(
    priority: MessagePriority,
    sendPriorityQueueLen, mediumPriorityQueueLen, lowPriorityQueueLen: int,
    maxHighPriorityQueueLen, maxMediumPriorityQueueLen, maxLowPriorityQueueLen: int,
    messageBytes: int = 0,
    highPriorityQueueBytes: int = 0,
    mediumPriorityQueueBytes: int = 0,
    lowPriorityQueueBytes: int = 0,
    maxOutboundQueueBytes: int = DefaultMaxOutboundQueueBytes,
    promoteOnEmpty: bool = true,
): QueueAction =
  let
    totalBytes =
      highPriorityQueueBytes + mediumPriorityQueueBytes + lowPriorityQueueBytes
    nonHighBytes = mediumPriorityQueueBytes + lowPriorityQueueBytes
    maxNonHighBytes =
      maxOutboundQueueBytes - highPriorityQueueReservedBytes(maxOutboundQueueBytes)
  let emptyQueues =
    sendPriorityQueueLen == 0 and mediumPriorityQueueLen == 0 and
    lowPriorityQueueLen == 0 and totalBytes == 0

  var send = true
  var slowPeerPenaltyDelta = 0.0
  var priority = priority

  if priority == MessagePriority.High or (promoteOnEmpty and emptyQueues):
    # A lone protocol-valid frame may exceed the normal backlog budget.
    priority = MessagePriority.High

    if sendPriorityQueueLen >= maxHighPriorityQueueLen or (
      not emptyQueues and not fitsWithin(
        totalBytes, messageBytes, maxOutboundQueueBytes
      )
    ):
      send = false
  elif priority == MessagePriority.Medium:
    if mediumPriorityQueueLen >= maxMediumPriorityQueueLen or
        not fitsWithin(totalBytes, messageBytes, maxOutboundQueueBytes) or
        not fitsWithin(nonHighBytes, messageBytes, maxNonHighBytes):
      send = false
      slowPeerPenaltyDelta = 1.0
  else:
    if lowPriorityQueueLen >= maxLowPriorityQueueLen or
        not fitsWithin(totalBytes, messageBytes, maxOutboundQueueBytes) or
        not fitsWithin(nonHighBytes, messageBytes, maxNonHighBytes):
      slowPeerPenaltyDelta = 1.0
      send = false

  QueueAction(
    priority: priority, send: send, slowPeerPenaltyDelta: slowPeerPenaltyDelta
  )

func determineQueueAction*(
    priority: MessagePriority,
    rpcmessagequeue: RpcMessageQueue,
    maxHighPriorityQueueLen, maxMediumPriorityQueueLen, maxLowPriorityQueueLen: int,
    messageBytes: int = 0,
    maxOutboundQueueBytes: int = DefaultMaxOutboundQueueBytes,
    promoteOnEmpty: bool = true,
): QueueAction =
  determineQueueAction(
    priority,
    rpcmessagequeue.sendPriorityQueue.len + rpcmessagequeue.budget.topicCounts[High],
    rpcmessagequeue.mediumPriorityQueue.len + rpcmessagequeue.budget.topicCounts[Medium],
    rpcmessagequeue.lowPriorityQueue.len + rpcmessagequeue.budget.topicCounts[Low],
    maxHighPriorityQueueLen,
    maxMediumPriorityQueueLen,
    maxLowPriorityQueueLen,
    messageBytes,
    rpcmessagequeue.budget.bytes[High],
    rpcmessagequeue.budget.bytes[Medium],
    rpcmessagequeue.budget.bytes[Low],
    maxOutboundQueueBytes,
    promoteOnEmpty,
  )

func outboundQueue*(p: PubSubPeer): OutboundQueue =
  p.rpcmessagequeue.budget

func queuedBytes*(p: PubSubPeer, priority: MessagePriority): int =
  ## Encoded RPC and topic-header bytes, including pending writes.
  ## Excludes transport framing, allocator overhead, and transport-owned copies.
  p.rpcmessagequeue.budget.bytes[priority]

func queuedBytes*(p: PubSubPeer): int =
  p.rpcmessagequeue.budget.bytes[High] + p.rpcmessagequeue.budget.bytes[Medium] +
    p.rpcmessagequeue.budget.bytes[Low]

func evictableQueuedBytes(p: PubSubPeer, priority: MessagePriority): int =
  p.rpcmessagequeue.budget.evictableBytes[priority]

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
  trace "starting pubsub read loop", stream, peerId = p, closed = stream.closed
  defer:
    trace "exiting pubsub read loop", stream, peerId = p, closed = stream.closed

  while not p.stopped and not stream.atEof:
    var data =
      try:
        await stream.readLp(p.maxMessageSize)
      except MaxSizeError as e:
        # Reset rather than half-close: the sender then re-opens the stream
        # and re-sends its subscriptions.
        trace "Oversized pubsub frame, resetting stream",
          peerId = p, stream, frameLen = e.msgLen, maxLen = e.maxLen
        await stream.reset()
        return
      except LPStreamEOFError:
        return
      except LPStreamError as e:
        trace "Exception occurred reading message PubSubPeer.handle",
          err = e.msg, stream, peer = p, closed = stream.closed
        return

    if p.stopped:
      return

    trace "read data from peer",
      stream, peer = p, closed = stream.closed, messageSize = data.len

    if p.handler.isNil:
      trace "Ignoring pubsub message without handler", stream, peerId = p
      continue

    try:
      await p.handler(p, move(data))
    except PeerRateLimitError as e:
      trace "peer rate limit exceeded in peerHandler", err = e.msg, stream, peer = p
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
    trace "Removing send stream", peer = p, stream = p.sendStream
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
): Future[Duration] {.async: (raises: [CancelledError, GetStreamDialError]).} =
  var opened = false
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
      return ZeroDuration

    # When the send channel goes up, subscriptions need to be sent to the
    # remote peer - if we had multiple channels up and one goes down, all
    # stop working so we make an effort to only keep a single channel alive

    trace "Get new send stream", peer = p, newStream

    # Careful to race conditions here.
    # Topic subscription relies on either connectedFut
    # to be completed, or onEvent to be called later
    p.sendStream = newStream
    opened = true
    p.address =
      if p.sendStream.observedAddr.isSome:
        Opt.some(p.sendStream.observedAddr.get)
      else:
        Opt.none(MultiAddress)

    if p.codec == "":
      # if codec was not know, it can be retrieved from newly established stream
      p.codec = newStream.protocol

    p.connectedFut.completeOnce()
    libp2p_pubsub_send_stream_opens.inc(labelValues = ["ok"])
    if p.onEvent != nil:
      p.onEvent(p, PubSubPeerEvent(kind: PubSubPeerEventKind.StreamOpened))

    let openedAt = Moment.now()
    await p.runHandleLoop(newStream)
    return Moment.now() - openedAt
  finally:
    if opened:
      await p.closeSendStream(PubSubPeerEventKind.StreamClosed)
    else:
      p.connectedFut.completeOnce()

proc jittered(p: PubSubPeer, delay: Duration): Duration =
  ## Spread the retries of the peers that lost the same remote together.
  if delay <= ZeroDuration:
    return delay

  let span = uint64(float(delay.nanoseconds) * SendStreamRetryJitter)
  delay - nanoseconds(int64(p.rng.generate(uint64) mod (span + 1)))

func doubled(delay, maxDelay: Duration): Duration =
  if delay > maxDelay div 2:
    maxDelay
  else:
    delay * 2

proc connectImpl(p: PubSubPeer) {.async: (raises: []).} =
  ## Back off failed opens and short-lived streams until a stream stays stable.
  var delay = p.sendStreamRetryBaseDelay
  try:
    while not p.stopped:
      try:
        let lifetime = await p.connectOnce()
        # A successful negotiation alone does not establish a stable stream.
        if lifetime >= p.sendStreamRetryMaxDelay:
          delay = p.sendStreamRetryBaseDelay
          continue
        if not p.stopped and p.sendStreamWarnings.allowLog():
          debug "Send stream closed before becoming stable, retrying",
            peer = p, lifetime, delay
      except GetStreamDialError as e:
        libp2p_pubsub_send_stream_opens.inc(labelValues = ["failed"])
        if not p.protocolSupported:
          inc p.unknownSendStreamFailures
          if p.unknownSendStreamFailures >= MaxUnknownSendStreamFailures:
            debug "Pubsub support unknown, send stream attempts exhausted", peer = p
            return
        if p.sendStreamWarnings.allowLog():
          debug "Could not establish send stream, retrying",
            peer = p, err = e.msg, delay
      if not p.stopped:
        await sleepAsync(p.jittered(delay))
        delay = delay.doubled(p.sendStreamRetryMaxDelay)
  except CancelledError:
    discard

proc connect*(p: PubSubPeer) =
  if p.stopped or p.connected:
    return
  if not p.protocolSupported and
      p.unknownSendStreamFailures >= MaxUnknownSendStreamFailures:
    return
  if not p.connectFut.isNil() and not p.connectFut.finished():
    return

  p.connectFut = connectImpl(p)

proc trackSend*(p: PubSubPeer, fut: Future[void]) =
  ## Take ownership of an in-flight send future on this peer.
  p.sendFuts.trackFut(fut)

proc hasRecvStream*(p: PubSubPeer): bool =
  p.recvStreams.len > 0

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

func priorityLabel(priority: MessagePriority): string =
  case priority
  of High:
    return "high"
  of Medium:
    return "medium"
  of Low:
    return "low"

func bytesNeeded(currentBytes, messageBytes, maxBytes: int): int =
  if fitsWithin(currentBytes, messageBytes, maxBytes):
    0
  elif currentBytes >= maxBytes:
    messageBytes
  else:
    messageBytes - (maxBytes - currentBytes)

proc chargeBytes(p: PubSubPeer, priority: MessagePriority, amount: int) =
  p.rpcmessagequeue.budget.bytes[priority] += amount

proc releaseBytes(p: PubSubPeer, priority: MessagePriority, amount: int) =
  discard p.outboundQueue.release(priority, amount)

proc recordQueueDrop(
    p: PubSubPeer,
    priority: MessagePriority,
    messageBytes: int,
    reason: string,
    penaltyDelta = 1.0,
) =
  p.slowPeerPenalty += penaltyDelta
  when defined(libp2p_expensive_metrics):
    let label = priorityLabel(priority)
    libp2p_pubsub_outbound_queue_dropped_messages.inc(labelValues = [label, reason])
    libp2p_pubsub_outbound_queue_dropped_bytes.inc(
      messageBytes.int64, labelValues = [label, reason]
    )

proc evictQueuedBytes(
    p: PubSubPeer, priority: MessagePriority, bytesToFree: int
) {.gcsafe.} =
  if priority == High or p.outboundQueue.failed:
    return

  var freedBytes = 0

  template evictFrom(queue: untyped) =
    while freedBytes < bytesToFree and queue.len > 0:
      let msg = queue.popFirst()
      let messageBytes = msg.data.len
      if not p.outboundQueue.release(
        priority, messageBytes, evictableBytes = messageBytes
      ):
        return
      p.recordQueueDrop(priority, messageBytes, "peer_limit", penaltyDelta = 0.0)
      freedBytes += messageBytes
      when defined(pubsubpeer_queue_metrics):
        if priority == Medium:
          libp2p_gossipsub_medium_priority_queue_size.dec(labelValues = [$p.peerId])
        else:
          libp2p_gossipsub_low_priority_queue_size.dec(labelValues = [$p.peerId])

  case priority
  of Medium:
    evictFrom(p.rpcmessagequeue.mediumPriorityQueue)
  of Low:
    evictFrom(p.rpcmessagequeue.lowPriorityQueue)
  of High:
    discard
  if not p.outboundQueue.failed and freedBytes < bytesToFree and
      p.outboundQueue.evictTopics != nil:
    discard p.outboundQueue.evictTopics(priority, bytesToFree - freedBytes)

proc makePeerRoom(p: PubSubPeer, priority: MessagePriority, messageBytes: int) =
  case priority
  of High:
    let removableBytes = p.evictableQueuedBytes(Low) + p.evictableQueuedBytes(Medium)
    if not fitsWithin(
      p.queuedBytes() - removableBytes, messageBytes, p.maxOutboundQueueBytes
    ):
      return
    var needed = bytesNeeded(p.queuedBytes(), messageBytes, p.maxOutboundQueueBytes)
    if needed > 0:
      p.evictQueuedBytes(Low, needed)
      needed = bytesNeeded(p.queuedBytes(), messageBytes, p.maxOutboundQueueBytes)
    if needed > 0:
      p.evictQueuedBytes(Medium, needed)
  of Medium:
    let
      nonHighBytes = p.queuedBytes(Medium) + p.queuedBytes(Low)
      maxNonHighBytes =
        p.maxOutboundQueueBytes - highPriorityQueueReservedBytes(
          p.maxOutboundQueueBytes
        )
      removableBytes = p.evictableQueuedBytes(Low)
      needed = max(
        bytesNeeded(p.queuedBytes(), messageBytes, p.maxOutboundQueueBytes),
        bytesNeeded(nonHighBytes, messageBytes, maxNonHighBytes),
      )
    if not fitsWithin(
      p.queuedBytes() - removableBytes, messageBytes, p.maxOutboundQueueBytes
    ) or not fitsWithin(nonHighBytes - removableBytes, messageBytes, maxNonHighBytes):
      return
    if needed > 0:
      p.evictQueuedBytes(Low, needed)
  of Low:
    discard

proc sendMsgContinue(
    stream: Stream, msgFut: Future[void].Raising([CancelledError, LPStreamError])
) {.async: (raises: [CancelledError]).} =
  # Continuation for a pending transport write from below
  try:
    await msgFut
    trace "sent pubsub message to remote", stream
  except CancelledError as exc:
    trace "sendMsgContinue cancelled", err = exc.msg, stream
    raise exc
  except LPStreamError as exc:
    trace "Unexpected exception in sendMsgContinue", err = exc.msg, stream
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
    trace "No send stream", peer = p, messageSize = msg.len
    return

  trace "sending encoded msg to peer", stream, messageSize = msg.len
  await sendMsgContinue(stream, stream.writeLp(msg))

proc sendMsg(
    p: PubSubPeer,
    msg: sink seq[byte],
    useCustomStream: bool = false,
    trackHighPriority: bool = false,
): Future[void] {.async: (raises: [CancelledError]).} =
  ## Starts a transport write and returns its lifecycle future for internal
  ## queue accounting. Do not await this from receive-handler paths.
  let messageBytes = msg.len
  if trackHighPriority:
    p.chargeBytes(High, messageBytes)
  defer:
    if trackHighPriority:
      p.releaseBytes(High, messageBytes)
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
      streamType = $streamType, stream, messageSize = msg.len
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

proc accountingFailed(p: PubSubPeer) =
  error "disconnecting peer after outbound queue accounting failure", peer = p
  if not p.stopped:
    p.stopped = true
    p.trackSend(p.closeSendStream(PubSubPeerEventKind.DisconnectionRequested))

proc sendHighPriorityMessage(
    p: PubSubPeer, msg: sink seq[byte], useCustomStream: bool
): Future[void] =
  let f = p.sendMsg(move(msg), useCustomStream, trackHighPriority = true)
  if not f.finished:
    p.rpcmessagequeue.sendPriorityQueue.addLast(f)
    when defined(pubsubpeer_queue_metrics):
      libp2p_gossipsub_high_priority_queue_size.inc(labelValues = [$p.peerId])
  return newFutureCompleted[void]()

proc enqueueNonHighPriorityMessage(
    p: PubSubPeer,
    msg: sink seq[byte],
    useCustomStream: bool,
    priority: MessagePriority,
    relayedSaltedId: Opt[SaltedId],
): Future[void] =
  let messageBytes = msg.len
  p.chargeBytes(priority, messageBytes)
  p.rpcmessagequeue.budget.evictableBytes[priority] += messageBytes
  let queuedMsg = QueuedMessage(
    data: move(msg), useCustomStream: useCustomStream, relayedSaltedId: relayedSaltedId
  )
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
    p: PubSubPeer,
    slowPeerPenaltyDelta: float64,
    priority: MessagePriority,
    messageBytes: int,
    reason = "limit",
): Future[void] =
  p.recordQueueDrop(priority, messageBytes, reason, slowPeerPenaltyDelta)
  case priority
  of MessagePriority.Medium:
    when defined(pubsubpeer_queue_metrics):
      libp2p_pubsub_medium_priority_queue_drops.inc()
    trace "medium priority queue full, dropping message", peer = p
  of MessagePriority.Low:
    when defined(pubsubpeer_queue_metrics):
      libp2p_pubsub_low_priority_queue_drops.inc()
    trace "low priority queue full, dropping message", peer = p
  of MessagePriority.High:
    raiseAssert "high-priority messages are not dropped via queue overflow scoring"
  return newFutureCompleted[void]()

func holdsIDontWant*(p: PubSubPeer, id: SaltedId): bool =
  ## True when the peer sent an IDONTWANT for `id` within the kept history.
  for iDontWant in p.iDontWants:
    if id in iDontWant:
      return true

  false

proc cancelQueuedRelay*(p: PubSubPeer, id: SaltedId): int =
  ## Removes only queued relays matching this ID, preserving the remaining order.
  var savedBytes = 0
  var entries: Deque[DoublyLinkedNode[QueuedMessage]]
  if not p.rpcmessagequeue.lowPriorityQueue.byId.pop(id, entries):
    return 0
  for node in entries:
    p.rpcmessagequeue.lowPriorityQueue.messages.remove(node)
    node.prev = nil
    node.next = nil
    dec p.rpcmessagequeue.lowPriorityQueue.count
    let messageBytes = node.value.data.len
    if not p.outboundQueue.release(Low, messageBytes, evictableBytes = messageBytes):
      return savedBytes
    savedBytes += messageBytes
    when defined(pubsubpeer_queue_metrics):
      libp2p_gossipsub_low_priority_queue_size.dec(labelValues = [$p.peerId])
  savedBytes

proc cancelQueuedRelays*(p: PubSubPeer, ids: HashSet[SaltedId]): int =
  ## Counts encoded bytes removed for the supplied IDs.
  var savedBytes = 0
  for id in ids:
    savedBytes += p.cancelQueuedRelay(id)
  savedBytes

proc admitMessage(
    p: PubSubPeer, priority: MessagePriority, messageBytes: int, promoteOnEmpty = true
): QueueAction =
  p.clearSendPriorityQueue()
  case priority
  of High:
    if p.rpcmessagequeue.sendPriorityQueue.len + p.outboundQueue.topicCounts[High] <
        p.maxHighPriorityQueueLen:
      p.makePeerRoom(priority, messageBytes)
  of Medium:
    if p.rpcmessagequeue.mediumPriorityQueue.len + p.outboundQueue.topicCounts[Medium] <
        p.maxMediumPriorityQueueLen:
      p.makePeerRoom(priority, messageBytes)
  of Low:
    discard
  if p.outboundQueue.failed:
    return QueueAction(priority: priority)
  determineQueueAction(
    priority, p.rpcmessagequeue, p.maxHighPriorityQueueLen, p.maxMediumPriorityQueueLen,
    p.maxLowPriorityQueueLen, messageBytes, p.maxOutboundQueueBytes, promoteOnEmpty,
  )

proc sendEncoded*(
    p: PubSubPeer,
    msg: sink seq[byte],
    priority: MessagePriority,
    useCustomStream: bool = false,
    relayedSaltedId: Opt[SaltedId] = Opt.none(SaltedId),
): Future[void] =
  ## Sends high-priority messages immediately; overflow disconnects the peer.
  ## Medium/low overflow drops the incoming message and penalizes the peer.
  ## Count and shared encoded-byte limits apply. Empty queues promote one
  ## protocol-valid frame to high priority. Pending writes remain charged.
  ## `relayedSaltedId` lets `cancelQueuedRelays` drop a queued relay.
  doAssert(not isNil(p), "pubsubpeer nil!")

  if p.stopped:
    return newFutureCompleted[void]()

  if msg.len <= 0:
    warn "empty message, skipping", peer = p, messageSize = msg.len
    newFutureCompleted[void]()
  elif msg.len > p.maxMessageSize:
    warn "trying to send a msg too big for pubsub",
      maxSize = p.maxMessageSize, msgSize = msg.len
    newFutureCompleted[void]()
  else:
    let action = p.admitMessage(priority, msg.len)
    if p.outboundQueue.failed:
      return newFutureCompleted[void]()

    case action.priority
    of High:
      if action.send:
        p.sendHighPriorityMessage(move(msg), useCustomStream)
      else:
        p.disconnectPeer()
    of Medium, Low:
      if action.send:
        p.enqueueNonHighPriorityMessage(
          move(msg), useCustomStream, action.priority, relayedSaltedId
        )
      else:
        p.dropNonHighPriorityMessage(
          action.slowPeerPenaltyDelta, action.priority, msg.len
        )

proc makeCustomDial(p: PubSubPeer): TopicStreamDial =
  if p.customStreamCallbacks.isNone:
    return nil
  return proc(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
    let stream = p.customStreamCallbacks.get().customStreamCreationCB(
        p.address, p.peerId, TopicStreamsCodec
      )
    if stream.isNil:
      raise newException(LPStreamError, "custom stream creation failed")
    return stream

proc sendTopicRPC*(
    p: PubSubPeer,
    msg: PreparedTopicRPC,
    priority: MessagePriority,
    useCustomStream: bool = false,
) =
  if p.stopped:
    return
  let customDial =
    if useCustomStream:
      p.makeCustomDial()
    else:
      nil
  let control = p.extensionsState.sendTopicRPC(p.peerId, msg, priority, customDial)
  if control.len > 0:
    p.trackSend(p.sendEncoded(control, MessagePriority.High, useCustomStream))

proc routeTopicRPC(
    p: PubSubPeer,
    msg: RPCMsg,
    anonymize: bool,
    priority: MessagePriority,
    useCustomStream: bool,
): bool =
  if msg.messages.len == 0 and msg.partialMessageExtension.isNone and
      not p.hasObservers():
    return false
  if not p.extensionsState.peerHasTopicStreams(p.peerId):
    return false
  var msgCopy = msg
  if p.hasObservers():
    p.sendObservers(msgCopy)
  sendMetrics(msgCopy)
  p.sendTopicRPC(makePreparedTopicRPC(msgCopy, anonymize), priority, useCustomStream)
  true

proc encodeRpcMsg(
    p: PubSubPeer, msg: RPCMsg, anonymize: bool
): seq[byte] {.raises: [].} =
  ## Encodes an `RPCMsg` for sending, running send observers and metrics.
  ##
  ## We re-encode the message to protect against valid but redundantly encoded
  ## protobufs with unknown or duplicated fields.
  if p.hasObservers():
    var mm = msg
    # trigger send hooks
    p.sendObservers(mm)
    sendMetrics(mm)
    encode(mm, anonymize)
  else:
    sendMetrics(msg)
    encode(msg, anonymize)

proc send*(
    p: PubSubPeer,
    msg: RPCMsg,
    anonymize: bool,
    priority: MessagePriority,
    useCustomStream: bool = false,
) {.raises: [].} =
  ## Sends an application-published `RPCMsg` to this peer, without splitting.
  ##
  ## Parameters:
  ## - `p`: The `PubSubPeer` instance to which the message is to be sent.
  ## - `msg`: The `RPCMsg` instance representing the message to be sent.
  ## - `anonymize`: A boolean flag indicating whether the message should be sent with anonymization.
  ## - `priority`: The message priority level (`High`, `Medium`, or `Low`).
  ##   High priority messages are sent immediately, medium and low priority messages are queued
  ##   and sent only after all high priority messages have been sent.

  if p.routeTopicRPC(msg, anonymize, priority, useCustomStream):
    return

  var encoded = encodeRpcMsg(p, msg, anonymize)

  if encoded.len > p.maxMessageSize:
    warn "message exceeds maximum message size; message will not be sent",
      encodedSize = encoded.len, maxMessageSize = p.maxMessageSize

  trace "Sending PubSub RPC",
    peerId = p.peerId, messageType = "rpc", messageSize = encoded.len
  p.trackSend(p.sendEncoded(move(encoded), priority, useCustomStream))

proc sendResponse*(
    p: PubSubPeer,
    msg: RPCMsg,
    anonymize: bool,
    priority: MessagePriority,
    useCustomStream: bool = false,
    relayedSaltedId: Opt[SaltedId] = Opt.none(SaltedId),
) {.raises: [].} =
  ## Sends a protocol response `RPCMsg` to this peer, batching multi-message
  ## responses together so that none exceed `maxMessageSize`.
  ##
  ## The RPC is sent as-is when it fits within `maxMessageSize`. Otherwise, when
  ## it contains messages, the messages are split into batches. Non-message
  ## fields (subscriptions, control and extensions) are attached to the first
  ## batch so they are not lost. RPCs without messages that still exceed
  ## `maxMessageSize`, and individual messages that still exceed
  ## `maxMessageSize`, are dropped with a warning.

  if p.routeTopicRPC(msg, anonymize, priority, useCustomStream):
    return

  proc send(toSendMsg: RPCMsg, saltedId = Opt.none(SaltedId)) =
    var encoded = encodeRpcMsg(p, toSendMsg, anonymize)
    trace "Sending PubSub RPC response",
      peerId = p.peerId, messageType = "rpc", messageSize = encoded.len
    p.trackSend(p.sendEncoded(move(encoded), priority, useCustomStream, saltedId))

  template wireSize(toSizeMsg: RPCMsg): int =
    toSizeMsg.anonymize(anonymize).encodedSize()

  let msgSize = wireSize(msg)
  if msgSize <= p.maxMessageSize:
    # A cancel drops the whole RPC, so tag it only when it carries that one message.
    let saltedId =
      if msg.messages.len == 1:
        relayedSaltedId
      else:
        Opt.none(SaltedId)
    send(msg, saltedId) # The whole RPC fits the limits, send it as-is.
    return

  if msg.messages.len == 0:
    # Nothing to split and nothing to send - the RPC only carries non-message
    # data that still exceeds `maxMessageSize`.
    warn "message exceeds maximum message size and contains no messages; message will not be sent",
      encodedSize = msgSize, maxMessageSize = p.maxMessageSize
    return

  # Batch as many messages as possible into a single encoded RPC so that each
  # batch stays within `maxMessageSize`. Non-message fields are carried by the
  # first batch only, so they are neither lost nor duplicated.
  var batch = msg
  batch.messages.setLen(0)
  let firstBatchSize = wireSize(batch)
  var isFirstBatch = true

  for m in msg.messages:
    batch.messages.add(m)

    if wireSize(batch) <= p.maxMessageSize:
      continue

    # The last message caused an overflow, send the batch without it.
    discard batch.messages.pop()

    if batch.messages.len > 0:
      send(batch)
    elif isFirstBatch and firstBatchSize > p.maxMessageSize:
      warn "RPC non-message fields exceed maximum message size; they will not be sent",
        encodedSize = firstBatchSize, maxMessageSize = p.maxMessageSize
    elif isFirstBatch and firstBatchSize > 0:
      # No message fits alongside the non-message fields. Send them on their own
      # so they are not lost.
      send(batch)

    batch = RPCMsg()
    isFirstBatch = false
    batch.messages.add(m)

    let messageSize = wireSize(batch)
    if messageSize > p.maxMessageSize:
      # The message alone exceeds `maxMessageSize`.
      discard batch.messages.pop()
      warn "message exceeds maximum message size; message will not be sent",
        messageSize = messageSize, maxMessageSize = p.maxMessageSize

  if batch.messages.len > 0:
    send(batch)

proc canAskIWant*(p: PubSubPeer, msgId: MessageId): bool =
  for sentIHave in p.sentIHaves.mitems():
    if msgId in sentIHave:
      sentIHave.excl(msgId)
      return true
  return false

proc sendNonHighPriorityTask(p: PubSubPeer) {.async: (raises: [CancelledError]).} =
  while not p.outboundQueue.failed:
    # we send non-priority messages only if there are no pending priority messages
    while p.rpcmessagequeue.mediumPriorityQueue.len == 0 and
        p.rpcmessagequeue.lowPriorityQueue.len == 0:
      await p.rpcmessagequeue.dataAvailableEvent.wait()
      p.rpcmessagequeue.dataAvailableEvent.clear()

    while p.rpcmessagequeue.sendPriorityQueue.len > 0:
      p.clearSendPriorityQueue()
      # One wait on the last future costs less than one wait per future.
      if p.rpcmessagequeue.sendPriorityQueue.len > 0:
        # `race` keeps the awaited future alive when this task is cancelled.
        discard await race(p.rpcmessagequeue.sendPriorityQueue[^1])

    if p.outboundQueue.failed:
      return
    # Pop after the wait above, so a message that waits stays cancellable.
    var priority = MessagePriority.Low
    var msg =
      if p.rpcmessagequeue.mediumPriorityQueue.len != 0:
        priority = MessagePriority.Medium
        p.rpcmessagequeue.mediumPriorityQueue.popFirst()
      elif p.rpcmessagequeue.lowPriorityQueue.len != 0:
        p.rpcmessagequeue.lowPriorityQueue.popFirst()
      else:
        continue

    let messageBytes = msg.data.len
    if not p.outboundQueue.release(priority, 0, evictableBytes = messageBytes):
      return
    when defined(pubsubpeer_queue_metrics):
      if priority == MessagePriority.Medium:
        libp2p_gossipsub_medium_priority_queue_size.dec(labelValues = [$p.peerId])
      else:
        libp2p_gossipsub_low_priority_queue_size.dec(labelValues = [$p.peerId])

    try:
      let useCustomStream = msg.useCustomStream
      await p.sendMsg(move(msg.data), useCustomStream)
    except CancelledError as exc:
      p.releaseBytes(priority, messageBytes)
      raise exc
    p.releaseBytes(priority, messageBytes)

proc startSendNonHighPriorityTask(p: PubSubPeer) =
  trace "starting sendNonHighPriorityTask", peer = p
  if p.rpcmessagequeue.sendNonHighPriorityTask.isNil:
    p.rpcmessagequeue.sendNonHighPriorityTask = p.sendNonHighPriorityTask()

proc stopTasks*(p: PubSubPeer) {.async: (raises: []).} =
  ## Prevents further work, cancels peer tasks, and waits for cleanup to finish.
  p.stopped = true
  if p.stoppingTopicStreams == nil:
    let extensions = move p.extensionsState
    p.stoppingTopicStreams = extensions.stopTopicStreams(p.peerId)
  # Repeated stops must wait for topic writers before releasing the shared budget.
  await p.stoppingTopicStreams
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
  p.rpcmessagequeue.budget.bytes = default(array[MessagePriority, int])
  p.rpcmessagequeue.budget.topicCounts = default(array[MessagePriority, int])
  p.rpcmessagequeue.budget.evictableBytes = default(array[MessagePriority, int])
  p.outboundQueue.admit = nil
  p.outboundQueue.evicted = nil
  p.outboundQueue.onFailure = nil

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
    sendStreamRetryBaseDelay: Duration = DefaultSendStreamRetryBaseDelay,
    sendStreamRetryMaxDelay: Duration = DefaultSendStreamRetryMaxDelay,
    rng: Rng = newRng(),
    maxOutboundQueueBytes: int = int.high,
): T =
  # GossipSub supplies finite byte budgets; FloodSub retains count-only limits.
  doAssert not handler.isNil, "RPC handler must be set"
  doAssert sendStreamRetryBaseDelay > ZeroDuration,
    "send stream retry base delay must be positive"
  doAssert sendStreamRetryMaxDelay >= sendStreamRetryBaseDelay,
    "send stream retry max delay must not be below the base delay"
  doAssert maxOutboundQueueBytes > 0
  let response = T(
    getStream: getStream,
    onEvent: onEvent,
    codec: codec,
    protocolSupported: codec != "",
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
    maxOutboundQueueBytes: maxOutboundQueueBytes,
    customStreamCallbacks: customStreamCallbacks,
    sendStreamRetryBaseDelay: sendStreamRetryBaseDelay,
    sendStreamRetryMaxDelay: sendStreamRetryMaxDelay,
    rng: rng,
  )
  let budget = OutboundQueue()
  response.rpcmessagequeue.budget = budget
  budget.onFailure = proc() {.gcsafe, raises: [].} =
    response.accountingFailed()
  budget.admit = proc(
      priority: MessagePriority, messageBytes: int
  ): QueueAction {.gcsafe, raises: [].} =
    if response.stopped:
      return QueueAction(priority: priority)
    # Independent topic writers do not need the control stream's immediate-send promotion.
    let action = response.admitMessage(priority, messageBytes, promoteOnEmpty = false)
    if budget.failed:
      return QueueAction(priority: priority)
    if not action.send:
      if action.priority == High:
        response.trackSend(response.disconnectPeer())
      else:
        discard response.dropNonHighPriorityMessage(
          action.slowPeerPenaltyDelta, action.priority, messageBytes
        )
    action
  budget.evicted = proc(
      priority: MessagePriority, messageBytes: int
  ) {.gcsafe, raises: [].} =
    response.recordQueueDrop(priority, messageBytes, "peer_limit", penaltyDelta = 0.0)
  response.sentIHaves.addFirst(default(HashSet[MessageId]))
  response.iDontWants.addFirst(default(HashSet[SaltedId]))
  response.startSendNonHighPriorityTask()

  response
