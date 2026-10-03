# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import std/[deques, sets]
import nimcrypto/sha2
import ../../../libp2p/protocols/pubsub/pubsubpeer
import ../../../libp2p/protocols/pubsub/gossipsub/types
import ../../../libp2p/protocols/pubsub/rpc/[messages, protobuf]
import ../../../libp2p/peerid
import ../../../libp2p/utils/future
import ../../tools/[unittest, crypto]

proc dummyGetConn(): Future[Stream] {.
    async: (raises: [CancelledError, GetStreamDialError])
.} =
  raise newException(GetStreamDialError, "this is not a real connection")

proc noopHandler(
    peer: PubSubPeer, data: sink seq[byte]
) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
  discard

type PendingConnection = ref object of Connection
  # These futures never finish, they're used to grow the high priority queue
  pendingWrites: seq[Future[void].Raising([CancelledError, LPStreamError])]

type RecorderConnection = ref object of Connection
  # First write blocks, later writes complete and are recorded in order.
  writes: seq[seq[byte]]
  firstWriteFut: Future[void].Raising([CancelledError, LPStreamError])

method initStream*(s: PendingConnection) {.raises: [].} =
  s.objName = "PendingConnection"
  procCall Connection(s).initStream()

method writeLp*(
    s: PendingConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  let fut = Future[void].Raising([CancelledError, LPStreamError]).init(
      "PendingConnection.writeLp"
    )
  s.pendingWrites.add(fut)
  fut

method getWrapped*(s: PendingConnection): Connection =
  s

method closeImpl*(s: PendingConnection) {.async: (raises: []).} =
  for fut in s.pendingWrites:
    if not fut.finished:
      fut.fail(newLPStreamClosedError())
  await procCall Connection(s).closeImpl()

proc createPendingConnection(): PendingConnection {.raises: [].} =
  let conn = PendingConnection(dir: Direction.Out, timeout: 0.milliseconds)
  conn.initStream()
  conn

method initStream*(s: RecorderConnection) {.raises: [].} =
  s.objName = "RecorderConnection"
  procCall Connection(s).initStream()

method writeLp*(
    s: RecorderConnection, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  s.writes.add(@msg)
  if s.firstWriteFut.isNil:
    s.firstWriteFut = Future[void].Raising([CancelledError, LPStreamError]).init(
        "RecorderConnection.writeLp"
      )
    s.firstWriteFut
  else:
    let fut = Future[void].Raising([CancelledError, LPStreamError]).init(
        "RecorderConnection.writeLp.completed"
      )
    fut.complete()
    fut

method getWrapped*(s: RecorderConnection): Connection =
  s

method closeImpl*(s: RecorderConnection) {.async: (raises: []).} =
  if not s.firstWriteFut.isNil:
    s.firstWriteFut.completeOnce()
  await procCall Connection(s).closeImpl()

proc createRecorderConnection(): RecorderConnection {.raises: [].} =
  let conn = RecorderConnection(dir: Direction.Out, timeout: 0.milliseconds)
  conn.initStream()
  conn

proc releaseFirstWrite(conn: RecorderConnection) {.raises: [].} =
  if not conn.firstWriteFut.isNil and not conn.firstWriteFut.finished:
    conn.firstWriteFut.complete()

proc callbacksDrained(
    fut: FutureBase
): Future[void].Raising([CancelledError]) {.raises: [].} =
  let drained = Future[void].Raising([CancelledError]).init("callbacksDrained")

  proc continuation(udata: pointer) {.gcsafe, raises: [].} =
    let drained = cast[Future[void]](udata)
    drained.completeOnce()

  fut.addCallback(continuation, cast[pointer](drained))
  drained

proc newDisconnectRecorder(disconnectRequested: ref bool): OnEvent =
  proc recordDisconnect(
      peer: PubSubPeer, event: PubSubPeerEvent
  ) {.gcsafe, raises: [].} =
    if event.kind == PubSubPeerEventKind.DisconnectionRequested:
      disconnectRequested[] = true

  recordDisconnect

proc createTestPeer(
    maxHigh: int = 2,
    maxMedium: int = 2,
    maxLow: int = 2,
    onEvent: OnEvent = nil,
    maxMessageSize: int = 100,
): PubSubPeer =
  PubSubPeer.new(
    PeerId.random(rng()).expect("random peer id"),
    dummyGetConn,
    onEvent,
    GossipSubCodec_12,
    maxMessageSize = maxMessageSize,
    handler = noopHandler,
    maxHighPriorityQueueLen = maxHigh,
    maxMediumPriorityQueueLen = maxMedium,
    maxLowPriorityQueueLen = maxLow,
  )

func testSaltedId(seed: byte): SaltedId =
  SaltedId(data: sha256.digest([seed]))

suite "Priority queue behavior":
  teardown:
    checkTrackers()

  asyncTest "Pending high priority sends delay lower priority messages":
    let disconnectRequestedForTest = new bool

    let peer = createTestPeer(
      maxHigh = 3, onEvent = newDisconnectRecorder(disconnectRequestedForTest)
    )
    let conn = createPendingConnection()
    defer:
      await peer.stopTasks()

    peer.sendStream = conn

    # These sends stay pending, keeping the high-priority backlog visible until
    # the underlying transport write completes.
    let f1 = peer.sendEncoded(@[1'u8, 2, 3], MessagePriority.High)
    let f2 = peer.sendEncoded(@[1'u8, 2, 3], MessagePriority.High)
    let f3 = peer.sendEncoded(@[1'u8, 2, 3], MessagePriority.High)
    let mediumFut = peer.sendEncoded(@[4'u8, 5, 6], MessagePriority.Medium)

    check:
      f1.finished
      f2.finished
      f3.finished
      mediumFut.finished
      conn.pendingWrites.len == 3
      not conn.pendingWrites[0].finished
      not conn.pendingWrites[1].finished
      not conn.pendingWrites[2].finished
      not disconnectRequestedForTest[]
      peer.hasSendStream()

    await conn.close()
    let drain1 = callbacksDrained(conn.pendingWrites[0])
    let drain2 = callbacksDrained(conn.pendingWrites[1])
    let drain3 = callbacksDrained(conn.pendingWrites[2])

    await allFutures(drain1, drain2, drain3)

    check:
      not disconnectRequestedForTest[]

  asyncTest "Medium priority messages wait while high priority send is pending":
    let disconnectRequestedForTest = new bool

    let peer = createTestPeer(
      maxMedium = 4, onEvent = newDisconnectRecorder(disconnectRequestedForTest)
    )
    let conn = createRecorderConnection()
    defer:
      await peer.stopTasks()

    peer.sendStream = conn

    let highMsg = @[1'u8, 2, 3]
    let mediumMsgs = @[@[10'u8, 0, 0], @[11'u8, 0, 0]]

    # The first high-priority send remains pending on the connection, but later
    # medium-priority messages are queued until it completes.
    var queuedHighMsg = highMsg
    let highFut = peer.sendEncoded(move(queuedHighMsg), MessagePriority.High)
    check highFut.finished

    for msg in mediumMsgs:
      var queuedMsg = msg
      let f = peer.sendEncoded(move(queuedMsg), MessagePriority.Medium)
      check f.finished

    check conn.writes == @[highMsg]

    conn.releaseFirstWrite()

    checkUntilTimeout:
      conn.writes == @[highMsg, mediumMsgs[0], mediumMsgs[1]]

    check:
      not disconnectRequestedForTest[]
      peer.hasSendStream()

  asyncTest "Low priority messages wait while high priority send is pending":
    let disconnectRequestedForTest = new bool

    let peer = createTestPeer(
      maxLow = 4, onEvent = newDisconnectRecorder(disconnectRequestedForTest)
    )
    let conn = createRecorderConnection()
    defer:
      await peer.stopTasks()

    peer.sendStream = conn

    let highMsg = @[1'u8, 2, 3]
    let lowMsgs = @[@[20'u8, 0, 0], @[21'u8, 0, 0]]

    # The first high-priority send remains pending on the connection, but later
    # low-priority messages are queued until it completes.
    var queuedHighMsg = highMsg
    let highFut = peer.sendEncoded(move(queuedHighMsg), MessagePriority.High)
    check highFut.finished

    for msg in lowMsgs:
      var queuedMsg = msg
      let f = peer.sendEncoded(move(queuedMsg), MessagePriority.Low)
      check f.finished

    check conn.writes == @[highMsg]

    conn.releaseFirstWrite()

    checkUntilTimeout:
      conn.writes == @[highMsg, lowMsgs[0], lowMsgs[1]]

    check:
      not disconnectRequestedForTest[]
      peer.hasSendStream()

  asyncTest "Cancelling a queued relay drops it and leaves the other queued messages":
    let peer = createTestPeer(maxLow = 4)
    let conn = createRecorderConnection()
    defer:
      peer.stopTasks()

    peer.sendStream = conn

    let
      highMsg = @[1'u8, 2, 3]
      cancelledMsg = @[30'u8, 0, 0]
      keptMsg = @[31'u8, 0, 0]
      cancelledId = testSaltedId(1)
      keptId = testSaltedId(2)

    var queuedHighMsg = highMsg
    let highFut = peer.sendEncoded(move(queuedHighMsg), MessagePriority.High)
    check highFut.finished

    var queuedCancelledMsg = cancelledMsg
    let cancelledFut = peer.sendEncoded(
      move(queuedCancelledMsg),
      MessagePriority.Low,
      relayedSaltedId = Opt.some(cancelledId),
    )
    var queuedKeptMsg = keptMsg
    let keptFut = peer.sendEncoded(
      move(queuedKeptMsg), MessagePriority.Low, relayedSaltedId = Opt.some(keptId)
    )

    check:
      cancelledFut.finished
      keptFut.finished
      conn.writes == @[highMsg]
      peer.cancelQueuedRelays([cancelledId]) == cancelledMsg.len
      peer.cancelQueuedRelays([cancelledId]) == 0

    conn.releaseFirstWrite()

    checkUntilTimeout:
      conn.writes == @[highMsg, keptMsg]

  asyncTest "An IDONTWANT in the peer history cancels a queued relay":
    let peer = createTestPeer(maxLow = 4)
    let conn = createRecorderConnection()
    defer:
      peer.stopTasks()

    peer.sendStream = conn

    let
      highMsg = @[1'u8, 2, 3]
      unwantedMsg = @[30'u8, 0, 0]
      unwantedId = testSaltedId(3)

    var queuedHighMsg = highMsg
    check peer.sendEncoded(move(queuedHighMsg), MessagePriority.High).finished

    var queuedUnwantedMsg = unwantedMsg
    check peer.sendEncoded(
      move(queuedUnwantedMsg),
      MessagePriority.Low,
      relayedSaltedId = Opt.some(unwantedId),
    ).finished

    # The whole history counts, not only the current heartbeat slot.
    peer.iDontWants.addFirst(default(HashSet[SaltedId]))
    peer.iDontWants[1].incl(unwantedId)

    let noDuplicates: seq[SaltedId] = @[]
    check peer.cancelQueuedRelays(noDuplicates) == unwantedMsg.len

    conn.releaseFirstWrite()

    checkUntilTimeout:
      conn.writes == @[highMsg]

  asyncTest "Empty queues fast-path medium and low sends while returning completed futures":
    let mediumPeer = createTestPeer()
    let lowPeer = createTestPeer()
    let mediumConn = createPendingConnection()
    let lowConn = createPendingConnection()
    defer:
      await mediumPeer.stopTasks()
      await lowPeer.stopTasks()

    # This is required so we can test the send path
    mediumPeer.sendStream = mediumConn
    lowPeer.sendStream = lowConn

    let mediumFut = mediumPeer.sendEncoded(@[1'u8, 2, 3], MessagePriority.Medium)
    let lowFut = lowPeer.sendEncoded(@[4'u8, 5, 6], MessagePriority.Low)

    check:
      mediumFut.finished
      lowFut.finished
      mediumConn.pendingWrites.len == 1
      lowConn.pendingWrites.len == 1
      mediumPeer.hasSendStream()
      lowPeer.hasSendStream()

    await mediumConn.close()
    await lowConn.close()
    let mediumDrain = callbacksDrained(mediumConn.pendingWrites[0])
    let lowDrain = callbacksDrained(lowConn.pendingWrites[0])

    checkUntilTimeout:
      mediumDrain.finished
      lowDrain.finished

  asyncTest "Empty and oversized messages are dropped before any queue logic":
    const maxSize = 100

    let disconnectRequestedForTest = new bool

    let peer = createTestPeer(
      onEvent = newDisconnectRecorder(disconnectRequestedForTest),
      maxMessageSize = maxSize,
    )
    let conn = createPendingConnection()
    defer:
      await conn.close()
      await peer.stopTasks()

    peer.sendStream = conn

    let emptyFut = peer.sendEncoded(newSeq[byte](0), MessagePriority.Medium)
    let oversizedFut =
      peer.sendEncoded(newSeq[byte](maxSize + 1), MessagePriority.Medium)

    check:
      emptyFut.finished
      oversizedFut.finished
      conn.pendingWrites.len == 0
      peer.slowPeerPenalty == 0.0
      not disconnectRequestedForTest[]
      peer.hasSendStream()

  test "Queue admission drops medium when backlog exists and medium queue is full":
    let queueAction = determineQueueAction(
      priority = MessagePriority.Medium,
      sendPriorityQueueLen = 1,
      mediumPriorityQueueLen = 1,
      lowPriorityQueueLen = 0,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 1,
      maxLowPriorityQueueLen = 2,
    )

    check:
      queueAction.priority == MessagePriority.Medium
      queueAction.send == false
      queueAction.slowPeerPenaltyDelta == 1.0

  test "Queue admission drops low when backlog exists and low queue is full":
    let queueAction = determineQueueAction(
      priority = MessagePriority.Low,
      sendPriorityQueueLen = 1,
      mediumPriorityQueueLen = 0,
      lowPriorityQueueLen = 1,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 1,
    )

    check:
      queueAction.priority == MessagePriority.Low
      queueAction.send == false
      queueAction.slowPeerPenaltyDelta == 1.0

  test "Queue admission disconnects when high priority queue is full":
    let queueAction = determineQueueAction(
      priority = MessagePriority.High,
      sendPriorityQueueLen = 1,
      mediumPriorityQueueLen = 0,
      lowPriorityQueueLen = 0,
      maxHighPriorityQueueLen = 1,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 2,
    )

    check:
      queueAction.priority == MessagePriority.High
      queueAction.send == false
      queueAction.slowPeerPenaltyDelta == 0.0

  test "Queue admission queues medium and low messages below their limits":
    let mediumAction = determineQueueAction(
      priority = MessagePriority.Medium,
      sendPriorityQueueLen = 0,
      mediumPriorityQueueLen = 1,
      lowPriorityQueueLen = 0,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 2,
    )
    let lowAction = determineQueueAction(
      priority = MessagePriority.Low,
      sendPriorityQueueLen = 0,
      mediumPriorityQueueLen = 0,
      lowPriorityQueueLen = 1,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 2,
    )

    check:
      mediumAction.priority == MessagePriority.Medium
      mediumAction.send == true
      mediumAction.slowPeerPenaltyDelta == 0.0
      lowAction.priority == MessagePriority.Low
      lowAction.send == true
      lowAction.slowPeerPenaltyDelta == 0.0

  test "All empty queues promote medium and low messages to high priority":
    let mediumAction = determineQueueAction(
      priority = MessagePriority.Medium,
      sendPriorityQueueLen = 0,
      mediumPriorityQueueLen = 0,
      lowPriorityQueueLen = 0,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 2,
    )
    let lowAction = determineQueueAction(
      priority = MessagePriority.Low,
      sendPriorityQueueLen = 0,
      mediumPriorityQueueLen = 0,
      lowPriorityQueueLen = 0,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 2,
    )

    check:
      mediumAction.priority == MessagePriority.High
      mediumAction.send == true
      mediumAction.slowPeerPenaltyDelta == 0.0
      lowAction.priority == MessagePriority.High
      lowAction.send == true
      lowAction.slowPeerPenaltyDelta == 0.0

  test "Promotion requires all queues empty, not just the message's own queue":
    let mediumBlockedByLow = determineQueueAction(
      priority = MessagePriority.Medium,
      sendPriorityQueueLen = 0,
      mediumPriorityQueueLen = 0,
      lowPriorityQueueLen = 1,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 2,
    )
    let lowBlockedByMedium = determineQueueAction(
      priority = MessagePriority.Low,
      sendPriorityQueueLen = 0,
      mediumPriorityQueueLen = 1,
      lowPriorityQueueLen = 0,
      maxHighPriorityQueueLen = 2,
      maxMediumPriorityQueueLen = 2,
      maxLowPriorityQueueLen = 2,
    )

    check:
      mediumBlockedByLow.priority == MessagePriority.Medium
      mediumBlockedByLow.send == true
      mediumBlockedByLow.slowPeerPenaltyDelta == 0.0
      lowBlockedByMedium.priority == MessagePriority.Low
      lowBlockedByMedium.send == true
      lowBlockedByMedium.slowPeerPenaltyDelta == 0.0

suite "PubSubPeer sendResponse":
  teardown:
    checkTrackers()

  const topic = "🌞"

  asyncTest "sendResponse sends a fitting RPC as-is":
    let peer = createTestPeer(maxMessageSize = 4096)
    let conn = createRecorderConnection()
    peer.sendStream = conn
    defer:
      await peer.stopTasks()

    let msg = RPCMsg(
      control: Opt.some(ControlMessage(graft: @[ControlGraft(topicID: topic)])),
      messages: @[
        Message(data: @[1'u8, 2, 3], topic: topic),
        Message(data: @[4'u8, 5, 6], topic: topic),
      ],
    )

    peer.sendResponse(msg, false, MessagePriority.High)

    check:
      conn.writes.len == 1
      conn.writes[0] == msg.encode(false)

    conn.releaseFirstWrite()

  asyncTest "sendResponse sizes an anonymized RPC after anonymization":
    let msg = RPCMsg.withMessages(
      @[Message(data: @[1'u8, 2, 3], topic: topic, signature: newSeq[byte](200))]
    )
    let encoded = msg.encode(true)
    check msg.encodedSize() > encoded.len

    let peer = createTestPeer(maxMessageSize = encoded.len)
    let conn = createRecorderConnection()
    peer.sendStream = conn
    defer:
      await peer.stopTasks()

    peer.sendResponse(msg, true, MessagePriority.High)

    check:
      conn.writes.len == 1
      conn.writes[0] == encoded

    conn.releaseFirstWrite()

  asyncTest "sendResponse batches an oversized RPC, keeping non-message fields in the first batch":
    let
      control = ControlMessage(graft: @[ControlGraft(topicID: topic)])
      m1 = Message(data: newSeq[byte](50), topic: topic)
      m2 = Message(data: newSeq[byte](60), topic: topic)

    let
      firstBatch = RPCMsg(control: Opt.some(control), messages: @[m1])
      fullMsg = RPCMsg(control: Opt.some(control), messages: @[m1, m2])
      maxSize = fullMsg.encodedSize() - 1

    let peer = createTestPeer(maxMessageSize = maxSize)
    let conn = createRecorderConnection()
    peer.sendStream = conn
    defer:
      await peer.stopTasks()

    peer.sendResponse(fullMsg, false, MessagePriority.High)

    check:
      conn.writes.len == 2
      conn.writes[0] == firstBatch.encode(false)
      conn.writes[1] == RPCMsg(messages: @[m2]).encode(false)

    conn.releaseFirstWrite()

  asyncTest "sendResponse drops an oversized message but still sends non-message fields":
    let
      control = ControlMessage(graft: @[ControlGraft(topicID: topic)])
      oversized = Message(data: newSeq[byte](200), topic: topic)
      controlOnly = RPCMsg(control: Opt.some(control))
      fullMsg = RPCMsg(control: Opt.some(control), messages: @[oversized])

    let peer = createTestPeer(maxMessageSize = controlOnly.encodedSize())
    let conn = createRecorderConnection()
    peer.sendStream = conn
    defer:
      await peer.stopTasks()

    peer.sendResponse(fullMsg, false, MessagePriority.High)

    check:
      conn.writes.len == 1
      conn.writes[0] == controlOnly.encode(false)

    conn.releaseFirstWrite()

  asyncTest "sendResponse drops an oversized RPC with no messages":
    var grafts: seq[ControlGraft]
    for i in 0 ..< 20:
      grafts.add(ControlGraft(topicID: topic & $i))

    let
      control = ControlMessage(graft: grafts)
      msg = RPCMsg(control: Opt.some(control))
      maxSize = msg.encodedSize() - 1

    let peer = createTestPeer(maxMessageSize = maxSize)
    let conn = createRecorderConnection()
    peer.sendStream = conn
    defer:
      await peer.stopTasks()

    peer.sendResponse(msg, false, MessagePriority.High)

    check conn.writes.len == 0
