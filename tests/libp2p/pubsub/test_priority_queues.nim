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
import ../../tools/[unittest, crypto, stall_stream]
import ./extensions/extension_recording

proc dummyGetConn(): Future[Stream] {.
    async: (raises: [CancelledError, GetStreamDialError])
.} =
  raise newException(GetStreamDialError, "this is not a real connection")

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
    maxOutboundBytes: int = DefaultMaxOutboundQueueBytes,
): PubSubPeer =
  PubSubPeer.new(
    PeerId.random(),
    dummyGetConn,
    onEvent,
    GossipSubCodec_12,
    maxMessageSize = maxMessageSize,
    handler = noopRpcHandler,
    maxHighPriorityQueueLen = maxHigh,
    maxMediumPriorityQueueLen = maxMedium,
    maxLowPriorityQueueLen = maxLow,
    maxOutboundQueueBytes = maxOutboundBytes,
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
    let conn = peer.stallSendStream()
    defer:
      await peer.stopTasks()

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
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

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

    conn.releasePendingWrites()

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
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

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

    conn.releasePendingWrites()

    checkUntilTimeout:
      conn.writes == @[highMsg, lowMsgs[0], lowMsgs[1]]

    check:
      not disconnectRequestedForTest[]
      peer.hasSendStream()

  asyncTest "Cancelling a queued relay drops it and leaves the other queued messages":
    let peer = createTestPeer(maxLow = 4)
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

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
      peer.cancelQueuedRelays([cancelledId].toHashSet()) == cancelledMsg.len
      peer.cancelQueuedRelays([cancelledId].toHashSet()) == 0
      peer.queuedBytes(Low) == keptMsg.len

    conn.releasePendingWrites()

    checkUntilTimeout:
      conn.writes == @[highMsg, keptMsg]

  asyncTest "An IDONTWANT in the peer history cancels a queued relay":
    let peer = createTestPeer(maxLow = 4)
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

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

    let noDuplicates = initHashSet[SaltedId]()
    check peer.cancelQueuedRelays(noDuplicates) == unwantedMsg.len
    check peer.queuedBytes(Low) == 0

    conn.releasePendingWrites()

    checkUntilTimeout:
      conn.writes == @[highMsg]

  asyncTest "Empty queues fast-path medium and low sends while returning completed futures":
    let mediumPeer = createTestPeer()
    let lowPeer = createTestPeer()
    let mediumConn = mediumPeer.stallSendStream()
    let lowConn = lowPeer.stallSendStream()
    defer:
      await mediumPeer.stopTasks()
      await lowPeer.stopTasks()

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
    let conn = peer.stallSendStream()
    defer:
      await conn.close()
      await peer.stopTasks()

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

suite "Priority queue byte budgets":
  teardown:
    checkTrackers()

  asyncTest "High byte limit accepts the boundary and disconnects on overflow":
    let disconnected = new bool
    let peer = createTestPeer(
      maxHigh = 10, maxOutboundBytes = 5, onEvent = newDisconnectRecorder(disconnected)
    )
    let conn = peer.stallSendStream()
    defer:
      await peer.stopTasks()
      await conn.close()

    await peer.sendEncoded(@[1'u8, 2], High)
    await peer.sendEncoded(@[3'u8, 4, 5], High)
    check:
      peer.queuedBytes(High) == 5
      conn.pendingWrites.len == 2
      not disconnected[]
    await peer.sendEncoded(@[6'u8], High)
    check:
      disconnected[]
      conn.pendingWrites.len == 2
      peer.slowPeerPenalty == 0.0
    await peer.stopTasks()
    check peer.queuedBytes(High) == 0

  asyncTest "One oversized valid frame is allowed when the queue is empty":
    for priority in [High, Medium, Low]:
      let disconnected = new bool
      let peer = createTestPeer(
        maxOutboundBytes = 2, onEvent = newDisconnectRecorder(disconnected)
      )
      let conn = peer.stallSendStream()
      await peer.sendEncoded(@[1'u8, 2, 3], priority)
      check:
        not disconnected[]
        conn.pendingWrites.len == 1
        peer.queuedBytes(High) == 3
      await peer.stopTasks()
      await conn.close()

  asyncTest "High-priority reservation limits non-high backlog":
    let peer = createTestPeer(maxHigh = 10, maxMedium = 10, maxOutboundBytes = 32)
    let conn = peer.stallSendStream()
    defer:
      await peer.stopTasks()
      await conn.close()

    await peer.sendEncoded(@[9'u8], High)
    await peer.sendEncoded(newSeq[byte](30), Medium)
    await sleepAsync(1.milliseconds)
    await peer.sendEncoded(@[1'u8], Medium)
    check:
      peer.queuedBytes(High) == 1
      peer.queuedBytes(Medium) == 30
      peer.slowPeerPenalty == 1.0

    await peer.sendEncoded(@[2'u8], High)
    check:
      peer.queuedBytes() == 32
      conn.pendingWrites.len == 2

  asyncTest "High evicts queued low then medium traffic":
    let peer =
      createTestPeer(maxHigh = 10, maxMedium = 10, maxLow = 10, maxOutboundBytes = 10)
    let conn = peer.stallSendStream()
    defer:
      await peer.stopTasks()
      await conn.close()

    await peer.sendEncoded(@[9'u8], High)
    await peer.sendEncoded(newSeq[byte](4), Low)
    await sleepAsync(1.milliseconds)
    await peer.sendEncoded(newSeq[byte](4), Low)
    await peer.sendEncoded(@[8'u8], Medium)
    await peer.sendEncoded(newSeq[byte](9), High)
    check:
      peer.queuedBytes(High) == 10
      peer.queuedBytes(Medium) == 0
      peer.queuedBytes(Low) == 0
      peer.slowPeerPenalty == 0.0
      conn.pendingWrites.len == 2

  asyncTest "Worker-held messages stay charged while waiting and writing":
    for priorityValue in [Medium, Low]:
      let priority = priorityValue
      let peer = createTestPeer(maxOutboundBytes = 16)
      let conn = peer.stallSendStream()
      await peer.sendEncoded(@[9'u8], High)
      await peer.sendEncoded(newSeq[byte](15), priority)
      await sleepAsync(1.milliseconds)
      check peer.queuedBytes(priority) == 15
      await peer.sendEncoded(@[4'u8], priority)
      check peer.slowPeerPenalty == 1.0

      conn.pendingWrites[0].complete()
      checkUntilTimeout:
        conn.pendingWrites.len == 2
      check:
        peer.queuedBytes(High) == 0
        peer.queuedBytes(priority) == 15
      await peer.sendEncoded(@[5'u8], priority)
      check:
        peer.slowPeerPenalty == 2.0
        conn.pendingWrites.len == 2
        peer.queuedBytes(priority) == 15

      conn.pendingWrites[1].complete()
      checkUntilTimeout:
        peer.queuedBytes(priority) == 0
      await peer.sendEncoded(@[6'u8], High)
      await peer.sendEncoded(newSeq[byte](15), priority)
      check peer.queuedBytes(priority) == 15
      await peer.stopTasks()
      for p in MessagePriority:
        check peer.queuedBytes(p) == 0
      await peer.stopTasks()
      await peer.sendEncoded(@[10'u8], priority)
      check peer.queuedBytes(priority) == 0
      await conn.close()

  asyncTest "Completed middle high sends release bytes before deque cleanup":
    let peer = createTestPeer(maxHigh = 10, maxOutboundBytes = 9)
    let conn = peer.stallSendStream()
    defer:
      await peer.stopTasks()
      await conn.close()
    for i in 0 ..< 3:
      await peer.sendEncoded(newSeq[byte](3), High)
    check peer.queuedBytes(High) == 9
    conn.pendingWrites[1].complete()
    checkUntilTimeout:
      peer.queuedBytes(High) == 6
    await peer.sendEncoded(newSeq[byte](3), High)
    check:
      conn.pendingWrites.len == 4
      peer.queuedBytes(High) == 9
      peer.hasSendStream()

  asyncTest "Failed writes and cancellation release all accounted bytes":
    let peer = createTestPeer()
    let conn = peer.stallSendStream()
    await peer.sendEncoded(@[1'u8, 2], High)
    await peer.sendEncoded(@[3'u8, 4, 5], Medium)
    await peer.sendEncoded(@[6'u8, 7, 8, 9], Low)
    await sleepAsync(1.milliseconds)
    await conn.close()
    checkUntilTimeout:
      peer.queuedBytes(High) == 0
    await peer.stopTasks()
    for priority in MessagePriority:
      check peer.queuedBytes(priority) == 0

  asyncTest "Messages waiting for stream setup are charged and released on stop":
    let peer = createTestPeer(maxOutboundBytes = 7)
    await peer.sendEncoded(@[1'u8, 2, 3], High)
    await peer.sendEncoded(@[4'u8, 5, 6, 7], Medium)
    await sleepAsync(1.milliseconds)
    check:
      peer.queuedBytes(High) == 3
      peer.queuedBytes(Medium) == 4
    await peer.sendEncoded(@[8'u8], Medium)
    check peer.slowPeerPenalty == 1.0
    await peer.stopTasks()
    for priority in MessagePriority:
      check peer.queuedBytes(priority) == 0

  test "Byte admission avoids addition overflow":
    let action = determineQueueAction(
      High,
      1,
      0,
      0,
      10,
      10,
      10,
      messageBytes = int.high,
      highPriorityQueueBytes = 1,
      maxOutboundQueueBytes = int.high,
    )
    check not action.send

suite "PubSubPeer sendResponse":
  teardown:
    checkTrackers()

  const topic = "🌞"

  asyncTest "sendResponse sends a fitting RPC as-is":
    let peer = createTestPeer(maxMessageSize = 4096)
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

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

    conn.releasePendingWrites()

  asyncTest "sendResponse sizes an anonymized RPC after anonymization":
    let msg = RPCMsg.withMessages(
      @[Message(data: @[1'u8, 2, 3], topic: topic, signature: newSeq[byte](200))]
    )
    let encoded = msg.encode(true)
    check msg.encodedSize() > encoded.len

    let peer = createTestPeer(maxMessageSize = encoded.len)
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

    peer.sendResponse(msg, true, MessagePriority.High)

    check:
      conn.writes.len == 1
      conn.writes[0] == encoded

    conn.releasePendingWrites()

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
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

    peer.sendResponse(fullMsg, false, MessagePriority.High)

    check:
      conn.writes.len == 2
      conn.writes[0] == firstBatch.encode(false)
      conn.writes[1] == RPCMsg(messages: @[m2]).encode(false)

    conn.releasePendingWrites()

  asyncTest "sendResponse drops an oversized message but still sends non-message fields":
    let
      control = ControlMessage(graft: @[ControlGraft(topicID: topic)])
      oversized = Message(data: newSeq[byte](200), topic: topic)
      controlOnly = RPCMsg(control: Opt.some(control))
      fullMsg = RPCMsg(control: Opt.some(control), messages: @[oversized])

    let peer = createTestPeer(maxMessageSize = controlOnly.encodedSize())
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

    peer.sendResponse(fullMsg, false, MessagePriority.High)

    check:
      conn.writes.len == 1
      conn.writes[0] == controlOnly.encode(false)

    conn.releasePendingWrites()

  asyncTest "sendResponse drops an oversized RPC with no messages":
    var grafts: seq[ControlGraft]
    for i in 0 ..< 20:
      grafts.add(ControlGraft(topicID: topic & $i))

    let
      control = ControlMessage(graft: grafts)
      msg = RPCMsg(control: Opt.some(control))
      maxSize = msg.encodedSize() - 1

    let peer = createTestPeer(maxMessageSize = maxSize)
    let conn = peer.stallSendStream(stallCount = 1)
    defer:
      await peer.stopTasks()
      await conn.close()

    peer.sendResponse(msg, false, MessagePriority.High)

    check conn.writes.len == 0

suite "Shared control and topic queue budgets":
  teardown:
    checkTrackers()

  proc topicState(peer: PubSubPeer, recorder: TopicStreamsRecorder): TopicStreams =
    let streams = TopicStreams.new(
      TopicStreamsConfig(),
      100,
      recorder.pendingDial(),
      recorder.receive(),
      recorder.violation(),
      recorder.penalize(),
      peer.outboundQueue,
    )
    doAssert streams.negotiate(makeRPC(ControlExtensions(topicStreams: Opt.some(true))))
    return streams

  asyncTest "control High and Medium evict queued topic Low frames":
    for priority in [High, Medium]:
      let peer = createTestPeer(maxOutboundBytes = 32)
      let conn = peer.stallSendStream()
      let recorder = TopicStreamsRecorder.new()
      let topics = peer.topicState(recorder)
      defer:
        await topics.stop()
        await conn.close()
        await peer.stopTasks()
      await peer.sendEncoded(@[1.byte], High)
      topics.sendTopic("a", newSeq[byte](20), Low)
      check peer.queuedBytes() == 24 # control, header, topic frame
      await peer.sendEncoded(newSeq[byte](25), priority)
      check:
        peer.queuedBytes() == 29
        peer.queuedBytes(Low) == 3 # retained topic header
        peer.slowPeerPenalty == 0

  asyncTest "topic traffic shares control-stream eviction and overflow policy":
    let peer = createTestPeer(maxOutboundBytes = 32)
    let conn = peer.stallSendStream()
    let recorder = TopicStreamsRecorder.new()
    let topics = peer.topicState(recorder)
    defer:
      await topics.stop()
      await conn.close()
      await peer.stopTasks()
    await peer.sendEncoded(@[1.byte], High)
    await peer.sendEncoded(newSeq[byte](25), Low)
    topics.sendTopic("a", newSeq[byte](20), Medium)
    check:
      peer.queuedBytes() == 24
      peer.queuedBytes(Low) == 0
      peer.queuedBytes(Medium) == 23
      peer.slowPeerPenalty == 0
    topics.sendTopic("a", newSeq[byte](9), Low)
    check:
      peer.queuedBytes() == 24
      peer.slowPeerPenalty == 1

  asyncTest "topic and control frames share each priority's count limit":
    for priority in [Medium, Low]:
      for topicFirst in [false, true]:
        let peer = createTestPeer(maxMedium = 1, maxLow = 1)
        let conn = peer.stallSendStream()
        let recorder = TopicStreamsRecorder.new()
        let topics = peer.topicState(recorder)
        defer:
          await topics.stop()
          await conn.close()
          await peer.stopTasks()
        await peer.sendEncoded(@[1.byte], High)
        if topicFirst:
          topics.sendTopic("a", @[2.byte], priority)
          await peer.sendEncoded(@[3.byte], priority)
        else:
          await peer.sendEncoded(@[2.byte], priority)
          topics.sendTopic("a", @[3.byte], priority)
        check peer.slowPeerPenalty == 1
        check peer.queuedBytes() == (if topicFirst: 5 else: 2)

  asyncTest "promoted topic frames remain charged and cannot be evicted":
    let disconnected = new bool
    let peer = createTestPeer(
      maxOutboundBytes = 4, onEvent = newDisconnectRecorder(disconnected)
    )
    let conn = peer.stallSendStream()
    let recorder = TopicStreamsRecorder.new()
    let topics = peer.topicState(recorder)
    defer:
      await topics.stop()
      await conn.close()
      await peer.stopTasks()
    topics.sendTopic("a", newSeq[byte](4), Low)
    check peer.queuedBytes(High) == 7
      # lone valid frame plus its header exceeds the budget
    await peer.sendEncoded(@[1.byte], High)
    check disconnected[]
    topics.sendTopic("b", @[1.byte], Low)
    check peer.queuedBytes() == 7

  asyncTest "completed topic writes leave room for control traffic at the minimum budget":
    let disconnected = new bool
    let peer = createTestPeer(
      maxMessageSize = 4,
      maxOutboundBytes = 8,
      onEvent = newDisconnectRecorder(disconnected),
    )
    let conn = peer.stallSendStream(stallCount = 0)
    let recorder = TopicStreamsRecorder.new()
    let topics =
      TopicStreams.new(recorder, maxMessageSize = 4, queue = peer.outboundQueue)
    check topics.negotiate(makeRPC(ControlExtensions(topicStreams: Opt.some(true))))
    defer:
      await topics.stop()
      await recorder.closeOutgoingStreams()
      await conn.close()
      await peer.stopTasks()
    let header = TopicRPCHeader(topic: Opt.some("ab")).encode()
    let frame = newSeq[byte](4)
    require header.len == 4
    topics.sendTopic("ab", frame, Low)
    check (await recorder.outgoingStreams[0].readLp(4)) == header
    check (await recorder.outgoingStreams[0].readLp(4)) == frame
    checkUntilTimeout:
      peer.queuedBytes() == header.len
    await peer.sendEncoded(frame, High)
    check:
      conn.writes == @[frame]
      not disconnected[]

  asyncTest "peer shutdown releases queued topic frames and retained headers":
    let peer = createTestPeer()
    peer.extensionsState =
      ExtensionsState.new(rng(), topicStreamsConfig = Opt.some(TopicStreamsConfig()))
    let recorder = TopicStreamsRecorder.new()
    let cleaningUp = newAsyncEvent()
    let releaseCleanup = newAsyncEvent()
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      try:
        await newAsyncEvent().wait()
      except CancelledError as exc:
        cleaningUp.fire()
        await noCancel releaseCleanup.wait()
        inc recorder.cancelledDials
        raise exc
      raiseAssert "pending dial only completes by cancellation"

    peer.extensionsState.initTopicStreams(
      peer.peerId,
      100,
      dial,
      recorder.receive(),
      recorder.violation(),
      peer.outboundQueue,
    )
    check peer.extensionsState.negotiateTopicStreams(
      peer.peerId, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
    )
    defer:
      await peer.stopTasks()
    for priority in [Low, Medium, Low]:
      peer.sendTopicRPC(
        makePreparedTopicRPC(
          RPCMsg.withMessages(Message(topic: "a", data: @[1.byte])), false
        ),
        priority,
      )
    check peer.queuedBytes() > 0
    let stopping = peer.stopTasks()
    await cleaningUp.wait()
    let stoppingAgain = peer.stopTasks()
    # Yield so an incorrectly completed second stop is observed before cleanup resumes.
    await sleepAsync(1.milliseconds)
    check:
      not stoppingAgain.finished
      peer.queuedBytes() > 0
    releaseCleanup.fire()
    await allFutures(stopping, stoppingAgain)
    check:
      peer.queuedBytes() == 0
      peer.outboundQueue.topicCounts == default(array[MessagePriority, int])
      peer.outboundQueue.evictableBytes == default(array[MessagePriority, int])
      recorder.cancelledDials == 1

  asyncTest "topic routing preserves explicit High priority and its overflow behavior":
    let disconnected = new bool
    let peer =
      createTestPeer(maxHigh = 2, onEvent = newDisconnectRecorder(disconnected))
    let conn = peer.stallSendStream()
    peer.extensionsState =
      ExtensionsState.new(rng(), topicStreamsConfig = Opt.some(TopicStreamsConfig()))
    let recorder = TopicStreamsRecorder.new()
    peer.extensionsState.initTopicStreams(
      peer.peerId,
      100,
      recorder.pendingDial(),
      recorder.receive(),
      recorder.violation(),
      peer.outboundQueue,
    )
    check peer.extensionsState.negotiateTopicStreams(
      peer.peerId, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
    )
    defer:
      await conn.close()
      await peer.stopTasks()
    await peer.sendEncoded(@[1.byte], High)
    let prepared = makePreparedTopicRPC(
      RPCMsg.withMessages(Message(topic: "a", data: @[1.byte])), false
    )
    peer.sendTopicRPC(prepared, High)
    check:
      peer.queuedBytes(Low) == 0
      peer.outboundQueue.topicCounts[High] == 1
    peer.sendTopicRPC(prepared, High)
    checkUntilTimeout:
      disconnected[]
    check peer.slowPeerPenalty == 0
