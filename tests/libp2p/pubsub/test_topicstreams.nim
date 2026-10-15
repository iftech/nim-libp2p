# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import ../../../libp2p/protocols/pubsub/topicstreams
import ../../../libp2p/protocols/pubsub/rpc/messages
import ../../../libp2p/stream/bridgestream
import ../../tools/unittest

suite "GossipSub topic stream wire format":
  test "full message reconstructs canonical signature input":
    let message = Message(
      data: @[1.byte, 2],
      topic: "topic",
      seqno: @[3.byte],
      signature: @[4.byte],
      key: @[5.byte],
    )
    let encoded = message.topicRPC(false).encode()
    let decoded = TopicRPC.decode(encoded).get()
    check decoded.publish.get().topic.isNone
    check decoded.toRPC("topic").get().messages[0] == message
    let anonymous = message.topicRPC(true).toRPC("topic").get().messages[0]
    check anonymous.signature.len == 0
    check anonymous.seqno.len == 0

  test "partial data and metadata-only requests restore topic":
    for partial in [
      PartialMessageExtensionRPC(
        topicID: Opt.some("topic"),
        groupID: Opt.some(@[1.byte]),
        partialMessage: Opt.some(@[2.byte]),
      ),
      PartialMessageExtensionRPC(
        topicID: Opt.some("topic"),
        groupID: Opt.some(@[1.byte]),
        partsMetadata: Opt.some(@[3.byte]),
      ),
    ]:
      let wire = partial.topicRPC().encode()
      let decoded = TopicRPC.decode(wire).get()
      check decoded.partial.get().topicID.isNone
      check decoded.toRPC("topic").get().partialMessageExtension.get() == partial

  test "reject empty, ambiguous, and topic-bearing payloads":
    check TopicRPC().toRPC("topic").isErr
    check TopicRPC(
      publish: Opt.some(TopicScopedMessage(data: @[1.byte])),
      partial: Opt.some(PartialMessageExtensionRPC()),
    ).toRPC("topic").isErr
    check TopicRPC(publish: Opt.some(TopicScopedMessage())).toRPC("topic").isErr
    check TopicRPC(
      publish: Opt.some(TopicScopedMessage(data: @[1.byte], topic: Opt.some("")))
    ).toRPC("topic").isErr
    check TopicRPC(partial: Opt.some(PartialMessageExtensionRPC(topicID: Opt.some("")))).toRPC(
      "topic"
    ).isErr

suite "GossipSub topic stream lifecycle":
  teardown:
    checkTrackers()

  asyncTest "independent topic writers, replacement, and bounded queue":
    var remotes: seq[Stream]
    var penalties = 0
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      let (local, remote) = bridgedConnections()
      remotes.add(remote)
      return local

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      discard

    proc violation() {.gcsafe, raises: [].} =
      discard

    proc penalize() {.gcsafe, raises: [].} =
      inc penalties

    let state = TopicStreams.new(
      TopicStreamsConfig(maxQueuedBytes: 128), 1024, dial, receive, violation, penalize
    )
    state.active = true
    defer:
      await state.stop()
      for remote in remotes:
        await remote.close()
    let payload = Message(data: @[1.byte], topic: "a").topicRPC(false).encode()
    state.sendTopic("a", payload, true)
    state.sendTopic("b", payload, true)
    check remotes.len == 2
    # Reading b does not depend on consuming a's application payload.
    let headerB = await remotes[1].readLp(1024)
    let payloadB = await remotes[1].readLp(1024)
    check TopicRPCHeader.decode(headerB).get().topic.get() == "b"
    check TopicRPC.decode(payloadB).isOk
    state.sendTopic("a", newSeq[byte](129), true)
    check penalties == 0
    await state.closeTopic("a")
    state.sendTopic("a", payload, true)
    check remotes.len == 3
    let headerA = await remotes[2].readLp(1024)
    let payloadA = await remotes[2].readLp(1024)
    check TopicRPCHeader.decode(headerA).get().topic.get() == "a"
    check TopicRPC.decode(payloadA).isOk

  asyncTest "early inbound stream infers support, contradictory control is rejected":
    var received = newFuture[RPCMsg]()
    var violations = 0
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "unused")

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      received.complete(msg)

    proc violation() {.gcsafe, raises: [].} =
      inc violations

    proc penalize() {.gcsafe, raises: [].} =
      discard

    let state =
      TopicStreams.new(TopicStreamsConfig(), 1024, dial, receive, violation, penalize)
    let (sender, receiver) = bridgedConnections()
    let task = state.readTopic(receiver)
    defer:
      await state.stop()
      await sender.close()
      await task.cancelAndWait()
    await sender.writeLp(TopicRPCHeader(topic: Opt.some("early")).encode())
    await sender.writeLp(
      Message(data: @[9.byte], topic: "early").topicRPC(false).encode()
    )
    let rpc = await received.wait(1.seconds)
    check rpc.messages[0].topic == "early"
    check state.active
    check not state.negotiate(
      RPCMsg.withControl(ControlMessage.withExtensions(ControlExtensions()))
    )
    check violations == 1

  asyncTest "legacy fallback and control stream payload rejection":
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "unused")

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      discard

    var violations = 0
    proc violation() {.gcsafe, raises: [].} =
      inc violations

    proc penalize() {.gcsafe, raises: [].} =
      discard

    let legacy =
      TopicStreams.new(TopicStreamsConfig(), 1024, dial, receive, violation, penalize)
    check legacy.negotiate(RPCMsg())
    check not legacy.active
    await legacy.stop()
    let modern =
      TopicStreams.new(TopicStreamsConfig(), 1024, dial, receive, violation, penalize)
    check modern.negotiate(
      RPCMsg.withControl(
        ControlMessage.withExtensions(ControlExtensions(topicStreams: Opt.some(true)))
      )
    )
    check not modern.negotiate(
      RPCMsg.withMessages(Message(topic: "t", data: @[1.byte]))
    )
    check violations == 1
    await modern.stop()

  asyncTest "accept three inbound streams per topic and reset the fourth":
    var penalties = 0
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "unused")

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      discard

    proc violation() {.gcsafe, raises: [].} =
      discard

    proc penalize() {.gcsafe, raises: [].} =
      inc penalties

    let state =
      TopicStreams.new(TopicStreamsConfig(), 1024, dial, receive, violation, penalize)
    var senders: seq[Stream]
    var tasks: seq[Future[void]]
    defer:
      await state.stop()
      for sender in senders:
        await sender.close()
      await allFutures(tasks.mapIt(it.cancelAndWait()))
    for i in 0 .. 3:
      let (sender, receiver) = bridgedConnections()
      senders.add(sender)
      tasks.add(state.readTopic(receiver))
      await sender.writeLp(TopicRPCHeader(topic: Opt.some("same")).encode())
    checkUntilTimeout:
      tasks[3].finished
    check penalties == 1
    for i in 0 .. 2:
      check not tasks[i].finished

  asyncTest "incoming byte budget is shared and released after cancellation":
    var penalties = 0
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "unused")

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      discard

    proc violation() {.gcsafe, raises: [].} =
      discard

    proc penalize() {.gcsafe, raises: [].} =
      inc penalties

    let state = TopicStreams.new(
      TopicStreamsConfig(maxIncomingBytes: 32), 1024, dial, receive, violation, penalize
    )
    var senders: seq[Stream]
    var tasks: seq[Future[void]]
    defer:
      await state.stop()
      for sender in senders:
        await sender.close()
      await allFutures(tasks.mapIt(it.cancelAndWait()))
    for i in 0 .. 1:
      let (sender, receiver) = bridgedConnections()
      senders.add(sender)
      tasks.add(state.readTopic(receiver))
      await sender.writeLp(TopicRPCHeader(topic: Opt.some($i)).encode())
    # The first reader reserves 24 bytes but receives no body.
    await senders[0].write(@[24.byte])
    await senders[1].write(@[24.byte])
    checkUntilTimeout:
      tasks[1].finished
    check penalties == 1
    await tasks[0].cancelAndWait()
    let (sender, receiver) = bridgedConnections()
    senders.add(sender)
    tasks.add(state.readTopic(receiver))
    await sender.writeLp(TopicRPCHeader(topic: Opt.some("again")).encode())
    await sender.write(@[24.byte])
    # Yield so the reader reserves the frame body before the negative check.
    await sleepAsync(1.milliseconds)
    check not tasks[2].finished
    check penalties == 1

  asyncTest "pending headers consume stream slots and time out":
    var penalties = 0
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      raise newException(LPStreamError, "unused")

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      discard

    proc violation() {.gcsafe, raises: [].} =
      discard

    proc penalize() {.gcsafe, raises: [].} =
      inc penalties

    let state = TopicStreams.new(
      TopicStreamsConfig(maxStreams: 3), 1024, dial, receive, violation, penalize
    )
    var senders: seq[Stream]
    var tasks: seq[Future[void]]
    defer:
      await state.stop()
      for sender in senders:
        await sender.close()
      await allFutures(tasks.mapIt(it.cancelAndWait()))
    for i in 0 .. 3:
      let (sender, receiver) = bridgedConnections()
      senders.add(sender)
      tasks.add(state.readTopic(receiver))
    check tasks[3].finished
    check penalties == 1
    await allFutures(tasks).wait(2.seconds)

  asyncTest "responder cannot send application bytes on an outgoing topic stream":
    let (sender, receiver) = bridgedConnections()
    var violations = 0
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      return sender

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      discard

    proc violation() {.gcsafe, raises: [].} =
      inc violations

    proc penalize() {.gcsafe, raises: [].} =
      discard

    let state =
      TopicStreams.new(TopicStreamsConfig(), 1024, dial, receive, violation, penalize)
    state.active = true
    defer:
      await state.stop()
      await receiver.close()
    state.sendTopic("one-way", Message(data: @[1.byte]).topicRPC(false).encode(), true)
    discard await receiver.readLp(1024)
    await receiver.write(@[1.byte])
    checkUntilTimeout:
      violations == 1

  asyncTest "pending dials share send budgets and cancellation releases reservations":
    for config in [
      TopicStreamsConfig(maxQueuedBytes: 128),
      TopicStreamsConfig(maxQueuedMessages: 2),
      TopicStreamsConfig(maxStreams: 3),
    ]:
      var dialCalls, penalties: int
      proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
        inc dialCalls
        await sleepAsync(10.seconds)
        raise newException(LPStreamError, "unused")

      proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
        discard

      proc violation() {.gcsafe, raises: [].} =
        discard

      proc penalize() {.gcsafe, raises: [].} =
        inc penalties

      let state = TopicStreams.new(config, 1024, dial, receive, violation, penalize)
      state.active = true
      let accepted = if config.maxStreams == 3: 3 else: 2
      for i in 0 .. accepted:
        state.sendTopic($i, newSeq[byte](40), true)
      check dialCalls == accepted
      check penalties == 0
      await state.closeTopic("0")
      state.sendTopic("0", newSeq[byte](40), true)
      check dialCalls == accepted + 1
      check penalties == 0
      await state.stop()
