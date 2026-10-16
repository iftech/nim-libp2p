# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import ../../../../libp2p/protocols/pubsub/gossipsub/extension_topic_streams
import ../../../../libp2p/protocols/pubsub/rpc/messages
import ../../../../libp2p/stream/bridgestream
import ../../../tools/unittest

suite "GossipSub topic stream wire format":
  test "full message reconstructs canonical signature input":
    let message = Message(
      data: @[1.byte, 2],
      topic: "topic",
      seqno: @[3.byte],
      signature: @[4.byte],
      key: @[5.byte],
    )
    let encoded = message.topicRPC().encode()
    let decoded = TopicRPC.decode(encoded).get()
    check decoded.publish.get().topic.isNone
    check decoded.toRPC("topic").get().messages[0] == message
    let anonymous = message.anonymize(true).topicRPC().toRPC("topic").get().messages[0]
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
      TopicStreamsConfig(maxStreams: 3, maxQueuedBytes: 128),
      1024,
      dial,
      receive,
      violation,
      penalize,
    )
    check state.negotiate(
      RPCMsg.withControl(
        ControlMessage.withExtensions(ControlExtensions(topicStreams: Opt.some(true)))
      )
    )

    defer:
      await state.stop()
      for remote in remotes:
        await remote.close()

    let payload = Message(data: @[1.byte], topic: "a").topicRPC().encode()
    state.sendTopic("a", payload, true)
    state.sendTopic("b", payload, true)
    check remotes.len == 2

    # Reading b does not depend on consuming a's application payload.
    let headerB = await remotes[1].readLp(1024)
    let payloadB = await remotes[1].readLp(1024)
    check TopicRPCHeader.decode(headerB).get().topic.get() == "b"
    check TopicRPC.decode(payloadB).isOk

    state.sendTopic("c", payload, true)
    check remotes.len == 3
    let (incoming, incomingStream) = bridgedConnections()
    defer:
      await incoming.close()
    await state.readTopic(incomingStream)
    state.sendTopic("a", newSeq[byte](129), true)
    check penalties == 0

    await state.closeTopic("a")
    state.sendTopic("a", payload, true)
    check remotes.len == 4
    let headerA = await remotes[3].readLp(1024)
    let payloadA = await remotes[3].readLp(1024)
    check TopicRPCHeader.decode(headerA).get().topic.get() == "a"
    check TopicRPC.decode(payloadA).isOk

    check not state.negotiate(
      RPCMsg.withControl(ControlMessage.withExtensions(ControlExtensions()))
    )
    check not state.isActive()

    var data: byte
    check (await remotes[3].readOnce(addr data, 1)) == 0

  asyncTest "closing a pending writer cancels its dial and releases queue capacity":
    let pending = newAsyncEvent()
    var cancelled = 0
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      try:
        await pending.wait()
      except CancelledError as exc:
        inc cancelled
        raise exc
      return nil

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      discard

    proc unexpected() {.gcsafe, raises: [].} =
      raiseAssert "closing a writer must not penalize the peer"

    let payload = Message(data: @[1.byte], topic: "a").topicRPC().encode()
    let state = TopicStreams.new(
      TopicStreamsConfig(
        maxQueuedBytes: TopicRPCHeader(topic: Opt.some("a")).encode().len + payload.len,
        maxQueuedMessages: 1,
      ),
      1024,
      dial,
      receive,
      unexpected,
      unexpected,
    )
    defer:
      await state.stop()
    check state.negotiate(
      RPCMsg.withControl(
        ControlMessage.withExtensions(ControlExtensions(topicStreams: Opt.some(true)))
      )
    )

    state.sendTopic("a", payload, true)
    await state.closeTopic("a")
    check cancelled == 1

    state.sendTopic("b", payload, true)
    await state.stop()
    check cancelled == 2

  asyncTest "reader errors release streams and preserve violation handling":
    for scenario in 0 .. 6:
      var violations, penalties = 0
      proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
        return nil

      proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
        raiseAssert "invalid frames must not reach the receiver"

      proc violation() {.gcsafe, raises: [].} =
        inc violations

      proc penalize() {.gcsafe, raises: [].} =
        inc penalties

      let state =
        TopicStreams.new(TopicStreamsConfig(), 32, dial, receive, violation, penalize)
      let (remote, local) = bridgedConnections()
      let reading = state.readTopic(local)
      defer:
        await reading.cancelAndWait()
        await state.stop()
        await remote.close()

      case scenario
      of 0: # Oversized header.
        await remote.write(@[33.byte])
      of 1: # Truncated header.
        await remote.write(@[2.byte, 10])
        await remote.close()
      else:
        await remote.writeLp(TopicRPCHeader(topic: Opt.some("a")).encode())
        case scenario
        of 2: # EOF while reading a frame length.
          await remote.close()
        of 3: # Truncated frame body.
          await remote.write(@[2.byte, 10])
          await remote.close()
        of 4: # Oversized frame.
          await remote.write(@[33.byte])
        of 5: # Empty frame.
          await remote.write(@[0.byte])
        else: # Malformed protobuf payload.
          await remote.writeLp(@[255.byte])

      await reading
      check local.closed()
      check penalties == (if scenario in [0, 4]: 1 else: 0)
      check violations == (if scenario in [5, 6]: 1 else: 0)

  asyncTest "fourth reader for a topic is rejected and stop closes the others":
    var penalties = 0
    let received = newAsyncEvent()
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      return nil

    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      received.fire()

    proc violation() {.gcsafe, raises: [].} =
      raiseAssert "concurrent topic readers must not cause a protocol violation"

    proc penalize() {.gcsafe, raises: [].} =
      inc penalties

    let state =
      TopicStreams.new(TopicStreamsConfig(), 1024, dial, receive, violation, penalize)
    var remotes: seq[Stream]
    var readers: seq[Future[void]]
    defer:
      await state.stop()
      for reader in readers:
        await reader.cancelAndWait()
      for remote in remotes:
        await remote.close()

    for i in 0 .. 3:
      let (remote, local) = bridgedConnections()
      remotes.add(remote)
      readers.add(state.readTopic(local))
      await remote.writeLp(TopicRPCHeader(topic: Opt.some("a")).encode())
      if i < 3:
        await remote.writeLp(Message(data: @[1.byte], topic: "a").topicRPC().encode())
        await received.wait()
        received.clear()
      else:
        await readers[i]
        check local.closed()

    check penalties == 1
    await state.stop()
    await allFutures(readers)
    for remote in remotes:
      var data: byte
      check (await remote.readOnce(addr data, 1)) == 0
