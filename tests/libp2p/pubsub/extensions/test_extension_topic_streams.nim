# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import ../../../../libp2p/protocols/pubsub/gossipsub/extension_topic_streams
import ../../../../libp2p/protocols/pubsub/rpc/messages
import ../../../../libp2p/stream/bridgestream
import ../../../tools/[unittest, bufferstream]
import ../converters
import ./extension_recording

const topic = "foobar"

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
        topicID: "topic", groupID: @[1.byte], partialMessage: @[2.byte]
      ),
      PartialMessageExtensionRPC(
        topicID: "topic", groupID: @[1.byte], partsMetadata: @[3.byte]
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
    check TopicRPC(publish: Opt.some(TopicScopedMessage(data: @[1.byte], topic: ""))).toRPC(
      "topic"
    ).isErr
    check TopicRPC(partial: Opt.some(PartialMessageExtensionRPC(topicID: ""))).toRPC(
      "topic"
    ).isErr

suite "GossipSub topic stream negotiation":
  teardown:
    checkTrackers()

  let subscription = RPCMsg.withSubscriptions(@[SubOpts(topic: topic, subscribe: true)])

  test "application payload on control stream is a protocol violation only after the peer advertised support":
    for (first, isSupported, expectedViolations) in [
      (subscription, false, 0), # peer without extensions
      (makeRPC(ControlExtensions(topicStreams: Opt.none(bool))), false, 0),
        # peer with other extensions only
      (makeRPC(ControlExtensions(topicStreams: false)), false, 0),
        # peer that denies topic streams
      (makeRPC(ControlExtensions(topicStreams: true)), true, 1),
        # peer that advertises topic streams
    ]:
      for payload in [
        RPCMsg.withMessages(Message(data: @[1.byte], topic: topic)), # message
        RPCMsg(
          partialMessageExtension: Opt.some(PartialMessageExtensionRPC(topicID: topic))
        ), # partial message
      ]:
        let recorder = TopicStreamsRecorder.new()
        let state = TopicStreams.new(recorder)
        check:
          state.negotiate(first)
          state.isActive() == isSupported
          state.negotiate(payload) == not isSupported
          recorder.violations == expectedViolations

  asyncTest "topic stream opened before the first control RPC requires that RPC to advertise support":
    for (first, isSupported, expectedViolations) in [
      (makeRPC(ControlExtensions(topicStreams: true)), true, 0),
        # advertises topic streams
      (subscription, false, 1), # denies support after opening the topic stream
    ]:
      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(recorder)
      let (remote, local) = bridgedConnections()
      # the peer opens a topic stream first, so we assume it supports topic streams
      let reading = state.readTopic(local)
      defer:
        await reading.cancelAndWait()
        await state.stop()
        await remote.close()

      # the peer publishes on it before its first control RPC arrives
      await remote.writeLp(TopicRPCHeader(topic: topic).encode())
      await remote.writeLp(Message(data: @[1.byte], topic: topic).topicRPC().encode())
      discard await recorder.received.popFirst()
      check:
        state.negotiate(first) == isSupported
        state.isActive() == isSupported
        recorder.violations == expectedViolations

suite "GossipSub topic stream lifecycle":
  teardown:
    checkTrackers()

  asyncTest "independent topic writers, replacement, and bounded queue":
    let recorder = TopicStreamsRecorder.new()
    let state =
      TopicStreams.new(recorder, TopicStreamsConfig(maxStreams: 3, maxQueuedBytes: 128))
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    defer:
      await state.stop()
      await recorder.closeOutgoingStreams()

    let payload = Message(data: @[1.byte], topic: "a").topicRPC().encode()
    state.sendTopic("a", payload, true)
    state.sendTopic("b", payload, true)
    check recorder.outgoingStreams.len == 2

    # Reading b does not depend on consuming a's application payload.
    let headerB = await recorder.outgoingStreams[1].readLp(1024)
    let payloadB = await recorder.outgoingStreams[1].readLp(1024)
    check TopicRPCHeader.decode(headerB).get().topic.get() == "b"
    check TopicRPC.decode(payloadB).isOk

    state.sendTopic("c", payload, true)
    check recorder.outgoingStreams.len == 3
    let (incoming, incomingStream) = bridgedConnections()
    defer:
      await incoming.close()
    await state.readTopic(incomingStream)
    state.sendTopic("a", newSeq[byte](129), true)
    check recorder.penalties == 0

    await state.closeTopic("a")
    state.sendTopic("a", payload, true)
    check recorder.outgoingStreams.len == 4
    let headerA = await recorder.outgoingStreams[3].readLp(1024)
    let payloadA = await recorder.outgoingStreams[3].readLp(1024)
    check TopicRPCHeader.decode(headerA).get().topic.get() == "a"
    check TopicRPC.decode(payloadA).isOk

    check not state.negotiate(makeRPC(ControlExtensions(topicStreams: Opt.none(bool))))
    check not state.isActive()

    var data: byte
    check (await recorder.outgoingStreams[3].readOnce(addr data, 1)) == 0

  asyncTest "closing a pending writer cancels its dial and releases queue capacity":
    let recorder = TopicStreamsRecorder.new()
    let payload = Message(data: @[1.byte], topic: "a").topicRPC().encode()
    let state = TopicStreams.new(
      TopicStreamsConfig(
        maxQueuedBytes: TopicRPCHeader(topic: "a").encode().len + payload.len,
        maxQueuedMessages: 1,
      ),
      1024,
      recorder.pendingDial(),
      recorder.receive(),
      recorder.violation(),
      recorder.penalize(),
    )
    defer:
      await state.stop()
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    state.sendTopic("a", payload, true)
    await state.closeTopic("a")
    check recorder.cancelledDials == 1

    state.sendTopic("b", payload, true)
    await state.stop()
    check:
      recorder.cancelledDials == 2
      recorder.penalties == 0
      recorder.violations == 0

  asyncTest "reader errors release streams and preserve violation handling":
    for scenario in 0 .. 6:
      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(recorder, maxMessageSize = 32)
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
        await remote.writeLp(TopicRPCHeader(topic: "a").encode())
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
      check:
        local.closed()
        recorder.received.len == 0
        recorder.penalties == (if scenario in [0, 4]: 1 else: 0)
        recorder.violations == (if scenario in [5, 6]: 1 else: 0)

  asyncTest "fourth reader for a topic is rejected and stop closes the others":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
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
      await remote.writeLp(TopicRPCHeader(topic: "a").encode())
      if i < 3:
        await remote.writeLp(Message(data: @[1.byte], topic: "a").topicRPC().encode())
        discard await recorder.received.popFirst()
      else:
        await readers[i]
        check local.closed()

    check:
      recorder.penalties == 1
      recorder.violations == 0
    await state.stop()
    for remote in remotes:
      var data: byte
      check (await remote.readOnce(addr data, 1)) == 0

suite "GossipSub topic stream send side":
  teardown:
    checkTrackers()

  let header = TopicRPCHeader(topic: topic).encode()

  asyncTest "frame over the maximum message size is dropped":
    # the header must fit under the same limit
    let maxMessageSize = header.len
    for (frameSize, expectedDials) in [
      (maxMessageSize, 1), # largest frame the peer accepts
      (maxMessageSize + 1, 0), # frame the peer would penalize
    ]:
      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(recorder, maxMessageSize = maxMessageSize)
      defer:
        await state.stop()
        await recorder.closeOutgoingStreams()
      check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

      state.sendTopic(topic, newSeq[byte](frameSize), true)
      check:
        recorder.outgoingStreams.len == expectedDials
        recorder.penalties == 0
        recorder.violations == 0

  asyncTest "queue budgets count the frame in flight until its write completes":
    let frames = [@[1.byte], @[2.byte], @[3.byte], @[4.byte]]
    for config in [
      # the header, frames[0] in flight and frames[1] queued fill the byte budget
      TopicStreamsConfig(maxQueuedBytes: header.len + frames[0].len + frames[1].len),
      # frames[0] in flight and frames[1] queued fill the message budget
      TopicStreamsConfig(maxQueuedMessages: 2),
    ]:
      let written = newAsyncQueue[seq[byte]]()
      let frameWritten = newAsyncEvent()
      proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
        return TestBufferStream.new(
          proc(
              data: sink seq[byte]
          ) {.async: (raises: [CancelledError, LPStreamError]).} =
            let frame = data[1 ..^ 1] # without the 1-byte length prefix
            await written.put(frame)
            if frame == frames[0]:
              await frameWritten.wait()
        )

      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(
        config,
        1024,
        dial,
        recorder.receive(),
        recorder.violation(),
        recorder.penalize(),
      )
      defer:
        await state.stop()
      check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

      state.sendTopic(topic, frames[0], true) # in flight until frameWritten fires
      state.sendTopic(topic, frames[1], true) # queued behind frames[0]
      check:
        (await written.popFirst()) == header
        (await written.popFirst()) == frames[0]
        written.len == 0

      state.sendTopic(topic, frames[2], true) # dropped: the budget is full
      frameWritten.fire() # frames[0]'s write completes and releases its budget
      check (await written.popFirst()) == frames[1]

      state.sendTopic(topic, frames[3], true) # accepted: the budget has room again
      check:
        (await written.popFirst()) == frames[3]
        recorder.penalties == 0
        recorder.violations == 0

suite "GossipSub topic stream receive side":
  teardown:
    checkTrackers()

  let header = TopicRPCHeader(topic: topic).encode()
  let message = Message(data: @[1.byte], topic: topic)
  let frame = message.topicRPC().encode()

  asyncTest "reader delivers one more frame after a protocol violation":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
    let (peerEnd, nodeEnd) = bridgedConnections()
    let reader = state.readTopic(nodeEnd)
    defer:
      await reader.cancelAndWait()
      await state.stop()
      await peerEnd.close()

    await peerEnd.writeLp(header)
    await peerEnd.writeLp(frame)
    check (await recorder.received.popFirst()).messages == @[message]

    # reader now waits for its next frame, past its check for a stopped transport
    # the peer opened a topic stream, so denying support is a protocol violation
    check:
      not state.negotiate(makeRPC(ControlExtensions(topicStreams: false)))
      recorder.violations == 1

    await peerEnd.writeLp(frame)
    # TODO: iftech/nim-libp2p#3403
    check (await recorder.received.popFirst()).messages == @[message]
    await reader # ends on its own after the frame, without the peer closing the stream
