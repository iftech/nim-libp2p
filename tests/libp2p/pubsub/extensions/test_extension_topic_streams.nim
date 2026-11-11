# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, results
import ../../../../libp2p/protocols/pubsub/gossipsub/extension_topic_streams
import ../../../../libp2p/protocols/pubsub/rpc/messages
import ../../../../libp2p/stream/bridgestream
import ../../../tools/[unittest, bufferstream]
import ../converters
import ./extension_recording

const
  topic = "foobar"
  otherTopic = "other"

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

  asyncTest "stop closes every reader stream":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
    var peerEnds: seq[Stream]
    var readers: seq[Future[void]]
    defer:
      await state.stop()
      await allFutures(readers.mapIt(it.cancelAndWait()))
      await allFutures(peerEnds.mapIt(it.close()))

    for _ in 0 ..< 3: # the peer opens three topic streams
      let (peerEnd, nodeEnd) = bridgedConnections()
      peerEnds.add(peerEnd)
      readers.add(state.readTopic(nodeEnd))
      await peerEnd.writeLp(TopicRPCHeader(topic: topic).encode())
      await peerEnd.writeLp(Message(data: @[1.byte], topic: topic).topicRPC().encode())
      discard await recorder.received.popFirst()

    await state.stop()
    for peerEnd in peerEnds:
      var data: byte
      check (await peerEnd.readOnce(addr data, 1)) == 0

suite "GossipSub topic stream send side":
  teardown:
    checkTrackers()

  let header = TopicRPCHeader(topic: topic).encode()
  let frames = [@[1.byte], @[2.byte], @[3.byte], @[4.byte]]

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

  asyncTest "frame for a new topic is dropped while readers and writers fill maxStreams":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder, TopicStreamsConfig(maxStreams: 3))
    var peerEnds: seq[Stream]
    var readers: seq[Future[void]]
    defer:
      await state.stop()
      await allFutures(readers.mapIt(it.cancelAndWait()))
      await allFutures(peerEnds.mapIt(it.close()))
      await recorder.closeOutgoingStreams()
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    state.sendTopic(topic, frames[0], true) # opens our writer for topic
    for _ in 0 ..< 2: # the peer opens two topic streams
      let (peerEnd, nodeEnd) = bridgedConnections()
      peerEnds.add(peerEnd)
      readers.add(state.readTopic(nodeEnd))

    # TODO: iftech/nim-libp2p#3406
    state.sendTopic(otherTopic, frames[1], true) # dropped: no stream left to open
    state.sendTopic(topic, frames[2], true) # written on the open writer
    check:
      recorder.outgoingStreams.len == 1
      (await recorder.outgoingStreams[0].readLp(1024)) == header
      (await recorder.outgoingStreams[0].readLp(1024)) == frames[0]
      (await recorder.outgoingStreams[0].readLp(1024)) == frames[2]

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

  asyncTest "stream over maxStreams is reset, and penalized only when readers alone fill maxStreams":
    for (writerCount, readerCount, expectedPenalties) in [
      (0, 3, 1), # readers still waiting for their header fill the limit
      # TODO: iftech/nim-libp2p#3406
      (1, 2, 0), # our writer for topic counts toward the limit
    ]:
      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(recorder, TopicStreamsConfig(maxStreams: 3))
      var peerEnds: seq[Stream]
      var readers: seq[Future[void]]
      defer:
        await state.stop()
        await noCancel allFutures(readers.mapIt(it.cancelAndWait()))
        await noCancel allFutures(peerEnds.mapIt(it.close()))
        await recorder.closeOutgoingStreams()
      check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

      for _ in 0 ..< writerCount:
        state.sendTopic(topic, frame, true)
      for _ in 0 ..< readerCount:
        let (peerEnd, nodeEnd) = bridgedConnections()
        peerEnds.add(peerEnd)
        readers.add(state.readTopic(nodeEnd))

      let (peerEnd, nodeEnd) = bridgedConnections()
      peerEnds.add(peerEnd)
      # without this header, an accepted stream would also end at the header timeout
      await peerEnd.writeLp(header)
      await state.readTopic(nodeEnd)
      check:
        nodeEnd.wasResetLocally()
        recorder.penalties == expectedPenalties
        recorder.violations == 0

  asyncTest "fourth open stream for a topic is reset and penalized":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
    var peerEnds: seq[Stream]
    var readers: seq[Future[void]]
    defer:
      await state.stop()
      await allFutures(readers.mapIt(it.cancelAndWait()))
      await allFutures(peerEnds.mapIt(it.close()))

    for _ in 0 ..< 3: # the peer opens three streams for topic
      let (peerEnd, nodeEnd) = bridgedConnections()
      peerEnds.add(peerEnd)
      readers.add(state.readTopic(nodeEnd))
      await peerEnd.writeLp(header)
      await peerEnd.writeLp(frame)
      check (await recorder.received.popFirst()).messages == @[message]

    let (fourthPeerEnd, fourthNodeEnd) = bridgedConnections()
    peerEnds.add(fourthPeerEnd)
    await fourthPeerEnd.writeLp(header)
    await state.readTopic(fourthNodeEnd)
    check:
      fourthNodeEnd.wasResetLocally()
      recorder.penalties == 1
      recorder.violations == 0

    # the limit counts streams per topic, so another topic is still accepted
    let (otherPeerEnd, otherNodeEnd) = bridgedConnections()
    peerEnds.add(otherPeerEnd)
    readers.add(state.readTopic(otherNodeEnd))
    await otherPeerEnd.writeLp(TopicRPCHeader(topic: otherTopic).encode())
    await otherPeerEnd.writeLp(frame)
    check (await recorder.received.popFirst()).messages ==
      @[Message(data: message.data, topic: otherTopic)]

    await peerEnds[0].close() # frees a slot for topic once its reader ends
    await readers[0]
    let (replacementPeerEnd, replacementNodeEnd) = bridgedConnections()
    peerEnds.add(replacementPeerEnd)
    readers.add(state.readTopic(replacementNodeEnd))
    await replacementPeerEnd.writeLp(header)
    await replacementPeerEnd.writeLp(frame)
    check (await recorder.received.popFirst()).messages == @[message]

  asyncTest "incoming budget counts the frame until receive returns":
    let recorder = TopicStreamsRecorder.new()
    let frameReceived = newAsyncEvent()
    proc receive(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
      await recorder.received.put(msg)
      await frameReceived.wait()

    let state = TopicStreams.new(
      # the headers of two streams and one frame fill the budget
      TopicStreamsConfig(maxIncomingBytes: 2 * header.len + frame.len),
      1024,
      recorder.dial(),
      receive,
      recorder.violation(),
      recorder.penalize(),
    )
    var peerEnds: seq[Stream]
    var readers: seq[Future[void]]
    defer:
      await state.stop()
      await allFutures(readers.mapIt(it.cancelAndWait()))
      await allFutures(peerEnds.mapIt(it.close()))

    for _ in 0 ..< 2: # the peer opens two topic streams
      let (peerEnd, nodeEnd) = bridgedConnections()
      peerEnds.add(peerEnd)
      readers.add(state.readTopic(nodeEnd))
      await peerEnd.writeLp(header)

    await peerEnds[0].writeLp(frame) # in receive until frameReceived fires
    check (await recorder.received.popFirst()).messages == @[message]
    await peerEnds[1].writeLp(frame) # penalized: the budget is full
    await readers[1]
    check:
      recorder.penalties == 1
      recorder.violations == 0

    frameReceived.fire() # receive returns and releases the frame's bytes
    let (peerEnd, nodeEnd) = bridgedConnections()
    peerEnds.add(peerEnd)
    readers.add(state.readTopic(nodeEnd))
    await peerEnd.writeLp(header)
    await peerEnd.writeLp(frame) # accepted: the budget has room again
    check (await recorder.received.popFirst()).messages == @[message]
