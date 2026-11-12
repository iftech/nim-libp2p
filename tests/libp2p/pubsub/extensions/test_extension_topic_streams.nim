# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils]
import chronos, results
import ../../../../libp2p/protocols/pubsub/gossipsub/extension_topic_streams
import ../../../../libp2p/protocols/pubsub/rpc/messages
import ../../../../libp2p/stream/[bridgestream, bufferstream]
import ../../../tools/[unittest, bufferstream, metrics_utils]
import ../converters
import ./extension_recording

type ReadSignallingStream = ref object of BufferStream
  reads: AsyncQueue[int]

method readOnce(
    s: ReadSignallingStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  let reading = procCall BufferStream(s).readOnce(pbytes, nbytes)
  await s.reads.addLast(nbytes)
  return await reading

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
    let state = TopicStreams.new(
      recorder, TopicStreamsConfig(maxOutgoingStreams: 3, maxQueuedBytes: 128)
    )
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    defer:
      await state.stop()
      await recorder.closeOutgoingStreams()

    let payload = Message(data: @[1.byte], topic: "a").topicRPC().encode()
    check state.sendTopic("a", payload, true)
    check state.sendTopic("b", payload, true)
    check recorder.outgoingStreams.len == 2

    # Reading b does not depend on consuming a's application payload.
    let headerB = await recorder.outgoingStreams[1].readLp(1024)
    let payloadB = await recorder.outgoingStreams[1].readLp(1024)
    check TopicRPCHeader.decode(headerB).get().topic.get() == "b"
    check TopicRPC.decode(payloadB).isOk

    check state.sendTopic("c", payload, true)
    check recorder.outgoingStreams.len == 3
    let rejected =
      metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["stream_limit"])
    check not state.sendTopic("d", payload, true)
    check:
      recorder.outgoingStreams.len == 3
      metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["stream_limit"]) ==
        rejected + 1
    check not state.sendTopic("a", newSeq[byte](129), true)
    check recorder.penalties == 0

    await state.closeTopic("a")
    check state.sendTopic("a", payload, true)
    check recorder.outgoingStreams.len == 4
    let headerA = await recorder.outgoingStreams[3].readLp(1024)
    let payloadA = await recorder.outgoingStreams[3].readLp(1024)
    check TopicRPCHeader.decode(headerA).get().topic.get() == "a"
    check TopicRPC.decode(payloadA).isOk

    check not state.negotiate(makeRPC(ControlExtensions(topicStreams: Opt.none(bool))))
    check not state.isActive()

    var data: byte
    check (await recorder.outgoingStreams[3].readOnce(addr data, 1)) == 0

  asyncTest "incoming limit counts pending headers independently of outgoing streams":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(
      recorder, TopicStreamsConfig(maxIncomingStreams: 3, maxOutgoingStreams: 1)
    )
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))
    var remotes: seq[Stream]
    var readers: seq[Future[void]]
    defer:
      await state.stop()
      await allFutures(readers)
      for remote in remotes:
        await remote.close()
      await recorder.closeOutgoingStreams()

    check state.sendTopic("outgoing", @[1.byte], true)
    for i in 0 .. 3:
      let (remote, local) = bridgedConnections()
      remotes.add(remote)
      readers.add(state.readTopic(local))
      if i < 3:
        check not readers[i].finished()
      else:
        await readers[i]
        check local.closed()
    check:
      recorder.penalties == 1
      recorder.violations == 0
      recorder.outgoingStreams.len == 1

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

    check state.sendTopic("a", payload, true)
    await state.closeTopic("a")
    check recorder.cancelledDials == 1

    check state.sendTopic("b", payload, true)
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

  asyncTest "readers drop frames after a protocol violation on another stream":
    for waitingForPayload in [true, false]:
      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(recorder)
      let local = ReadSignallingStream(reads: newAsyncQueue[int]())
      local.initStream()
      let (violatingRemote, violatingLocal) = bridgedConnections()
      let reading = state.readTopic(local)
      let violating = state.readTopic(violatingLocal)
      defer:
        await reading.cancelAndWait()
        await violating.cancelAndWait()
        await state.stop()
        await violatingRemote.close()

      let header = TopicRPCHeader(topic: "a").encode()
      let payload = Message(data: @[1.byte], topic: "a").topicRPC().encode()
      require header.len < 128 and payload.len < 128
      check (await local.reads.popFirst()) == 1
      await local.pushData(@[byte(header.len)] & header)
      check (await local.reads.popFirst()) == header.len
      check (await local.reads.popFirst()) == 1

      if waitingForPayload:
        await local.pushData(@[byte(payload.len)])
        check (await local.reads.popFirst()) == payload.len
      check not reading.finished()

      await violatingRemote.writeLp(TopicRPCHeader(topic: "b").encode())
      await violatingRemote.write(@[0.byte])
      await violating
      check recorder.violations == 1

      if waitingForPayload:
        await local.pushData(payload)
      else:
        # A length alone must suffice to stop the reader without reading a body.
        await local.pushData(@[byte(payload.len)])
      await reading
      check:
        local.closed()
        violatingLocal.closed()
        recorder.received.len == 0
        recorder.violations == 1
        recorder.penalties == 0

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

  const maxMessageSize = 1024
  let header = TopicRPCHeader(topic: topic).encode()
  let frames = [@[1.byte], @[2.byte], @[3.byte], @[4.byte]]

  asyncTest "minimum valid budgets deliver a maximum-size header and frame":
    const limit = 64
    let topic = repeat('a', limit - 2)
    let header = TopicRPCHeader(topic: topic).encode()
    let message = Message(topic: topic, data: newSeq[byte](limit - 4))
    let frame = message.topicRPC().encode()
    require header.len == limit and frame.len == limit
    let config =
      TopicStreamsConfig(maxQueuedBytes: 2 * limit, maxIncomingBytes: 2 * limit)
    check config.validate(limit).isOk
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder, config, limit)
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))
    let (remote, local) = bridgedConnections()
    let reading = state.readTopic(local)
    defer:
      await reading.cancelAndWait()
      await state.stop()
      await remote.close()
      await recorder.closeOutgoingStreams()
    check state.sendTopic(topic, frame, true)
    check (await recorder.outgoingStreams[0].readLp(limit)) == header
    check (await recorder.outgoingStreams[0].readLp(limit)) == frame
    await remote.writeLp(header)
    await remote.writeLp(frame)
    check (await recorder.received.popFirst()).messages == @[message]
    check recorder.penalties == 0

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

      let rejected =
        metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["invalid_frame"])
      check state.sendTopic(topic, newSeq[byte](frameSize), true) == (
        expectedDials == 1
      )
      check:
        metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["invalid_frame"]) ==
          rejected + float64(1 - expectedDials)
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
        maxMessageSize,
        dial,
        recorder.receive(),
        recorder.violation(),
        recorder.penalize(),
      )
      defer:
        await state.stop()
      check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

      check state.sendTopic(topic, frames[0], true) # in flight until frameWritten fires
      check state.sendTopic(topic, frames[1], true) # queued behind frames[0]
      check:
        (await written.popFirst()) == header
        (await written.popFirst()) == frames[0]
        written.len == 0

      let rejected =
        metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["queue_full"])
      check not state.sendTopic(topic, frames[2], true) # dropped: the budget is full
      check metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["queue_full"]) ==
        rejected + 1
      frameWritten.fire() # frames[0]'s write completes and releases its budget
      check (await written.popFirst()) == frames[1]

      check state.sendTopic(topic, frames[3], true) # accepted: the budget has room again
      check:
        (await written.popFirst()) == frames[3]
        recorder.penalties == 0
        recorder.violations == 0

  asyncTest "incoming streams do not consume the outgoing stream budget":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(
      recorder, TopicStreamsConfig(maxIncomingStreams: 3, maxOutgoingStreams: 3)
    )
    var peerEnds: seq[Stream]
    var readers: seq[Future[void]]
    defer:
      await state.stop()
      await allFutures(readers.mapIt(it.cancelAndWait()))
      await allFutures(peerEnds.mapIt(it.close()))
      await recorder.closeOutgoingStreams()
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    check state.sendTopic(topic, frames[0], true) # opens our writer for topic
    for _ in 0 ..< 2: # the peer opens two topic streams
      let (peerEnd, nodeEnd) = bridgedConnections()
      peerEnds.add(peerEnd)
      readers.add(state.readTopic(nodeEnd))

    check state.sendTopic(otherTopic, frames[1], true)
    check state.sendTopic(topic, frames[2], true) # written on the open writer
    check:
      recorder.outgoingStreams.len == 2
      (await recorder.outgoingStreams[0].readLp(1024)) == header
      (await recorder.outgoingStreams[0].readLp(1024)) == frames[0]
      (await recorder.outgoingStreams[0].readLp(1024)) == frames[2]
      (await recorder.outgoingStreams[1].readLp(1024)) ==
        TopicRPCHeader(topic: otherTopic).encode()
      (await recorder.outgoingStreams[1].readLp(1024)) == frames[1]

  asyncTest "messages for different topics in one RPC go to their own topic streams":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
    defer:
      await state.stop()
      await recorder.closeOutgoingStreams()
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    # an IWANT reply carries messages for several topics
    let messages = @[
      Message(topic: topic, data: @[1.byte]),
      Message(topic: otherTopic, data: @[2.byte]),
    ]
    let prepared = makePreparedTopicRPC(RPCMsg.withMessages(messages), false)
    let accepted = state.sendTopicRPC(prepared, false)
    check:
      prepared.control.len == 0
      accepted.messages == messages
      recorder.outgoingStreams.len == 2
      (await recorder.outgoingStreams[0].readLp(1024)) == header
      (await recorder.outgoingStreams[0].readLp(1024)) == messages[0].topicRPC().encode()
      (await recorder.outgoingStreams[1].readLp(1024)) ==
        TopicRPCHeader(topic: otherTopic).encode()
      (await recorder.outgoingStreams[1].readLp(1024)) == messages[1].topicRPC().encode()

  test "message with empty data is sent on neither the topic stream nor the control stream":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    # an empty publish payload and a message on the control stream are both protocol violations
    let prepared = makePreparedTopicRPC(
      RPCMsg.withMessages(Message(topic: topic, data: newSeq[byte]())), false
    )
    let accepted = state.sendTopicRPC(prepared, true)
    check:
      prepared.control.len == 0
      accepted.messages.len == 0
      recorder.outgoingStreams.len == 0

suite "GossipSub topic stream receive side":
  teardown:
    checkTrackers()

  let header = TopicRPCHeader(topic: topic).encode()
  let message = Message(data: @[1.byte], topic: topic)
  let frame = message.topicRPC().encode()

  asyncTest "reader delivers every frame on a topic stream in order":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
    let (peerEnd, nodeEnd) = bridgedConnections()
    let reader = state.readTopic(nodeEnd)
    defer:
      await reader.cancelAndWait()
      await state.stop()
      await peerEnd.close()

    let messages = [message, Message(data: @[2.byte], topic: topic)]
    await peerEnd.writeLp(header)
    for m in messages:
      await peerEnd.writeLp(m.topicRPC().encode())
    check:
      (await recorder.received.popFirst()).messages == @[messages[0]]
      (await recorder.received.popFirst()).messages == @[messages[1]]

  asyncTest "malformed header or frame is a protocol violation":
    let frameWithTopic = TopicRPC(
      publish: Opt.some(TopicScopedMessage(data: @[1.byte], topic: topic))
    ).encode()
    for writes in [
      @[@[255.byte]], # undecodable header
      @[newSeq[byte]()], # zero-length header
      @[TopicRPCHeader(topic: "").encode()], # empty topic
      @[header, frameWithTopic], # publish frame that names its topic
    ]:
      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(recorder)
      let (peerEnd, nodeEnd) = bridgedConnections()
      let reader = state.readTopic(nodeEnd)
      defer:
        await reader.cancelAndWait()
        await state.stop()
        await peerEnd.close()

      for data in writes:
        await peerEnd.writeLp(data)
      await reader # ends on its own at the violation
      check:
        nodeEnd.wasResetLocally()
        recorder.received.len == 0
        recorder.penalties == 0
        recorder.violations == 1

  asyncTest "stream without a header is reset after the header timeout":
    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(recorder)
    let (peerEnd, nodeEnd) = bridgedConnections()
    defer:
      await state.stop()
      await peerEnd.close()

    await state.readTopic(nodeEnd)
    check:
      nodeEnd.wasResetLocally()
      recorder.penalties == 0
      recorder.violations == 0

  asyncTest "reader drops the next frame after a control stream protocol violation":
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

    # The reader is waiting for its next frame when the violation stops the transport.
    # the peer opened a topic stream, so denying support is a protocol violation
    check:
      not state.negotiate(makeRPC(ControlExtensions(topicStreams: false)))
      recorder.violations == 1

    await peerEnd.writeLp(frame)
    await reader
    check:
      recorder.received.len == 0
      nodeEnd.wasResetLocally()

  asyncTest "stream over maxIncomingStreams is reset and penalized independently of writers":
    for writerCount in [0, 1]:
      let recorder = TopicStreamsRecorder.new()
      let state = TopicStreams.new(recorder, TopicStreamsConfig(maxIncomingStreams: 3))
      var peerEnds: seq[Stream]
      var readers: seq[Future[void]]
      defer:
        await state.stop()
        await noCancel allFutures(readers.mapIt(it.cancelAndWait()))
        await noCancel allFutures(peerEnds.mapIt(it.close()))
        await recorder.closeOutgoingStreams()
      check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

      for _ in 0 ..< writerCount:
        check state.sendTopic(topic, frame, true)
      for _ in 0 ..< 3: # readers still waiting for their header fill the limit
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
        recorder.penalties == 1
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
    await peerEnds[1].writeLp(frame) # reset without penalty: the budget is full
    await readers[1]
    check:
      recorder.penalties == 0
      recorder.violations == 0

    frameReceived.fire() # receive returns and releases the frame's bytes
    let (peerEnd, nodeEnd) = bridgedConnections()
    peerEnds.add(peerEnd)
    readers.add(state.readTopic(nodeEnd))
    await peerEnd.writeLp(header)
    await peerEnd.writeLp(frame) # accepted: the budget has room again
    check (await recorder.received.popFirst()).messages == @[message]

  asyncTest "header budget exhaustion resets without penalty":
    let recorder = TopicStreamsRecorder.new()
    let state =
      TopicStreams.new(recorder, TopicStreamsConfig(maxIncomingBytes: header.len))
    let local = ReadSignallingStream(reads: newAsyncQueue[int]())
    local.initStream()
    let reading = state.readTopic(local)
    let (excessRemote, excessLocal) = bridgedConnections()
    defer:
      await reading.cancelAndWait()
      await state.stop()
      await excessRemote.close()
    check (await local.reads.popFirst()) == 1
    await local.pushData(@[byte(header.len)] & header)
    check (await local.reads.popFirst()) == header.len
    check (await local.reads.popFirst()) == 1
    await excessRemote.writeLp(header)
    await state.readTopic(excessLocal)
    check:
      excessLocal.wasResetLocally()
      recorder.penalties == 0
      recorder.violations == 0
