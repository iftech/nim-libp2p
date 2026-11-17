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

const
  topic = "foobar"
  otherTopic = "other"

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
    state.sendTopic(topic, frame, true)
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
      state.sendTopic(topic, newSeq[byte](frameSize), true)
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

      state.sendTopic(topic, frames[0], true) # in flight until frameWritten fires
      state.sendTopic(topic, frames[1], true) # queued behind frames[0]
      check:
        (await written.popFirst()) == header
        (await written.popFirst()) == frames[0]
        written.len == 0

      let rejected =
        metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["queue_full"])
      state.sendTopic(topic, frames[2], true) # dropped: the budget is full
      check metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["queue_full"]) ==
        rejected + 1
      frameWritten.fire() # frames[0]'s write completes and releases its budget
      check (await written.popFirst()) == frames[1]

      state.sendTopic(topic, frames[3], true) # accepted: the budget has room again
      check:
        (await written.popFirst()) == frames[3]
        recorder.penalties == 0
        recorder.violations == 0

  asyncTest "queue budgets release the frame in flight when the writer closes":
    let written = newAsyncQueue[seq[byte]]()
    proc dial(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
      return TestBufferStream.new(
        proc(
            data: sink seq[byte]
        ) {.async: (raises: [CancelledError, LPStreamError]).} =
          let frame = data[1 ..^ 1] # without the 1-byte length prefix
          await written.put(frame)
          if frame == frames[0]:
            await newAsyncEvent().wait() # completes only by cancellation
      )

    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(
      TopicStreamsConfig(
        maxQueuedBytes: header.len + frames[0].len, maxQueuedMessages: 1
      ),
      maxMessageSize,
      dial,
      recorder.receive(),
      recorder.violation(),
      recorder.penalize(),
    )
    defer:
      await state.stop()
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    state.sendTopic(topic, frames[0], true)
    check:
      (await written.popFirst()) == header
      (await written.popFirst()) == frames[0]

    let rejected =
      metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["queue_full"])
    state.sendTopic(topic, frames[0], true) # dropped: frames[0]'s write holds the budget
    check metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["queue_full"]) ==
      rejected + 1

    await state.closeTopic(topic) # cancels frames[0]'s write
    state.sendTopic(topic, frames[0], true) # fits only if the close released frames[0]
    check:
      (await written.popFirst()) == header # on a new stream
      (await written.popFirst()) == frames[0]

  asyncTest "pending dial is cancelled after the dial timeout, and the next frame dials again":
    var dials: seq[Future[Stream].Raising([CancelledError, LPStreamError])]
    proc dial(): Future[Stream] {.
        async: (raises: [CancelledError, LPStreamError], raw: true)
    .} =
      let dialing = Future[Stream].Raising([CancelledError, LPStreamError]).init()
      dials.add(dialing)
      return dialing

    let recorder = TopicStreamsRecorder.new()
    let state = TopicStreams.new(
      TopicStreamsConfig(),
      maxMessageSize,
      dial,
      recorder.receive(),
      recorder.violation(),
      recorder.penalize(),
    )
    defer:
      await state.stop()
    check state.negotiate(makeRPC(ControlExtensions(topicStreams: true)))

    state.sendTopic(topic, frames[0], true)
    # nothing completes the dial, so the dial timeout cancels it and ends the writer
    await dials[0].join()
    state.sendTopic(topic, frames[1], true)
    check:
      dials[0].cancelled()
      dials.len == 2

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

    state.sendTopic(topic, frames[0], true) # opens our writer for topic
    for _ in 0 ..< 2: # the peer opens two topic streams
      let (peerEnd, nodeEnd) = bridgedConnections()
      peerEnds.add(peerEnd)
      readers.add(state.readTopic(nodeEnd))

    state.sendTopic(otherTopic, frames[1], true)
    state.sendTopic(topic, frames[2], true) # written on the open writer
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
    let control = state.sendTopicRPC(
      makePreparedTopicRPC(RPCMsg.withMessages(messages), false), false
    )
    check:
      control.len == 0
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
    let control = state.sendTopicRPC(
      makePreparedTopicRPC(
        RPCMsg.withMessages(Message(topic: topic, data: newSeq[byte]())), false
      ),
      true,
    )
    check:
      control.len == 0
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
        state.sendTopic(topic, frame, true)
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
