# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, results
import ../../../../libp2p/protocols/pubsub/gossipsub/extension_topic_streams
import ../../../../libp2p/protocols/pubsub/rpc/messages
import ../../../../libp2p/stream/[bridgestream, bufferstream]
import ../../../tools/[unittest, bufferstream, crypto, metrics_utils]
import ../converters
import ./extension_recording

const topic = "foobar"

suite "GossipSub topic stream wire format":
  test "full message reconstructs canonical signature input":
    let message = Message(
      fromPeer: PeerId.random(),
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
    check TopicRPC(
      partial: Opt.some(PartialMessageExtensionRPC(partialMessage: newSeq[byte]()))
    ).toRPC("topic").isErr

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
    let rejected =
      metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["stream_limit"])
    state.sendTopic("d", payload, true)
    check:
      recorder.outgoingStreams.len == 3
      metricValue(libp2p_gossipsub_topic_stream_frames_rejected, ["stream_limit"]) ==
        rejected + 1
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

    state.sendTopic("outgoing", @[1.byte], true)
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
