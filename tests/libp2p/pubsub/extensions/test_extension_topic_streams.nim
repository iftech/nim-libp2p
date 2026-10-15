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
    check (await remotes[3].readOnce(addr data, 1).wait(1.seconds)) == 0
