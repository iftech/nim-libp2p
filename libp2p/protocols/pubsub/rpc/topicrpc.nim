# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import protobuf_serialization, protobuf_serialization/pkg/results
import ./messages
import ../../../utils/protobuf
import ../../../peerid

type
  TopicRPCHeader* {.proto2.} = object
    topic* {.fieldNumber: 1.}: Opt[string]

  TopicScopedMessage* {.proto, implicit.} = object
    fromPeer* {.fieldNumber: 1, ext.}: PeerId
    data* {.fieldNumber: 2.}: seq[byte]
    seqno* {.fieldNumber: 3.}: seq[byte]
    # Presence is retained solely to reject the reserved wire field.
    topic* {.fieldNumber: 4.}: Opt[string]
    signature* {.fieldNumber: 5.}: seq[byte]
    key* {.fieldNumber: 6.}: seq[byte]

  TopicRPC* {.proto2.} = object
    publish* {.fieldNumber: 1.}: Opt[TopicScopedMessage]
    partial* {.fieldNumber: 2.}: Opt[PartialMessageExtensionRPC]

Protobuf.serializerFor([TopicRPCHeader, TopicRPC])

proc topicRPC*(msg: Message, anonymize: bool): TopicRPC =
  let m = msg.anonymize(anonymize)
  TopicRPC(
    publish: Opt.some(
      TopicScopedMessage(
        fromPeer: m.fromPeer,
        data: m.data,
        seqno: m.seqno,
        signature: m.signature,
        key: m.key,
      )
    )
  )

proc topicRPC*(msg: PartialMessageExtensionRPC): TopicRPC =
  var partial = msg
  partial.topicID = Opt.none(string)
  TopicRPC(partial: Opt.some(partial))

proc toRPC*(msg: sink TopicRPC, topic: string): Result[RPCMsg, string] =
  if msg.publish.isSome == msg.partial.isSome:
    return err("TopicRPC must contain exactly one payload")
  if msg.publish.isSome:
    var m = msg.publish.get()
    if m.topic.isSome or m.data.len == 0:
      return err("invalid topic-scoped publish")
    return ok(
      RPCMsg.withMessages(
        Message(
          fromPeer: move(m.fromPeer),
          data: move(m.data),
          seqno: move(m.seqno),
          topic: topic,
          signature: move(m.signature),
          key: move(m.key),
        )
      )
    )
  var partial = msg.partial.get()
  if partial.topicID.isSome:
    return err("topic must be omitted from partial payload")
  # Metadata-only requests are valid partial-message extension traffic.
  if partial.partialMessage.isSome and partial.partialMessage.get().len == 0:
    return err("empty partial application payload")
  partial.topicID = Opt.some(topic)
  ok(RPCMsg(partialMessageExtension: Opt.some(move(partial))))
