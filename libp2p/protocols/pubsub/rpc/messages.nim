# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import sequtils, chronicles, stew/endians2
import protobuf_serialization
import ../../../[peerid, routing_record]
import ../../../utils/[opt, shortlog]

export results

proc expectedFields[T](
    t: typedesc[T], existingFieldNames: seq[string]
) {.raises: [CatchableError].} =
  var fieldNames: seq[string]
  for name, _ in fieldPairs(T()):
    fieldNames &= name
  if fieldNames != existingFieldNames:
    fieldNames.keepIf(
      proc(it: string): bool =
        it notin existingFieldNames
    )
    raise newException(
      CatchableError,
      $T &
        " fields changed, please search for and revise all relevant procs. New fields: " &
        $fieldNames,
    )

type
  MessageId* = seq[byte]

  SaltedId* = object
    # Salted hash of message ID - used instead of the ordinary message ID to
    # avoid hash poisoning attacks and to make memory usage more predictable
    # with respect to the variable-length message id
    data*: MDigest[256]

  PeerInfoMsg* {.proto2.} = object
    peerId* {.fieldNumber: 1, ext.}: Opt[PeerId]
    signedPeerRecord* {.fieldNumber: 2.}: Opt[seq[byte]]

  SubOpts* {.proto2.} = object
    subscribe* {.fieldNumber: 1.}: Opt[bool]
    topic* {.fieldNumber: 2.}: Opt[string]
    # When true, it signals the receiver that the sender prefers partial messages.
    requestsPartial* {.fieldNumber: 3.}: Opt[bool]
    # When true, it signals the receiver that the sender supports sending partial
    # messages on this topic.
    # When requestsPartial is true, this is assumed to be true.
    supportsSendingPartial* {.fieldNumber: 4.}: Opt[bool]

  Message* {.proto, implicit.} = object
    fromPeer* {.fieldNumber: 1, ext.}: PeerId
    data* {.fieldNumber: 2.}: seq[byte]
    seqno* {.fieldNumber: 3.}: seq[byte]
    topic* {.fieldNumber: 4, required.}: string
    signature* {.fieldNumber: 5.}: seq[byte]
    key* {.fieldNumber: 6.}: seq[byte]

  ControlExtensions* {.proto2.} = object
    partialMessageExtension* {.fieldNumber: 10.}: Opt[bool]

    # Experimental extensions fields:
    testExtension* {.fieldNumber: 6492434.}: Opt[bool]
    pingpongExtension* {.fieldNumber: 3145728.}: Opt[bool]
    preambleExtension* {.fieldNumber: 4194304.}: Opt[bool]

  ControlMessage* {.proto2.} = object
    ihave* {.fieldNumber: 1.}: seq[ControlIHave]
    iwant* {.fieldNumber: 2.}: seq[ControlIWant]
    graft* {.fieldNumber: 3.}: seq[ControlGraft]
    prune* {.fieldNumber: 4.}: seq[ControlPrune]
    idontwant* {.fieldNumber: 5.}: seq[ControlIWant]
    extensions* {.fieldNumber: 6.}: Opt[ControlExtensions]

  ControlIHave* {.proto, implicit.} = object
    topicID* {.fieldNumber: 1.}: string
    messageIDs* {.fieldNumber: 2.}: seq[MessageId]

  ControlIWant* {.proto2.} = object
    messageIDs* {.fieldNumber: 1.}: seq[MessageId]

  ControlGraft* {.proto, implicit.} = object
    topicID* {.fieldNumber: 1.}: string

  ControlPrune* {.proto, implicit.} = object
    topicID* {.fieldNumber: 1.}: string
    peers* {.fieldNumber: 2.}: seq[PeerInfoMsg]
    backoff* {.fieldNumber: 3, pint.}: uint64

  TestExtensionRPC* {.proto2.} = object

  PartialMessageExtensionRPC* {.proto2.} = object
    topicID* {.fieldNumber: 1.}: Opt[string]
    groupID* {.fieldNumber: 2.}: Opt[seq[byte]]
    partialMessage* {.fieldNumber: 3.}: Opt[seq[byte]]
    partsMetadata* {.fieldNumber: 4.}: Opt[seq[byte]]

  PingPongExtensionRPC* {.proto2.} = object
    ping* {.fieldNumber: 1.}: Opt[seq[byte]]
    pong* {.fieldNumber: 2.}: Opt[seq[byte]]

  Preamble* {.proto2.} = object
    topicID* {.fieldNumber: 1.}: Opt[string]
    messageID* {.fieldNumber: 2.}: Opt[MessageId]
    messageLength* {.fieldNumber: 3, pint.}: Opt[uint32]

  IMReceiving* {.proto2.} = object
    messageID* {.fieldNumber: 1.}: Opt[MessageId]
    messageLength* {.fieldNumber: 2, pint.}: Opt[uint32]

  PreambleExtensionRPC* {.proto2.} = object
    preamble* {.fieldNumber: 1.}: seq[Preamble]
    imreceiving* {.fieldNumber: 2.}: seq[IMReceiving]

  RPCMsg* {.proto2.} = object
    subscriptions* {.fieldNumber: 1.}: seq[SubOpts]
    messages* {.fieldNumber: 2.}: seq[Message]
    control* {.fieldNumber: 3.}: Opt[ControlMessage]
    partialMessageExtension* {.fieldNumber: 10.}: Opt[PartialMessageExtensionRPC]
    testExtension* {.fieldNumber: 6492434.}: Opt[TestExtensionRPC]
    pingpongExtension* {.fieldNumber: 3145728.}: Opt[PingPongExtensionRPC]
    preambleExtension* {.fieldNumber: 4194304.}: Opt[PreambleExtensionRPC]

func shortLog[T](optVal: Opt[T]): string =
  if optVal.isSome:
    let value = optVal.get()
    when compiles(value.shortLog):
      value.shortLog
    else:
      $value
  else:
    "<unset>"

func len[T](opt: Opt[T]): int =
  if opt.isSome:
    opt.get().len
  else:
    0

func shortLog*(s: ControlIHave): auto =
  (topic: s.topicID.shortLog, messageIDs: mapIt(s.messageIDs, it.shortLog))

chronicles.formatIt(ControlIHave):
  shortLog(it)

func shortLog*(s: ControlIWant): auto =
  (messageIDs: mapIt(s.messageIDs, it.shortLog))

chronicles.formatIt(ControlIWant):
  shortLog(it)

func shortLog*(s: ControlGraft): auto =
  (topic: s.topicID.shortLog)

chronicles.formatIt(ControlGraft):
  shortLog(it)

func shortLog*(s: ControlPrune): auto =
  (topic: s.topicID.shortLog)

chronicles.formatIt(ControlPrune):
  shortLog(it)

func shortLog*(s: Preamble): auto =
  (topic: s.topicID.shortLog, messageID: s.messageID.shortLog)

chronicles.formatIt(Preamble):
  shortLog(it)

func shortLog*(s: IMReceiving): auto =
  (messageID: s.messageID.shortLog)

chronicles.formatIt(IMReceiving):
  shortLog(it)

func shortLog*(so: Opt[ControlExtensions]): auto =
  if so.isNone():
    (
      partialMessageExtension: "<unset>",
      testExtension: "<unset>",
      pingpongExtension: "<unset>",
      preambleExtension: "<unset>",
    )
  else:
    let s = so.get()
    (
      partialMessageExtension: shortLog(s.partialMessageExtension),
      testExtension: shortLog(s.testExtension),
      pingpongExtension: shortLog(s.pingpongExtension),
      preambleExtension: shortLog(s.preambleExtension),
    )

chronicles.formatIt(Opt[ControlExtensions]):
  shortLog(it)

func shortLog*(c: ControlMessage): auto =
  (
    ihave: mapIt(c.ihave, it.shortLog),
    iwant: mapIt(c.iwant, it.shortLog),
    graft: mapIt(c.graft, it.shortLog),
    prune: mapIt(c.prune, it.shortLog),
    extensions: shortLog(c.extensions),
  )

chronicles.formatIt(ControlMessage):
  shortLog(it)

func shortLog*(msg: Message): auto =
  (
    topic: msg.topic.shortLog,
    seqno:
      if msg.seqno.len == 8:
        $fromBytesBE(uint64, msg.seqno)
      elif msg.seqno.len == 0:
        "<unset>"
      else:
        "<invalid>",
    fromPeer: msg.fromPeer.shortLog,
    dataLen: msg.data.len,
    key: msg.key.shortLog,
    signaturePresent: msg.signature.len > 0,
  )

chronicles.formatIt(Message):
  shortLog(it)

func shortLog*(pme: PartialMessageExtensionRPC): auto =
  (
    topicID: pme.topicID.shortLog,
    groupID: pme.groupID.shortLog,
    partialMessage: pme.partialMessage.shortLog,
    partsMetadata: pme.partsMetadata.shortLog,
  )

chronicles.formatIt(PartialMessageExtensionRPC):
  shortLog(it)

func shortLog*(rpc: PingPongExtensionRPC): auto =
  (ping: rpc.ping.shortLog, pong: rpc.pong.shortLog)

chronicles.formatIt(PingPongExtensionRPC):
  shortLog(it)

func shortLog*(rpc: PreambleExtensionRPC): auto =
  (
    preamble: mapIt(rpc.preamble, it.shortLog),
    imreceiving: mapIt(rpc.imreceiving, it.shortLog),
  )

chronicles.formatIt(PreambleExtensionRPC):
  shortLog(it)

func shortLog*(m: RPCMsg): auto =
  (
    subscriptions: m.subscriptions,
    messages: mapIt(m.messages, it.shortLog),
    control: m.control.valueOr(ControlMessage()).shortLog,
    partialMessageExtension:
      m.partialMessageExtension.valueOr(PartialMessageExtensionRPC()).shortLog,
    testExtension: m.testExtension.shortLog,
    pingpongExtension: m.pingpongExtension.valueOr(PingPongExtensionRPC()).shortLog,
    preambleExtension: m.preambleExtension.valueOr(PreambleExtensionRPC()).shortLog,
  )

chronicles.formatIt(RPCMsg):
  shortLog(it)

static:
  expectedFields(PeerInfoMsg, @["peerId", "signedPeerRecord"])
proc byteSize(peerInfo: PeerInfoMsg): int =
  peerInfo.peerId.len + peerInfo.signedPeerRecord.len

proc byteSize(v: Opt[bool]): int =
  if v.isSome(): 1 else: 0

static:
  expectedFields(
    SubOpts, @["subscribe", "topic", "requestsPartial", "supportsSendingPartial"]
  )
proc byteSize(subOpts: SubOpts): int =
  1 + # subscribe: 1 byte for the bool
  subOpts.topic.len + #
  subOpts.requestsPartial.byteSize() + #
  subOpts.supportsSendingPartial.byteSize()

static:
  expectedFields(Message, @["fromPeer", "data", "seqno", "topic", "signature", "key"])
proc byteSize*(msg: Message): int =
  msg.fromPeer.len + msg.data.len + msg.seqno.len + msg.signature.len + msg.key.len +
    msg.topic.len

proc byteSize*(msgs: seq[Message]): int =
  msgs.foldl(a + b.byteSize, 0)

static:
  expectedFields(ControlIHave, @["topicID", "messageIDs"])
proc byteSize(controlIHave: ControlIHave): int =
  controlIHave.topicID.len + controlIHave.messageIDs.foldl(a + b.len, 0)

proc byteSize*(ihaves: seq[ControlIHave]): int =
  ihaves.foldl(a + b.byteSize, 0)

static:
  expectedFields(ControlIWant, @["messageIDs"])
proc byteSize(controlIWant: ControlIWant): int =
  controlIWant.messageIDs.foldl(a + b.len, 0)

proc byteSize*(iwants: seq[ControlIWant]): int =
  iwants.foldl(a + b.byteSize, 0)

static:
  expectedFields(ControlGraft, @["topicID"])
proc byteSize(controlGraft: ControlGraft): int =
  controlGraft.topicID.len

static:
  expectedFields(ControlPrune, @["topicID", "peers", "backoff"])
proc byteSize(controlPrune: ControlPrune): int =
  controlPrune.topicID.len + controlPrune.peers.foldl(a + b.byteSize, 0) + 8
    # 8 bytes for uint64

static:
  expectedFields(Preamble, @["topicID", "messageID", "messageLength"])
proc byteSize(controlPreamble: Preamble): int =
  controlPreamble.topicID.len + controlPreamble.messageID.len + 4 # 4 bytes for uint32

proc byteSize*(preambles: seq[Preamble]): int =
  preambles.foldl(a + b.byteSize, 0)

static:
  expectedFields(IMReceiving, @["messageID", "messageLength"])
proc byteSize(m: IMReceiving): int =
  m.messageID.len + 4 # 4 bytes for uint32

proc byteSize*(imreceivings: seq[IMReceiving]): int =
  imreceivings.foldl(a + b.byteSize, 0)

static:
  expectedFields(
    ControlExtensions,
    @[
      "partialMessageExtension", "testExtension", "pingpongExtension",
      "preambleExtension",
    ],
  )
proc byteSize(controlExtensions: ControlExtensions): int =
  controlExtensions.partialMessageExtension.byteSize() +
    controlExtensions.testExtension.byteSize() +
    controlExtensions.pingpongExtension.byteSize() +
    controlExtensions.preambleExtension.byteSize()

proc byteSize(rpc: PingPongExtensionRPC): int =
  rpc.ping.len + rpc.pong.len

proc byteSize(controlExtensions: Opt[ControlExtensions]): int =
  controlExtensions.ifValue(ce):
    ce.byteSize()
  else:
    0

static:
  expectedFields(TestExtensionRPC, @[])
proc byteSize(testExtensions: TestExtensionRPC): int =
  0 # type is empty

static:
  expectedFields(
    PartialMessageExtensionRPC,
    @["topicID", "groupID", "partialMessage", "partsMetadata"],
  )
proc byteSize(pme: PartialMessageExtensionRPC): int =
  pme.topicID.len + pme.groupID.len + pme.partialMessage.len + pme.partsMetadata.len

static:
  expectedFields(
    ControlMessage, @["ihave", "iwant", "graft", "prune", "idontwant", "extensions"]
  )
proc byteSize(control: ControlMessage): int =
  control.ihave.foldl(a + b.byteSize, 0) + control.iwant.foldl(a + b.byteSize, 0) +
    control.graft.foldl(a + b.byteSize, 0) + control.prune.foldl(a + b.byteSize, 0) +
    control.idontwant.foldl(a + b.byteSize, 0) + byteSize(control.extensions)

static:
  expectedFields(PreambleExtensionRPC, @["preamble", "imreceiving"])
proc byteSize(v: PreambleExtensionRPC): int =
  v.preamble.foldl(a + b.byteSize, 0) + v.imreceiving.foldl(a + b.byteSize, 0)

static:
  expectedFields(
    RPCMsg,
    @[
      "subscriptions", "messages", "control", "partialMessageExtension",
      "testExtension", "pingpongExtension", "preambleExtension",
    ],
  )
proc byteSize*(rpc: RPCMsg): int =
  var size = rpc.subscriptions.foldl(a + b.byteSize, 0) + byteSize(rpc.messages)
  rpc.control.ifValue(v):
    size += v.byteSize
  rpc.partialMessageExtension.ifValue(v):
    size += v.byteSize
  rpc.testExtension.ifValue(v):
    size += v.byteSize
  rpc.pingpongExtension.ifValue(v):
    size += v.byteSize
  rpc.preambleExtension.ifValue(v):
    size += v.byteSize
  size

proc withIWant*(
    _: typedesc[ControlMessage], msgIds: sink seq[MessageId]
): ControlMessage =
  ControlMessage(iwant: @[ControlIWant(messageIDs: move(msgIds))])

proc withIWant*(_: typedesc[ControlMessage], msgId: MessageId): ControlMessage =
  ControlMessage.withIWant(@[msgId])

proc withIDontWant*(
    _: typedesc[ControlMessage], msgIds: sink seq[MessageId]
): ControlMessage =
  ControlMessage(idontwant: @[ControlIWant(messageIDs: move(msgIds))])

proc withIDontWant*(_: typedesc[ControlMessage], msgId: MessageId): ControlMessage =
  ControlMessage.withIDontWant(@[msgId])

proc withIHave*(
    _: typedesc[ControlMessage], topicID: string, messageIDs: sink seq[MessageId]
): ControlMessage =
  ControlMessage(ihave: @[ControlIHave(topicID: topicID, messageIDs: move(messageIDs))])

proc withGraft*(_: typedesc[ControlMessage], topicID: string): ControlMessage =
  ControlMessage(graft: @[ControlGraft(topicID: topicID)])

proc withPrune*(
    _: typedesc[ControlMessage],
    topicID: string,
    backoff: uint64,
    peers: sink seq[PeerInfoMsg],
): ControlMessage =
  ControlMessage(
    prune: @[ControlPrune(topicID: topicID, peers: move(peers), backoff: backoff)]
  )

proc withExtensions*(
    _: typedesc[ControlMessage], ext: sink ControlExtensions
): ControlMessage =
  ControlMessage(extensions: Opt.some(move(ext)))

proc withControl*(_: typedesc[RPCMsg], control: sink ControlMessage): RPCMsg =
  RPCMsg(control: Opt.some(move(control)))

proc withMessages*(_: typedesc[RPCMsg], messages: sink seq[Message]): RPCMsg =
  RPCMsg(messages: move(messages))

proc withMessages*(_: typedesc[RPCMsg], msg: sink Message): RPCMsg =
  RPCMsg.withMessages(@[move(msg)])

proc withSubscriptions*(_: typedesc[RPCMsg], subscriptions: sink seq[SubOpts]): RPCMsg =
  RPCMsg(subscriptions: move(subscriptions))

proc withPing*(_: typedesc[RPCMsg], ping: sink seq[byte]): RPCMsg =
  RPCMsg(pingpongExtension: Opt.some(PingPongExtensionRPC(ping: Opt.some(move(ping)))))

proc withPing*(_: typedesc[RPCMsg], ping: sink Opt[seq[byte]]): RPCMsg =
  RPCMsg(pingpongExtension: Opt.some(PingPongExtensionRPC(ping: move(ping))))

proc withPong*(_: typedesc[RPCMsg], pong: sink seq[byte]): RPCMsg =
  RPCMsg(pingpongExtension: Opt.some(PingPongExtensionRPC(pong: Opt.some(move(pong)))))

proc withPreamble*(_: typedesc[RPCMsg], preamble: sink seq[Preamble]): RPCMsg =
  RPCMsg(preambleExtension: Opt.some(PreambleExtensionRPC(preamble: move(preamble))))

proc withPreamble*(
    _: typedesc[RPCMsg], msgs: seq[Message], msgIds: seq[MessageId]
): RPCMsg =
  var preambles: seq[Preamble]
  for i, m in msgs:
    preambles.add(
      Preamble(
        topicID: Opt.some(m.topic),
        messageID: Opt.some(msgIds[i]),
        messageLength: Opt.some(m.data.len.uint32),
      )
    )
  RPCMsg.withPreamble(preambles)

proc withPreamble*(
    _: typedesc[RPCMsg], topic: string, msgId: MessageId, messageLength: int
): RPCMsg =
  RPCMsg.withPreamble(
    @[
      Preamble(
        topicID: Opt.some(topic),
        messageID: Opt.some(msgId),
        messageLength: Opt.some(messageLength.uint32),
      )
    ]
  )

proc withIMReceiving*(_: typedesc[RPCMsg], imreceiving: sink seq[IMReceiving]): RPCMsg =
  RPCMsg(
    preambleExtension: Opt.some(PreambleExtensionRPC(imreceiving: move(imreceiving)))
  )

proc withIMReceiving*(_: typedesc[RPCMsg], preamble: sink Preamble): RPCMsg =
  let messageLength = preamble.messageLength
  RPCMsg.withIMReceiving(
    @[IMReceiving(messageID: move(preamble.messageID), messageLength: messageLength)]
  )

template isSubscribe*(s: SubOpts): bool =
  s.subscribe.get(false)

func anonymize*(msg: Message, anonymize: bool): Message =
  if anonymize:
    Message(data: msg.data, topic: msg.topic)
  else:
    msg

func anonymize*(msg: RPCMsg, anonymize: bool): RPCMsg =
  if anonymize and msg.messages.len > 0:
    var anonMsg = msg
    for m in anonMsg.messages.mitems:
      m.fromPeer = PeerId()
      m.seqno = @[]
      m.signature = @[]
      m.key = @[]
    anonMsg
  else:
    msg

func validate*(sub: SubOpts): LPResult[void] =
  if sub.topic.isNone:
    return err("Subsciption topic must be set")
  ok()

func validate*(msg: RPCMsg): LPResult[void] =
  # validates RPCMsg after it is received and decoded.
  for sub in msg.subscriptions:
    ?sub.validate()
  for message in msg.messages:
    if message.topic.len == 0:
      return err("Message topic must be set")
  ok()
