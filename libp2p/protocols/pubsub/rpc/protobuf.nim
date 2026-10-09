# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import protobuf_serialization, protobuf_serialization/pkg/results
import ../../../utils/[protobuf]
import ../../../[peerid]
import messages

proc encode*(msg: Message, anonymize: bool): seq[byte] =
  encode(Protobuf, msg.anonymize(anonymize))

proc decodeMessage(buf: seq[byte]): Message {.raises: [SerializationError].} =
  decode(Protobuf, buf, Message)

proc decode*(_: type Message, buf: seq[byte]): LPResult[Message] =
  try:
    ok(decodeMessage(buf))
  except SerializationError as e:
    err(e, "failed to decode Message from protobuf bytes")

proc encode*(msg: RPCMsg, anonymize: bool): seq[byte] =
  let encoded = encode(Protobuf, msg.anonymize(anonymize))
  trackEncodeBytes(encoded.len, RPCMsg, "gossipsub")
  encoded

proc decodeRPCMessage(buf: seq[byte]): RPCMsg {.raises: [SerializationError].} =
  trackDecodeBytes(buf.len, RPCMsg, "gossipsub")
  decode(Protobuf, buf, RPCMsg)

proc decode*(_: type RPCMsg, buf: seq[byte]): LPResult[RPCMsg] =
  try:
    let msg = decodeRPCMessage(buf)
    ?msg.validate()
    ok(msg)
  except SerializationError as e:
    err(e, "failed to decode RPCMsg from protobuf bytes")

proc encodedSize*(rpc: RPCMsg): int =
  Protobuf.computeSize(rpc)
