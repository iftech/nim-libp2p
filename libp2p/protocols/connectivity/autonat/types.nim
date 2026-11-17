# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import results, chronos, chronicles
import
  protobuf_serialization,
  protobuf_serialization/pkg/results,
  protobuf_serialization/std/enums,
  ../../../multiaddress,
  ../../../peerid,
  ../../../errors,
  ../../../utils/protobuf

logScope:
  topics = "libp2p autonat"

const
  AutonatCodec* = "/libp2p/autonat/1.0.0"
  AddressLimit* = 8
  DefaultMaxIncomingStreamsTotal* = 8
  DefaultMaxIncomingStreamsPerPeer* = 1

type
  AutonatError* = object of LPError
  AutonatUnreachableError* = object of LPError

  MsgType* {.pure.} = enum
    Dial = 0
    DialResponse = 1

  ResponseStatus* = enum
    Ok = 0
    DialError = 100
    DialRefused = 101
    BadRequest = 200
    InternalError = 300

  AutonatPeerInfo* {.proto2.} = object
    id* {.fieldNumber: 1, ext.}: Opt[PeerId]
    addrs* {.fieldNumber: 2, ext.}: seq[MultiAddress]

  AutonatDial* {.proto2.} = object
    peerInfo* {.fieldNumber: 1.}: Opt[AutonatPeerInfo]

  AutonatDialResponse* {.proto2.} = object
    status* {.fieldNumber: 1, ext.}: Opt[ResponseStatus]
    text* {.fieldNumber: 2.}: Opt[string]
    ma* {.fieldNumber: 3, ext.}: Opt[MultiAddress]

  AutonatMsg* {.proto2.} = object
    msgType* {.fieldNumber: 1, ext.}: Opt[MsgType]
    dial* {.fieldNumber: 2.}: Opt[AutonatDial]
    response* {.fieldNumber: 3.}: Opt[AutonatDialResponse]

  NetworkReachability* {.pure.} = enum
    Unknown
    NotReachable
    Reachable

proc isReachable*(self: NetworkReachability): bool =
  self == NetworkReachability.Reachable

Protobuf.serializerFor([AutonatMsg], withMetrics = true, domain = "autonat-v1")
