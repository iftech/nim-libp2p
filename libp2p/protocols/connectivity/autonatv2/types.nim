# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import results, chronos
import
  protobuf_serialization,
  protobuf_serialization/pkg/results,
  protobuf_serialization/std/enums
import ../../../[multiaddress, peerid]
import ../../../errors
import ../../../protocodec
import ../../../utils/protobuf
from ../autonat/types import NetworkReachability

export NetworkReachability

const
  DefaultDialTimeout*: Duration = 15.seconds
  DefaultAmplificationAttackDialTimeout*: Duration = 3.seconds
  DefaultDialDataSize*: uint64 = 50 * 1024 # 50 KiB > 50 KB
  DefaultMaxConcurrentDialBacks*: int = 8
  DefaultMaxConcurrentRequestsPerPeer*: int = 2
  DefaultMaxConcurrentRequestsTotal*: int = 16
  AutonatV2MsgLpSize*: int = 1024
  DialBackLpSize*: int = 1024
  # readLp needs to receive more than 4096 bytes (since it's a DialDataResponse) + overhead
  DialDataResponseLpSize*: int = 5000
  AutonatV2DialRequestCodec* = ProtoCodec("/libp2p/autonat/2/dial-request")
  AutonatV2DialBackCodec* = ProtoCodec("/libp2p/autonat/2/dial-back")

type
  AutonatV2Response* = object
    reachability*: NetworkReachability
    dialResp*: DialResponse
    addrs*: Opt[MultiAddress]

  AutonatV2Error* = object of LPError

  Nonce* = uint64

  AddrIdx* = uint32

  NumBytes* = uint64

  ResponseStatus* {.pure.} = enum
    EInternalError = 0
    ERequestRejected = 100
    EDialRefused = 101
    Ok = 200

  DialBackStatus* {.pure.} = enum
    Ok = 0

  DialStatus* {.pure.} = enum
    Unused = 0
    EDialError = 100
    EDialBackError = 101
    Ok = 200

  DialRequest* {.proto3.} = object
    addrs* {.fieldNumber: 1, ext.}: seq[MultiAddress]
    nonce* {.fieldNumber: 2, fixed.}: Nonce

  DialResponse* {.proto3.} = object
    status* {.fieldNumber: 1, ext.}: ResponseStatus
    addrIdx* {.fieldNumber: 2, pint.}: Opt[AddrIdx]
    dialStatus* {.fieldNumber: 3, ext.}: Opt[DialStatus]

  DialBack* {.proto3.} = object
    nonce* {.fieldNumber: 1, fixed.}: Nonce

  DialBackResponse* {.proto3.} = object
    status* {.fieldNumber: 1, ext.}: DialBackStatus

  DialDataRequest* {.proto3.} = object
    addrIdx* {.fieldNumber: 1, pint.}: AddrIdx
    numBytes* {.fieldNumber: 2, pint.}: NumBytes

  DialDataResponse* {.proto3.} = object
    data* {.fieldNumber: 1.}: seq[byte]

  MsgKind* {.pure, proto3.} = enum
    notSet = 0
    DialRequest = 1
    DialResponse = 2
    DialDataRequest = 3
    DialDataResponse = 4

  AutonatV2MsgOneof* {.proto3, oneof.} = object
    case kind*: MsgKind
    of MsgKind.notSet:
      discard
    of MsgKind.DialRequest:
      dialRequest* {.fieldNumber: 1.}: DialRequest
    of MsgKind.DialResponse:
      dialResponse* {.fieldNumber: 2.}: DialResponse
    of MsgKind.DialDataRequest:
      dialDataRequest* {.fieldNumber: 3.}: DialDataRequest
    of MsgKind.DialDataResponse:
      dialDataResponse* {.fieldNumber: 4.}: DialDataResponse

  AutonatV2Msg* {.proto3.} = object
    oneof* {.oneof.}: AutonatV2MsgOneof

Protobuf.serializerFor([DialBack, DialBackResponse])
Protobuf.serializerFor([AutonatV2Msg], withMetrics = true, domain = "autonat-v2")

# Custom `==` is needed to ensure consistent comparison with Opt-based fields
proc `==`*(a, b: AutonatV2Msg): bool =
  a.oneof.kind == b.oneof.kind and a.encode() == b.encode()
