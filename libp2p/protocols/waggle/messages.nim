# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

{.push raises: [].}

import protobuf_serialization, protobuf_serialization/pkg/results
import ../../utils/protobuf

export results

# https://github.com/libp2p/specs/pull/732, revision 9328b68
type
  TopicSubscription* {.proto2.} = object
    topicId* {.fieldNumber: 1, required.}: seq[byte]

  ObjectPieces* {.proto2.} = object
    objectId* {.fieldNumber: 2, required.}: seq[byte]
    piecesMetadata* {.fieldNumber: 3.}: Opt[seq[byte]]
    pieces* {.fieldNumber: 4.}: Opt[seq[byte]]

Protobuf.serializerFor(
  [TopicSubscription, ObjectPieces], withMetrics = true, domain = "waggle"
)

func encodedSize*(msg: ObjectPieces): int =
  Protobuf.computeSize(msg)
