# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../../../libp2p/protocols/pubsub/pubsubpeer
import ../../../libp2p/peerid
import ../../tools/crypto

proc noopRpcHandler(
    peer: PubSubPeer, data: sink seq[byte]
) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
  discard

proc newQueuePeer*(
    maxOutboundQueueBytes = DefaultMaxOutboundQueueBytes,
    maxMediumPriorityQueueLen = DefaultMaxMediumPriorityQueueLen,
    maxHighPriorityQueueLen = DefaultMaxHighPriorityQueueLen,
    maxLowPriorityQueueLen = DefaultMaxLowPriorityQueueLen,
    maxMessageSize = 1024,
    getStream: GetStream = nil,
    onEvent: OnEvent = nil,
    codec = UnsetProtoCodec,
): PubSubPeer =
  PubSubPeer.new(
    PeerId.random(),
    getStream,
    onEvent,
    codec,
    maxMessageSize,
    noopRpcHandler,
    rng = rng(),
    maxOutboundQueueBytes = maxOutboundQueueBytes,
    maxMediumPriorityQueueLen = maxMediumPriorityQueueLen,
    maxHighPriorityQueueLen = maxHighPriorityQueueLen,
    maxLowPriorityQueueLen = maxLowPriorityQueueLen,
  )
