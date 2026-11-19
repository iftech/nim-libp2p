# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

type
  MessagePriority* {.pure.} = enum
    High
      ## Protocol-critical messages: subscriptions, GRAFT, PRUNE, IHAVE,
      ## IDontWant, control responses. Sent immediately. If max is exceeded
      ## we drop the peer.
    Medium
      ## Locally published messages. Sent before low priority traffic.
      ## They are dropped if exceeded max. Peer is not disconnected.
    Low
      ## Relayed messages and IWANT replies
      ## They are dropped if exceeded max. Peer is not disconnected.

  QueueAction* = object
    priority*: MessagePriority
    send*: bool
      # if true msg should be sent respecting priority, if false it means drop/disconnect
    slowPeerPenaltyDelta*: float64

  QueueEviction* =
    proc(priority: MessagePriority, amount: int): int {.gcsafe, raises: [].}

  OutboundQueue* = ref object
    ## Accounting shared with topic writers; PubSubPeer owns admission and limits.
    bytes*, evictableBytes*: array[MessagePriority, int]
    topicCounts*: array[MessagePriority, int]
    admit*: proc(priority: MessagePriority, messageBytes: int): QueueAction {.
      gcsafe, raises: []
    .}
    evictTopics*: QueueEviction
    # Synchronous notification; must not re-enter admission or mutate topic writers.
    evicted*: proc(priority: MessagePriority, messageBytes: int) {.gcsafe, raises: [].}

func queuedBytes*(q: OutboundQueue): int =
  q.bytes[High] + q.bytes[Medium] + q.bytes[Low]
