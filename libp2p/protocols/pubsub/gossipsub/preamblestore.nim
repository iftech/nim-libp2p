# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, std/[tables, heapqueue, sets]
import ../rpc/messages
import ../../../peerid

type
  PeerSet = object
    order: seq[PeerId]
    peers: HashSet[PeerId]

  PreambleInfo* = ref object
    messageId*: MessageId
    messageLength*: uint32
    topicId*: string
    sender*: PeerId
    startsAt*: Moment
    expiresAt*: Moment
    deleted: bool # tombstone marker
    peerSet: PeerSet

  PreambleStore* = object
    byId: Table[MessageId, PreambleInfo]
    heap: HeapQueue[PreambleInfo]

proc `<`(a, b: PreambleInfo): bool =
  a.expiresAt < b.expiresAt

proc init*(
    T: typedesc[PreambleInfo],
    preamble: Preamble,
    sender: PeerId,
    startsAt: Moment,
    expiresAt: Moment,
): T =
  PreambleInfo(
    messageId: preamble.messageID.get(),
    messageLength: preamble.messageLength.get(0),
    topicId: preamble.topicID.get(),
    sender: sender,
    startsAt: startsAt,
    expiresAt: expiresAt,
    peerSet: PeerSet(),
  )

proc init*(T: typedesc[PreambleStore]): T =
  T(byId: initTable[MessageId, PreambleInfo](), heap: initHeapQueue[PreambleInfo]())

proc insert*(ps: var PreambleStore, info: PreambleInfo) =
  try:
    if ps.byId.hasKey(info.messageId):
      ps.byId[info.messageId].deleted = true
    ps.byId[info.messageId] = info
    ps.heap.push(info)
  except KeyError:
    raiseAssert "checked with hasKey"

proc hasKey*(ps: PreambleStore, msgId: MessageId): bool =
  return ps.byId.hasKey(msgId)

proc `[]`*(ps: PreambleStore, msgId: MessageId): PreambleInfo =
  ps.byId[msgId]

proc del*(ps: var PreambleStore, msgId: MessageId) =
  try:
    if ps.byId.hasKey(msgId):
      ps.byId[msgId].deleted = true
      ps.byId.del(msgId)
  except KeyError:
    raiseAssert "checked with hasKey"

proc len*(ps: PreambleStore): int =
  return ps.byId.len

proc popExpired*(ps: var PreambleStore, now: Moment): Opt[PreambleInfo] =
  while ps.heap.len > 0:
    if ps.heap[0].deleted:
      discard ps.heap.pop()
    elif ps.heap[0].expiresAt <= now:
      let top = ps.heap.pop()
      ps.byId.del(top.messageId)
      return Opt.some(top)
    else:
      return Opt.none(PreambleInfo)

template withValue*(ps: var PreambleStore, key: MessageId, value, body: untyped) =
  try:
    if ps.hasKey(key):
      let value {.inject.} = ps.byId[key]
      body
  except system.KeyError:
    raiseAssert "checked with hasKey"

const maxPossiblePeersOnPeerSet* = 6

proc addPossiblePeerToQuery*(ps: var PreambleStore, msgId: MessageId, peerId: PeerId) =
  if not ps.hasKey(msgId):
    return

  try:
    var preamble = ps[msgId]
    if not preamble.peerSet.peers.contains(peerId):
      if preamble.peerSet.order.len == maxPossiblePeersOnPeerSet:
        let evicted: PeerId = preamble.peerSet.order[0]
        preamble.peerSet.order.delete(0)
        preamble.peerSet.peers.excl(evicted)
      preamble.peerSet.order.add(peerId)
      preamble.peerSet.peers.incl(peerId)
  except KeyError:
    raiseAssert "checked with hasKey"

proc possiblePeersToQuery*(preamble: PreambleInfo): seq[PeerId] =
  preamble.peerSet.order
