# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/
    [peerid, protocols/pubsub/gossipsub/preamblestore, protocols/pubsub/rpc/messages]
import ../../tools/[unittest]
import ./utils

proc mockPreamble(
    id: MessageId = MessageId(@[1.byte, 2.byte, 3.byte]),
    startOffset: Duration = 0.seconds,
    expireOffset: Duration = 10.seconds,
    sender: PeerId = PeerId.random(),
): PreambleInfo =
  let now = Moment.now()
  PreambleInfo.init(
    Preamble(messageID: id, messageLength: 123.uint32, topicID: "topic-123"),
    sender = sender,
    startsAt = now + startOffset,
    expiresAt = now + expireOffset,
  )

suite "preamble store":
  teardown:
    checkTrackers()

  test "insert and retrieve":
    var store = PreambleStore.init()

    let p = mockPreamble()
    store.insert(p)
    check:
      store.hasKey(p.messageId)
      store[p.messageId] == p

  test "heap order is preserved on inserts":
    var store = PreambleStore.init()
    for i in 0 .. 9:
      let p = mockPreamble(MessageId(@[i.byte]), 0.seconds, i.seconds)
      store.insert(p)

    var lastExpiresAt = Moment.low()
    var lastStartsAt = Moment.low()
    while true:
      let popped = store.popExpired(Moment.now() + 20.seconds)
      if popped.isNone:
        break
      check popped.get().expiresAt >= lastExpiresAt
      lastExpiresAt = popped.get().expiresAt
      check popped.get().startsAt >= lastStartsAt
      lastStartsAt = popped.get().startsAt

  test "deletion marks AND heap pop discards deleted":
    var store = PreambleStore.init()
    let p1 = mockPreamble(MessageId(@[1.byte, 1.byte, 1.byte]), 0.seconds, 1.seconds)
    let p2 = mockPreamble(MessageId(@[2.byte, 2.byte, 2.byte]), 0.seconds, 2.seconds)
    store.insert(p1)
    store.insert(p2)
    store.del(p1.messageId)

    # p1 is now deleted in heap, but still there
    let res = store.popExpired(Moment.now() + 5.seconds)
    check:
      res.isSome()
      res.get().messageId == p2.messageId # p1 was skipped

  test "overwrite twice keeps latest, heap has garbage record":
    var store = PreambleStore.init()

    let m1 = MessageId(@[1.byte, 1.byte, 1.byte])
    store.insert(mockPreamble(m1, 0.seconds, 1.seconds))
    store.insert(mockPreamble(m1, 0.seconds, 5.seconds))

    let res = store.popExpired(Moment.now() + 2.seconds)
    check res.isNone() # first insert is expired but ignored

    let res2 = store.popExpired(Moment.now() + 10.seconds)
    check:
      res2.isSome()
      res2.get().messageId == m1

  test "possiblePeersToQuery is affected by eviction and caps at 6":
    var store = PreambleStore.init()

    let p = mockPreamble()
    store.insert(p)

    # add 10 peers — only last 6 should survive
    var peersInserted: seq[PeerId] = @[]
    for i in 0 ..< maxPossiblePeersOnPeerSet * 2:
      let peerId = PeerId.random()
      peersInserted.add(peerId)
      store.addPossiblePeerToQuery(p.messageId, peerId)

    let peersToQuery = store[p.messageId].possiblePeersToQuery()
    check:
      peersToQuery.len == maxPossiblePeersOnPeerSet
      peersToQuery ==
        peersInserted[maxPossiblePeersOnPeerSet ..< maxPossiblePeersOnPeerSet * 2]

  test "re-adding same peer doesn't evict or reorder":
    var store = PreambleStore.init()
    let p = mockPreamble()

    store.insert(p)

    for _ in 0 .. maxPossiblePeersOnPeerSet * 2:
      store.addPossiblePeerToQuery(p.messageId, p.sender)

    let peersToQuery = store[p.messageId].possiblePeersToQuery()
    check:
      peersToQuery.len == 1
      peersToQuery[0] == p.sender

  test "withValue macro works sanely":
    var store = PreambleStore.init()
    let p = mockPreamble()
    store.insert(p)

    var inside = false
    store.withValue(p.messageId, val):
      check val.messageId == p.messageId
      inside = true
    check inside

  test "len matches insert/delete":
    var store = PreambleStore.init()
    check store.len == 0

    let p = mockPreamble()

    store.insert(p)
    check store.len == 1
    store.del(p.messageId)
    check store.len == 0
