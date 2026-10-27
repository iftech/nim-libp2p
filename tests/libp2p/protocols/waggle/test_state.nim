# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./utils
import ../../../../libp2p/protocols/waggle/state
import ../../../tools/[unittest, crypto]

const topic = @[byte 1]

suite "Waggle reconciliation state":
  test "reconciliation sends only missing pieces and suppresses repeated metadata":
    let state = WaggleState.new(10, 2)
    let peer = PeerId.random()
    check state.store(topic, BitShard(id: @[byte 1], have: 3)).get()
    let tx = state.prepare(topic, 1, peer, @[byte 1]).get().get()
    check tx.message.pieces == Opt.some(@[byte 3])
    check tx.message.piecesMetadata == Opt.some(@[byte 3])
    tx.commit()
    check state.prepare(topic, 1, peer, @[byte 1]).get().isNone
    check state.store(topic, BitShard(id: @[byte 1], have: 7)).get()
    let next = state.prepare(topic, 1, peer, @[byte 1]).get().get()
    check next.message.pieces == Opt.some(@[byte 4])
    check next.message.piecesMetadata == Opt.some(@[byte 7])

  test "metadata gossip does not mark omitted pieces as sent":
    let state = WaggleState.new(10, 2)
    let peer = PeerId.random()
    discard state.store(topic, BitShard(id: @[byte 1], have: 7)).get()
    let gossip =
      state.prepare(topic, 1, peer, @[byte 1], metadataOnly = true).get().get()
    check gossip.message.pieces.isNone
    gossip.commit()
    let pieces = state.prepare(topic, 1, peer, @[byte 1]).get().get()
    check pieces.message.pieces == Opt.some(@[byte 7])
    check pieces.message.piecesMetadata.isNone

  test "incoming metadata selects replies and controls application delivery":
    let state = WaggleState.new(10, 2)
    let peer = PeerId.random()
    discard state.store(topic, BitShard(id: @[byte 1], have: 3)).get()
    let incoming = ObjectPieces(
      objectId: @[byte 1],
      piecesMetadata: Opt.some(@[byte 5]),
      pieces: Opt.some(@[byte 4]),
    )
    let action = state.received(topic, 1, peer, incoming).get()
    check action.emit
    check action.reply.get().message.pieces == Opt.some(@[byte 2])
    check not state.peerView(topic, 1, @[byte 1]).advertised
    action.reply.get().commit()
    check state.peerView(topic, 1, @[byte 1]).advertised
    check not state
      .received(
        topic,
        1,
        peer,
        ObjectPieces(objectId: @[byte 1], piecesMetadata: Opt.some(@[byte 5])),
      )
      .get().active

  test "unknown objects are surfaced and duplicate advertisements suppressed":
    let state = WaggleState.new(2, 1)
    let peer = PeerId.random()
    let msg = ObjectPieces(objectId: @[byte 1], piecesMetadata: Opt.some(@[byte 1]))
    check state.received(topic, 1, peer, msg).get().emit
    check not state.received(topic, 1, peer, msg).get().active
    let payload = ObjectPieces(objectId: @[byte 1], pieces: Opt.some(@[byte 1]))
    check state.received(topic, 1, peer, payload).get().emit
    check state.received(@[byte 2], 1, peer, msg).isErr

  test "LRU eviction and remote view bounds release state":
    let state = WaggleState.new(2, 2)
    let peer = PeerId.random()
    for id in 1.byte .. 2.byte:
      discard state.store(topic, BitShard(id: @[id], have: 1)).get()
    discard state.prepare(topic, 1, peer, @[byte 1]).get()
    discard state.store(topic, BitShard(id: @[byte 3], have: 1)).get()
    check state.cachedObjects(topic) == 2
    check state.prepare(topic, 1, peer, @[byte 2]).get().isNone
    for id in 1.byte .. 10.byte:
      discard state
        .received(
          topic,
          2,
          peer,
          ObjectPieces(objectId: @[id], piecesMetadata: Opt.some(@[byte 1])),
        )
        .get()
    check state.trackedObjects(topic, 2) == 2
    state.removeConnection(2)
    check state.trackedObjects(topic, 2) == 0
    state.removeTopic(topic)
    check state.cachedObjects(topic) == 0
    check state.trackedObjects(topic, 1) == 0

  test "invalid metadata is rejected without advancing tracked state":
    let state = WaggleState.new(2, 1)
    let peer = PeerId.random()
    discard state.store(topic, BitShard(id: @[byte 1], have: 1)).get()
    state.prepare(topic, 1, peer, @[byte 1]).get().get().commit()
    check state.received(
      topic,
      1,
      peer,
      ObjectPieces(objectId: @[byte 1], piecesMetadata: Opt.some(@[byte 255])),
    ).isErr
    check state.prepare(topic, 1, peer, @[byte 1]).get().isNone

  test "local reads refresh eviction order":
    let state = WaggleState.new(2, 1)
    let peer = PeerId.random()
    discard state.store(topic, BitShard(id: @[byte 1], have: 1)).get()
    discard state.store(topic, BitShard(id: @[byte 2], have: 1)).get()
    check state.prepare(topic, 1, peer, @[byte 1]).get().isSome
    discard state.store(topic, BitShard(id: @[byte 3], have: 1)).get()
    check state.prepare(topic, 1, peer, @[byte 2]).get().isNone
    check state.prepare(topic, 1, peer, @[byte 1]).get().isSome
    check state.prepare(topic, 1, peer, @[byte 3]).get().isSome

  test "replacing a full cache entry refreshes eviction order":
    let state = WaggleState.new(2, 1)
    let peer = PeerId.random()
    discard state.store(topic, BitShard(id: @[byte 1], have: 1)).get()
    discard state.store(topic, BitShard(id: @[byte 2], have: 1)).get()
    check state.store(topic, BitShard(id: @[byte 1], have: 3)).get()
    check state.prepare(topic, 1, peer, @[byte 2]).get().isSome
    discard state.store(topic, BitShard(id: @[byte 1], have: 3)).get()
    discard state.store(topic, BitShard(id: @[byte 3], have: 1)).get()
    check state.prepare(topic, 1, peer, @[byte 2]).get().isNone
    check state.prepare(topic, 1, peer, @[byte 1]).get().get().message.pieces ==
      Opt.some(@[byte 3])
    check state.prepare(topic, 1, peer, @[byte 3]).get().isSome

  test "duplicate remote advertisements refresh eviction order":
    let state = WaggleState.new(2, 1)
    let peer = PeerId.random()
    let first = ObjectPieces(objectId: @[byte 1], piecesMetadata: Opt.some(@[byte 1]))
    let second = ObjectPieces(objectId: @[byte 2], piecesMetadata: Opt.some(@[byte 1]))
    let third = ObjectPieces(objectId: @[byte 3], piecesMetadata: Opt.some(@[byte 1]))
    check state.received(topic, 1, peer, first).get().active
    check state.received(topic, 1, peer, second).get().active
    check not state.received(topic, 1, peer, first).get().active
    check state.received(topic, 1, peer, third).get().active
    check state.peerView(topic, 1, first.objectId).known
    check not state.peerView(topic, 1, second.objectId).known
    check state.peerView(topic, 1, third.objectId).known

  test "both bit metadata consumers reject invalid encodings":
    let metadata = BitMetadata(have: 1)
    let shard = BitShard(id: @[byte 1], have: 1)
    let peer = PeerId.random()
    for data in [newSeq[byte](), @[byte 1, 2], @[byte 8]]:
      check metadata.update(data).error == "invalid bit metadata"
      check metadata.have == 1
      check shard.actionFromMetadata(peer, 1, Opt.some(data)).error ==
        "invalid bit metadata"

  test "expiry stops serving objects and forgets stale peer views":
    let state = WaggleState.new(2, 1, 10.seconds)
    let peer = PeerId.random()
    let now = Moment.now()
    discard state.store(topic, BitShard(id: @[byte 1], have: 1), now).get()
    state.prepare(topic, 1, peer, @[byte 1], now = now).get().get().commit()
    check state.peerView(topic, 1, @[byte 1], now).known
    check state.hasLocal(topic, @[byte 1], now + 9.seconds)
    check not state.hasLocal(topic, @[byte 1], now + 10.seconds)
    check state.prepare(topic, 1, peer, @[byte 1], now = now + 10.seconds).get().isNone
    check not state.peerView(topic, 1, @[byte 1], now + 10.seconds).known
    discard state.store(topic, BitShard(id: @[byte 1], have: 1), now + 10.seconds).get()
    check state.prepare(topic, 1, peer, @[byte 1], now = now + 10.seconds).get().isSome

  test "removal clears one object's snapshot and views without disturbing another":
    let state = WaggleState.new(2, 1)
    let peer = PeerId.random()
    for id in [1.byte, 2.byte]:
      discard state.store(topic, BitShard(id: @[id], have: 1)).get()
      state.prepare(topic, 1, peer, @[id]).get().get().commit()
    check state.removeObject(topic, @[byte 1])
    check not state.removeObject(topic, @[byte 1])
    check not state.hasLocal(topic, @[byte 1])
    check not state.peerView(topic, 1, @[byte 1]).known
    check state.hasLocal(topic, @[byte 2])
    check state.peerView(topic, 1, @[byte 2]).known

  test "metadata discovery creates an observer without claiming to know its pieces":
    let state = WaggleState.new(2, 1)
    let peer = PeerId.random()
    discard state.store(topic, BitShard(id: @[byte 1], have: 1)).get()
    check state.peerView(topic, 1, @[byte 1]) == (false, false)
    state.prepare(topic, 1, peer, @[byte 1], metadataOnly = true).get().get().commit()
    check state.peerView(topic, 1, @[byte 1]) == (false, true)
    discard state
      .received(
        topic,
        1,
        peer,
        ObjectPieces(objectId: @[byte 1], piecesMetadata: Opt.some(@[byte 0])),
      )
      .get()
    check state.peerView(topic, 1, @[byte 1]) == (true, true)
