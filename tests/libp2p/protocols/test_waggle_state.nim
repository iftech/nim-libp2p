# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ./waggle_utils
import ../../../libp2p/protocols/waggle/state
import ../../tools/[unittest, crypto]

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
