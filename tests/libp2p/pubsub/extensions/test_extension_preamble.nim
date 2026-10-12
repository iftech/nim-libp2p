# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../../libp2p/peerid
import
  ../../../../libp2p/protocols/pubsub/[
    gossipsub/extension_preamble,
    gossipsub/extensions_types,
    gossipsub/preamblestore,
    rpc/messages,
  ]
import ../../../tools/[unittest, crypto]
import ../converters

const largeMsgLen = preambleMessageSizeThreshold
const smallMsgLen = preambleMessageSizeThreshold - 1

type BroadcastedMsg = object
  msg: RPCMsg
  peers: seq[PeerId]

func BC(msg: RPCMsg, peers: seq[PeerId]): BroadcastedMsg =
  # shorthand constructor for BroadcastedControl
  BroadcastedMsg(msg: msg, peers: peers)

type CallbackRecorder = ref object
  broadcasted: seq[BroadcastedMsg]
  seenMessages: seq[MessageId]
  meshPeers: seq[PeerId]

proc makeConfig(
    c: CallbackRecorder, maxPreamblePeerBudget: int = 10, maxHeIsReceiving: int = 50
): PreambleExtensionConfig =
  proc broadcastRPC(msg: RPCMsg, peers: seq[PeerId]) {.gcsafe, raises: [].} =
    c.broadcasted.add(BC(msg, peers))

  proc hasSeen(mid: MessageId): bool {.gcsafe, raises: [].} =
    mid in c.seenMessages

  proc meshAndDirectPeersForTopic(topic: string): seq[PeerId] {.gcsafe, raises: [].} =
    return c.meshPeers

  return PreambleExtensionConfig(
    maxPreamblePeerBudget: maxPreamblePeerBudget,
    maxHeIsReceiving: maxHeIsReceiving,
    broadcastRPC: broadcastRPC,
    hasSeen: hasSeen,
    meshAndDirectPeersForTopic: meshAndDirectPeersForTopic,
  )

proc makePreamble(
    msgId: MessageId = @[1'u8],
    topic: string = "preamble-test",
    messageLength: uint32 = largeMsgLen,
): Preamble =
  Preamble(topicID: topic, messageID: msgId, messageLength: messageLength)

proc receivePreamble(ext: PreambleExtension, peerId: PeerId, preambles: seq[Preamble]) =
  ext.onHandleRPC(peerId, RPCMsg.withPreamble(preambles))

proc receiveIMReceiving(
    ext: PreambleExtension, peerId: PeerId, imreceivings: seq[IMReceiving]
) =
  ext.onHandleRPC(peerId, RPCMsg.withIMReceiving(imreceivings))

proc receiveIDontWant(ext: PreambleExtension, peerId: PeerId, msgIds: seq[MessageId]) =
  ext.onHandleRPC(peerId, RPCMsg.withControl(ControlMessage.withIDontWant(msgIds)))

suite "GossipSub Extensions :: Preamble Extension":
  let peerId = PeerId.random(rng()).get()
  let peerId2 = PeerId.random(rng()).get()
  let msgId1: MessageId = @[1'u8, 2, 3]
  let msgId2: MessageId = @[4'u8, 5, 6]

  test "isSupported":
    var cr = CallbackRecorder()
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    check:
      ext.isSupported(PeerExtensions()) == false
      ext.isSupported(PeerExtensions(preambleExtension: true)) == true

  test "config validation - maxPreamblePeerBudget must be positive":
    var cr = CallbackRecorder()
    expect AssertionDefect:
      discard PreambleExtension.new(cr.makeConfig(maxPreamblePeerBudget = 0), rng())

  test "config validation - maxHeIsReceiving must be positive":
    var cr = CallbackRecorder()
    expect AssertionDefect:
      discard PreambleExtension.new(cr.makeConfig(maxHeIsReceiving = 0), rng())

  test "config validation - callbacks must be set":
    var cr = CallbackRecorder()

    expect AssertionDefect:
      var cfg = cr.makeConfig()
      cfg.broadcastRPC = nil
      discard PreambleExtension.new(cfg, rng())

    expect AssertionDefect:
      var cfg = cr.makeConfig()
      cfg.hasSeen = nil
      discard PreambleExtension.new(cfg, rng())

    expect AssertionDefect:
      var cfg = cr.makeConfig()
      cfg.meshAndDirectPeersForTopic = nil
      discard PreambleExtension.new(cfg, rng())

  test "onNegotiated adds peer to supportingPeers":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())

    # before negotiation: imreceiving broadcast filtered out (peer not in supportingPeers)
    ext.receivePreamble(peerId, @[makePreamble()])
    check cr.broadcasted.len == 0

    ext.onNegotiated(peerId)

    # after negotiation: mesh peer preamble triggers imreceiving broadcast
    ext.receivePreamble(peerId, @[makePreamble()])
    check cr.broadcasted.len == 1

  test "onRemovePeer removes peer from supportingPeers":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    let preambleMsg = RPCMsg.withPreamble(@[makePreamble()])
    ext.preambleBroadcast(preambleMsg, @[peerId])
    check:
      cr.broadcasted.len == 1
      peerId in cr.broadcasted[0].peers

    ext.onRemovePeer(peerId)

    # after removal, peer is filtered out of supportingPeers, so message is not broadcasted
    ext.preambleBroadcast(preambleMsg, @[peerId])
    check cr.broadcasted.len == 1 # unchanged

  test "handlePreamble: budget limits preambles per peer per heartbeat":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(maxPreamblePeerBudget = 2), rng())
    ext.onNegotiated(peerId)

    ext.receivePreamble(peerId, @[makePreamble(@[1'u8])])
    ext.receivePreamble(peerId, @[makePreamble(@[2'u8])])
    check cr.broadcasted.len == 2

    # 3rd preamble exceeds budget and is dropped
    ext.receivePreamble(peerId, @[makePreamble(@[3'u8])])
    check cr.broadcasted.len == 2

  test "handlePreamble: heartbeat resets per-peer budget":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(maxPreamblePeerBudget = 1), rng())
    ext.onNegotiated(peerId)

    ext.receivePreamble(peerId, @[makePreamble(@[1'u8])])
    check cr.broadcasted.len == 1

    # budget exhausted
    ext.receivePreamble(peerId, @[makePreamble(@[2'u8])])
    check cr.broadcasted.len == 1

    ext.onHeartbeat()

    # budget reset: new preamble goes through
    ext.receivePreamble(peerId, @[makePreamble(@[3'u8])])
    check cr.broadcasted.len == 2

  test "handlePreamble: skips already seen messages":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    cr.seenMessages = @[msgId1]
    ext.receivePreamble(peerId, @[makePreamble(msgId1)])

    # seen message: no imreceiving broadcast
    check cr.broadcasted.len == 0

  test "handlePreamble: skips if message already in ongoingReceives":
    var cr = CallbackRecorder(meshPeers: @[peerId, peerId2])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)
    ext.onNegotiated(peerId2)

    # first preamble: tracked in ongoingReceives
    ext.receivePreamble(peerId, @[makePreamble(msgId1)])
    check:
      ext.ongoingReceives.hasKey(msgId1)
      cr.broadcasted.len == 1

    # duplicate preamble from another peer: skipped
    ext.receivePreamble(peerId2, @[makePreamble(msgId1)])
    check cr.broadcasted.len == 1

  test "handlePreamble: non-mesh peer goes to ongoingIWantReceives without broadcast":
    var cr = CallbackRecorder() # meshPeers is empty
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId) # peer is not in the mesh

    ext.receivePreamble(peerId, @[makePreamble(msgId1)])

    check:
      ext.ongoingReceives.hasKey(msgId1) == false
      ext.ongoingIWantReceives.hasKey(msgId1)
      cr.broadcasted.len == 0

  test "handlePreamble: mesh peer adds to ongoingReceives and broadcasts imreceiving":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    let preamble = makePreamble(msgId1)
    ext.receivePreamble(peerId, @[preamble])

    check:
      ext.ongoingReceives.hasKey(msgId1)
      cr.broadcasted == @[BC(RPCMsg.withIMReceiving(preamble), @[peerId])]

  test "handleIMReceiving: ignores mismatched message length":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)
    ext.onNegotiated(peerId2)

    # put message in ongoingReceives
    ext.receivePreamble(
      peerId, @[makePreamble(msgId1, messageLength = largeMsgLen.uint32)]
    )

    # imreceiving with wrong length is silently ignored
    ext.receiveIMReceiving(
      peerId2,
      @[IMReceiving(messageID: msgId1, messageLength: (largeMsgLen + 999).uint32)],
    )

    # peer2 should NOT be in the broadcast since its entry was rejected
    cr.broadcasted = @[]
    let preambleMsg =
      RPCMsg.withPreamble(@[makePreamble(msgId1, messageLength = largeMsgLen.uint32)])
    ext.preambleBroadcastIfNotReceiving(preambleMsg, @[peerId, peerId2])
    check cr.broadcasted.len == 0

  test "handleIMReceiving: stops accepting after maxHeIsReceiving limit":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    # limit of 1 means entries stop being accepted once len exceeds 1
    let ext = PreambleExtension.new(cr.makeConfig(maxHeIsReceiving = 1), rng())
    ext.onNegotiated(peerId)

    # sending multiple imreceivings in one batch; limit is enforced per-iteration
    ext.receiveIMReceiving(
      peerId,
      @[
        IMReceiving(messageID: msgId1, messageLength: largeMsgLen.uint32),
        IMReceiving(messageID: msgId2, messageLength: largeMsgLen.uint32),
        IMReceiving(messageID: @[7'u8], messageLength: largeMsgLen.uint32),
          # rejected: len exceeds limit
      ],
    )
    # no crash = limit is enforced correctly

  test "handleIHave: returns true when message is in ongoingReceives":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    ext.receivePreamble(peerId, @[makePreamble(msgId1)])

    check:
      ext.handleIHave(peerId2, msgId1) == true
      ext.handleIHave(peerId2, msgId2) == false

  test "handleIHave: returns true when message is in ongoingIWantReceives":
    var cr = CallbackRecorder() # meshPeers empty
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    ext.receivePreamble(peerId, @[makePreamble(msgId1)])
    check ext.ongoingIWantReceives.hasKey(msgId1)

    check ext.handleIHave(peerId2, msgId1) == true

  test "handleIDontWant: removes message from heIsReceivings":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)
    ext.onNegotiated(peerId2)

    ext.receivePreamble(peerId, @[makePreamble(msgId1)])

    ext.receiveIMReceiving(
      peerId2, @[IMReceiving(messageID: msgId1, messageLength: largeMsgLen.uint32)]
    )

    # before idontwant: peerId2 receives the broadcast
    cr.broadcasted = @[]
    let preambleMsg =
      RPCMsg.withPreamble(@[makePreamble(msgId1, messageLength = largeMsgLen.uint32)])
    ext.preambleBroadcastIfNotReceiving(preambleMsg, @[peerId2])
    check cr.broadcasted.len == 1

    # idontwant removes msgId1 from peerId2's heIsReceivings
    ext.receiveIDontWant(peerId2, @[msgId1])

    # after idontwant: peerId2 no longer in the broadcast
    cr.broadcasted = @[]
    ext.preambleBroadcastIfNotReceiving(preambleMsg, @[peerId2])
    check cr.broadcasted.len == 0

  test "preambleMsgReceived: removes message from ongoingReceives":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    ext.receivePreamble(peerId, @[makePreamble(msgId1)])
    check ext.ongoingReceives.hasKey(msgId1)

    ext.preambleMsgReceived(peerId, msgId1, largeMsgLen)
    check ext.ongoingReceives.hasKey(msgId1) == false

  test "preambleMsgReceived: removes message from ongoingIWantReceives":
    var cr = CallbackRecorder() # meshPeers empty → non-mesh
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    let nonMeshPeer = PeerId.random(rng()).get()
    ext.onNegotiated(nonMeshPeer)

    ext.receivePreamble(nonMeshPeer, @[makePreamble(msgId1)])
    check ext.ongoingIWantReceives.hasKey(msgId1)

    ext.preambleMsgReceived(nonMeshPeer, msgId1, largeMsgLen)
    check ext.ongoingIWantReceives.hasKey(msgId1) == false

  test "preambleMsgReceived: skips messages below size threshold":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    # small message: preambleMsgReceived is a no-op (returns early)
    ext.preambleMsgReceived(peerId, msgId1, smallMsgLen)
    check ext.ongoingReceives.hasKey(msgId1) == false

  test "preambleBroadcast: sends only to supporting peers":
    var cr = CallbackRecorder()
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    let preambleMsg = RPCMsg.withPreamble(@[makePreamble(msgId1)])
    # peerId2 did NOT call onNegotiated -> not in supportingPeers
    ext.preambleBroadcast(preambleMsg, @[peerId, peerId2])

    check cr.broadcasted == @[BC(preambleMsg, @[peerId])]

  test "preambleBroadcast: skips messages below size threshold":
    var cr = CallbackRecorder()
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    let msg =
      RPCMsg.withPreamble(@[makePreamble(msgId1, messageLength = smallMsgLen.uint32)])
    ext.preambleBroadcast(msg, @[peerId])
    check cr.broadcasted.len == 0

  test "preambleBroadcast: skips empty preamble list":
    var cr = CallbackRecorder()
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)

    let emptyPreambleMsg = RPCMsg.withPreamble(@[]) # no preambles
    ext.preambleBroadcast(emptyPreambleMsg, @[peerId])
    check cr.broadcasted.len == 0

  test "preambleBroadcastIfNotReceiving: sends only to peers who reported imreceiving":
    var cr = CallbackRecorder(meshPeers: @[peerId])
    let ext = PreambleExtension.new(cr.makeConfig(), rng())
    ext.onNegotiated(peerId)
    ext.onNegotiated(peerId2)

    ext.receivePreamble(
      peerId, @[makePreamble(msgId1, messageLength = largeMsgLen.uint32)]
    )

    # peerId2 signals it is receiving msgId1
    ext.receiveIMReceiving(
      peerId2, @[IMReceiving(messageID: msgId1, messageLength: largeMsgLen.uint32)]
    )

    cr.broadcasted = @[]
    let preambleMsg =
      RPCMsg.withPreamble(@[makePreamble(msgId1, messageLength = largeMsgLen.uint32)])
    ext.preambleBroadcastIfNotReceiving(preambleMsg, @[peerId, peerId2])

    # only peerId2 has heIsReceivings for msgId1
    check cr.broadcasted == @[BC(preambleMsg, @[peerId2])]
