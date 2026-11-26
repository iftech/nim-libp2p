# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/protocols/pubsub/
    [floodsub, gossipsub, pubsubpeer, rpc/message, rpc/messages, rpc/protobuf]
import ../../tools/[unittest, stall_stream]
import ./utils

suite "GossipSub relay cancellation":
  const topic = "relay-cancellation"

  teardown:
    checkTrackers()

  asyncTest "RPC duplicates and IDONTWANT cancel relays independently of metrics":
    for duplicate in [false, true]:
      let (gossip, conns, peers) = setupGossipSubWithPeers(1, topic)
      let peer = peers[0]
      let conn = peer.stallSendStream(stallCount = 1)
      defer:
        await peer.stopTasks()
        await conn.close()
        await teardownGossipSub(gossip, conns)
      gossip.verifySignature = false
      let msg = Message.init(conns[0].peerId, @[42.byte], topic, Opt.some(1'u64))
      let id = gossip.msgIdProvider(msg).get()
      let salted = gossip.salt(id)
      discard gossip.addSeen(salted)
      await peer.sendEncoded(@[0.byte], MessagePriority.High)
      await peer.sendEncoded(
        @[1.byte, 2, 3], MessagePriority.Low, relayedSaltedId = Opt.some(salted)
      )
      await peer.sendEncoded(@[4.byte], MessagePriority.Low)
      let empty = RPCMsg.withControl(ControlMessage(idontwant: @[ControlIWant()]))
      for i in 0 ..< 100:
        await gossip.rpcHandler(peer, empty.encode(false))
      check peer.queuedBytes(MessagePriority.Low) == 4
      let rpc =
        if duplicate:
          RPCMsg.withMessages(msg)
        else:
          RPCMsg.withControl(ControlMessage.withIDontWant(id))
      await gossip.rpcHandler(peer, rpc.encode(false))
      check peer.queuedBytes(MessagePriority.Low) == 1
      check peer.outboundQueue.evictableBytes[MessagePriority.Low] == 1
      await gossip.rpcHandler(peer, rpc.encode(false))
      check peer.queuedBytes(MessagePriority.Low) == 1
      conn.releasePendingWrites()
      checkUntilTimeout:
        conn.writes == @[@[0.byte], @[4.byte]]
      check peer.cancelQueuedRelay(salted) == 0
