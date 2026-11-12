# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import ../../../../libp2p/peerid
import ../../../../libp2p/protocols/pubsub/gossipsub/extensions
import ../../../../libp2p/protocols/pubsub/rpc/[messages, protobuf]
import ../../../../libp2p/stream/connection
import ../../../tools/[unittest, crypto]
import ./extension_recording

suite "GossipSub Extensions :: Topic streams":
  teardown:
    checkTrackers()

  test "absent transports allow control RPCs without activating topic streams":
    for config in [Opt.none(TopicStreamsConfig), Opt.some(TopicStreamsConfig())]:
      let state = TopicStreamsExtension.new(config, noopBehaviorPenaltyProc)
      let peer = PeerId.random()
      check:
        state.negotiateTopicStreams(peer, RPCMsg())
        state.negotiateTopicStreams(
          peer, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
        )
        not state.peerHasTopicStreams(peer)

  test "capability advertisement follows configuration":
    let disabled = ExtensionsState.new(rng())
    let enabled =
      ExtensionsState.new(rng(), topicStreamsConfig = Opt.some(TopicStreamsConfig()))
    check disabled.makeControlExtensions().topicStreams.isNone
    check enabled.makeControlExtensions().topicStreams == Opt.some(true)
    let peer = PeerId.random()
    check not disabled.peerHasTopicStreams(peer)
    check not enabled.peerHasTopicStreams(peer)

  asyncTest "extension routes payloads and closes topic writers across peers":
    let state =
      TopicStreamsExtension.new(Opt.some(TopicStreamsConfig()), noopBehaviorPenaltyProc)
    let peers = [PeerId.random(), PeerId.random()]
    let recorder = TopicStreamsRecorder.new()
    defer:
      for peer in peers:
        await state.stopTopicStreams(peer)
      await recorder.closeOutgoingStreams()

    for peer in peers:
      state.initTopicStreams(
        peer, 1024, recorder.dial(), recorder.receive(), recorder.violation()
      )
      check:
        state.negotiateTopicStreams(
          peer, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
        )
        state.peerHasTopicStreams(peer)

    let msg = RPCMsg(
      subscriptions: @[SubOpts(topic: Opt.some("a"), subscribe: Opt.some(true))],
      messages: @[Message(topic: "a", data: @[1.byte], signature: @[2.byte])],
      partialMessageExtension: Opt.some(
        PartialMessageExtensionRPC(topicID: Opt.some("a"), groupID: Opt.some(@[3.byte]))
      ),
    )
    let prepared = makePreparedTopicRPC(msg, true)
    for peer in peers:
      let controlRPC = RPCMsg.decode(state.sendTopicRPC(peer, prepared, true)).get()
      check controlRPC == RPCMsg.withSubscriptions(msg.subscriptions)

    check recorder.outgoingStreams.len == peers.len
    for remote in recorder.outgoingStreams:
      check TopicRPCHeader.decode(await remote.readLp(1024)).get() ==
        TopicRPCHeader(topic: Opt.some("a"))
      let publish = TopicRPC.decode(await remote.readLp(1024)).get()
      check publish == TopicRPC(publish: Opt.some(TopicScopedMessage(data: @[1.byte])))
      let partial = TopicRPC.decode(await remote.readLp(1024)).get()
      check partial ==
        TopicRPC(
          partial: Opt.some(PartialMessageExtensionRPC(groupID: Opt.some(@[3.byte])))
        )

    await allFutures(state.closeTopicStreams("a"))
    for remote in recorder.outgoingStreams:
      var data: byte
      check (await remote.readOnce(addr data, 1)) == 0
    check recorder.violations == 0

  asyncTest "stopping a peer does not remove a replacement transport":
    let state =
      TopicStreamsExtension.new(Opt.some(TopicStreamsConfig()), noopBehaviorPenaltyProc)
    let peer = PeerId.random()
    let recorder = TopicStreamsRecorder.new()
    defer:
      await state.stopTopicStreams(peer)

    state.initTopicStreams(
      peer, 1024, recorder.pendingDial(), recorder.receive(), recorder.violation()
    )
    check state.negotiateTopicStreams(
      peer, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
    )
    discard state.sendTopicRPC(
      peer,
      makePreparedTopicRPC(
        RPCMsg.withMessages(Message(topic: "a", data: @[1.byte])), false
      ),
      false,
    )
    let stopping = state.stopTopicStreams(peer)
    check not state.peerHasTopicStreams(peer)
    state.initTopicStreams(
      peer, 1024, recorder.pendingDial(), recorder.receive(), recorder.violation()
    )
    check state.negotiateTopicStreams(
      peer, makeRPC(ControlExtensions(topicStreams: Opt.some(true)))
    )
    await stopping
    check:
      recorder.cancelledDials == 1
      state.peerHasTopicStreams(peer)
      recorder.violations == 0
