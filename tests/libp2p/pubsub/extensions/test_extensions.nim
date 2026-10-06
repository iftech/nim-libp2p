# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import ../../../../libp2p/peerid
import
  ../../../../libp2p/protocols/pubsub/
    [gossipsub/extensions, gossipsub/extensions_types, rpc/messages]
import ../../../tools/[unittest, crypto]
import ./extension_recording

proc makeRPC(extensions: ControlExtensions = ControlExtensions()): RPCMsg =
  RPCMsg.withControl(ControlMessage.withExtensions(extensions))

proc createBehaviorPenaltyProc*(): (ref seq[PeerId], UpdatePeerBehaviorPenaltyProc) =
  let peers = new seq[PeerId]
  peers[] = @[]

  let cb: UpdatePeerBehaviorPenaltyProc = proc(
      peerId: PeerId, _: float64
  ) {.closure, gcsafe.} =
    peers[].add(peerId)

  (peers, cb)

suite "GossipSub Extensions :: State":
  let peerId = PeerId.random(rng()).get()

  test "default unconfigured state":
    var state = ExtensionsState.new(rng())

    # call all proc, that are called from gossipsub here.
    # by calling these test can't assert much, but it should
    # not cause tests to fail.
    state.handleRPC(peerId, RPCMsg())
    state.addPeer(peerId)
    state.addPeer(peerId)
    state.handleRPC(peerId, makeRPC())
    state.removePeer(peerId)
    state.removePeer(peerId)
    state.heartbeat()
    state.heartbeat()

    # procs that return value should return default value
    check state.makeControlExtensions() == ControlExtensions()

  test "ensure default behavior for unconfigured partial message extension":
    var state = ExtensionsState.new(rng())

    # expect to fail because this is user facing function, they shouldn't
    # call if extensions is not configured.
    expect AssertionDefect:
      discard state.publishPartial("logos", @[1.byte], @[])

    # should return false, backwards compatible behavior
    check state.peerRequestsPartial(peerId, "logos") == false

  test "state reports misbehaving when ControlExtensions is sent more than once":
    var (reportedPeers, behaviorPenaltyCb) = createBehaviorPenaltyProc()
    var state = ExtensionsState.new(rng(), behaviorPenaltyCb)

    # peer sends ControlExtensions for the first time
    state.handleRPC(peerId, makeRPC())

    # when peer sends ControlExtensions after that, misbehavior should be reported
    for i in 1 ..< 5:
      state.handleRPC(peerId, makeRPC())
      check reportedPeers[] == repeat[PeerId](peerId, i)

  test "state reports misbehaving when ControlExtensions is sent more than once - many peers reported":
    var (reportedPeers, behaviorPenaltyCb) = createBehaviorPenaltyProc()
    var state = ExtensionsState.new(rng(), behaviorPenaltyCb)

    var peers = newSeq[PeerId]()
    for i in 0 ..< 5:
      let pid = PeerId.random(rng()).get()
      state.handleRPC(pid, makeRPC())
      state.handleRPC(pid, makeRPC())
      peers.add(pid)

      check reportedPeers[] == peers

  test "state reports misbehaving when ControlExtensions is not first message on the stream":
    var (reportedPeers, behaviorPenaltyCb) = createBehaviorPenaltyProc()
    var state = ExtensionsState.new(rng(), behaviorPenaltyCb)

    # peer sends RPCMsg without ControlExtensions
    state.handleRPC(peerId, RPCMsg())
    # peer sends RPCMsg with ControlExtensions (second msg on the stream)
    state.handleRPC(peerId, makeRPC())

    # misbehavior should be reported
    check reportedPeers[] == @[peerId]

  test "peer is removed":
    var (reportedPeers, behaviorPenaltyCb) = createBehaviorPenaltyProc()
    var state = ExtensionsState.new(rng(), behaviorPenaltyCb)

    for i in 0 ..< 5:
      let pid = PeerId.random(rng()).get()
      state.handleRPC(pid, makeRPC())

      # when peer is removed state is cleared, so second handleRPC()
      # call will not cause misbehavior
      state.removePeer(pid)
      state.handleRPC(pid, makeRPC())

      check reportedPeers[].len == 0

  test "isControlSent tracks addPeer and removePeer":
    var state = ExtensionsState.new(rng())
    let pid = PeerId.random(rng()).get()

    # initially false
    check not state.isControlSent(pid)

    # true after addPeer
    state.addPeer(pid)
    check state.isControlSent(pid)

    # calling addPeer again doesn't change anything
    state.addPeer(pid)
    check state.isControlSent(pid)

    # cleared after removePeer
    state.removePeer(pid)
    check not state.isControlSent(pid)

    # can be re-added after remove (reconnection)
    state.addPeer(pid)
    check state.isControlSent(pid)

  test "addPeer called twice does not trigger duplicate onNegotiated":
    var ext = RecordingExtension()
    var state = ExtensionsState.new(rng(), externalExtensions = @[Extension(ext)])
    let pid = PeerId.random(rng()).get()

    # peer sends extensions first (path A: handleRPC then addPeer)
    state.handleRPC(pid, makeRPC(ControlExtensions(testExtension: Opt.some(true))))
    state.addPeer(pid)
    check ext.negotiatedPeers == @[pid]

    # second addPeer for the same peer must NOT trigger onNegotiated again
    state.addPeer(pid)
    check ext.negotiatedPeers == @[pid]

  test "onNegotiated fires again after removePeer":
    var ext = RecordingExtension()
    var state = ExtensionsState.new(rng(), externalExtensions = @[Extension(ext)])
    let pid = PeerId.random(rng()).get()

    state.handleRPC(pid, makeRPC(ControlExtensions(testExtension: Opt.some(true))))
    state.addPeer(pid)
    check ext.negotiatedPeers == @[pid]

    state.removePeer(pid)
    state.handleRPC(pid, makeRPC(ControlExtensions(testExtension: Opt.some(true))))
    state.addPeer(pid)
    check ext.negotiatedPeers == @[pid, pid]

  test "state calls all extensions callbacks":
    var ext = RecordingExtension()
    var state = ExtensionsState.new(rng(), externalExtensions = @[Extension(ext)])

    # assert that onHeartbeat is called
    state.heartbeat()
    check ext.heartbeatCount == 1
    state.heartbeat()
    check ext.heartbeatCount == 2

    # assert that onNegotiated is not called (ControlExtensions is empty)
    state.handleRPC(peerId, makeRPC(ControlExtensions()))
    check ext.handledRPC.len == 1
    check ext.negotiatedPeers.len == 0
    state.addPeer(peerId)
    check ext.negotiatedPeers.len == 0

    # assert that onNegotiated is not called (testExtension is false)
    state.handleRPC(peerId, makeRPC(ControlExtensions(testExtension: Opt.some(false))))
    check ext.handledRPC.len == 2
    check ext.negotiatedPeers.len == 0
    state.addPeer(peerId)
    check ext.negotiatedPeers.len == 0

    # assert that onNegotiated is called (handleRPC, then addPeer)
    let peerId1 = PeerId.random(rng()).get()
    state.handleRPC(peerId1, makeRPC(ControlExtensions(testExtension: Opt.some(true))))
    check ext.handledRPC.len == 3
    check ext.negotiatedPeers.len == 0
    state.addPeer(peerId1)
    check ext.negotiatedPeers == @[peerId1]

    # assert that onNegotiated is called (addPeer, then handleRPC)
    let peerId2 = PeerId.random(rng()).get()
    state.addPeer(peerId2)
    check ext.negotiatedPeers.len == 1
    state.handleRPC(peerId2, makeRPC(ControlExtensions(testExtension: Opt.some(true))))
    check ext.handledRPC.len == 4
    check ext.negotiatedPeers == @[peerId1, peerId2]

    # assert that onRemovePeer is called
    state.removePeer(peerId1)
    state.removePeer(peerId2)
    check ext.removedPeers == @[peerId1, peerId2]
