# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sets, tables]
import ../../../[peerid]
import ../../../crypto/crypto
import ../rpc/messages
import
  ./[
    extensions_types, extension_test, extension_partial_message, partial_message,
    extension_pingpong, extension_preamble,
  ]

export
  TestExtensionConfig, PartialMessageExtensionConfig, TopicOpts,
  PingPongExtensionConfig, PreambleExtensionConfig

proc noopBehaviorPenaltyProc*(_: PeerId, _: float64) {.gcsafe, raises: [].} =
  discard

type ExtensionsState* = ref object
  sentExtensions: HashSet[PeerId] # tells to which peers has node sent ControlExtensions.
  peerExtensions: Table[PeerId, PeerExtensions]
    # tells what peer capabilities are (what extensions are supported by them).
  receivedNonExtCtrlMsg: Table[PeerId, bool]
  updatePeerBehaviorPenalty: UpdatePeerBehaviorPenaltyProc
  nodeExtensions: ControlExtensions # tells what node's capabilities are.
  extensions: seq[Extension]
    # list of all extensions. state will delegate events to all elements of this list.
  partialMessageExtension: Opt[PartialMessageExtension]
    # partialMessageExtension is needed to expose specific functionality of PartialMessageExtension via state.
  preambleExtension: Opt[PreambleExtension]
    # preambleExtension is needed to expose specific functionality of PreambleExtension via state.

proc new*(
    T: typedesc[ExtensionsState],
    rng: Rng,
    updatePeerBehaviorPenalty: UpdatePeerBehaviorPenaltyProc = noopBehaviorPenaltyProc,
    testExtensionConfig: Opt[TestExtensionConfig] = Opt.none(TestExtensionConfig),
    partialMessageExtensionConfig: Opt[PartialMessageExtensionConfig] =
      Opt.none(PartialMessageExtensionConfig),
    pingpongExtensionConfig: Opt[PingPongExtensionConfig] =
      Opt.none(PingPongExtensionConfig),
    preambleExtensionConfig: Opt[PreambleExtensionConfig] =
      Opt.none(PreambleExtensionConfig),
    externalExtensions: seq[Extension] = @[],
      # external extensions are created outside of state and they are added to 
      # state's extensions list.
): T =
  var state: T

  var nodeExtensions = ControlExtensions()
  var extensions = newSeq[Extension]()
  var partialMessageExtension: Opt[PartialMessageExtension] =
    Opt.none(PartialMessageExtension)
  var preambleExtension: Opt[PreambleExtension] = Opt.none(PreambleExtension)

  testExtensionConfig.ifValue(c):
    extensions.add(TestExtension.new(c))
    nodeExtensions.testExtension = Opt.some(true)

  partialMessageExtensionConfig.ifValue(c):
    var cfg = c
    cfg.isSupported = proc(peerId: PeerId): bool {.gcsafe, raises: [].} =
      let peerExt = state.peerExtensions.getOrDefault(peerId)
      return state.partialMessageExtension.get().isSupported(peerExt)
    cfg.updatePeerBehaviorPenalty = updatePeerBehaviorPenalty
    partialMessageExtension = Opt.some(PartialMessageExtension.new(cfg))
    extensions.add(partialMessageExtension.get())
    nodeExtensions.partialMessageExtension = Opt.some(true)

  pingpongExtensionConfig.ifValue(c):
    extensions.add(PingPongExtension.new(c))
    nodeExtensions.pingpongExtension = Opt.some(true)

  preambleExtensionConfig.ifValue(c):
    preambleExtension = Opt.some(PreambleExtension.new(c, rng))
    extensions.add(preambleExtension.get())
    nodeExtensions.preambleExtension = Opt.some(true)

  extensions.add(externalExtensions)

  state = T(
    updatePeerBehaviorPenalty: updatePeerBehaviorPenalty,
    sentExtensions: initHashSet[PeerId](),
    nodeExtensions: nodeExtensions,
    extensions: extensions,
    partialMessageExtension: partialMessageExtension,
    preambleExtension: preambleExtension,
  )
  return state

proc toPeerExtensions(ce: ControlExtensions): PeerExtensions =
  let testExtension = ce.testExtension.valueOr:
    false
  let partialMessageExtension = ce.partialMessageExtension.valueOr:
    false
  let pingpongExtension = ce.pingpongExtension.valueOr:
    false
  let preambleExtension = ce.preambleExtension.valueOr:
    false

  PeerExtensions(
    testExtension: testExtension,
    partialMessageExtension: partialMessageExtension,
    pingpongExtension: pingpongExtension,
    preambleExtension: preambleExtension,
  )

proc onHandleRPC(state: ExtensionsState, peerId: PeerId, rpc: RPCMsg) =
  # extension event called when node receives every RPC message.

  for _, e in state.extensions:
    e.onHandleRPC(peerId, rpc)

proc onNegotiated(state: ExtensionsState, peerId: PeerId) =
  # extension event called when both sides have negotiated (exchanged) extensions.
  # it will be called only once per connection session as soon as extensions are exchanged.

  for _, e in state.extensions:
    if e.isSupported(state.peerExtensions.getOrDefault(peerId)):
      e.onNegotiated(peerId)

proc onHeartbeat(state: ExtensionsState) =
  # extension event called on every gossipsub heartbeat.

  for _, e in state.extensions:
    e.onHeartbeat()

proc onRemovePeer(state: ExtensionsState, peerId: PeerId) =
  # extension event called when peer disconnects from gossipsub.

  for _, e in state.extensions:
    if e.isSupported(state.peerExtensions.getOrDefault(peerId)):
      e.onRemovePeer(peerId)

proc heartbeat*(state: ExtensionsState) =
  # triggers heartbeat event in extensions state.

  state.onHeartbeat()

proc isControlSent*(state: ExtensionsState, peerId: PeerId): bool =
  peerId in state.sentExtensions

proc addPeer*(state: ExtensionsState, peerId: PeerId) =
  # called after peer has connected to node, when gossipsub is about to send
  # extensions control message and mark the peer as sent from our side.

  # when node has received control extensions from peer then extensions have negotiated
  if not state.isControlSent(peerId) and peerId in state.peerExtensions:
    state.onNegotiated(peerId)

  state.sentExtensions.incl(peerId)

proc removePeer*(state: ExtensionsState, peerId: PeerId) =
  # called after peer has disconnected from node

  # first delegate event to all extensions
  state.onRemovePeer(peerId)

  # then remove all data from sate associated with peer
  if state.peerExtensions.hasKey(peerId):
    state.peerExtensions.del(peerId)
  state.sentExtensions.excl(peerId)
  state.receivedNonExtCtrlMsg.del(peerId)

proc handleRPC*(state: ExtensionsState, peerId: PeerId, rpc: RPCMsg) =
  if rpc.control.isSome() and rpc.control.get().extensions.isSome():
    if state.receivedNonExtCtrlMsg.hasKey(peerId):
      # peer is sending control message that was not the first message transmitted on the stream.
      state.updatePeerBehaviorPenalty(peerId, 0.1)
    elif state.peerExtensions.hasKey(peerId):
      # peer is sending control message again but this node has already received extensions.
      # this is protocol error, therefore nodes reports misbehavior.
      state.updatePeerBehaviorPenalty(peerId, 0.1)
    else:
      # peer is sending extensions control message for the first time
      let ctrlExtensions = rpc.control.get().extensions.get()
      state.peerExtensions[peerId] = ctrlExtensions.toPeerExtensions()

      # when node has sent it's extensions then extensions have negotiated
      if peerId in state.sentExtensions:
        state.onNegotiated(peerId)
  else:
    state.receivedNonExtCtrlMsg[peerId] = true

  # onHandleRPC event is always called
  state.onHandleRPC(peerId, rpc)

proc makeControlExtensions*(state: ExtensionsState): ControlExtensions =
  return state.nodeExtensions

proc publishPartial*(
    state: ExtensionsState,
    topic: string,
    groupId: GroupId,
    partsMetadata: PartsMetadata,
    peers: seq[PeerId] = @[],
): int =
  state.partialMessageExtension.ifValue(e):
    return e.publishPartial(topic, groupId, partsMetadata, peers)
  else:
    # raises because this proc is called by user
    raiseAssert "partial message extension is not configured"

proc peerRequestsPartial*(state: ExtensionsState, peerId: PeerId, topic: string): bool =
  state.partialMessageExtension.ifValue(e):
    return e.peerRequestsPartial(peerId, topic)
  else:
    # should not raise, because this is called whenever IDONTWANT is being sent.
    # so when extension is not configured it should return false, backwards compatible behavior.
    return false

proc preambleBroadcast*(state: ExtensionsState, msg: RPCMsg, peers: seq[PeerId]) =
  state.preambleExtension.ifValue(e):
    e.preambleBroadcast(msg, peers)

proc preambleBroadcastIfNotReceiving*(
    state: ExtensionsState, msg: RPCMsg, peers: seq[PeerId]
) =
  state.preambleExtension.ifValue(e):
    e.preambleBroadcastIfNotReceiving(msg, peers)

proc preambleMsgReceived*(
    state: ExtensionsState, peerId: PeerId, msgId: MessageId, msgLen: int
) =
  state.preambleExtension.ifValue(e):
    e.preambleMsgReceived(peerId, msgId, msgLen)

proc preambleHandleIHave*(
    state: ExtensionsState, peerId: PeerId, msgId: MessageId
): bool =
  state.preambleExtension.ifValue(e):
    return e.handleIHave(peerId, msgId)
  return false
