# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import tables, sets, sequtils, algorithm, chronicles, results, metrics
import ../../../utils/tablekey
import ../../../[peerid]
import ../rpc/messages
import ./[extensions_types, partial_message]

logScope:
  topics = "libp2p gossipsub"

declareGauge(
  libp2p_gossipsub_partial_message_groups,
  "number of partial-message groups currently tracked",
)
declareCounter(
  libp2p_gossipsub_partial_message_groups_dropped,
  "number of partial-message groups dropped due to configured limits",
)

type
  TopicOpts* = object
    requestsPartial*: bool
    supportsSendingPartial*: bool

  PartialMessageExtensionConfig* = object
    # PartialMessageExtensionConfig hold all configuration need for partial message extension.

    # configuration set by node
    sendRPC*:
      proc(peerID: PeerId, rpc: PartialMessageExtensionRPC) {.gcsafe, raises: [].}
      # implements logic for sending PartialMessageExtensionRPC to the peer.
      # default implementation is set by GossipSub.createExtensionsState.
    publishToPeers*: proc(topic: string): seq[PeerId] {.gcsafe, raises: [].}
      # implements logic for getting list of peers that should be considered when 
      # publishing to the topic.
      # default implementation is set by GossipSub.createExtensionsState.
    nodeTopicOpts*: proc(topic: string): TopicOpts {.gcsafe, raises: [].}
      # implements logic for getting this node's partial messages preference for topic.
      # default implementation is set by GossipSub.createExtensionsState.
    isSupported*: proc(peer: PeerId): bool {.gcsafe, raises: [].}
      # implements logic for checking if peer supports this extension ("partial message").
      # default implementation is set by ExtensionsState.new.
    updatePeerBehaviorPenalty*: UpdatePeerBehaviorPenaltyProc
      # callback to updated peer behavior penalty when peer is not follow extensions protocol. 
      # default implementation is set by GossipSub.createExtensionsState (via ExtensionsState).

    # configuration set by application (user)
    unionPartsMetadata*:
      proc(a, b: PartsMetadata): LPResult[PartsMetadata] {.gcsafe, raises: [].}
      # creates union of two PartsMetadata and returns it.
      # needs to be implemented by application.
    materializeParts*: proc(
      topic: string, groupId: GroupId, metadata: PartsMetadata
    ): LPResult[PartsData] {.gcsafe, raises: [].}
      # produces encoded message data for the parts of (topic, groupId) specified by
      # metadata. it should return as many of the requested parts as are available.
      # empty metadata must be treated as a request for all available parts.
      # returns error if metadata is invalid or the request cannot be satisfied.
      # needs to be implemented by application.
    validateRPC*:
      proc(rpc: PartialMessageExtensionRPC): LPResult[void] {.gcsafe, raises: [].}
      # implements logic for performing sanity checks on PartialMessageExtensionRPC.
      # when error is returned extension will not process PartialMessageExtensionRPC.
      # needs to be implemented by application.
    onIncomingRPC*:
      proc(peer: PeerId, rpc: PartialMessageExtensionRPC) {.gcsafe, raises: [].}
      # called when PartialMessageExtensionRPC is received and ValidateRPCProc did not return
      # error for this message.
      # needs to be implemented by application.
    heartbeatsTillEviction*: int
      # number of heartbeats for which metadata will be retained before eviction
    maxPartialGroups*: int = 1000 # global cap; excess trimmed LRU each heartbeat
    maxPartialGroupsPerPeer*: int = 100

  PeerGroupState = ref object
    receivedPartsMetadata: Opt[PartsMetadata] # parts metadata peer sent to this node
    sentPartsMetadata: Opt[PartsMetadata] # parts metadata this node sent to peer

  GroupState = ref object
    peerState: Table[PeerId, PeerGroupState]
    heartbeatsTillEviction: int
    lastPublishedMetadata: PartsMetadata
    creator: Opt[PeerId] # peer this group was allocated for, none if locally published

  PeerTopicKey = object of TableKey
    peerId: PeerId
    topic: string

  TopicGroupKey = object of TableKey
    topic: string
    groupId: GroupId

  PartialMessageExtension* = ref object of Extension
    config: PartialMessageExtensionConfig
    groupState: Table[TopicGroupKey, GroupState]
    peerTopicOpts: Table[PeerTopicKey, TopicOpts]
    peerGroupCount: CountTable[PeerId] # groups allocated per peer, keyed by creator

proc new(T: typedesc[PeerTopicKey], peerId: PeerId, topic: string): PeerTopicKey =
  PeerTopicKey(key: TableKey.makeKey(peerId, topic), peerId: peerId, topic: topic)

proc new(T: typedesc[TopicGroupKey], topic: string, groupId: GroupId): TopicGroupKey =
  TopicGroupKey(key: TableKey.makeKey(topic, groupId), topic: topic, groupId: groupId)

proc doAssert(config: PartialMessageExtensionConfig) =
  proc msg(arg: string): string =
    return "PartialMessageExtensionConfig." & arg & " must be set"

  doAssert(config.sendRPC != nil, msg("sendRPC"))
  doAssert(config.publishToPeers != nil, msg("publishToPeers"))
  doAssert(config.isSupported != nil, msg("isSupported"))
  doAssert(config.updatePeerBehaviorPenalty != nil, msg("updatePeerBehaviorPenalty"))
  doAssert(config.nodeTopicOpts != nil, msg("nodeTopicOpts"))
  doAssert(config.unionPartsMetadata != nil, msg("unionPartsMetadata"))
  doAssert(config.materializeParts != nil, msg("materializeParts"))
  doAssert(config.validateRPC != nil, msg("validateRPC"))
  doAssert(config.onIncomingRPC != nil, msg("onIncomingRPC"))
  doAssert(config.heartbeatsTillEviction >= 1, msg("heartbeatsTillEviction"))
  doAssert(config.maxPartialGroups >= 1, msg("maxPartialGroups"))
  doAssert(config.maxPartialGroupsPerPeer >= 1, msg("maxPartialGroupsPerPeer"))

proc new*(
    T: typedesc[PartialMessageExtension], config: PartialMessageExtensionConfig
): PartialMessageExtension =
  config.doAssert()
  PartialMessageExtension(config: config)

method isSupported*(
    ext: PartialMessageExtension, pe: PeerExtensions
): bool {.gcsafe, raises: [].} =
  return pe.partialMessageExtension

proc peerRequestsPartial*(
    ext: PartialMessageExtension, peerId: PeerId, topic: string
): bool =
  let opt = ext.peerTopicOpts.getOrDefault(PeerTopicKey.new(peerId, topic))
  return opt.requestsPartial

proc updateGroupCountMetric(ext: PartialMessageExtension) =
  libp2p_gossipsub_partial_message_groups.set(ext.groupState.len.int64)

proc releasePeerGroup(ext: PartialMessageExtension, peerId: PeerId) =
  if ext.peerGroupCount.getOrDefault(peerId) <= 1:
    ext.peerGroupCount.del(peerId)
    return
  ext.peerGroupCount.inc(peerId, -1)

proc evictGroup(ext: PartialMessageExtension, key: TopicGroupKey) =
  let group = ext.groupState.getOrDefault(key)
  if group.isNil():
    return
  group.creator.ifValue(creator):
    ext.releasePeerGroup(creator)
  ext.groupState.del(key)
  ext.updateGroupCountMetric()

proc reduceHeartbeatsTillEviction(ext: PartialMessageExtension) =
  var toRemove: seq[TopicGroupKey] = @[]
  for key, group in ext.groupState.mpairs:
    group.heartbeatsTillEviction.dec
    if group.heartbeatsTillEviction <= 0:
      toRemove.add(key)
  for key in toRemove:
    ext.evictGroup(key)

template getGroupState(
    ext: PartialMessageExtension, topic: string, groupId: GroupId
): GroupState =
  ext.groupState.mgetOrPut(TopicGroupKey.new(topic, groupId), GroupState())

proc trimToMaxGroups(ext: PartialMessageExtension) =
  ## Evicts least-recently-used groups down to maxPartialGroups, ranking by
  ## heartbeatsTillEviction (refreshed whenever a group sees new metadata).
  let excess = ext.groupState.len - ext.config.maxPartialGroups
  if excess <= 0:
    return
  var groups = ext.groupState.pairs.toSeq()
  groups.sort do(a, b: (TopicGroupKey, GroupState)) -> int:
    cmp(a[1].heartbeatsTillEviction, b[1].heartbeatsTillEviction)
  for (key, _) in groups[0 ..< excess]:
    ext.evictGroup(key)
    libp2p_gossipsub_partial_message_groups_dropped.inc()

proc acquireGroupState(
    ext: PartialMessageExtension, peerId: PeerId, topic: string, groupId: GroupId
): GroupState =
  ## Returns the group for (topic, groupId), allocating one for peerId if absent.
  ## Returns nil when allocating would exceed the per-peer limit.
  let key = TopicGroupKey.new(topic, groupId)
  let existing = ext.groupState.getOrDefault(key)
  if not existing.isNil():
    return existing

  if ext.peerGroupCount.getOrDefault(peerId) >= ext.config.maxPartialGroupsPerPeer:
    libp2p_gossipsub_partial_message_groups_dropped.inc()
    return nil

  let group = GroupState(creator: Opt.some(peerId))
  ext.groupState[key] = group
  ext.peerGroupCount.inc(peerId)
  ext.updateGroupCountMetric()
  group

proc trackedGroups(ext: PartialMessageExtension): int =
  ext.groupState.len

proc hasGroup(ext: PartialMessageExtension, topic: string, groupId: GroupId): bool =
  ext.groupState.hasKey(TopicGroupKey.new(topic, groupId))

when defined(libp2p_testing):
  export trackedGroups, hasGroup

template getPeerState(gs: GroupState, peerId: PeerId): PeerGroupState =
  gs.peerState.mgetOrPut(peerId, PeerGroupState())

template hasPeer(gs: GroupState, peerId: PeerId): bool =
  gs.peerState.hasKey(peerId)

template hasPublished(gs: GroupState): bool =
  gs.lastPublishedMetadata.len > 0

template createdBy(gs: GroupState, peerId: PeerId): bool =
  gs.creator == Opt.some(peerId)

template isReclaimable(gs: GroupState): bool =
  gs.peerState.len == 0 and not gs.hasPublished()

proc unionWithSentPartsMetadata(
    ext: PartialMessageExtension,
    peerState: var PeerGroupState,
    newMetadata: PartsMetadata,
): bool =
  var hasChanged: bool = false

  if peerState.sentPartsMetadata.isNone:
    hasChanged = true
    peerState.sentPartsMetadata = Opt.some(newMetadata)
  elif peerState.sentPartsMetadata.get() != newMetadata:
    let unionRes =
      ext.config.unionPartsMetadata(peerState.sentPartsMetadata.get(), newMetadata)
    if unionRes.isErr():
      # union failed, it is safe to use the most recent parts metadata
      warn "Parts metadata union failed", reason = unionRes.error
      hasChanged = true
      peerState.sentPartsMetadata = Opt.some(newMetadata)
    elif unionRes.get() != peerState.sentPartsMetadata.get():
      # union has produced different metadata then what has been sent
      hasChanged = true
      peerState.sentPartsMetadata = Opt.some(unionRes.get())

  return hasChanged

proc peersRequestingPartial(ext: PartialMessageExtension, topic: string): seq[PeerId] =
  var peers: seq[PeerId]

  for ptKey, topicOpt in ext.peerTopicOpts:
    if topicOpt.requestsPartial and ptKey.topic == topic:
      peers.add(ptKey.peerId)

  return peers

proc gossipPartsMetadata*(ext: PartialMessageExtension) =
  for tgKey, group in ext.groupState.mpairs:
    if not group.hasPublished():
      # node has not published anything on this (topic, group)
      continue

    for peerId in ext.peersRequestingPartial(tgKey.topic):
      var peerState = group.getPeerState(peerId)
      if ext.unionWithSentPartsMetadata(peerState, group.lastPublishedMetadata):
        let rpc = PartialMessageExtensionRPC(
          topicID: Opt.some(tgKey.topic),
          groupID: Opt.some(tgKey.groupId),
          partsMetadata: peerState.sentPartsMetadata,
        )
        ext.config.sendRPC(peerId, rpc)

method onHeartbeat*(ext: PartialMessageExtension) {.gcsafe, raises: [].} =
  ext.reduceHeartbeatsTillEviction()
  ext.trimToMaxGroups()
  ext.gossipPartsMetadata()

method onNegotiated*(
    ext: PartialMessageExtension, peerId: PeerId
) {.gcsafe, raises: [].} =
  discard # NOOP

method onRemovePeer*(
    ext: PartialMessageExtension, peerId: PeerId
) {.gcsafe, raises: [].} =
  var toEvict: seq[TopicGroupKey] = @[]
  for key, group in ext.groupState:
    group.peerState.del(peerId)
    if not group.createdBy(peerId):
      continue
    if group.isReclaimable():
      toEvict.add(key)
      continue
    group.creator = Opt.none(PeerId)
  for key in toEvict:
    ext.evictGroup(key)
  ext.peerGroupCount.del(peerId)

  # remove peer subscription options from _peerTopicOpts_
  var toRemove: seq[PeerTopicKey] = @[]
  for key, _ in ext.peerTopicOpts:
    if key.peerId == peerId:
      toRemove.add(key)
  for key in toRemove:
    ext.peerTopicOpts.del(key)

proc handleSubscribeRPC(ext: PartialMessageExtension, peerId: PeerId, rpc: SubOpts) =
  let key = PeerTopicKey.new(peerId, rpc.topic.get())
  if rpc.isSubscribe:
    let rp = rpc.requestsPartial.valueOr:
      false
    let ssp = rpc.supportsSendingPartial.valueOr:
      false

    if rp or ssp:
      # store only if peer requests or supports sending partial
      # because absence of information results in default values TopicOpts()
      # that has same values as if both properties are false.
      ext.peerTopicOpts[key] =
        TopicOpts(requestsPartial: rp, supportsSendingPartial: ssp)
  else:
    ext.peerTopicOpts.del(key)

proc shouldHandlePartialRPC(
    ext: PartialMessageExtension, peerId: PeerId, rpc: PartialMessageExtensionRPC
): bool =
  let nodeTopicOpts = ext.config.nodeTopicOpts(rpc.topicID.get())
  if nodeTopicOpts.requestsPartial:
    return true

  # We only send parts to a peer that asked for them.
  if not ext.peerRequestsPartial(peerId, rpc.topicID.get()):
    return false

  if nodeTopicOpts.supportsSendingPartial:
    return true

  # An unsubscribed fanout publisher has no topic opts set, but it has published
  # to this group, so it can still fulfill parts the peer is missing.
  # Look up without creating state.
  let groupState =
    ext.groupState.getOrDefault(TopicGroupKey.new(rpc.topicID.get(), rpc.groupID.get()))
  groupState != nil and groupState.hasPublished()

proc recordReceivedMetadata(
    ext: PartialMessageExtension, peerId: PeerId, rpc: PartialMessageExtensionRPC
) =
  if rpc.partsMetadata.isNone:
    return
  let groupState = ext.acquireGroupState(peerId, rpc.topicID.get(), rpc.groupID.get())
  if groupState.isNil():
    return
  var peerState = groupState.getPeerState(peerId)
  peerState.receivedPartsMetadata = rpc.partsMetadata
  groupState.heartbeatsTillEviction = ext.config.heartbeatsTillEviction

proc handlePartialRPC(
    ext: PartialMessageExtension, peerId: PeerId, rpc: PartialMessageExtensionRPC
) =
  if rpc.groupID.isNone or rpc.groupID.get().len == 0 or rpc.topicID.isNone or
      rpc.topicID.get().len == 0:
    trace "received RPC with unset groupId or topicId"
    ext.config.updatePeerBehaviorPenalty(peerId, 0.1)
    return

  ext.config.validateRPC(rpc).isOkOr:
    trace "RPC rejected by application validation", reason = error
    return

  ext.recordReceivedMetadata(peerId, rpc)

  if shouldHandlePartialRPC(ext, peerId, rpc):
    ext.config.onIncomingRPC(peerId, rpc)

method onHandleRPC*(
    ext: PartialMessageExtension, peerId: PeerId, rpc: RPCMsg
) {.gcsafe, raises: [].} =
  for subRPC in rpc.subscriptions:
    ext.handleSubscribeRPC(peerId, subRPC)

  rpc.partialMessageExtension.ifValue(partialExtRPC):
    ext.handlePartialRPC(peerId, partialExtRPC)

proc publishPartialToPeer(
    ext: PartialMessageExtension,
    topic: string,
    groupId: GroupId,
    msgPartsMetadata: PartsMetadata,
    groupState: var GroupState,
    peer: PeerId,
    peerRequestsPartial: bool,
): bool {.raises: [].} =
  var rpc =
    PartialMessageExtensionRPC(topicID: Opt.some(topic), groupID: Opt.some(groupId))
  var peerState = groupState.getPeerState(peer)
  var hasChanges: bool = false

  # if peer has requested partial messages and node knows what parts peer has requested, then
  # attempt to fulfill any parts that peer is missing.
  if peerRequestsPartial and peerState.receivedPartsMetadata.isSome():
    let materializeRes =
      ext.config.materializeParts(topic, groupId, peerState.receivedPartsMetadata.get())
    if materializeRes.isErr():
      # there might be error with last PartsMetadata so it is discarded,
      # to avoid any error with future messages.
      peerState.receivedPartsMetadata = Opt.none(PartsMetadata)
    else:
      let data = materializeRes.get()
      if data.len > 0: # some parts have been filled
        hasChanges = true
        rpc.partialMessage = Opt.some(data)

        # since some parts have been filled, update requested parts metadata
        # with what has been filled
        let unionRes = ext.config.unionPartsMetadata(
          peerState.receivedPartsMetadata.get(), msgPartsMetadata
        )
        if unionRes.isErr:
          warn "failed to create union from the two parts metadata",
            err = unionRes.error
          # technically should never happen since materializeParts was successful
        else:
          peerState.receivedPartsMetadata = Opt.some(unionRes.get())

  # union sentPartsMetadata with new parts metadata and send if there are any changes
  if ext.unionWithSentPartsMetadata(peerState, msgPartsMetadata):
    hasChanges = true
    rpc.partsMetadata = peerState.sentPartsMetadata

  # if there are any changes send RPC
  if hasChanges:
    ext.config.sendRPC(peer, rpc)

  return hasChanges # aka has published

proc publishPartial*(
    ext: PartialMessageExtension,
    topic: string,
    groupId: GroupId,
    partsMetadata: PartsMetadata,
    peers: seq[PeerId] = @[],
      # overrides the peers to whom partial messages is going to be published.
): int {.raises: [].} =
  if groupId.len == 0:
    warn "could not publish partial message without groupId", groupId
    return 0

  var groupState = ext.getGroupState(topic, groupId)
  groupState.heartbeatsTillEviction = ext.config.heartbeatsTillEviction
  groupState.lastPublishedMetadata = partsMetadata
  ext.updateGroupCountMetric()

  let publishToPeers =
    if peers.len > 0:
      peers
    else:
      # Extend this node's current publish targets
      # with peers that already exchanged metadata for this group.
      # This preserves replies to a remote peer acting as an unsubscribed
      # fanout publisher.
      var targets = ext.config.publishToPeers(topic).toHashSet()
      for p in groupState.peerState.keys:
        targets.incl(p)
      targets.toSeq()

  let nodeRequestsPartial = ext.config.nodeTopicOpts(topic).requestsPartial

  var publishedToCount: int = 0
  for p in publishToPeers:
    if not ext.config.isSupported(p):
      continue

    let peerSubOpt = ext.peerTopicOpts.getOrDefault(PeerTopicKey.new(p, topic))
    if peerSubOpt.requestsPartial:
      # If the peer requests partials, publish to it without checking this
      # node's own topic opts. A node may publish partials as a fanout
      # publisher without being subscribed to the topic.
      if ext.publishPartialToPeer(topic, groupId, partsMetadata, groupState, p, true):
        publishedToCount.inc
      continue

    # If this node requests partials, send metadata to peers that either
    # advertised partial support for the topic or already have per-group
    # state. The hasPeer check covers peers that already sent metadata for
    # this group without ever sending a subscription RPC.
    if nodeRequestsPartial and
        (peerSubOpt.supportsSendingPartial or groupState.hasPeer(p)):
      if ext.publishPartialToPeer(topic, groupId, partsMetadata, groupState, p, false):
        publishedToCount.inc

  return publishedToCount
