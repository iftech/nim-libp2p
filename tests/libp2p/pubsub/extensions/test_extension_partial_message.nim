# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, tables, results, strutils, stew/byteutils, sequtils
import ../../../../libp2p/peerid
import
  ../../../../libp2p/protocols/pubsub/[
    gossipsub/extension_partial_message,
    gossipsub/extensions_types,
    gossipsub/partial_message,
    rpc/messages,
  ]
import ../../../tools/[unittest, crypto]
import ./my_partial_message
import ../converters

proc isPartialTopic(topic: string): bool =
  # convention: in this test file, topics that have "partial" in their name will be considered
  # to be requesting partial messages
  return topic.contains("partial")

type PeerRPC = object
  peerId: PeerId # who sent RPC or to whom RPC was sent to (depending on usage)
  rpc: PartialMessageExtensionRPC

type CallbackRecorder = ref object
  publishToPeers: seq[PeerId]
  sentRPC: seq[PeerRPC] # peerId - to whom PRC was sent to
  incomingRPC: seq[PeerRPC] # peerId - who sent RPC
  peerPenalty: Table[PeerId, float64]
  store: MyPartialMessageStore # messages published by this node

proc config(c: CallbackRecorder): PartialMessageExtensionConfig =
  if c.store.isNil:
    c.store = MyPartialMessageStore()

  proc sendRPC(peerId: PeerId, rpc: PartialMessageExtensionRPC) {.gcsafe, raises: [].} =
    c.sentRPC.add(PeerRPC(peerId: peerId, rpc: rpc))

  proc publishToPeers(topic: string): seq[PeerId] {.gcsafe, raises: [].} =
    return c.publishToPeers

  proc nodeTopicOpts(topic: string): TopicOpts {.gcsafe, raises: [].} =
    return TopicOpts(requestsPartial: isPartialTopic(topic))

  proc isSupported(peer: PeerId): bool {.gcsafe, raises: [].} =
    return true

  proc updatePeerBehaviorPenalty(peerId: PeerId, delta: float) {.gcsafe, raises: [].} =
    let p = c.peerPenalty.getOrDefault(peerId)
    c.peerPenalty[peerId] = p + delta

  proc validateRPC(
      rpc: PartialMessageExtensionRPC
  ): LPResult[void] {.gcsafe, raises: [].} =
    checkLen(rpc.partsMetadata)
    return ok()

  proc onIncomingRPC(
      peerId: PeerId, rpc: PartialMessageExtensionRPC
  ) {.gcsafe, raises: [].} =
    c.incomingRPC.add(PeerRPC(peerId: peerId, rpc: rpc))

  return PartialMessageExtensionConfig(
    sendRPC: sendRPC,
    publishToPeers: publishToPeers,
    isSupported: isSupported,
    updatePeerBehaviorPenalty: updatePeerBehaviorPenalty,
    nodeTopicOpts: nodeTopicOpts,
    unionPartsMetadata: my_partial_message.unionPartsMetadata,
    materializeParts: c.store.materializePartsFn(),
    validateRPC: validateRPC,
    onIncomingRPC: onIncomingRPC,
    heartbeatsTillEviction: 3,
  )

proc subscribe(
    ext: PartialMessageExtension, peerId: PeerId, topic: string, subscribe: bool
) =
  # helper utility for subscribing
  ext.onHandleRPC(
    peerId,
    RPCMsg(
      subscriptions: @[
        SubOpts(
          topic: topic,
          subscribe: subscribe,
          requestsPartial: Opt.some(isPartialTopic(topic)),
        )
      ]
    ),
  )

proc publishPartial(
    ext: PartialMessageExtension,
    cr: CallbackRecorder,
    topic: string,
    pm: MyPartialMessage,
    peers: seq[PeerId] = @[],
): int =
  # stores message so config.materializeParts can serve it, then publishes
  cr.store.messages[pm.groupId] = pm
  ext.publishPartial(topic, pm.groupId, pm.partsMetadata(), peers)

proc handlePartialMessage(
    ext: PartialMessageExtension, peerId: PeerId, rpc: PartialMessageExtensionRPC
) =
  ext.onHandleRPC(peerId, RPCMsg(partialMessageExtension: Opt.some(rpc)))

proc sendGroupMetadata(
    ext: PartialMessageExtension, peerId: PeerId, topic, groupId: string
) =
  ext.handlePartialMessage(
    peerId,
    PartialMessageExtensionRPC(
      topicID: topic,
      groupID: groupId.toBytes,
      partsMetadata: MyPartsMetadata.want(@[1]),
    ),
  )

suite "GossipSub Extensions :: Partial Message Extension":
  let peerId = PeerId.random(rng()).get()
  let groupId = "group-id-1".toBytes

  test "isSupported":
    let ext = PartialMessageExtension.new()
    check:
      ext.isSupported(PeerExtensions()) == false
      ext.isSupported(PeerExtensions(partialMessageExtension: true)) == true

  test "config validation":
    var cr = CallbackRecorder()

    expect AssertionDefect:
      discard PartialMessageExtension.new(PartialMessageExtensionConfig())

    expect AssertionDefect:
      var config = cr.config()
      config.sendRPC = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.publishToPeers = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.isSupported = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.nodeTopicOpts = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.validateRPC = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.onIncomingRPC = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.unionPartsMetadata = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.materializeParts = nil
      discard PartialMessageExtension.new(config)

    expect AssertionDefect:
      var config = cr.config()
      config.heartbeatsTillEviction = 0
      discard PartialMessageExtension.new(config)

  test "subscribe/unsubscribe":
    const topicPartial = "logos-partial"
    const topicFull = "logos-full"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    # should subscribe with requesting partial
    check ext.peerRequestsPartial(peerId, topicPartial) == false
    ext.subscribe(peerId, topicPartial, true)
    check ext.peerRequestsPartial(peerId, topicPartial)

    # unsubscribe should remove information about this topic
    ext.subscribe(peerId, topicPartial, false)
    check ext.peerRequestsPartial(peerId, topicPartial) == false

    # unsubscribe same peer again (should not raise)
    ext.subscribe(peerId, topicPartial, false)

    # should subscribe without partial
    check ext.peerRequestsPartial(peerId, topicFull) == false
    ext.subscribe(peerId, topicFull, true)
    check ext.peerRequestsPartial(peerId, topicFull) == false

    # when peer is removed there should not be any data associated with them
    ext.subscribe(peerId, topicPartial, true)
    ext.onRemovePeer(peerId)
    check ext.peerRequestsPartial(peerId, topicPartial) == false

    # remove same peer again (should not raise)
    ext.onRemovePeer(peerId)

  test "RPC validation":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    # invalid RPC case
    ext.handlePartialMessage(
      peerId,
      PartialMessageExtensionRPC(
        topicID: topic, groupID: groupId, partsMetadata: @[1.byte] # invalid metadata
      ),
    )
    check cr.incomingRPC.len == 0 # should not call onIncomingRPC

    # valid RPC case
    let pmRPC = PartialMessageExtensionRPC(
      topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1, 2])
    )
    ext.handlePartialMessage(peerId, pmRPC)
    check:
      cr.incomingRPC.len == 1 # should call onIncomingRPC
      cr.incomingRPC[0] == PeerRPC(peerId: peerId, rpc: pmRPC)

  test "handleRPC: calls onIncomingRPC when node serves partials and peer requests them":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var config = cr.config()
    config.nodeTopicOpts = proc(topic: string): TopicOpts {.gcsafe, raises: [].} =
      TopicOpts(requestsPartial: false, supportsSendingPartial: true)
    var ext = PartialMessageExtension.new(config)

    ext.subscribe(peerId, topic, true)

    let pmRPC = PartialMessageExtensionRPC(
      topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1, 2])
    )
    ext.handlePartialMessage(peerId, pmRPC)
    check:
      cr.incomingRPC.len == 1
      cr.incomingRPC[0] == PeerRPC(peerId: peerId, rpc: pmRPC)

  test "handleRPC: does not call onIncomingRPC":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var config = cr.config()
    config.nodeTopicOpts = proc(topic: string): TopicOpts {.gcsafe, raises: [].} =
      TopicOpts(requestsPartial: false, supportsSendingPartial: false)
    var ext = PartialMessageExtension.new(config)

    ext.subscribe(peerId, topic, true)

    let pmRPC = PartialMessageExtensionRPC(
      topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1, 2])
    )
    ext.handlePartialMessage(peerId, pmRPC)
    check:
      cr.incomingRPC.len == 0

  test "handleRPC: calls onIncomingRPC for unsubscribed fanout publisher that has published":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var config = cr.config()
    config.nodeTopicOpts = proc(topic: string): TopicOpts {.gcsafe, raises: [].} =
      TopicOpts(requestsPartial: false, supportsSendingPartial: false)
    var ext = PartialMessageExtension.new(config)

    # peer subscribes requesting partials
    ext.subscribe(peerId, topic, true)

    # node publishes to the group, establishing lastPublishedMetadata
    let pm = MyPartialMessage(
      groupId: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    check ext.publishPartial(cr, topic, pm) == 1

    # peer requests missing parts
    let pmRPC = PartialMessageExtensionRPC(
      topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1, 2])
    )
    ext.handlePartialMessage(peerId, pmRPC)
    check:
      cr.incomingRPC.len == 1
      cr.incomingRPC[0] == PeerRPC(peerId: peerId, rpc: pmRPC)

  test "handleRPC: adds penalty when groupId or topicId is not set":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    # handle partial message without groupId
    ext.handlePartialMessage(
      peerId,
      PartialMessageExtensionRPC(
        groupID: @[], # intentionally empty
        topicID: topic,
      ),
    )
    # the peer should be penalized
    check cr.peerPenalty[peerId] == 0.1

    # handle partial message without topicId
    ext.handlePartialMessage(
      peerId,
      PartialMessageExtensionRPC(
        groupID: @[1.byte], # intentionally empty
        topicID: "", # intentionally empty
      ),
    )
    # the peer should be penalized (again)
    check cr.peerPenalty[peerId] == 0.2

  test "publish partial message: to all in topic advertizing parts":
    # the usecase when application is publishing partial message to all peers subscribed on topic.
    # and since no peer has asked for any part in particular, only parts metadata are being sent.
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    # peer subscribes with partial capability
    ext.subscribe(peerId, topic, true)

    # application/user is publishing message with parts [1, 2, 3]
    let pm = MyPartialMessage(
      groupId: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    check ext.publishPartial(cr, topic, pm) == 1 # should publish to one peer

    # the peer should receive partial messages RPC 
    check:
      cr.sentRPC.len == 1
      cr.sentRPC[0] ==
        PeerRPC(
          peerId: peerId,
          rpc: PartialMessageExtensionRPC(
            groupID: groupId,
            topicID: topic,
            partsMetadata: MyPartsMetadata.have(@[1, 2, 3]),
              # only metadata are sent because peer has not asked for any parts
            partialMessage: Opt.none(seq[byte]),
          ),
        )

    # publishing same message again should not send to peer
    # because peer has already received same parts metadata
    check ext.publishPartial(cr, topic, pm) == 0
    check cr.sentRPC.len == 1

  test "publish partial message: selected peers filling request":
    # usecase when application sends partial message to peer in response to their seeking request.
    # application only pushes partial message to selected peer (peer that was seeking parts).
    # this test can be seen as continuation of test above. consider full usecase:
    # - precondition: all nodes have all parts
    # - node A: publishes new message (eagerly advertizing new parts)
    # - node B: receives metadata (this is where first test ends)
    # - node B: requests missing parts  
    # - node A: fulfills request sending message only to node B (this is where second test, this test, ends)
    const topic = "logos-partial"
    var cr = CallbackRecorder(
      publishToPeers: @[peerId]
        # note: this is list of peers that we publish to by default, 
        # but in this test this list is ignored because test is publishing to selected peers.
    )
    var ext = PartialMessageExtension.new(cr.config())
    let selectedPeerId = PeerId.random(rng()).get()

    # must subscribe all peers with partial capability
    ext.subscribe(peerId, topic, true)
    ext.subscribe(selectedPeerId, topic, true)

    # selected peer sends RPC seeking parts [1, 2]
    ext.handlePartialMessage(
      selectedPeerId,
      PartialMessageExtensionRPC(
        topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1, 2])
      ),
    )

    # application/user is publishing message with parts [1, 2, 3] to selected peer
    # as a response to their seeking request
    let pm = MyPartialMessage(
      groupId: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    check ext.publishPartial(cr, topic, pm, peers = @[selectedPeerId]) == 1
      # should publish to selected peer

    # the selected peer should receive partial messages RPC
    check:
      cr.sentRPC.len == 1
      cr.sentRPC[0] ==
        PeerRPC(
          peerId: selectedPeerId, # selected peer receives RPC
          rpc: PartialMessageExtensionRPC(
            groupID: groupId,
            topicID: topic,
            partialMessage: "onetwo".toBytes,
              # only parts [1, 2] are sent as those were requested
              # and part [3] is ignored
            partsMetadata: MyPartsMetadata.have(@[1, 2, 3]),
              # peer receives all parts metadata because it was never sent to them
          ),
        )

    # publishing same message again should not send to peer
    # because peer's request is already fulfilled
    check ext.publishPartial(cr, topic, pm, peers = @[selectedPeerId]) == 0
    check cr.sentRPC.len == 1

  test "publish partial message: materializeParts is only called for requesting peers":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var config = cr.config()
    var requested: seq[(string, GroupId, PartsMetadata)]
    config.materializeParts = proc(
        topic: string, groupId: GroupId, metadata: PartsMetadata
    ): LPResult[PartsData] {.gcsafe, raises: [].} =
      requested.add((topic, groupId, metadata))
      cr.store.materializeParts(topic, groupId, metadata)
    var ext = PartialMessageExtension.new(config)
    let requestingPeerId = PeerId.random(rng()).get()

    ext.subscribe(peerId, topic, true)
    ext.subscribe(requestingPeerId, topic, true)

    # requesting peer seeks parts [1, 2]
    ext.handlePartialMessage(
      requestingPeerId,
      PartialMessageExtensionRPC(
        topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1, 2])
      ),
    )

    let pm = MyPartialMessage(
      groupId: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    check ext.publishPartial(cr, topic, pm) == 2

    check:
      # only the peer that sent a request is asked to materialize parts
      requested == @[(topic, groupId, MyPartsMetadata.want(@[1, 2]))]
      cr.sentRPC.len == 2
      PeerRPC(
        peerId: requestingPeerId,
        rpc: PartialMessageExtensionRPC(
          groupID: groupId,
          topicID: topic,
          partialMessage: "onetwo".toBytes,
          partsMetadata: MyPartsMetadata.have(@[1, 2, 3]),
        ),
      ) in cr.sentRPC
      PeerRPC(
        peerId: peerId,
        rpc: PartialMessageExtensionRPC(
          groupID: groupId,
          topicID: topic,
          partsMetadata: MyPartsMetadata.have(@[1, 2, 3]),
          partialMessage: Opt.none(seq[byte]),
        ),
      ) in cr.sentRPC

  test "publish partial message: selected peer without subscription can receive explicit metadata reply":
    const topic = "logos-partial"
    var cr = CallbackRecorder()
    var ext = PartialMessageExtension.new(cr.config())
    let publisherPeerId = PeerId.random(rng()).get()

    # publisher sent metadata for this group but is not subscribed to the topic
    ext.handlePartialMessage(
      publisherPeerId,
      PartialMessageExtensionRPC(
        topicID: topic,
        groupID: groupId,
        partsMetadata: MyPartsMetadata.have(@[1, 2, 3]),
      ),
    )

    # local node can still send an explicit metadata reply to that peer
    let pm = MyPartialMessage(
      groupId: groupId, data: initTable[Chunk, seq[byte]](), want: @[1, 2]
    )

    check ext.publishPartial(cr, topic, pm, peers = @[publisherPeerId]) == 1
    check:
      cr.sentRPC.len == 1
      cr.sentRPC[0] ==
        PeerRPC(
          peerId: publisherPeerId,
          rpc: PartialMessageExtensionRPC(
            groupID: groupId,
            topicID: topic,
            partsMetadata: MyPartsMetadata.want(@[1, 2]),
            partialMessage: Opt.none(seq[byte]),
          ),
        )

  test "publish partial message: fanout publisher":
    # fanout usecase when application publishes parts on a topic it has not
    # subscribed to.
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var config = cr.config()
    # override nodeTopicOpts to mimic a non-subscribed publisher: both flags false
    config.nodeTopicOpts = proc(topic: string): TopicOpts {.gcsafe, raises: [].} =
      TopicOpts()
    var ext = PartialMessageExtension.new(config)

    # peer subscribes with partial capability
    ext.subscribe(peerId, topic, true)

    # application/user is publishing message with parts [1, 2, 3]
    let pm = MyPartialMessage(
      groupId: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    check ext.publishPartial(cr, topic, pm, peers = @[peerId]) == 1
      # should publish to peer even though node is not subscribed

    # peer should receive parts metadata announcing what publisher has
    check:
      cr.sentRPC.len == 1
      cr.sentRPC[0] ==
        PeerRPC(
          peerId: peerId,
          rpc: PartialMessageExtensionRPC(
            groupID: groupId,
            topicID: topic,
            partsMetadata: MyPartsMetadata.have(@[1, 2, 3]),
            partialMessage: Opt.none(seq[byte]),
          ),
        )

  test "publish partial message: broadcast reaches publish targets and peers with group state":
    # broadcast publish (no explicit peers) should reach the union of:
    #   - default publish targets returned by publishToPeers, and
    #   - peers that already have per-group state for this topic.
    # the stateOnlyPeer is intentionally not subscribed, it is reached
    # only through groupState.peerState.keys and receives metadata-only.
    const topic = "logos-partial"
    let publishTargetPeerId = PeerId.random(rng()).get()
    let stateOnlyPeerId = PeerId.random(rng()).get()
    var cr = CallbackRecorder(publishToPeers: @[publishTargetPeerId])
    var ext = PartialMessageExtension.new(cr.config())

    ext.subscribe(publishTargetPeerId, topic, true)
    ext.handlePartialMessage(
      stateOnlyPeerId,
      PartialMessageExtensionRPC(
        topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1])
      ),
    )

    let pm = MyPartialMessage(groupId: groupId, data: {1: "one".toBytes}.toTable)
    check ext.publishPartial(cr, topic, pm) == 2 # both peers reached
    check cr.sentRPC.len == 2

    let publishTargetRPC = cr.sentRPC.filterIt(it.peerId == publishTargetPeerId)
    let stateOnlyRPC = cr.sentRPC.filterIt(it.peerId == stateOnlyPeerId)
    check:
      publishTargetRPC.len == 1
      publishTargetRPC[0].rpc.partialMessage.isNone
        # default publish target has sent no group metadata, gets announcement only
      publishTargetRPC[0].rpc.partsMetadata == MyPartsMetadata.have(@[1])
      stateOnlyRPC.len == 1
      stateOnlyRPC[0].rpc.partialMessage.isNone
        # reached via peerState.keys fallback, not subscribed, so metadata-only
      stateOnlyRPC[0].rpc.partsMetadata == MyPartsMetadata.have(@[1])

  test "publish parts metadata":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    ext.subscribe(peerId, topic, true)

    # should publish to peer because peer is subscribed
    # and because we are sending new parts metadata
    let pm = MyPartialMessage(groupId: groupId, data: {1: "one".toBytes}.toTable)
    check ext.publishPartial(cr, topic, pm) == 1

    check:
      cr.sentRPC.len == 1
      cr.sentRPC[0] ==
        PeerRPC(
          peerId: peerId,
          rpc: PartialMessageExtensionRPC(
            groupID: groupId, topicID: topic, partsMetadata: pm.partsMetadata()
          ),
        )

    # publishing same message again should not publish
    # because peer already has this parts metadata
    check ext.publishPartial(cr, topic, pm) == 0
    check cr.sentRPC.len == 1

    # publishing new partial message should send new parts metadata
    let pm2 = MyPartialMessage(groupId: groupId, data: {2: "two".toBytes}.toTable)
    check ext.publishPartial(cr, topic, pm2) == 1
    check:
      cr.sentRPC.len == 2
      cr.sentRPC[1] ==
        PeerRPC(
          peerId: peerId,
          rpc: PartialMessageExtensionRPC(
            groupID: groupId,
            topicID: topic,
            partsMetadata: pm.partsMetadata() & pm2.partsMetadata(),
          ),
        )

  test "heartbeat evicts metadata":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    ext.subscribe(peerId, topic, true)

    ext.handlePartialMessage(
      peerId,
      PartialMessageExtensionRPC(
        topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1])
      ),
    )

    # trigger as many heartbeat events to cause eviction of all state groups
    for i in 0 ..< cr.config().heartbeatsTillEviction + 1:
      ext.onHeartbeat()

    # should publish to peer because peer is still subscribed
    # and because we are sending new partsMetadata.
    let pm = MyPartialMessage(groupId: groupId, data: {1: "one".toBytes}.toTable)
    check ext.publishPartial(cr, topic, pm) == 1

    # and published RPC should not have partial message only parts metadata
    # as their parts metadata was evicted
    check:
      cr.sentRPC.len == 1
      cr.sentRPC[0] ==
        PeerRPC(
          peerId: peerId,
          rpc: PartialMessageExtensionRPC(
            topicID: topic,
            groupID: groupId,
            partsMetadata: MyPartsMetadata.have(toSeq(pm.data.keys)),
            partialMessage: Opt.none(seq[byte]),
          ),
        )

  test "removing peer removes metadata":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    ext.subscribe(peerId, topic, true)

    ext.handlePartialMessage(
      peerId,
      PartialMessageExtensionRPC(
        topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1])
      ),
    )

    # when peer is removed, its parts metadata will be removed
    ext.onRemovePeer(peerId)

    # should not publish to peer because metadata has been removed
    let pm = MyPartialMessage(groupId: groupId, data: {1: "one".toBytes}.toTable)
    check ext.publishPartial(cr, topic, pm) == 0

  test "publishPartial and onIncomingRPC are not called when groupId is not set":
    const topic = "logos-partial"
    var cr = CallbackRecorder(publishToPeers: @[peerId])
    var ext = PartialMessageExtension.new(cr.config())

    ext.subscribe(peerId, topic, true)

    # should not call onIncomingRPC, groupID is not set
    ext.handlePartialMessage(
      peerId,
      PartialMessageExtensionRPC(
        topicID: topic, partsMetadata: MyPartsMetadata.want(@[1, 2])
      ),
    )
    check cr.incomingRPC.len == 0

    # should call onIncomingRPC, groupID is set
    ext.handlePartialMessage(
      peerId,
      PartialMessageExtensionRPC(
        topicID: topic, groupID: groupId, partsMetadata: MyPartsMetadata.want(@[1, 2])
      ),
    )
    check cr.incomingRPC.len == 1

    # should not publish when groupId is not set
    var pm = MyPartialMessage(
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable
    )
    check ext.publishPartial(cr, topic, pm) == 0

    # should publish with groupId
    pm.groupId = groupId
    check ext.publishPartial(cr, topic, pm) == 1

  test "gossip metadata":
    const topic = "logos-partial"
    var cr = CallbackRecorder()
    var cfg = cr.config()
    cfg.heartbeatsTillEviction = 100 # do not evict for this test
    var ext = PartialMessageExtension.new(cfg)

    # publishing a partial message will store the parts metadata.
    # however, since no one is subscribed, nothing will actually be published.
    let pm = MyPartialMessage(
      groupId: groupId,
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
    )
    check ext.publishPartial(cr, topic, pm) == 0
    check cr.sentRPC.len == 0

    # subscribe peer to topic (requesting partial).
    ext.subscribe(peerId, topic, true)

    # then when gossip happens (on heartbeat), parts metadata 
    # should be sent to all peers.
    ext.onHeartbeat()

    # and because peer has requested partial messages, then
    # it will receive gossip message.
    check:
      cr.sentRPC.len == 1
      cr.sentRPC[0] ==
        PeerRPC(
          peerId: peerId,
          rpc: PartialMessageExtensionRPC(
            topicID: topic,
            groupID: groupId,
            partsMetadata: MyPartsMetadata.have(toSeq(pm.data.keys)),
          ),
        )

    # doing gossip again should not send any new messages,
    # because peer already knows the same parts metadata.
    ext.onHeartbeat()
    check cr.sentRPC.len == 1

  test "heartbeat trims groups to global limit":
    const topic = "partial-topic"
    var cr = CallbackRecorder()
    var cfg = cr.config()
    cfg.maxPartialGroups = 3
    cfg.heartbeatsTillEviction = 100
    var ext = PartialMessageExtension.new(cfg)

    # distinct peers each adding one group so per-peer cap is not the limiter
    for i in 0 ..< 10:
      let p = PeerId.random(rng()).get()
      ext.sendGroupMetadata(p, topic, "g-" & $i)

    # all groups are accepted; the global limit is enforced lazily on heartbeat
    check ext.trackedGroups == 10
    ext.onHeartbeat()
    check ext.trackedGroups == 3

  test "heartbeat trims least-recently-used groups first":
    const topic = "partial-topic"
    var cr = CallbackRecorder()
    var cfg = cr.config()
    cfg.maxPartialGroups = 2
    cfg.maxPartialGroupsPerPeer = 100
    cfg.heartbeatsTillEviction = 10
    var ext = PartialMessageExtension.new(cfg)

    let p1 = PeerId.random(rng()).get()
    let p2 = PeerId.random(rng()).get()
    let p3 = PeerId.random(rng()).get()

    ext.sendGroupMetadata(p1, topic, "g-1")
    ext.sendGroupMetadata(p2, topic, "g-2")
    ext.onHeartbeat() # ages g-1 and g-2 equally

    ext.sendGroupMetadata(p1, topic, "g-1") # refresh g-1, making g-2 the oldest
    ext.sendGroupMetadata(p3, topic, "g-3") # fresh group, total now exceeds limit
    check ext.trackedGroups == 3

    ext.onHeartbeat() # trims down to 2, evicting the least-recently-used g-2
    check:
      ext.trackedGroups == 2
      ext.hasGroup(topic, "g-1".toBytes)
      ext.hasGroup(topic, "g-3".toBytes)
      not ext.hasGroup(topic, "g-2".toBytes)

  test "group store enforces per-peer limit":
    const topic = "partial-topic"
    var cr = CallbackRecorder()
    var cfg = cr.config()
    cfg.maxPartialGroups = 100
    cfg.maxPartialGroupsPerPeer = 2
    cfg.heartbeatsTillEviction = 100
    var ext = PartialMessageExtension.new(cfg)

    for i in 0 ..< 10:
      ext.sendGroupMetadata(peerId, topic, "g-" & $i)

    # single peer cannot exceed its own budget despite global budget remaining
    check ext.trackedGroups == 2

    # a different peer still has its own budget
    let otherPeer = PeerId.random(rng()).get()
    ext.sendGroupMetadata(otherPeer, topic, "other")
    check ext.trackedGroups == 3

  test "removing a peer frees its group budget":
    const topic = "partial-topic"
    var cr = CallbackRecorder()
    var cfg = cr.config()
    cfg.maxPartialGroups = 100
    cfg.maxPartialGroupsPerPeer = 1
    cfg.heartbeatsTillEviction = 100
    var ext = PartialMessageExtension.new(cfg)

    ext.sendGroupMetadata(peerId, topic, "g-1")
    ext.sendGroupMetadata(peerId, topic, "g-2") # rejected, peer at budget
    check ext.trackedGroups == 1

    # removal evicts the empty group the peer created instead of orphaning it
    ext.onRemovePeer(peerId)
    check ext.trackedGroups == 0

    ext.sendGroupMetadata(peerId, topic, "g-3") # budget reclaimed
    check ext.trackedGroups == 1

  test "heartbeat eviction frees group budget":
    const topic = "partial-topic"
    var cr = CallbackRecorder()
    var cfg = cr.config()
    cfg.maxPartialGroups = 1
    cfg.maxPartialGroupsPerPeer = 1
    cfg.heartbeatsTillEviction = 1
    var ext = PartialMessageExtension.new(cfg)

    ext.sendGroupMetadata(peerId, topic, "g-1")
    check ext.trackedGroups == 1

    ext.sendGroupMetadata(peerId, topic, "g-2") # at capacity, rejected
    check ext.trackedGroups == 1

    # heartbeat reclaims the expired group, freeing both global and per-peer budget
    ext.onHeartbeat()
    check ext.trackedGroups == 0

    ext.sendGroupMetadata(peerId, topic, "g-3")
    check ext.trackedGroups == 1
