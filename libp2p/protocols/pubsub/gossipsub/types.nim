# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos
import std/[tables, sets]
import ".."/[floodsub, peertable, mcache, pubsubpeer]
import "../rpc"/[messages]
import "../../.."/[peerid, multiaddress]
import results
import extensions, preamblestore

export results, tables, sets
export RateLimit # downstream code names it through this module

const
  GossipSubCodec_13* = "/meshsub/1.3.0"
  GossipSubCodec_12* = "/meshsub/1.2.0"
  GossipSubCodec_11* = "/meshsub/1.1.0"
  GossipSubCodec_10* = "/meshsub/1.0.0"

# overlay parameters
const
  GossipSubD* = 6
  GossipSubDlo* = 4
  GossipSubDhi* = 12

# gossip parameters
const
  GossipSubHistoryLength* = 5
  GossipSubHistoryGossip* = 3
  GossipSubSeenMaxSize* = 4_000_000

  # heartbeat interval
  GossipSubHeartbeatInterval* = 1.seconds

# fanout ttl
const GossipSubFanoutTTL* = 1.minutes

# gossip parameters
const GossipBackoffPeriod* = 1.minutes

const
  BackoffSlackTime* = 2 # seconds
  IHavePeerBudget* = 10
  PreamblePeerBudget* = 10
  PullOperation* = true
  # the max amount of IHave to expose, not by spec, but go as example
  # rust sigp: https://github.com/sigp/rust-libp2p/blob/f53d02bc873fef2bf52cd31e3d5ce366a41d8a8c/protocols/gossipsub/src/config.rs#L572
  # go: https://github.com/libp2p/go-libp2p-pubsub/blob/08c17398fb11b2ab06ca141dddc8ec97272eb772/gossipsub.go#L155
  IHaveMaxLength* = 5000
  IDontWantMaxCount* = 1000
    # maximum number of IDontWant messages in one slot of the history
  MaxOpportunisticGraftPeers* = 2
  IWantHistoryLen* = 3 # number of heartbeats that an IWANT request stays in flight
  DefaultMaxIWantsPerMessage* = 2

type
  IWantRequest* = object
    peerId*: PeerId
    heartbeat*: uint64

  TopicInfo* = object # gossip 1.1 related
    graftTime*: Moment
    lastGraftSent*: Moment
    meshTime*: Duration
    inMesh*: bool
    meshMessageDeliveriesActive*: bool
    firstMessageDeliveries*: float64
    meshMessageDeliveries*: float64
    meshFailurePenalty*: float64
    invalidMessageDeliveries*: float64

  TopicParams* = object
    topicWeight*: float64

    # p1
    timeInMeshWeight*: float64
    timeInMeshQuantum*: Duration
    timeInMeshCap*: float64

    # p2
    firstMessageDeliveriesWeight*: float64
    firstMessageDeliveriesDecay*: float64
    firstMessageDeliveriesCap*: float64

    # p3
    meshMessageDeliveriesWeight*: float64
    meshMessageDeliveriesDecay*: float64
    meshMessageDeliveriesThreshold*: float64
    meshMessageDeliveriesCap*: float64
    meshMessageDeliveriesActivation*: Duration
    meshMessageDeliveriesWindow*: Duration

    # p3b
    meshFailurePenaltyWeight*: float64
    meshFailurePenaltyDecay*: float64

    # p4
    invalidMessageDeliveriesWeight*: float64
    invalidMessageDeliveriesDecay*: float64

  PeerStats* = object
    topicInfos*: Table[string, TopicInfo]
    expire*: Moment # updated on disconnect, to retain scores until expire
    # the following are copies from PubSubPeer, in order to restore them on re-connection
    score*: float64 # a copy of the score to keep in case the peer is disconnected
    appScore*: float64 # application specific score
    slowPeerPenalty*: float64 # penalty from repeated medium/low queue overflow drops
    behaviourPenalty*: float64 # the eventual penalty score

  GossipSubParams* = object
    # explicit is used to check if the GossipSubParams instance was created by the user either passing params to GossipSubParams(...)
    # or GossipSubParams.init(...). In the first case explicit should be set to true when calling the Nim constructor.
    # In the second case, the param isn't necessary and should be always be set to true by init.
    # If none of those options were used, it means the instance was created using Nim default values.
    # In this case, GossipSubParams.init() should be called when initing GossipSub to set the values to their default value defined by nim-libp2p.
    explicit*: bool
    pruneBackoff*: Duration
    unsubscribeBackoff*: Duration
    floodPublish*: bool
    gossipFactor*: float64
    d*: int
    dLow*: int
    dHigh*: int
    dScore*: int
    dOut*: int
    dLazy*: int

    heartbeatInterval*: Duration

    historyLength*: int
    historyGossip*: int

    fanoutTTL*: Duration
    seenTTL*: Duration
    seenMaxSize*: int

    gossipThreshold*: float64
    publishThreshold*: float64
    graylistThreshold*: float64
    acceptPXThreshold*: float64
    opportunisticGraftThreshold*: float64
    decayInterval*: Duration
    decayToZero*: float64
    retainScore*: Duration

    appSpecificWeight*: float64
    ipColocationFactorWeight*: float64
    ipColocationFactorThreshold*: float64
    slowPeerPenaltyWeight*: float64
    slowPeerPenaltyThreshold*: float64
    slowPeerPenaltyDecay*: float64
    behaviourPenaltyWeight*: float64
    behaviourPenaltyDecay*: float64

    directPeers*: Table[PeerId, seq[MultiAddress]]

    disconnectBadPeers*: bool
    enablePX*: bool

    bandwidthEstimatebps*: int
      # This is currently used only for limting flood publishing. 0 disables flood-limiting completely

    overheadRateLimit*: Opt[RateLimit]
    disconnectPeerAboveRateLimit*: bool

    # Max number of high-priority sends. When this limit has been reached, the peer will be disconnected.
    maxHighPriorityQueueLen*: int
    # Max number of enqueued medium-priority messages. Excess messages are dropped.
    maxMediumPriorityQueueLen*: int
    # Max number of enqueued low-priority messages. Excess messages are dropped.
    maxLowPriorityQueueLen*: int

    # Max number of peers we send an IWANT to for the same message at the same time.
    maxIWantsPerMessage*: int

    # Broadcast an IDONTWANT message automatically when the message exceeds the IDONTWANT message size threshold
    sendIDontWantOnPublish*: bool

    # Extensions configuration
    testExtensionConfig*: Opt[TestExtensionConfig]
    partialMessageExtensionConfig*: Opt[PartialMessageExtensionConfig]
    pingpongExtensionConfig*: Opt[PingPongExtensionConfig]
    preambleExtensionConfig*: Opt[PreambleExtensionConfig]

  BackoffTable* = Table[string, Table[PeerId, Moment]]
  ValidationSeenTable* = Table[SaltedId, HashSet[PubSubPeer]]
  OngoingReceivesStore* = PreambleStore

  RoutingRecordsPair* = tuple[id: PeerId, record: Opt[PeerRecord]]
  RoutingRecordsHandler* = proc(
    peer: PeerId,
    tag: string, # For gossipsub, the topic
    peers: seq[RoutingRecordsPair],
  ) {.gcsafe, raises: [].}

  GossipSub* = ref object of FloodSub
    mesh*: PeerTable # peers that we send messages to when we are subscribed to the topic
    fanout*: PeerTable
      # peers that we send messages to when we're not subscribed to the topic
    gossipsub*: PeerTable # peers that are subscribed to a topic
    subscribedDirectPeers*: PeerTable # directpeers that we keep alive
    backingOff*: BackoffTable # peers to backoff from when replenishing the mesh
    lastFanoutPubSub*: Table[string, Moment] # last publish time for fanout topics
    mcache*: MCache # messages cache
    validationSeen*: ValidationSeenTable # peers who sent us message in validation
    requestedIWants*: Table[SaltedId, seq[IWantRequest]]
      # peers with an IWANT request in flight, per message
    heartbeatCount*: uint64 # heartbeats since start, used to expire IWANT requests
    heartbeatFut*: Future[void] # cancellation future for heartbeat interval
    scoringHeartbeatFut*: Future[void]
      # cancellation future for scoring heartbeat interval
    heartbeatRunning*: bool
    extensionsState*: ExtensionsState
    peerStats*: Table[PeerId, PeerStats]
    parameters*: GossipSubParams
    topicParams*: Table[string, TopicParams]
    directPeersLoop*: Future[void]
    peersInIP*: Table[MultiAddress, HashSet[PeerId]]
    routingRecordsHandler*: seq[RoutingRecordsHandler] # Callback for peer exchange
    heartbeatEvents*: seq[AsyncEvent]
    scoringHeartbeatEvents*: seq[AsyncEvent]
    pendingTasks*: seq[Future[void]]
    stopFut*: Future[void].Raising([]) # Concurrent stops share cleanup after tasks move.
    overheadMetricsWindowStart*: Moment
    rpcOverheadBytesMax*: int
    peerOverheadBytesPerSecondMax*: int

  MeshMetrics* = object # scratch buffers for metrics
    otherPeersPerTopicMesh*: int64
    otherPeersPerTopicFanout*: int64
    otherPeersPerTopicGossipsub*: int64
    noPeersTopics*: int64 # npeers == 0
    lowPeersTopics*: int64 # npeers < dlow
    healthyPeersTopics*: int64 # npeers >= dlow
    underDoutTopics*: int64
