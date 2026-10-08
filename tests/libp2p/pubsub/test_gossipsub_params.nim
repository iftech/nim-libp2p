# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import ../../../libp2p/protocols/pubsub/gossipsub/[types]
import ../../../libp2p/protocols/pubsub/[gossipsub, pubsubpeer]
import ../../../libp2p/[peerid, multiaddress]
import ../../tools/unittest

suite "GossipSubParams validation":
  proc newDefaultValidParams(): GossipSubParams =
    GossipSubParams.init()

  test "default parameters are valid":
    var params = newDefaultValidParams()
    check:
      params.validateParameters().isOk()
      params.seenMaxSize == GossipSubSeenMaxSize

  test "dOut fails when equal to dLow":
    const errorMessage =
      "gossipsub: dOut parameter error, Number of outbound connections to keep in the mesh. Must be less than D_lo and at most D/2"
    var params = newDefaultValidParams()
    params.dLow = 4
    params.d = 8
    params.dOut = params.dLow
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "dOut fails when bigger than d/2":
    const errorMessage =
      "gossipsub: dOut parameter error, Number of outbound connections to keep in the mesh. Must be less than D_lo and at most D/2"
    var params = newDefaultValidParams()
    params.dLow = 4
    params.d = 5
    params.dOut = 3
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "dOut succeeds when less than dLow and equals d/2":
    var params = newDefaultValidParams()
    params.dLow = 4
    params.d = 6
    params.dOut = 3
    check params.validateParameters()

  test "gossipThreshold fails when zero":
    const errorMessage = "gossipsub: gossipThreshold parameter error, Must be < 0"
    var params = newDefaultValidParams()
    params.gossipThreshold = 0.0
    var res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "gossipThreshold succeeds when negative":
    var params = newDefaultValidParams()
    params.gossipThreshold = -0.1
    check params.validateParameters()

  test "unsubscribeBackoff fails when zero":
    const errorMessage =
      "gossipsub: unsubscribeBackoff parameter error, Must be > 0 seconds"
    var params = newDefaultValidParams()
    params.unsubscribeBackoff = 0.seconds
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "unsubscribeBackoff succeeds when positive":
    var params = newDefaultValidParams()
    params.unsubscribeBackoff = 1.seconds
    check params.validateParameters()

  test "historyLength fails when zero":
    const errorMessage = "gossipsub: historyLength parameter error, Must be > 0"
    var params = newDefaultValidParams()
    params.historyLength = 0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "historyGossip fails when negative":
    const errorMessage = "gossipsub: historyGossip parameter error, Must be >= 0"
    var params = newDefaultValidParams()
    params.historyGossip = -1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "historyGossip succeeds when zero":
    var params = newDefaultValidParams()
    params.historyGossip = 0
    check params.validateParameters()

  test "seenMaxSize fails when zero":
    const errorMessage = "gossipsub: seenMaxSize parameter error, Must be > 0"
    var params = newDefaultValidParams()
    params.seenMaxSize = 0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "seenMaxSize succeeds when positive":
    var params = newDefaultValidParams()
    params.seenMaxSize = 1
    check params.validateParameters()

  test "publishThreshold fails when equal to gossipThreshold":
    const errorMessage =
      "gossipsub: publishThreshold parameter error, Must be < gossipThreshold"
    var params = newDefaultValidParams()
    params.publishThreshold = params.gossipThreshold
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "publishThreshold succeeds when less than gossipThreshold":
    var params = newDefaultValidParams()
    params.publishThreshold = params.gossipThreshold - 1.0
    check params.validateParameters()

  test "graylistThreshold fails when equal to publishThreshold":
    const errorMessage =
      "gossipsub: graylistThreshold parameter error, Must be < publishThreshold"
    var params = newDefaultValidParams()
    params.graylistThreshold = params.publishThreshold
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "graylistThreshold succeeds when less than publishThreshold":
    var params = newDefaultValidParams()
    params.graylistThreshold = params.publishThreshold - 1.0
    check params.validateParameters()

  test "acceptPXThreshold fails when negative":
    const errorMessage = "gossipsub: acceptPXThreshold parameter error, Must be >= 0"
    var params = newDefaultValidParams()
    params.acceptPXThreshold = -0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "acceptPXThreshold succeeds when zero":
    var params = newDefaultValidParams()
    params.acceptPXThreshold = 0.0
    check params.validateParameters()

  test "opportunisticGraftThreshold fails when negative":
    const errorMessage =
      "gossipsub: opportunisticGraftThreshold parameter error, Must be >= 0"
    var params = newDefaultValidParams()
    params.opportunisticGraftThreshold = -0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "opportunisticGraftThreshold succeeds when zero":
    var params = newDefaultValidParams()
    params.opportunisticGraftThreshold = 0.0
    check params.validateParameters()

  test "decayToZero fails when greater than 0.5":
    const errorMessage =
      "gossipsub: decayToZero parameter error, Should be close to 0.0"
    var params = newDefaultValidParams()
    params.decayToZero = 0.51
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "decayToZero fails when zero":
    const errorMessage =
      "gossipsub: decayToZero parameter error, Should be close to 0.0"
    var params = newDefaultValidParams()
    params.decayToZero = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "decayToZero succeeds when exactly 0.5":
    var params = newDefaultValidParams()
    params.decayToZero = 0.5
    check params.validateParameters()

  test "decayToZero succeeds when small positive value":
    var params = newDefaultValidParams()
    params.decayToZero = 0.00001
    check params.validateParameters()

  test "appSpecificWeight fails when negative":
    const errorMessage =
      "gossipsub: appSpecificWeight parameter error, Must be positive"
    var params = newDefaultValidParams()
    params.appSpecificWeight = -0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "appSpecificWeight succeeds when zero":
    var params = newDefaultValidParams()
    params.appSpecificWeight = 0.0
    check params.validateParameters()

  test "ipColocationFactorWeight fails when positive":
    const errorMessage =
      "gossipsub: ipColocationFactorWeight parameter error, Must be negative or 0"
    var params = newDefaultValidParams()
    params.ipColocationFactorWeight = 0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "ipColocationFactorWeight succeeds when zero":
    var params = newDefaultValidParams()
    params.ipColocationFactorWeight = 0.0
    check params.validateParameters()

  test "ipColocationFactorWeight succeeds when negative":
    var params = newDefaultValidParams()
    params.ipColocationFactorWeight = -10.0
    check params.validateParameters()

  test "ipColocationFactorThreshold fails when less than 1":
    const errorMessage =
      "gossipsub: ipColocationFactorThreshold parameter error, Must be at least 1"
    var params = newDefaultValidParams()
    params.ipColocationFactorThreshold = 0.9
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "ipColocationFactorThreshold succeeds when exactly 1":
    var params = newDefaultValidParams()
    params.ipColocationFactorThreshold = 1.0
    check params.validateParameters()

  test "behaviourPenaltyWeight fails when zero":
    const errorMessage =
      "gossipsub: behaviourPenaltyWeight parameter error, Must be negative"
    var params = newDefaultValidParams()
    params.behaviourPenaltyWeight = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "behaviourPenaltyWeight succeeds when negative":
    var params = newDefaultValidParams()
    params.behaviourPenaltyWeight = -0.0001
    check params.validateParameters()

  test "behaviourPenaltyDecay fails when negative":
    const errorMessage =
      "gossipsub: behaviourPenaltyDecay parameter error, Must be between 0 and 1"
    var params = newDefaultValidParams()
    params.behaviourPenaltyDecay = -0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "behaviourPenaltyDecay fails when equal to 1":
    const errorMessage =
      "gossipsub: behaviourPenaltyDecay parameter error, Must be between 0 and 1"
    var params = newDefaultValidParams()
    params.behaviourPenaltyDecay = 1.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "behaviourPenaltyDecay succeeds when zero":
    var params = newDefaultValidParams()
    params.behaviourPenaltyDecay = 0.0
    check params.validateParameters()

  test "behaviourPenaltyDecay succeeds when between 0 and 1":
    var params = newDefaultValidParams()
    params.behaviourPenaltyDecay = 0.5
    check params.validateParameters()

  test "slowPeerPenaltyWeight fails when positive":
    const errorMessage =
      "gossipsub: slowPeerPenaltyWeight parameter error, Must be negative or 0"
    var params = newDefaultValidParams()
    params.slowPeerPenaltyWeight = 0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "slowPeerPenaltyWeight succeeds when zero":
    var params = newDefaultValidParams()
    params.slowPeerPenaltyWeight = 0.0
    check params.validateParameters()

  test "slowPeerPenaltyWeight succeeds when negative":
    var params = newDefaultValidParams()
    params.slowPeerPenaltyWeight = -0.0001
    check params.validateParameters()

  test "slowPeerPenaltyThreshold fails when negative":
    const errorMessage =
      "gossipsub: slowPeerPenaltyThreshold parameter error, Must be positive or 0"
    var params = newDefaultValidParams()
    params.slowPeerPenaltyThreshold = -0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "slowPeerPenaltyThreshold succeeds when zero":
    var params = newDefaultValidParams()
    params.slowPeerPenaltyThreshold = 0.0
    check params.validateParameters()

  test "slowPeerPenaltyThreshold succeeds when positive":
    var params = newDefaultValidParams()
    params.slowPeerPenaltyThreshold = 1.0
    check params.validateParameters()

  test "slowPeerPenaltyDecay fails when negative":
    const errorMessage =
      "gossipsub: slowPeerPenaltyDecay parameter error, Must be between 0 and 1 (exclusive)"
    var params = newDefaultValidParams()
    params.slowPeerPenaltyDecay = -0.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "slowPeerPenaltyDecay fails when zero":
    const errorMessage =
      "gossipsub: slowPeerPenaltyDecay parameter error, Must be between 0 and 1 (exclusive)"
    var params = newDefaultValidParams()
    params.slowPeerPenaltyDecay = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "slowPeerPenaltyDecay fails when equal to 1":
    const errorMessage =
      "gossipsub: slowPeerPenaltyDecay parameter error, Must be between 0 and 1 (exclusive)"
    var params = newDefaultValidParams()
    params.slowPeerPenaltyDecay = 1.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "slowPeerPenaltyDecay succeeds when between 0 and 1":
    var params = newDefaultValidParams()
    params.slowPeerPenaltyDecay = 0.5
    check params.validateParameters()

  test "maxHighPriorityQueueLen fails when zero":
    const errorMessage =
      "gossipsub: maxHighPriorityQueueLen parameter error, Must be > 0"
    var params = newDefaultValidParams()
    params.maxHighPriorityQueueLen = 0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "maxHighPriorityQueueLen succeeds when positive":
    var params = newDefaultValidParams()
    params.maxHighPriorityQueueLen = 1
    check params.validateParameters()

  test "maxMediumPriorityQueueLen fails when zero":
    const errorMessage =
      "gossipsub: maxMediumPriorityQueueLen parameter error, Must be > 0"
    var params = newDefaultValidParams()
    params.maxMediumPriorityQueueLen = 0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "maxMediumPriorityQueueLen succeeds when positive":
    var params = newDefaultValidParams()
    params.maxMediumPriorityQueueLen = 1
    check params.validateParameters()

  test "maxLowPriorityQueueLen fails when zero":
    const errorMessage =
      "gossipsub: maxLowPriorityQueueLen parameter error, Must be > 0"
    var params = newDefaultValidParams()
    params.maxLowPriorityQueueLen = 0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "maxLowPriorityQueueLen succeeds when positive":
    var params = newDefaultValidParams()
    params.maxLowPriorityQueueLen = 1
    check params.validateParameters()

  test "overheadRateLimit.bytes fails when zero":
    const errorMessage =
      "gossipsub: overheadRateLimit.bytes parameter error, Must be > 0"
    var params = newDefaultValidParams()
    params.overheadRateLimit = Opt.some(RateLimit(bytes: 0, interval: 1.seconds))
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "overheadRateLimit.interval fails when zero":
    const errorMessage =
      "gossipsub: overheadRateLimit.interval parameter error, Must be > 0"
    var params = newDefaultValidParams()
    params.overheadRateLimit = Opt.some(RateLimit(bytes: 1, interval: ZeroDuration))
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "overheadRateLimit succeeds when both fields are positive":
    var params = newDefaultValidParams()
    params.overheadRateLimit = Opt.some(RateLimit(bytes: 1, interval: 1.seconds))
    check params.validateParameters()

  test "disconnectPeerAboveRateLimit fails without overheadRateLimit":
    const errorMessage =
      "gossipsub: disconnectPeerAboveRateLimit parameter error, Requires overheadRateLimit"
    var params = newDefaultValidParams()
    params.disconnectPeerAboveRateLimit = true
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "disconnectPeerAboveRateLimit succeeds with overheadRateLimit":
    var params = newDefaultValidParams()
    params.overheadRateLimit = Opt.some(RateLimit(bytes: 1, interval: 1.seconds))
    params.disconnectPeerAboveRateLimit = true
    check params.validateParameters()

suite "TopicParams validation":
  proc newDefaultValidTopicParams(): TopicParams =
    TopicParams.init()

  test "default topic parameters are valid":
    var params = newDefaultValidTopicParams()
    check params.validateParameters()

  test "timeInMeshWeight fails when zero":
    const errorMessage =
      "gossipsub: timeInMeshWeight parameter error, Must be a small positive value"
    var params = newDefaultValidTopicParams()
    params.timeInMeshWeight = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "timeInMeshWeight fails when greater than 1":
    const errorMessage =
      "gossipsub: timeInMeshWeight parameter error, Must be a small positive value"
    var params = newDefaultValidTopicParams()
    params.timeInMeshWeight = 1.1
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "timeInMeshWeight succeeds when exactly 1":
    var params = newDefaultValidTopicParams()
    params.timeInMeshWeight = 1.0
    check params.validateParameters()

  test "timeInMeshWeight succeeds when small positive value":
    var params = newDefaultValidTopicParams()
    params.timeInMeshWeight = 0.01
    check params.validateParameters()

  test "timeInMeshCap fails when zero":
    const errorMessage =
      "gossipsub: timeInMeshCap parameter error, Should be a positive value"
    var params = newDefaultValidTopicParams()
    params.timeInMeshCap = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "timeInMeshCap succeeds when positive":
    var params = newDefaultValidTopicParams()
    params.timeInMeshCap = 10.0
    check params.validateParameters()

  test "firstMessageDeliveriesWeight fails when zero":
    const errorMessage =
      "gossipsub: firstMessageDeliveriesWeight parameter error, Should be a positive value"
    var params = newDefaultValidTopicParams()
    params.firstMessageDeliveriesWeight = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "firstMessageDeliveriesWeight succeeds when positive":
    var params = newDefaultValidTopicParams()
    params.firstMessageDeliveriesWeight = 1.0
    check params.validateParameters()

  test "meshMessageDeliveriesWeight fails when zero":
    const errorMessage =
      "gossipsub: meshMessageDeliveriesWeight parameter error, Should be a negative value"
    var params = newDefaultValidTopicParams()
    params.meshMessageDeliveriesWeight = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "meshMessageDeliveriesWeight succeeds when negative":
    var params = newDefaultValidTopicParams()
    params.meshMessageDeliveriesWeight = -1.0
    check params.validateParameters()

  test "meshMessageDeliveriesThreshold fails when zero":
    const errorMessage =
      "gossipsub: meshMessageDeliveriesThreshold parameter error, Should be a positive value"
    var params = newDefaultValidTopicParams()
    params.meshMessageDeliveriesThreshold = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "meshMessageDeliveriesThreshold succeeds when positive":
    var params = newDefaultValidTopicParams()
    params.meshMessageDeliveriesThreshold = 5.0
    check params.validateParameters()

  test "meshMessageDeliveriesCap fails when less than threshold":
    const errorMessage =
      "gossipsub: meshMessageDeliveriesCap parameter error, Should be >= meshMessageDeliveriesThreshold"
    var params = newDefaultValidTopicParams()
    params.meshMessageDeliveriesThreshold = 10.0
    params.meshMessageDeliveriesCap = 9.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "meshMessageDeliveriesCap succeeds when equal to threshold":
    var params = newDefaultValidTopicParams()
    params.meshMessageDeliveriesThreshold = 10.0
    params.meshMessageDeliveriesCap = 10.0
    check params.validateParameters()

  test "meshFailurePenaltyWeight fails when zero":
    const errorMessage =
      "gossipsub: meshFailurePenaltyWeight parameter error, Should be a negative value"
    var params = newDefaultValidTopicParams()
    params.meshFailurePenaltyWeight = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "meshFailurePenaltyWeight succeeds when negative":
    var params = newDefaultValidTopicParams()
    params.meshFailurePenaltyWeight = -1.0
    check params.validateParameters()

  test "invalidMessageDeliveriesWeight fails when zero":
    const errorMessage =
      "gossipsub: invalidMessageDeliveriesWeight parameter error, Should be a negative value"
    var params = newDefaultValidTopicParams()
    params.invalidMessageDeliveriesWeight = 0.0
    let res = params.validateParameters()
    check res.isErr()
    check res.error == errorMessage

  test "invalidMessageDeliveriesWeight succeeds when negative":
    var params = newDefaultValidTopicParams()
    params.invalidMessageDeliveriesWeight = -1.0
    check params.validateParameters()
