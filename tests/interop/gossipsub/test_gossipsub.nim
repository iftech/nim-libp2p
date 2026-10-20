# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, json
import
  ../../../libp2p/[peerid, protocols/pubsub/gossipsub, protocols/pubsub/rpc/message]
import ../../../interop/gossipsub/src/[node, instructions]
import ../../tools/[unittest]

suite "GossipSub Interop":
  const expectedPeerIds = [
    # Node 0
    "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
    # Node 1
    "12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X",
    # Node 2
    "12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3",
    # Node 3
    "12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo",
    # Node 4
    "12D3KooWLJtG8fd2hkQzTn96MrLvThmnNQjTUFZwGEsLRz5EmSzc",
  ]

  test "nodePeerId matches Go implementation for node 0-4":
    for i in 0 ..< expectedPeerIds.len:
      let pid = nodePeerId(i)
      let expected = PeerId.init(expectedPeerIds[i]).get()
      check pid == expected

  test "message ID is the raw first 8 bytes":
    var data = newSeq[byte](1024)
    # Message ID 42: big-endian encoding
    data[7] = 42
    let msg = Message(data: data, topic: "foobar")
    let res = interopMsgIdProvider(msg)
    check:
      res.isOk
      res.get() == @[byte 0, 0, 0, 0, 0, 0, 0, 42]

  test "parse initGossipSub instruction":
    let j = parseJson("""{"type": "initGossipSub", "gossipSubParams": {"D": 6}}""")
    let instr = parseInstruction(j)
    check:
      instr.kind == InitGossipSub
      instr.gossipSubParams.d == 6

  test "parse connect instruction":
    let j = parseJson("""{"type": "connect", "connectTo": [1, 2, 3]}""")
    let instr = parseInstruction(j)
    check:
      instr.kind == Connect
      instr.connectTo == @[1, 2, 3]

  test "parse ifNodeIDEquals instruction":
    let j = parseJson(
      """{"type": "ifNodeIDEquals", "nodeID": 5, "instruction": {"type": "connect", "connectTo": [0]}}"""
    )
    let instr = parseInstruction(j)
    check:
      instr.kind == IfNodeIDEquals
      instr.nodeID == 5
      instr.inner.kind == Connect
      instr.inner.connectTo == @[0]

  test "parse waitUntil instruction":
    let j = parseJson("""{"type": "waitUntil", "elapsedSeconds": 30}""")
    let instr = parseInstruction(j)
    check:
      instr.kind == WaitUntil
      instr.elapsed == 30.seconds

  test "parse subscribeToTopic instruction":
    let j = parseJson("""{"type": "subscribeToTopic", "topicID": "foobar"}""")
    let instr = parseInstruction(j)
    check:
      instr.kind == SubscribeToTopic
      instr.topicID == "foobar"
      instr.partial == false

  test "parse subscribeToTopic with partial":
    let j = parseJson(
      """{"type": "subscribeToTopic", "topicID": "foobar", "partial": true}"""
    )
    let instr = parseInstruction(j)
    check:
      instr.kind == SubscribeToTopic
      instr.partial == true

  test "parse publish instruction":
    let j = parseJson(
      """{"type": "publish", "messageID": 7, "messageSizeBytes": 2048, "topicID": "test"}"""
    )
    let instr = parseInstruction(j)
    check:
      instr.kind == Publish
      instr.publishMessageID == 7
      instr.messageSizeBytes == 2048
      instr.publishTopicID == "test"

  test "parse setTopicValidationDelay with float seconds":
    let j = parseJson(
      """{"type": "setTopicValidationDelay", "topicID": "foobar", "delaySeconds": 0.3}"""
    )
    let instr = parseInstruction(j)
    check:
      instr.kind == SetTopicValidationDelay
      instr.validationTopicID == "foobar"
      instr.delay == 300.milliseconds

  test "parse addPartialMessage instruction":
    let j = parseJson(
      """{"type": "addPartialMessage", "topicID": "a-subnet", "groupID": 42, "parts": 5}"""
    )
    let instr = parseInstruction(j)
    check:
      instr.kind == AddPartialMessage
      instr.addTopicID == "a-subnet"
      instr.groupID == 42'u64
      instr.partsBitmap == 5'u8 # bits 0 and 2

  test "parse publishPartial instruction":
    let j =
      parseJson("""{"type": "publishPartial", "topicID": "a-subnet", "groupID": 42}""")
    let instr = parseInstruction(j)
    check:
      instr.kind == PublishPartial
      instr.publishPartialTopicID == "a-subnet"
      instr.publishPartialGroupID == 42'u64
      instr.publishToNodeIDs.len == 0

  test "parse publishPartial with publishToNodeIDs":
    let j = parseJson(
      """{"type": "publishPartial", "topicID": "a-subnet", "groupID": 42, "publishToNodeIDs": [0, 1, 2]}"""
    )
    let instr = parseInstruction(j)
    check:
      instr.kind == PublishPartial
      instr.publishToNodeIDs == @[0, 1, 2]

  test "parse ifNodeIDEquals wrapping addPartialMessage":
    let j = parseJson(
      """{"type": "ifNodeIDEquals", "nodeID": 3, "instruction": {"type": "addPartialMessage", "topicID": "a-subnet", "groupID": 1, "parts": 255}}"""
    )
    let instr = parseInstruction(j)
    check:
      instr.kind == IfNodeIDEquals
      instr.nodeID == 3
      instr.inner.kind == AddPartialMessage
      instr.inner.addTopicID == "a-subnet"
      instr.inner.groupID == 1'u64
      instr.inner.partsBitmap == 255'u8

  test "parse full script":
    let j = parseJson(
      """{"script": [
      {"type": "initGossipSub", "gossipSubParams": {}},
      {"type": "waitUntil", "elapsedSeconds": 10},
      {"type": "subscribeToTopic", "topicID": "test"}
    ]}"""
    )
    let script = parseScript(j)
    check:
      script.len == 3
      script[0].kind == InitGossipSub
      script[1].kind == WaitUntil
      script[2].kind == SubscribeToTopic

  test "toGossipSubParams maps all fields and uses default for missing ones":
    let default = GossipSubParams.init()

    let empty = toGossipSubParams(parseJson("""{}"""))
    check:
      empty.d == default.d
      empty.heartbeatInterval == default.heartbeatInterval

    let params = toGossipSubParams(
      parseJson(
        """{
        "D": 8, "Dlo": 5, "Dhi": 14,
        "HeartbeatInterval": 2000000000,
        "FanoutTTL": 60000000000,
        "PruneBackoff": 30000000000,
        "UnsubscribeBackoff": 10000000000,
        "HistoryLength": 10,
        "HistoryGossip": 5,
        "Dlazy": 8,
        "GossipFactor": 0.5
      }"""
      )
    )
    check:
      params.d == 8
      params.dLow == 5
      params.dHigh == 14
      params.heartbeatInterval == 2.seconds
      params.fanoutTTL == 1.minutes
      params.pruneBackoff == 30.seconds
      params.unsubscribeBackoff == 10.seconds
      params.historyLength == 10
      params.historyGossip == 5
      params.dLazy == 8
      params.gossipFactor == 0.5
