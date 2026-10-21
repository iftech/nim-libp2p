# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import ../../../../libp2p/protocols/pubsub/[gossipsub, pubsub, rpc/messages]
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

suite "GossipSub Component - Signature Flags":
  const
    topic = "foobar"
    testData = "test message".toBytes()

  teardown:
    checkTrackers()

  asyncTest "Default - messages are signed when sign=true and contain fromPeer and seqno when anonymize=false":
    let nodes = generateNodes(
        2, gossip = true, sign = true, verifySignature = true, anonymize = false
      )
      .toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    var (receivedMessages, checkForMessage) = createCheckForMessages()
    nodes[1].addOnRecvObserver(checkForMessage)

    tryPublish await nodes[0].publish(topic, testData), 1

    checkUntilTimeout:
      receivedMessages[].len > 0

    let rm = receivedMessages[][0]
    check:
      rm.data == testData
      rm.fromPeer.data.len > 0
      rm.seqno.len > 0
      rm.signature.len > 0
      rm.key.len > 0

  asyncTest "Seqno - instances initialize their counters independently":
    let nodes = generateNodes(2, gossip = true) & generateNodes(2, gossip = false)

    check:
      nodes[0].msgSeqno != nodes[1].msgSeqno
      nodes[2].msgSeqno != nodes[3].msgSeqno

  asyncTest "Sign flag - messages are not signed when sign=false":
    let nodes = generateNodes(
        2, gossip = true, sign = false, verifySignature = false, anonymize = false
      )
      .toGossipSub()

    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    var (receivedMessages, checkForMessage) = createCheckForMessages()
    nodes[1].addOnRecvObserver(checkForMessage)

    tryPublish await nodes[0].publish(topic, testData), 1

    checkUntilTimeout:
      receivedMessages[].len > 0

    let rm = receivedMessages[][0]
    check:
      rm.data == testData
      rm.signature.len == 0
      rm.key.len == 0

  asyncTest "Anonymize flag - messages are anonymous when anonymize=true":
    let nodes = generateNodes(
        2, gossip = true, sign = true, verifySignature = true, anonymize = true
      )
      .toGossipSub() # anonymize = true takes precedence
    startAndDeferStop(nodes)
    await connectStar(nodes)

    subscribeAllNodes(nodes, topic, voidTopicHandler)
    waitSubscribeStar(nodes, topic)

    var (receivedMessages, checkForMessage) = createCheckForMessages()
    nodes[1].addOnRecvObserver(checkForMessage)

    let testData = "anonymous message".toBytes()
    tryPublish await nodes[0].publish(topic, testData), 1

    checkUntilTimeout:
      receivedMessages[].len > 0

    let rm = receivedMessages[][0]
    check:
      rm.data == testData
      rm.fromPeer.data.len == 0
      rm.seqno.len == 0
      rm.signature.len == 0
      rm.key.len == 0

  type NodeConfig = object
    sign: bool
    verify: bool
    anonymize: bool

  type Scenario = object
    senderConfig: NodeConfig
    receiverConfig: NodeConfig
    shouldWork: bool

  const scenarios: seq[Scenario] = @[
    # valid combos
    # S default, R default
    Scenario(
      senderConfig: NodeConfig(sign: true, verify: true, anonymize: false),
      receiverConfig: NodeConfig(sign: true, verify: true, anonymize: false),
      shouldWork: true,
    ),
    # S default, R anonymous
    Scenario(
      senderConfig: NodeConfig(sign: true, verify: true, anonymize: false),
      receiverConfig: NodeConfig(sign: false, verify: false, anonymize: true),
      shouldWork: true,
    ),
    # S anonymous, R anonymous
    Scenario(
      senderConfig: NodeConfig(sign: false, verify: false, anonymize: true),
      receiverConfig: NodeConfig(sign: false, verify: false, anonymize: true),
      shouldWork: true,
    ),
    # S only sign, R only verify
    Scenario(
      senderConfig: NodeConfig(sign: true, verify: false, anonymize: false),
      receiverConfig: NodeConfig(sign: false, verify: true, anonymize: false),
      shouldWork: true,
    ),
    # S only verify, R only sign
    Scenario(
      senderConfig: NodeConfig(sign: true, verify: true, anonymize: true),
      receiverConfig: NodeConfig(sign: false, verify: false, anonymize: false),
      shouldWork: true,
    ),
    # S anonymous (not signed despite the flag), R minimal
    Scenario(
      senderConfig: NodeConfig(sign: false, verify: true, anonymize: true),
      receiverConfig: NodeConfig(sign: true, verify: false, anonymize: false),
      shouldWork: true,
    ),
    # S unsigned, R unsigned
    Scenario(
      senderConfig: NodeConfig(sign: false, verify: false, anonymize: false),
      receiverConfig: NodeConfig(sign: false, verify: false, anonymize: false),
      shouldWork: true,
    ),

    # invalid combos
    # S anonymous, R default
    Scenario(
      senderConfig: NodeConfig(sign: false, verify: false, anonymize: true),
      receiverConfig: NodeConfig(sign: true, verify: true, anonymize: false),
      shouldWork: false,
    ),
    # S unsigned, R anonymous but verify 
    Scenario(
      senderConfig: NodeConfig(sign: false, verify: false, anonymize: false),
      receiverConfig: NodeConfig(sign: true, verify: true, anonymize: true),
      shouldWork: false,
    ),
    # S unsigned, R default
    Scenario(
      senderConfig: NodeConfig(sign: false, verify: false, anonymize: false),
      receiverConfig: NodeConfig(sign: true, verify: true, anonymize: false),
      shouldWork: false,
    ),
  ]

  for scenario in scenarios:
    let
      title = "Compatibility matrix: " & $scenario
      # Create a copy to avoid lent iterator capture issue
      localScenario = scenario
    asyncTest title:
      let
        sender = generateNodes(
          1,
          gossip = true,
          sign = localScenario.senderConfig.sign,
          verifySignature = localScenario.senderConfig.verify,
          anonymize = localScenario.senderConfig.anonymize,
        )
          .toGossipSub()[0]
        receiver = generateNodes(
          1,
          gossip = true,
          sign = localScenario.receiverConfig.sign,
          verifySignature = localScenario.receiverConfig.verify,
          anonymize = localScenario.receiverConfig.anonymize,
        )
          .toGossipSub()[0]
        nodes = @[sender, receiver]

      startAndDeferStop(nodes)
      await connectStar(nodes)

      let (messageReceivedFut, handler) = createCompleteHandler()

      subscribeAllNodes(nodes, topic, handler)
      waitSubscribeStar(nodes, topic)

      tryPublish await sender.publish(topic, testData), 1

      if localScenario.shouldWork:
        checkUntilTimeout:
          messageReceivedFut.finished() == true
      else:
        # wait some time before asserting that messages is not received
        await sleepAsync(300.milliseconds)
        check:
          messageReceivedFut.finished() == false
