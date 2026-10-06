# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, streams, sequtils, strutils, tables, stew/endians2
import
  ../../../libp2p/[
    multiaddress,
    protocols/pubsub/gossipsub,
    protocols/pubsub/pubsubpeer,
    protocols/pubsub/rpc/messages,
    switch,
    utils/future,
  ]
import
  ../../../interop/gossipsub/src/[node, instructions, runner, interop_partial_message]
import ../../tools/[unittest, multiaddress]

proc getAddr(node: GossipSub): MultiAddress =
  node.switch.peerInfo.addrs[0]

suite "GossipSub Interop - Script runner - Component":
  asyncTest "script runs connect + subscribe + publish":
    # Standalone peer node (no runner)
    let peer = createNode(1, TcpAutoAddress)
    await peer.switch.start()
    defer:
      await peer.switch.stop()

    const topic = "foobar"
    let receivedMsgIdFut = newFuture[string]()
    let peerAddr = peer.getAddr()

    # Peer subscribes to receive messages
    peer.subscribe(
      topic,
      proc(topic: string, data: seq[byte]) {.async.} =
        if data.len >= 8:
          receivedMsgIdFut.completeOnce($extractMsgId(data))
      ,
    )

    # Build a script for node 0
    let script = @[
      ScriptInstruction(kind: InitGossipSub, gossipSubParams: GossipSubParams.init()),
      ScriptInstruction(kind: Connect, connectTo: @[1]),
      ScriptInstruction(kind: SubscribeToTopic, topicID: topic, partial: false),
      ScriptInstruction(kind: WaitUntil, elapsed: 2.seconds),
      ScriptInstruction(
        kind: Publish,
        publishMessageID: 99,
        messageSizeBytes: 512,
        publishTopicID: topic,
      ),
      ScriptInstruction(
        kind: SetTopicValidationDelay, validationTopicID: topic, delay: 300.milliseconds
      ),
    ]

    var stream = newStringStream()
    let runner = newScriptRunner(
      nodeId = 0,
      logStream = stream,
      listenAddr = TcpAutoAddress,
      resolveAddr = proc(id: int): MultiAddress {.gcsafe.} =
        return peerAddr,
    )
    await runner.node.switch.start()
    defer:
      await runner.node.switch.stop()

    await runner.runScript(script)

    check (await receivedMsgIdFut) == "99"

  asyncTest "ifNodeIDEquals filters correctly":
    # Standalone peer node (no runner)
    let peer = createNode(1, TcpAutoAddress)
    await peer.switch.start()
    defer:
      await peer.switch.stop()

    let peerAddr = peer.getAddr()

    let inner = new ScriptInstruction
    inner[] = ScriptInstruction(kind: Connect, connectTo: @[1])

    let script = @[
      ScriptInstruction(kind: InitGossipSub, gossipSubParams: GossipSubParams.init()),
      # This should be skipped (node 5 != node 0)
      ScriptInstruction(kind: IfNodeIDEquals, nodeID: 5, inner: inner),
    ]

    var stream = newStringStream()
    let runner = newScriptRunner(
      nodeId = 0,
      logStream = stream,
      listenAddr = TcpAutoAddress,
      resolveAddr = proc(id: int): MultiAddress {.gcsafe.} =
        return peerAddr,
    )
    await runner.node.switch.start()
    defer:
      await runner.node.switch.stop()

    await runner.runScript(script)

    # Node 0 should not be connected
    check runner.node.switch.connectedPeers(Direction.Out).len == 0

    # Run with matching nodeID
    let script2 = @[ScriptInstruction(kind: IfNodeIDEquals, nodeID: 0, inner: inner)]

    let runner2 = newScriptRunner(
      nodeId = 0,
      logStream = stream,
      listenAddr = TcpAutoAddress,
      resolveAddr = proc(id: int): MultiAddress {.gcsafe.} =
        return peerAddr,
    )
    await runner2.node.switch.start()
    defer:
      await runner2.node.switch.stop()

    await runner2.runScript(script2)

    # Now should be connected
    check runner2.node.switch.connectedPeers(Direction.Out).len == 1

  asyncTest "two nodes exchange partial messages and both log 'All parts received'":
    # Node 0 has parts 0-3 (0b00001111), Node 1 has parts 4-7 (0b11110000)
    # After exchange, both should have all parts.

    let logStream0 = newStringStream()
    let logStream1 = newStringStream()

    let runner0 = newScriptRunner(
      nodeId = 0,
      logStream = logStream0,
      listenAddr = TcpAutoAddress,
      enablePartialMessages = true,
    )
    let runner1 = newScriptRunner(
      nodeId = 1,
      logStream = logStream1,
      listenAddr = TcpAutoAddress,
      enablePartialMessages = true,
    )

    await allFutures(@[runner0, runner1].mapIt(it.start()))
    defer:
      await allFutures(@[runner0, runner1].mapIt(it.stop()))

    runner1.setResolveAddr(
      proc(id: int): MultiAddress {.gcsafe.} =
        runner0.node.getAddr()
    )

    const topic = "foobar"
    const groupId = 42'u64
    let key = makeKey(topic, groupId)

    # Node 0 subscribes to the topic and adds parts 0-3
    runner0.node.subscribe(
      topic, nil, requestsPartial = true, supportsSendingPartial = true
    )

    let pm0 = InteropPartialMessage.new(groupId)
    pm0.fillParts(InteropPartsMetadata.init(0b00001111))
    runner0.messages[key] = pm0

    # Build a script for node 1
    let script = @[
      ScriptInstruction(kind: InitGossipSub, gossipSubParams: GossipSubParams.init()),
      ScriptInstruction(kind: Connect, connectTo: @[0]),
      ScriptInstruction(kind: WaitUntil, elapsed: 1.seconds),
      ScriptInstruction(kind: SubscribeToTopic, topicID: topic, partial: true),
      ScriptInstruction(kind: WaitUntil, elapsed: 5.seconds),
      ScriptInstruction(
        kind: AddPartialMessage,
        addTopicID: topic,
        groupID: groupId,
        partsBitmap: 0b11110000,
      ),
      ScriptInstruction(
        kind: PublishPartial,
        publishPartialTopicID: topic,
        publishPartialGroupID: groupId,
        publishToNodeIDs: @[0],
      ),
    ]

    await runner1.runScript(script)

    # Assert both nodes receive full messages
    checkUntilTimeout:
      runner0.messages[key].isComplete()
      runner1.messages[key].isComplete()
      logStream0.data.contains("Received Partial Message")
      logStream1.data.contains("Received Partial Message")
      logStream0.data.contains("All parts received")
      logStream1.data.contains("All parts received")

  asyncTest "fanout scenario":
    let logStream0 = newStringStream()
    let logStream1 = newStringStream()

    let runner0 = newScriptRunner(
      nodeId = 0,
      logStream = logStream0,
      listenAddr = TcpAutoAddress,
      enablePartialMessages = true,
    )
    let runner1 = newScriptRunner(
      nodeId = 1,
      logStream = logStream1,
      listenAddr = TcpAutoAddress,
      enablePartialMessages = true,
    )

    await allFutures(@[runner0, runner1].mapIt(it.start()))
    defer:
      await allFutures(@[runner0, runner1].mapIt(it.stop()))

    runner0.setResolveAddr(
      proc(id: int): MultiAddress {.gcsafe.} =
        runner1.node.getAddr()
    )

    const topic = "foobar"
    const groupId = 77'u64
    let key = makeKey(topic, groupId)

    # Node 0 has the message and is not subscribed, publishes to 1 explicitly
    let node0Script = @[
      ScriptInstruction(kind: InitGossipSub, gossipSubParams: GossipSubParams.init()),
      ScriptInstruction(kind: Connect, connectTo: @[1]),
      ScriptInstruction(kind: WaitUntil, elapsed: 3.seconds),
      ScriptInstruction(
        kind: AddPartialMessage,
        addTopicID: topic,
        groupID: groupId,
        partsBitmap: 0b11111111,
      ),
      ScriptInstruction(
        kind: PublishPartial,
        publishPartialTopicID: topic,
        publishPartialGroupID: groupId,
        publishToNodeIDs: @[1],
      ),
      ScriptInstruction(kind: WaitUntil, elapsed: 6.seconds),
    ]

    # Node 1 supports partials and is subscribed
    let node1Script = @[
      ScriptInstruction(kind: InitGossipSub, gossipSubParams: GossipSubParams.init()),
      ScriptInstruction(kind: SubscribeToTopic, topicID: topic, partial: true),
      ScriptInstruction(kind: WaitUntil, elapsed: 6.seconds),
    ]

    await allFutures(@[runner0.runScript(node0Script), runner1.runScript(node1Script)])

    checkUntilTimeout:
      key in runner0.messages
      key in runner1.messages
      runner0.messages[key].isComplete()
      runner1.messages[key].isComplete()
      logStream0.data.contains("All parts received")
      logStream1.data.contains("All parts received")

  asyncTest "received message logs include duplicates once per inbound rpc":
    let sender = createNode(0, TcpAutoAddress)
    let receiverLog = newStringStream()
    let receiver =
      newScriptRunner(nodeId = 1, logStream = receiverLog, listenAddr = TcpAutoAddress)

    await sender.switch.start()
    await receiver.start()
    defer:
      await receiver.stop()
      await sender.switch.stop()

    await sender.switch.connect(
      receiver.node.peerInfo.peerId, @[receiver.node.getAddr()]
    )

    checkUntilTimeout:
      receiver.node.peerInfo.peerId in sender.peers

    const topic = "foobar"
    await receiver.executeInstruction(
      ScriptInstruction(kind: SubscribeToTopic, topicID: topic, partial: false)
    )

    var data = newSeq[byte](sizeof(uint64))
    data[0 ..< sizeof(uint64)] = toBytesBE(123'u64)

    let duplicateRpc = RPCMsg.withMessages(Message(topic: topic, data: data))
    let peer = sender.peers[receiver.node.peerInfo.peerId]

    sender.broadcast(@[peer], duplicateRpc, MessagePriority.High)
    sender.broadcast(@[peer], duplicateRpc, MessagePriority.High)

    checkUntilTimeout:
      receiverLog.data.count(""""msg":"Received Message"""") == 2
      receiverLog.data.count(""""id":"123"""") == 2
