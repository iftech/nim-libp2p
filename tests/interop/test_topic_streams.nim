# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/[switch, crypto/rng]
import ../../libp2p/protocols/pubsub/gossipsub
import ../tools/unittest
import ./topic_streams

type EchoMode = enum
  Correct
  WrongPayload
  WrongTopic
  Silent
  WithoutTopicStreams

proc runEchoTest(mode: EchoMode): Future[bool] {.async.} =
  var params = GossipSubParams.init()
  if mode != WithoutTopicStreams:
    params.topicStreamsConfig = Opt.some(TopicStreamsConfig())
  let
    rng = newRng()
    switch = newTopicStreamsSwitch(rng)
    gossip = GossipSub.init(switch = switch, rng = rng, parameters = params)
  switch.mount(gossip)

  var received = 0

  proc echoMessage(topic: string, data: seq[byte]) {.async.} =
    inc received
    case mode
    of Silent:
      discard
    of WrongPayload:
      discard await gossip.publish(topic, @[0.byte])
    of WrongTopic:
      let otherTopic =
        if topic == topicStreamsTopics[0]:
          topicStreamsTopics[1]
        else:
          topicStreamsTopics[0]
      discard await gossip.publish(otherTopic, data)
    of Correct, WithoutTopicStreams:
      discard await gossip.publish(topic, data)

  for topic in topicStreamsTopics:
    gossip.subscribe(topic, echoMessage)
  await switch.start()
  defer:
    await switch.stop()
  # Silent must reach the timeout; keep it short while allowing other cases more CI time.
  result = await topicStreamsInteropTest(
    switch.peerInfo.addrs[0],
    switch.peerInfo.peerId,
    timeout = (if mode == Silent: 2.seconds else: 10.seconds),
  )

  case mode
  of Correct:
    check received == 4
  of WrongPayload, WrongTopic, Silent:
    check received == 1
  of WithoutTopicStreams:
    check received == 0

suite "Topic streams interop tests with Nim nodes":
  teardown:
    checkTrackers()

  asyncTest "Two signed round trips per topic reuse QUIC streams":
    check await runEchoTest(Correct)

  asyncTest "Fails for an incorrect payload":
    check not await runEchoTest(WrongPayload)

  asyncTest "Fails for an incorrect topic":
    check not await runEchoTest(WrongTopic)

  asyncTest "Fails when no echo arrives":
    check not await runEchoTest(Silent)

  asyncTest "Fails when the echo peer only supports ordinary GossipSub":
    check not await runEchoTest(WithoutTopicStreams)
