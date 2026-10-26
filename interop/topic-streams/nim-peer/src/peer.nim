# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, os
import ../../../../libp2p/[builders, multiaddress, crypto/rng]
import ../../../../libp2p/protocols/pubsub/gossipsub

proc main() {.async.} =
  let rng = newRng()
  let switch = SwitchBuilder
    .new()
    .withRng(rng)
    .withAddresses(@[MultiAddress.init("/ip4/127.0.0.1/udp/0/quic-v1").get()])
    .withQuicTransport()
    .build()
  let params = GossipSubParams.init(topicStreamsConfig = Opt.some(TopicStreamsConfig()))
  let gossip = GossipSub.init(switch = switch, rng = rng, parameters = params)
  switch.mount(gossip)

  proc echoMessage(topic: string, data: seq[byte]) {.async.} =
    let peers = await gossip.publish(topic, data)
    if peers == 0:
      echo "echo publish returned 0, topic=", topic

  for topic in ["interop/topic-streams/small", "interop/topic-streams/large"]:
    gossip.subscribe(topic, echoMessage)

  await switch.start()
  defer:
    await switch.stop()
  writeFile(paramStr(1), $switch.peerInfo.addrs[0] & "/p2p/" & $switch.peerInfo.peerId)
  # Keep the peer alive beyond the Go timeout; run.sh stops it when Go exits.
  await sleepAsync(60.seconds)

when isMainModule:
  waitFor main()
