# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[tables, sets, sequtils]
import chronos, chronicles
import
  ../../libp2p/[
    switch,
    peerid,
    peerinfo,
    multiaddress,
    multistream,
    crypto/crypto,
    protocols/identify,
  ]
import ../../libp2p/muxers/muxer
import ../../libp2p/transports/quictransport
import ../../libp2p/protocols/pubsub/[gossipsub, pubsubpeer, rpc/message]

const topicStreamsTopics* =
  ["interop/topic-streams/small", "interop/topic-streams/large"]

proc newTopicStreamsSwitch*(rng: Rng): Switch =
  # Keep optional protocols out of the standalone interop build.
  let
    key = PrivateKey.random(rng).get()
    peerInfo =
      PeerInfo.new(key, @[MultiAddress.init("/ip4/127.0.0.1/udp/0/quic-v1").get()])
    addressManager = AddressManager.new()
    identify = Identify.new(peerInfo, addressManager = addressManager)
    peerStore = PeerStore.new(identify)
    connManager = ConnManager.new()
    ms = MultistreamSelect.new()
    transports = @[Transport(QuicTransport.new(Upgrade(ms: ms), key, rng, connManager))]
  connManager.peerStore = peerStore
  result = Switch(
    peerInfo: peerInfo,
    peerStore: peerStore,
    connManager: connManager,
    ms: ms,
    transports: transports,
    dialer: Dialer.new(peerInfo.peerId, connManager, peerStore, transports, ms),
    addressManager: addressManager,
    rng: rng,
  )
  result.mount(identify)

proc topicStreamsInteropTest*(
    otherAddr: MultiAddress, otherPeerId: PeerId, timeout: Duration = 45.seconds
): Future[bool] {.async.} =
  ## Runs signed round trips over QUIC topic streams against an echo peer.
  ## Returns false for an unexpected echo, fallback, stream replacement, or timeout.
  let
    rng = newRng()
    switch = newTopicStreamsSwitch(rng)
    gossip = GossipSub.init(
      switch = switch,
      rng = rng,
      parameters =
        GossipSubParams.init(topicStreamsConfig = Opt.some(TopicStreamsConfig())),
    )
  switch.mount(gossip)

  var
    response: Future[bool]
    expectedTopic: string
    expectedPayload: seq[byte]
  proc onValidated(peer: PubSubPeer, msg: Message, msgId: MessageId) =
    if response != nil and not response.finished:
      response.complete(
        peer.peerId == otherPeerId and msg.fromPeer == otherPeerId and
          msg.topic == expectedTopic and msg.data == expectedPayload and
          msg.signature.len > 0
      )

  gossip.addObserver(PubSubObserver(onValidated: onValidated))
  for topic in topicStreamsTopics:
    gossip.subscribe(topic, nil)

  proc topicStreams(): HashSet[Stream] =
    for mux in switch.connManager.getConnections().getOrDefault(otherPeerId):
      for stream in mux.getStreams():
        if stream.protocol == TopicStreamsCodec:
          result.incl(stream)

  proc scenario(): Future[bool] {.async.} =
    await switch.connect(otherPeerId, @[otherAddr])
    while not topicStreamsTopics.allIt(gossip.mesh.getOrDefault(it).len == 1):
      await sleepAsync(10.milliseconds)
    if not gossip.extensionsState.peerHasTopicStreams(otherPeerId):
      error "Echo peer did not negotiate topic streams"
      return false

    var firstRoundStreams: HashSet[Stream]
    for round in 0 .. 1:
      for i, topic in topicStreamsTopics:
        expectedTopic = topic
        expectedPayload = repeat(
          byte(round + 1),
          if i == 0:
            32
          else:
            256 * 1024,
        )
        response = newFuture[bool]()
        let published = await gossip.publish(topic, expectedPayload)
        if published == 0:
          error "No peer received the interop publish", topic, round
          return false
        if not await response:
          error "Unexpected topic stream echo", topic, round
          return false

        let streams = topicStreams()
        let expectedCount =
          if round == 0:
            i + 1
          else:
            2
        for direction in [Direction.In, Direction.Out]:
          if toSeq(streams).countIt(it.dir == direction) != expectedCount:
            error "Unexpected topic stream count", topic, round, direction
            return false
        if round == 0:
          if not (firstRoundStreams <= streams):
            error "Topic stream replaced during first round", topic
            return false
          firstRoundStreams = streams
        elif streams != firstRoundStreams:
          error "Topic streams were not reused", topic
          return false
    return true

  await switch.start()
  defer:
    await switch.stop()
  try:
    return await scenario().wait(timeout)
  except AsyncTimeoutError:
    error "Topic streams interop timed out"
    return false
