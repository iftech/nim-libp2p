# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import ../../libp2p/[switch, builders, peerid, wire]
import ../../libp2p/protocols/pubsub/[gossipsub, gossipsub/extensions, rpc/message]
import ../libp2p/pubsub/extensions/my_partial_message
import ../tools/[crypto, unittest, multiaddress]
import ./partial_message

proc publishPartial(
    node: GossipSub, store: MyPartialMessageStore, topic: string, pm: MyPartialMessage
) {.async: (raises: []).} =
  # stores message so config.materializeParts can serve it, then publishes
  store.messages[pm.groupId] = pm
  await node.publishPartial(topic, pm.groupId, pm.partsMetadata())

proc createOtherPeer(): tuple[
  switch: Switch, gossipsub: GossipSub, store: MyPartialMessageStore
] =
  let switch = SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[TcpAutoAddress])
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

  let store = MyPartialMessageStore()

  proc validateRPC(
      rpc: PartialMessageExtensionRPC
  ): LPResult[void] {.gcsafe, raises: [].} =
    return ok()

  proc onIncomingRPC(
      peer: PeerId, rpc: PartialMessageExtensionRPC
  ) {.gcsafe, raises: [].} =
    discard

  var gossipsub = GossipSub.init(
    switch = switch,
    rng = rng(),
    parameters = (
      var param = GossipSubParams.init()
      param.partialMessageExtensionConfig = Opt.some(
        PartialMessageExtensionConfig(
          unionPartsMetadata: my_partial_message.unionPartsMetadata,
          materializeParts: store.materializePartsFn(),
          validateRPC: validateRPC,
          onIncomingRPC: onIncomingRPC,
          heartbeatsTillEviction: 100,
        )
      )
      param
    ),
  )

  switch.mount(gossipsub)

  (switch, gossipsub, store)

suite "Gossipsub Partial Message Interop Tests with Nim nodes":
  const ourAddress = "/ip4/127.0.0.1/tcp/0"

  teardown:
    checkTrackers()

  asyncTest "Happy path":
    # create and start "other peer"
    let otherPeer = createOtherPeer()
    await otherPeer.switch.start()
    defer:
      await otherPeer.switch.stop()

    # create and start "nim peer" with interop test
    let interopRes = partialMessageInteropTest(
      ourAddress, $otherPeer.switch.peerInfo.addrs[0], otherPeer.switch.peerInfo.peerId
    )

    # other peer publishes expected message
    otherPeer.gossipsub.subscribe(partialTopic, nil, requestsPartial = true)
    await otherPeer.gossipsub.publishPartial(
      otherPeer.store, partialTopic, makePartialMessage()
    )

    # interop test should end successfully
    check await interopRes

  asyncTest "Fails when wrong message is published":
    # create and start "other peer"
    let otherPeer = createOtherPeer()
    await otherPeer.switch.start()
    defer:
      await otherPeer.switch.stop()

    # create and start "nim peer" with interop test
    let interopRes = partialMessageInteropTest(
      ourAddress, $otherPeer.switch.peerInfo.addrs[0], otherPeer.switch.peerInfo.peerId
    )

    # other peer publishes incorrect message
    otherPeer.gossipsub.subscribe(partialTopic, nil, requestsPartial = true)
    var pm = makePartialMessage()
    pm.groupId = "wrong-id".toBytes # unexpected groupId
    await otherPeer.gossipsub.publishPartial(otherPeer.store, partialTopic, pm)

    # interop test should end unsuccessfully
    check not await interopRes

  asyncTest "Fails when message is not published":
    # create and start "other peer"
    let otherPeer = createOtherPeer()
    await otherPeer.switch.start()
    defer:
      await otherPeer.switch.stop()

    # create and start "nim peer" with interop test
    let interopRes = partialMessageInteropTest(
      ourAddress,
      $otherPeer.switch.peerInfo.addrs[0],
      otherPeer.switch.peerInfo.peerId,
      timeout = 10.seconds, # reduce timeout so test doesn't spend time unnecessarily
    )

    # other peer just subscribes without publishing anything
    otherPeer.gossipsub.subscribe(partialTopic, nil, requestsPartial = true)

    # interop test should end unsuccessfully
    check not await interopRes

  asyncTest "Fails when peer is unreachable":
    const unreachableAddress = "/ip4/127.0.0.1/tcp/59999"
    let fakePeerId = PeerId.random(rng()).get()

    expect DialFailedError:
      discard
        await partialMessageInteropTest(ourAddress, unreachableAddress, fakePeerId)
