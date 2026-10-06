# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils, tables, chronicles, sequtils
import ../../libp2p/[builders, peerid, wire]
import ../../libp2p/protocols/pubsub/[gossipsub, gossipsub/extensions, rpc/message]
import ../tools/crypto
import ../libp2p/pubsub/extensions/my_partial_message
import ../tools/multiaddress

const partialTopic* = "logos-partial"

proc makePartialMessage*(): MyPartialMessage =
  MyPartialMessage(
    groupId: "interop-group".toBytes,
    data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
  )

proc partialMessageInteropTest*(
    ourAddr: string,
    otherAddr: string,
    otherPeerId: PeerId,
    timeout: Duration = 1.minutes,
): Future[bool] {.async.} =
  # this proc implements interop test for testing gossipsub partial message extension.
  # there are two entities:
  #   - "other peer" is peer that can be implemented in any other libp2p implementation. 
  #   - "nim peer" is peer created in this proc here.
  # interop test is as follows:
  #   - "other peer" sends partial message with some data. 
  #   - "nim peer" listens on incoming messages and asserts that other peer has sent
  #     the parts metadata that nim peer expects. other peer must know what to send in advance.

  let
    keyBytes = @[
      8.byte, 2, 18, 32, 222, 176, 113, 24, 159, 196, 204, 239, 181, 76, 141, 249, 59,
      226, 244, 36, 1, 145, 17, 142, 4, 151, 172, 69, 65, 12, 254, 222, 161, 39, 7, 73,
    ]
    key = PrivateKey.init(keyBytes).expect("should have a private key")

  var switch = SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[ma(ourAddr)])
    .withPrivateKey(key)
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

  proc validateRPC(
      rpc: PartialMessageExtensionRPC
  ): LPResult[void] {.gcsafe, raises: [].} =
    return ok()

  var requestFulfilled = newFuture[bool]()

  proc onIncomingRPC(
      peer: PeerId, rpc: PartialMessageExtensionRPC
  ) {.gcsafe, raises: [].} =
    # other peer must publish only one partial message.
    # in this callback code asserts that other peer
    # has published exactly that message and that nim peer has received.

    if rpc.topicID.get() != partialTopic:
      error "partial message topic did not match",
        got = $rpc.topicID.get(), expected = $partialTopic
      requestFulfilled.complete(false)
      return

    let pm = makePartialMessage()
    let expectedMetadata = MyPartsMetadata.have(toSeq(pm.data.keys))

    if rpc.groupID.get() != pm.groupId:
      error "partial message groupId did not match",
        got = $rpc.groupID.get(), expected = $pm.groupId
      requestFulfilled.complete(false)
      return

    if rpc.partsMetadata.isNone or rpc.partsMetadata.get() != expectedMetadata:
      error "parts metadata does not match"
      requestFulfilled.complete(false)
      return

    # successful interop
    requestFulfilled.complete(true)

  var gossipsub = GossipSub.init(
    switch = switch,
    rng = rng(),
    parameters = (
      var param = GossipSubParams.init()
      param.partialMessageExtensionConfig = Opt.some(
        PartialMessageExtensionConfig(
          unionPartsMetadata: my_partial_message.unionPartsMetadata,
          materializeParts: MyPartialMessageStore().materializePartsFn(),
            # nim peer only receives in this test, it never serves parts
          validateRPC: validateRPC,
          onIncomingRPC: onIncomingRPC,
          heartbeatsTillEviction: 100,
        )
      )
      param
    ),
  )

  switch.mount(gossipsub)
  await switch.start()
  defer:
    await switch.stop()

  # other peer was started before nim peer. it is safe to connect to them
  # right away and subscribe to partial messages topic.
  await switch.connect(otherPeerId, @[ma(otherAddr)])
  gossipsub.subscribe(partialTopic, nil, requestsPartial = true)

  # wait on request to be fulfilled
  try:
    return await requestFulfilled.wait(timeout)
  except AsyncTimeoutError:
    return false
