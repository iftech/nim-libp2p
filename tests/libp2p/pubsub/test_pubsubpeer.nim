# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./utils
import ../../../libp2p/protocols/pubsub/[pubsubpeer, gossipsub]
import ../../tools/[unittest, bufferstream]

proc failingGetStream(attempts: ref int, failures: int, stream: Stream): GetStream =
  return proc(): Future[Stream] {.
      async: (raises: [CancelledError, GetStreamDialError])
  .} =
    inc attempts[]
    if attempts[] <= failures:
      raise (ref GetStreamDialError)(msg: "unreachable")
    return stream

proc newPeer(getStream: GetStream, baseDelay, maxDelay: Duration): PubSubPeer =
  PubSubPeer.new(
    randomPeerId(),
    getStream,
    nil,
    GossipSubCodec_12,
    1024,
    voidPeerHandler,
    sendStreamRetryBaseDelay = baseDelay,
    sendStreamRetryMaxDelay = maxDelay,
  )

suite "PubSubPeer send stream":
  teardown:
    checkTrackers()

  asyncTest "retries failed send stream opens until one succeeds":
    const failures = 5
    let attempts = new int
    let peer = newPeer(
      failingGetStream(attempts, failures, TestBufferStream.new(noop)),
      1.milliseconds,
      4.milliseconds,
    )
    peer.connect()

    checkUntilTimeout:
      peer.connected
    check attempts[] > failures

    await peer.stopTasks()

  asyncTest "keeps retrying after the delay reaches the cap":
    let attempts = new int
    let peer =
      newPeer(failingGetStream(attempts, int.high, nil), 1.milliseconds, 2.milliseconds)
    peer.connect()

    checkUntilTimeout:
      attempts[] >= 20
    check not peer.connected

    await peer.stopTasks()

  asyncTest "stopTasks cancels a pending retry":
    let attempts = new int
    let peer = newPeer(failingGetStream(attempts, int.high, nil), 1.hours, 1.hours)
    peer.connect()

    checkUntilTimeout:
      attempts[] >= 1
    let before = attempts[]
    let stopped = await peer.stopTasks().withTimeout(1.seconds)

    check:
      stopped
      attempts[] == before
