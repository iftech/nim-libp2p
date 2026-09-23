# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./utils
import ../../../libp2p/protocols/pubsub/[pubsubpeer, gossipsub]
import ../../tools/[unittest, bufferstream]

type FlakyDialer = ref object
  attempts: int
  failures: int
  stream: Stream

proc getStream(d: FlakyDialer): GetStream =
  return proc(): Future[Stream] {.
      async: (raises: [CancelledError, GetStreamDialError])
  .} =
    inc d.attempts
    if d.attempts <= d.failures:
      raise (ref GetStreamDialError)(msg: "unreachable")
    return d.stream

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
    let dialer = FlakyDialer(failures: 5, stream: TestBufferStream.new(noop))
    let peer = newPeer(dialer.getStream(), 1.milliseconds, 4.milliseconds)
    peer.connect()

    checkUntilTimeout:
      peer.connected
    check dialer.attempts > dialer.failures

    await peer.stopTasks()

  asyncTest "keeps retrying after the delay reaches the cap":
    let dialer = FlakyDialer(failures: int.high)
    let peer = newPeer(dialer.getStream(), 1.milliseconds, 2.milliseconds)
    peer.connect()

    checkUntilTimeout:
      dialer.attempts >= 20
    check not peer.connected

    await peer.stopTasks()

  asyncTest "stopTasks cancels a pending retry":
    let dialer = FlakyDialer(failures: int.high)
    let peer = newPeer(dialer.getStream(), 1.hours, 1.hours)
    peer.connect()

    checkUntilTimeout:
      dialer.attempts >= 1
    let before = dialer.attempts
    let stopped = await peer.stopTasks().withTimeout(1.seconds)

    check:
      stopped
      dialer.attempts == before
