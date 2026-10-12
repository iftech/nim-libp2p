# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Run with -d:release -d:chronicles_log_level=ERROR. Measures synchronous sends
## and mixed-size bursts behind a stalled write. Heap figures exclude GC reserve.
## Override queueBenchBytes to compare byte budgets with count-only limits.

import std/strformat
from std/times import cpuTime
import chronos
import ../../libp2p/protocols/pubsub/pubsubpeer
import ../../libp2p/peerid
import ../tools/crypto

const
  queueBenchBytes {.intdefine.} = 1024 * 1024
  queueBenchMessages {.intdefine.} = 100_000

type BenchStream = ref object of Connection
  stalled: bool
  pending: Future[void].Raising([CancelledError, LPStreamError])

method writeLp*(
    s: BenchStream, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  if s.stalled:
    s.pending =
      Future[void].Raising([CancelledError, LPStreamError]).init("bench.write")
    s.pending
  else:
    let f = Future[void].Raising([CancelledError, LPStreamError]).init("bench.write")
    f.complete()
    f

method getWrapped*(s: BenchStream): Connection =
  s

proc getStream(): Future[Stream] {.
    async: (raises: [CancelledError, GetStreamDialError])
.} =
  raise newException(GetStreamDialError, "benchmark has no dialer")

proc handler(
    peer: PubSubPeer, data: sink seq[byte]
) {.async: (raises: [CancelledError, PeerRateLimitError]).} =
  discard

proc bench(stalled: bool) {.async.} =
  let peer = PubSubPeer.new(
    PeerId.random(rng()).expect("peer id"),
    getStream,
    nil,
    "/meshsub/1.2.0",
    maxMessageSize = 65536,
    handler = handler,
  )
  when declared(DefaultMaxMediumPriorityQueueBytes):
    peer.maxMediumPriorityQueueBytes = queueBenchBytes
  let stream =
    BenchStream(dir: Direction.Out, timeout: 0.milliseconds, stalled: stalled)
  stream.initStream()
  peer.sendStream = stream
  if stalled:
    discard peer.sendEncoded(@[1'u8], High)

  GC_fullCollect()
  let before = getOccupiedMem()
  let started = cpuTime()
  for i in 0 ..< queueBenchMessages:
    let size =
      if stalled:
        [256, 4096, 65536][i mod 3]
      else:
        256
    discard peer.sendEncoded(newSeq[byte](size), Medium)
  let elapsed = cpuTime() - started
  GC_fullCollect()
  let retained = getOccupiedMem() - before
  let drops = int(peer.slowPeerPenalty)
  echo &"stalled={stalled} budget={queueBenchBytes} messages={queueBenchMessages} " &
    &"ns/send={elapsed * 1e9 / float(queueBenchMessages):.1f} " &
    &"heap_delta={retained} drops={drops}"
  when declared(queuedBytes):
    echo &"accounted_medium_bytes={peer.queuedBytes(Medium)}"
  await peer.stopTasks()
  await stream.close()
  GC_fullCollect()
  echo &"heap_delta_after_cleanup={getOccupiedMem() - before}"

waitFor bench(false)
waitFor bench(true)
