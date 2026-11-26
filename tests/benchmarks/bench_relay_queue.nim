# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Compare identical release builds with -d:chronicles_log_level=ERROR.
## Add -d:nimTypeNames for allocator counters. Counts include payloads/futures.
## Reuse queue capacity after warmup; report retained heap separately.
## Optional arguments select one workload: drain 1024 2000000.

import std/[strformat, os, strutils]
from std/times import cpuTime
import chronos, nimcrypto/sha2
import ../../libp2p/protocols/pubsub/[pubsubpeer, rpc/messages]
import ../../libp2p/peerid
import ../tools/crypto

const relayBenchMessages {.intdefine.} = 200_000

let messageCount =
  if paramCount() >= 3:
    parseInt(paramStr(3))
  else:
    relayBenchMessages

type BenchStream = ref object of Connection
  stalled: bool
  pending: Future[void].Raising([CancelledError, LPStreamError])

method writeLp*(
    s: BenchStream, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  let fut = Future[void].Raising([CancelledError, LPStreamError]).init("bench.write")
  if s.stalled:
    doAssert s.pending == nil or s.pending.finished
    s.pending = fut
  else:
    fut.complete()
  fut

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

proc allocations(): int =
  when defined(nimTypeNames):
    getMemCounters()[0]
  else:
    0

proc bench(mode: string, depth: int) {.async.} =
  let peer = PubSubPeer.new(
    PeerId.random(rng()).expect("peer id"),
    getStream,
    nil,
    "/meshsub/1.2.0",
    65536,
    handler,
    maxLowPriorityQueueLen = 1024,
  )
  let stream = BenchStream(dir: Direction.Out, timeout: 0.milliseconds)
  stream.initStream()
  peer.sendStream = stream
  defer:
    await peer.stopTasks()
    await stream.close()

  var ids: array[1025, SaltedId]
  for i in 0 ..< ids.len:
    ids[i] = SaltedId(data: sha256.digest([byte(i and 255), byte(i shr 8)]))

  proc enqueue(i: int) =
    let id =
      if mode == "drain-untracked":
        Opt.none(SaltedId)
      elif mode == "cancel-same-id":
        Opt.some(ids[0])
      else:
        Opt.some(ids[i])
    discard peer.sendEncoded(newSeq[byte](256), Low, relayedSaltedId = id)

  proc blockWriter() =
    stream.stalled = true
    discard peer.sendEncoded(@[1.byte], High)

  proc drain() {.async.} =
    stream.stalled = false
    stream.pending.complete()
    while peer.queuedBytes() != 0:
      await sleepAsync(0.milliseconds)

  proc burst() {.async.} =
    blockWriter()
    for i in 0 ..< depth:
      enqueue(i)
    if mode == "cancel":
      for i in 0 ..< depth:
        doAssert peer.cancelQueuedRelay(ids[i]) == 256
    elif mode == "cancel-same-id":
      doAssert peer.cancelQueuedRelay(ids[0]) == depth * 256
    await drain()

  GC_fullCollect()
  let initialHeap = getOccupiedMem()
  # Grow queue/index capacity before measuring repeated operation.
  for i in 0 ..< 8:
    await burst()
  GC_fullCollect()
  let emptyHeap = getOccupiedMem()
  if mode in ["churn", "miss"]:
    blockWriter()
    for i in 0 ..< depth:
      enqueue(i)
  GC_fullCollect()
  let
    occupiedHeap = getOccupiedMem()
    allocBefore = allocations()
    started = cpuTime()
  var operations = 0
  if mode in ["churn", "miss"]:
    for i in 0 ..< messageCount:
      if mode == "churn":
        let index = i mod depth
        doAssert peer.cancelQueuedRelay(ids[index]) == 256
        enqueue(index)
      else:
        doAssert peer.cancelQueuedRelay(ids[1024]) == 0
      inc operations
  else:
    for i in 0 ..< max(1, messageCount div depth):
      await burst()
      operations += depth
  let
    elapsed = cpuTime() - started
    allocated {.used.} = allocations() - allocBefore
  doAssert peer.slowPeerPenalty == 0
  if mode in ["churn", "miss"]:
    await drain()
  GC_fullCollect()
  let retainedHeap = getOccupiedMem()
  let allocationsPerOp =
    when defined(nimTypeNames):
      &"{float(allocated) / float(operations):.4f}"
    else:
      "n/a"
  echo &"mode={mode} depth={depth} operations={operations} " &
    &"ns/op={elapsed * 1e9 / float(operations):.1f} " & &"allocs/op={allocationsPerOp} " &
    &"empty_queue_heap={emptyHeap - initialHeap} " &
    &"occupied_queue_heap={occupiedHeap - initialHeap} " &
    &"retained_queue_heap={retainedHeap - initialHeap}"

if paramCount() >= 2:
  waitFor bench(paramStr(1), parseInt(paramStr(2)))
else:
  for depth in [32, 1024]:
    for mode in ["drain", "drain-untracked", "cancel", "cancel-same-id"]:
      waitFor bench(mode, depth)
  for mode in ["churn", "miss"]:
    waitFor bench(mode, 1024)
