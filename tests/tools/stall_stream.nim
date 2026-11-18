# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, std/[sequtils, strutils], stew/byteutils
import ../../libp2p/protocols/pubsub/pubsubpeer

type StallStream* = ref object of Connection
  ## Records every write in order. The first `stallCount` writes stay pending.
  ## Later writes complete at once. Closing fails any pending write.
  writes*: seq[seq[byte]] # messages written, in order
  written*: AsyncEvent # fires on every write
  pendingWrites*: seq[Future[void].Raising([CancelledError, LPStreamError])]
  stallCount: int

method writeLp*(
    s: StallStream, msg: openArray[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  s.writes.add(@msg)
  s.written.fire()
  let fut =
    Future[void].Raising([CancelledError, LPStreamError]).init("StallStream.writeLp")
  if s.pendingWrites.len >= s.stallCount:
    fut.complete()
  else:
    s.pendingWrites.add(fut)
  fut

method getWrapped*(s: StallStream): Connection =
  s

method closeImpl*(s: StallStream) {.async: (raises: []).} =
  for fut in s.pendingWrites:
    if not fut.finished:
      fut.fail(newLPStreamClosedError())
  await procCall Connection(s).closeImpl()

proc releasePendingWrites*(s: StallStream) {.raises: [].} =
  for fut in s.pendingWrites:
    if not fut.finished:
      fut.complete()

proc stallSendStream*(peer: PubSubPeer, stallCount: int = int.high): StallStream =
  ## Point `peer`'s send stream at a stall stream so its outbound queues fill up.
  ## The replaced stream is left open on purpose: if it closed, the peer would
  ## dial a new stream and overwrite the stall stream. It is closed at teardown.
  let stream = StallStream(
    dir: Direction.Out,
    timeout: 0.milliseconds,
    written: newAsyncEvent(),
    stallCount: stallCount,
  )
  stream.initStream()
  peer.sendStream = stream
  stream

func carries*(writes: seq[seq[byte]], data: seq[byte]): bool =
  let dataStr = string.fromBytes(data)
  writes.anyIt(string.fromBytes(it).contains(dataStr))

proc waitForWrite*(
    s: StallStream, data: seq[byte]
) {.async: (raises: [CancelledError]).} =
  ## Waits until a write carries `data`.
  while not s.writes.carries(data):
    s.written.clear()
    await s.written.wait()
