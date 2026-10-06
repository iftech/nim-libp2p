# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../../libp2p/[multiaddress, peerid, switch]
import ../../libp2p/protocols/protocol
import ../../libp2p/stream/connection

const MaxRequestSize = 64 * 1024

type
  Fault* {.pure.} = enum
    Pass ## a write succeeds; a read returns `reply`, then EOF
    Hang ## blocks until cancelled
    Fail ## raises an `LPStreamError` that is not EOF

  FaultStream* = ref object of Stream
    onWrite*: Fault
    onRead*: Fault
    reply*: seq[byte]
    replyPos: int
    reads*: int
    hung*: AsyncEvent ## fires when a call starts to hang
    cancels*: int ## hung calls that were cancelled
    parked: Future[void].Raising([CancelledError, LPStreamError])

  FaultSwitch* = ref object of Switch
    ## Hands out `stream` for every dial, with no network.
    stream*: Stream

proc new*(
    T: typedesc[FaultStream],
    onWrite = Fault.Pass,
    onRead = Fault.Pass,
    reply: seq[byte] = @[],
): T =
  let stream = T(onWrite: onWrite, onRead: onRead, reply: reply, hung: newAsyncEvent())
  stream.initStream()
  stream

proc hang(s: FaultStream) {.async: (raises: [CancelledError, LPStreamError]).} =
  s.parked =
    Future[void].Raising([CancelledError, LPStreamError]).init("FaultStream.hang")
  s.hung.fire()
  try:
    await s.parked
  except CancelledError as e:
    s.cancels.inc()
    raise e

method getWrapped*(s: FaultStream): Connection =
  nil

method closeImpl*(s: FaultStream): Future[void] {.async: (raises: []).} =
  if not s.parked.isNil() and not s.parked.finished():
    s.parked.fail(newLPStreamClosedError())
  await procCall Connection(s).closeImpl()

method write*(
    s: FaultStream, msg: sink seq[byte]
) {.async: (raises: [CancelledError, LPStreamError]).} =
  if s.closed():
    raise newLPStreamClosedError()

  case s.onWrite
  of Fault.Pass:
    discard
  of Fault.Hang:
    await s.hang()
  of Fault.Fail:
    raise newException(LPStreamError, "fault stream write failed")

method readOnce*(
    s: FaultStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  if s.closed():
    raise newLPStreamClosedError()

  s.reads.inc()
  case s.onRead
  of Fault.Hang:
    await s.hang()
  of Fault.Fail:
    raise newException(LPStreamError, "fault stream read failed")
  of Fault.Pass:
    discard

  if s.atEof() or s.replyPos >= s.reply.len:
    s.isEof = true
    raise newLPStreamEOFError()

  let n = min(nbytes, s.reply.len - s.replyPos)
  copyMem(pbytes, addr s.reply[s.replyPos], n)
  s.replyPos += n
  n

proc new*(T: typedesc[FaultSwitch], base: Switch, stream: Stream): T =
  T(
    peerInfo: base.peerInfo,
    peerStore: base.peerStore,
    connManager: base.connManager,
    transports: base.transports,
    muxedUpgrade: base.muxedUpgrade,
    ms: base.ms,
    dialer: base.dialer,
    nameResolver: base.nameResolver,
    addressManager: base.addressManager,
    services: base.services,
    rng: base.rng,
    stream: stream,
  )

method dial*(
    self: FaultSwitch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  self.stream

proc readThenReplyTillEof*(reply: seq[byte]): LPProtoHandler =
  proc(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    try:
      while true:
        discard await stream.readLp(MaxRequestSize)
        await stream.writeLp(reply)
    except LPStreamError:
      discard
    finally:
      await noCancel stream.close()

proc readTillEof*(): LPProtoHandler =
  ## Read requests and answer none. EOF, a reset or a cancel ends the handler.
  proc(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    try:
      while true:
        discard await stream.readLp(MaxRequestSize)
    except LPStreamError:
      discard
    finally:
      await noCancel stream.close()
