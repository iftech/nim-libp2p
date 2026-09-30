# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[strutils, sequtils]
import chronos, results, chronicles, stew/byteutils
import stream/connection, protocols/protocol

logScope:
  topics = "libp2p multistream"

const
  MsgSize = 1024
  Codec = "/multistream/1.0.0"

  Na = "na\n"
  Ls = "ls\n"

type
  Matcher* = proc(proto: string): bool {.gcsafe, raises: [].}

  MultiStreamError* = object of LPError

  MultiStreamFailure* {.pure.} = enum
    MalformedMessage = "MultistreamSelect failed, malformed message"
    HandshakeFailed = "MultistreamSelect handshake failed"
    InvalidFirstMessage = "MultistreamSelect handling failed, invalid first message"

  MultiStreamResult*[T] = Result[T, MultiStreamFailure]

  HandlerHolder* = ref object
    protos*: seq[string]
    protocol*: LPProtocol
    match*: Matcher

  MultistreamSelect* = ref object of RootObj
    handlers*: seq[HandlerHolder]
    codec*: string

proc new*(T: typedesc[MultistreamSelect]): T =
  T(codec: Codec)

func decodeMessage(data: openArray[byte]): MultiStreamResult[string] =
  if data.len == 0 or data[^1] != byte('\n'):
    return err(MultiStreamFailure.MalformedMessage)

  ok(string.fromBytes(data.toOpenArray(0, data.high - 1)))

template readMessage(stream: Stream): MultiStreamResult[string] =
  decodeMessage(await stream.readLp(MsgSize))

proc trySelect*(
    _: MultistreamSelect | type MultistreamSelect, stream: Stream, proto: seq[string]
): Future[MultiStreamResult[string]] {.
    async: (raises: [CancelledError, LPStreamError])
.} =
  ## Returns "" when the remote supports none of `proto`.
  trace "Multistream handshake started", stream, protocol = Codec
  await stream.writeLp(Codec & "\n")
  if proto.len() > 0:
    trace "Protocol negotiation started", stream, protocol = proto[0]
    await stream.writeLp(proto[0] & "\n")

  let header = ?stream.readMessage()
  if header != Codec:
    trace "Multistream handshake failed", stream, protocol = header
    return err(MultiStreamFailure.HandshakeFailed)

  trace "Multistream handshake completed", stream
  if proto.len() == 0:
    return ok(Codec)

  let response = ?stream.readMessage()
  trace "Protocol negotiation response received", stream, protocol = response
  if response == proto[0]:
    trace "Protocol negotiation completed", stream, protocol = proto[0]
    stream.protocol = proto[0]
    return ok(proto[0])

  if proto.len() > 1:
    trace "Protocol alternatives available", stream, protocols = proto[1 .. ^1]
  for p in proto.toOpenArray(1, proto.high):
    trace "Protocol negotiation retrying", stream, protocol = p
    await stream.writeLp(p & "\n")
    let alternative = ?stream.readMessage()
    if alternative == p:
      trace "Protocol negotiation completed", stream, protocol = p
      stream.protocol = p
      return ok(p)

  ok("")

proc select*(
    _: MultistreamSelect | type MultistreamSelect, stream: Stream, proto: seq[string]
): Future[string] {.async: (raises: [CancelledError, LPStreamError, MultiStreamError]).} =
  (await MultistreamSelect.trySelect(stream, proto)).valueOrRaise(MultiStreamError)

proc select*(
    _: MultistreamSelect | type MultistreamSelect, stream: Stream, proto: string
): Future[bool] {.async: (raises: [CancelledError, LPStreamError, MultiStreamError]).} =
  if proto.len > 0:
    (await MultistreamSelect.select(stream, @[proto])) == proto
  else:
    (await MultistreamSelect.select(stream, @[])) == Codec

proc select*(
    m: MultistreamSelect, stream: Stream
): Future[bool] {.
    async: (raises: [CancelledError, LPStreamError, MultiStreamError], raw: true)
.} =
  m.select(stream, "")

proc list*(
    m: MultistreamSelect, stream: Stream
): Future[seq[string]] {.
    async: (raises: [CancelledError, LPStreamError, MultiStreamError])
.} =
  ## list remote protos requests on connection
  if not await m.select(stream):
    return

  await stream.writeLp(Ls) # send ls

  var list = newSeq[string]()
  let ms = string.fromBytes(await stream.readLp(MsgSize))
  for s in ms.split("\n"):
    if s.len() > 0:
      list.add(s)

  list

proc tryHandle*(
    _: type MultistreamSelect,
    stream: Stream,
    protos: seq[string],
    matchers = newSeq[Matcher](),
    active: bool = false,
): Future[MultiStreamResult[string]] {.
    async: (raises: [CancelledError, LPStreamError])
.} =
  ## Returns "" when the stream reaches EOF before a proposal matches.
  trace "Multistream negotiation started", stream, handshaked = active
  var handshaked = active
  while not stream.atEof:
    let ms = ?stream.readMessage()

    if not handshaked and ms != Codec:
      trace "Multistream handshake rejected",
        stream, receivedProtocol = ms, reason = "unexpected first message"
      return err(MultiStreamFailure.InvalidFirstMessage)

    trace "Protocol negotiation request received", stream, protocol = ms
    case ms
    of "ls":
      trace "Protocol list requested", stream
      #TODO this doens't seem to follow spec, each protocol
      # should be length prefixed. Not very important
      # since LS is getting deprecated
      await stream.writeLp(protos.join("\n") & "\n")
    of Codec:
      if not handshaked:
        await stream.writeLp(Codec & "\n")
        handshaked = true
      else:
        trace "Duplicate multistream handshake rejected", stream
        await stream.writeLp(Na)
    elif ms.len > 0 and (ms in protos or matchers.anyIt(it(ms))):
      trace "Protocol handler selected", stream, protocol = ms
      await stream.writeLp(ms & "\n")
      stream.protocol = ms
      return ok(ms)
    else:
      trace "Protocol negotiation rejected",
        stream, protocol = ms, reason = "no handler"
      await stream.writeLp(Na)

  ok("")

proc handle*(
    _: type MultistreamSelect,
    stream: Stream,
    protos: seq[string],
    matchers = newSeq[Matcher](),
    active: bool = false,
): Future[string] {.async: (raises: [CancelledError, LPStreamError, MultiStreamError]).} =
  (await MultistreamSelect.tryHandle(stream, protos, matchers, active)).valueOrRaise(
    MultiStreamError
  )

proc lookupProtocol*(m: MultistreamSelect, proto: string): Opt[LPProtocol] =
  ## Find the LPProtocol registered for the given protocol string, if any.
  ## Returns `Opt.none` when no handler matches.
  for h in m.handlers:
    if (h.match != nil and h.match(proto)) or h.protos.contains(proto):
      return Opt.some(h.protocol)
  return Opt.none(LPProtocol)

func allProtosAndMatchers(m: MultistreamSelect): (seq[string], seq[Matcher]) =
  var
    protos: seq[string]
    matchers: seq[Matcher]

  for h in m.handlers:
    if h.match != nil:
      matchers.add(h.match)
    for proto in h.protos:
      protos.add(proto)

  return (protos, matchers)

proc handle*(
    m: MultistreamSelect, stream: Stream, active: bool = false
) {.async: (raises: [CancelledError]).} =
  trace "Multistream handler started", stream, handshaked = active
  defer:
    trace "Multistream handler stopped", stream
    await noCancel stream.close()

  let negotiated =
    try:
      let (protos, matchers) = m.allProtosAndMatchers()
      await MultistreamSelect.tryHandle(stream, protos, matchers, active)
    except LPStreamError as e:
      trace "Multistream negotiation failed", err = e.msg, stream
      return
  let ms = negotiated.valueOr:
    trace "Multistream negotiation failed", err = error, stream
    return

  m.lookupProtocol(ms).ifValue(p):
    trace "Protocol handler selected", stream, protocol = ms

    if not p.reserveIncoming(stream.peerId):
      debug "Inbound stream budget exceeded, rejecting incoming stream",
        stream, protocol = ms, peerId = stream.peerId
      return

    try:
      let h = p.handler
      await h(stream, ms)
    finally:
      p.releaseIncoming(stream.peerId)
  else:
    trace "Protocol handler unavailable", stream, protocol = ms

proc addHandler*(m: MultistreamSelect, protocol: LPProtocol, matcher: Matcher = nil) =
  trace "Protocol handlers registered", protocols = protocol.codecs
  m.handlers.add(
    HandlerHolder(protos: protocol.codecs, protocol: protocol, match: matcher)
  )

proc removeHandler*(m: MultistreamSelect, protocol: LPProtocol): bool =
  ## Removes the handler registered for `protocol`.
  for i, handler in m.handlers:
    if handler.protocol == protocol:
      m.handlers.del(i)
      return true
  false

proc addHandler*[E](
    m: MultistreamSelect,
    codec: string,
    handler:
      LPProtoHandler | proc(
        stream: Stream, proto: string
      ): InternalRaisesFuture[void, E],
    matcher: Matcher = nil,
) =
  ## helper to allow registering pure handlers
  let protocol = new LPProtocol
  protocol.codec = codec
  protocol.handler = handler

  m.addHandler(protocol, matcher)

proc start*(m: MultistreamSelect) {.async: (raises: [CancelledError]).} =
  let futs = m.handlers.mapIt(it.protocol.start())
  try:
    await allFutures(futs)
    for fut in futs:
      await fut
  except CancelledError as exc:
    var pending: seq[Future[void].Raising([])]
    doAssert m.handlers.len == futs.len, "Handlers modified while starting"
    for i, fut in futs:
      if not fut.finished:
        pending.add fut.cancelAndWait()
      elif fut.completed:
        pending.add m.handlers[i].protocol.stop()
      else:
        static:
          doAssert typeof(fut).E is (CancelledError,)
    await noCancel allFutures(pending)
    raise exc

proc stop*(m: MultistreamSelect) {.async: (raises: []).} =
  let futs = m.handlers.mapIt(it.protocol.stop())
  await noCancel allFutures(futs)
  for fut in futs:
    await fut
