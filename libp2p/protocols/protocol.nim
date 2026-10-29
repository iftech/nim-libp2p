# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[tables]
import chronos, results, metrics
import ../stream/connection
import ../utils/opt

export results

declareCounter(
  libp2p_protocol_stream_cap_rejections_total,
  "protocol stream budget rejections",
  labels = ["protocol", "direction", "scope"],
)

declareGauge(
  libp2p_protocol_streams_open,
  "protocol stream instances currently open",
  labels = ["protocol", "direction"],
)
declarePublicCounter(
  libp2p_streams_opened, "protocol streams opened", labels = ["protocol", "direction"]
)
declarePublicCounter(
  libp2p_streams_closed, "protocol streams closed", labels = ["protocol", "direction"]
)

const
  scopeTotal = "total"
  scopePerPeer = "per_peer"
  dirIn = "in"
  dirOut = "out"

when defined(libp2p_testing):
  export
    libp2p_protocol_stream_cap_rejections_total, libp2p_protocol_streams_open,
    scopeTotal, scopePerPeer, dirIn, dirOut

type
  LPProtoHandler* = proc(stream: Stream, proto: string): Future[void] {.
    async: (raises: [CancelledError])
  .}

  StreamBudgetState = ref object
    totalIncoming: int
    totalOutgoing: int
    perPeerIncoming: CountTable[PeerId]
    perPeerOutgoing: CountTable[PeerId]

  LPProtocol* = ref object of RootObj
    started*: bool
    codecs*: seq[string]
    handlerImpl: LPProtoHandler ## invoked by the protocol negotiator
    maxIncomingStreamsTotal: Opt[int]
    maxIncomingStreamsPerPeer: Opt[int]
    maxOutgoingStreamsTotal: Opt[int]
    maxOutgoingStreamsPerPeer: Opt[int]
    streamBudget: StreamBudgetState
      ## Runtime counters shared across all codecs of this protocol

method start*(p: LPProtocol) {.base, async: (raises: [CancelledError]).} =
  p.started = true

method stop*(p: LPProtocol) {.base, async: (raises: []).} =
  p.started = false

func codec*(p: LPProtocol): string =
  doAssert(p.codecs.len > 0, "codecs sequence must not be empty")
  p.codecs[0]

func `codec=`*(p: LPProtocol, codec: string) =
  p.codecs.insert(codec, 0)

template `handler`*(p: LPProtocol): LPProtoHandler =
  p.handlerImpl

template `handler`*(p: LPProtocol, stream: Stream, proto: string): Future[void] =
  p.handlerImpl(stream, proto)

func `handler=`*(p: LPProtocol, handler: LPProtoHandler) =
  p.handlerImpl = handler

func setStreamLimits*(
    p: LPProtocol,
    maxIncomingStreamsTotal: Opt[int] | int = Opt.none(int),
    maxIncomingStreamsPerPeer: Opt[int] | int = Opt.none(int),
    maxOutgoingStreamsTotal: Opt[int] | int = Opt.none(int),
    maxOutgoingStreamsPerPeer: Opt[int] | int = Opt.none(int),
) =
  ## Sets the stream budgets of a protocol built without `LPProtocol.new`.
  doAssert(not p.started, "stream limits must be set before the protocol starts")

  p.maxIncomingStreamsTotal = toOpt(maxIncomingStreamsTotal)
  p.maxIncomingStreamsPerPeer = toOpt(maxIncomingStreamsPerPeer)
  p.maxOutgoingStreamsTotal = toOpt(maxOutgoingStreamsTotal)
  p.maxOutgoingStreamsPerPeer = toOpt(maxOutgoingStreamsPerPeer)

  # keeping streamBudget uninitialized makes `reserve` and `release` return early (fast path).
  p.streamBudget =
    if p.maxIncomingStreamsTotal.isSome or p.maxIncomingStreamsPerPeer.isSome or
        p.maxOutgoingStreamsTotal.isSome or p.maxOutgoingStreamsPerPeer.isSome:
      StreamBudgetState()
    else:
      nil

proc new*(
    T: type LPProtocol,
    codecs: seq[string],
    handler: LPProtoHandler,
    maxIncomingStreamsTotal: Opt[int] | int = Opt.none(int),
    maxIncomingStreamsPerPeer: Opt[int] | int = Opt.none(int),
    maxOutgoingStreamsTotal: Opt[int] | int = Opt.none(int),
    maxOutgoingStreamsPerPeer: Opt[int] | int = Opt.none(int),
): T =
  doAssert(codecs.len > 0, "codecs sequence must not be empty")
  doAssert(not handler.isNil, "handler must be set")

  let proto = T(codecs: codecs, handlerImpl: handler)
  proto.setStreamLimits(
    maxIncomingStreamsTotal, maxIncomingStreamsPerPeer, maxOutgoingStreamsTotal,
    maxOutgoingStreamsPerPeer,
  )

  proto

func budgetReason(p: LPProtocol, peerId: PeerId, dir: Direction): (bool, string) =
  ## Returns (canAccept, scope) indicating whether a stream can be accepted
  ## and which scope would reject it.
  let budget = p.streamBudget
  if budget.isNil:
    return (true, "")

  if dir == Direction.In:
    if p.maxIncomingStreamsPerPeer.isSome and
        budget.perPeerIncoming.getOrDefault(peerId) >= p.maxIncomingStreamsPerPeer.get:
      return (false, scopePerPeer)
    if p.maxIncomingStreamsTotal.isSome and
        budget.totalIncoming >= p.maxIncomingStreamsTotal.get:
      return (false, scopeTotal)
  else:
    if p.maxOutgoingStreamsPerPeer.isSome and
        budget.perPeerOutgoing.getOrDefault(peerId) >= p.maxOutgoingStreamsPerPeer.get:
      return (false, scopePerPeer)
    if p.maxOutgoingStreamsTotal.isSome and
        budget.totalOutgoing >= p.maxOutgoingStreamsTotal.get:
      return (false, scopeTotal)

  return (true, "")

func canAcceptIncoming*(p: LPProtocol, peerId: PeerId): bool =
  ## Returns true if an incoming stream from `peerId` is within all configured
  ## inbound budgets. Returns false when any limit would be exceeded.
  let (canAccept, _) = p.budgetReason(peerId, Direction.In)
  canAccept

proc reserveIncoming*(p: LPProtocol, peerId: PeerId): bool =
  let budget = p.streamBudget
  if budget.isNil:
    libp2p_protocol_streams_open.inc(labelValues = [p.codec, dirIn])
    libp2p_streams_opened.inc(labelValues = [p.codec, dirIn])
    return true

  let (canAccept, scope) = p.budgetReason(peerId, Direction.In)
  if not canAccept:
    libp2p_protocol_stream_cap_rejections_total.inc(
      labelValues = [p.codec, dirIn, scope]
    )
    return false

  budget.totalIncoming.inc
  budget.perPeerIncoming.inc(peerId)
  libp2p_protocol_streams_open.inc(labelValues = [p.codec, dirIn])
  libp2p_streams_opened.inc(labelValues = [p.codec, dirIn])
  return true

proc releaseIncoming*(p: LPProtocol, peerId: PeerId) =
  let budget = p.streamBudget
  if budget.isNil:
    libp2p_protocol_streams_open.dec(labelValues = [p.codec, dirIn])
    libp2p_streams_closed.inc(labelValues = [p.codec, dirIn])
    return

  let pb = budget.perPeerIncoming[peerId]
  if pb == 0:
    return # there was no reserve for this peer
  elif pb == 1:
    budget.perPeerIncoming.del(peerId)
  else:
    budget.perPeerIncoming.inc(peerId, -1)

  budget.totalIncoming.dec
  libp2p_protocol_streams_open.dec(labelValues = [p.codec, dirIn])
  libp2p_streams_closed.inc(labelValues = [p.codec, dirIn])

func canOpenOutgoing*(p: LPProtocol, peerId: PeerId): bool =
  ## Returns true if an outgoing stream to `peerId` is within all configured
  ## outbound budgets. Returns false when any limit would be exceeded.
  let (canAccept, _) = p.budgetReason(peerId, Direction.Out)
  canAccept

proc reserveOutgoing*(p: LPProtocol, peerId: PeerId): bool =
  let budget = p.streamBudget
  if budget.isNil:
    libp2p_protocol_streams_open.inc(labelValues = [p.codec, dirOut])
    libp2p_streams_opened.inc(labelValues = [p.codec, dirOut])
    return true

  let (canAccept, scope) = p.budgetReason(peerId, Direction.Out)
  if not canAccept:
    libp2p_protocol_stream_cap_rejections_total.inc(
      labelValues = [p.codec, dirOut, scope]
    )
    return false

  budget.totalOutgoing.inc
  budget.perPeerOutgoing.inc(peerId)
  libp2p_protocol_streams_open.inc(labelValues = [p.codec, dirOut])
  libp2p_streams_opened.inc(labelValues = [p.codec, dirOut])
  return true

proc releaseOutgoing*(p: LPProtocol, peerId: PeerId) =
  let budget = p.streamBudget
  if budget.isNil:
    libp2p_protocol_streams_open.dec(labelValues = [p.codec, dirOut])
    libp2p_streams_closed.inc(labelValues = [p.codec, dirOut])
    return

  let pb = budget.perPeerOutgoing[peerId]
  if pb == 0:
    return # there was no reserve for this peer
  elif pb == 1:
    budget.perPeerOutgoing.del(peerId)
  else:
    budget.perPeerOutgoing.inc(peerId, -1)

  budget.totalOutgoing.dec
  libp2p_protocol_streams_open.dec(labelValues = [p.codec, dirOut])
  libp2p_streams_closed.inc(labelValues = [p.codec, dirOut])
