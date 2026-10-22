# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, metrics
import ../../libp2p/[peerid, protocols/protocol, stream/connection]
import ../tools/[unittest, crypto]

proc handler(
    stream: Stream, proto: string
): Future[void] {.async: (raises: [CancelledError]).} =
  discard

template handleKeyError(body: untyped): float64 =
  try:
    body
  except exceptions.KeyError:
    0.0

template rejectionCounterIn(proto: LPProtocol, scope: string): float64 =
  handleKeyError:
    libp2p_protocol_stream_cap_rejections_total.value([proto.codecs[0], dirIn, scope])

template rejectionCounterOut(proto: LPProtocol, scope: string): float64 =
  handleKeyError:
    libp2p_protocol_stream_cap_rejections_total.value([proto.codecs[0], dirOut, scope])

template openGaugeIn(proto: LPProtocol): float64 =
  handleKeyError:
    libp2p_protocol_streams_open.value([proto.codecs[0], dirIn])

template openGaugeOut(proto: LPProtocol): float64 =
  handleKeyError:
    libp2p_protocol_streams_open.value([proto.codecs[0], dirOut])

template clearGauges(codecs: seq[string]) =
  libp2p_protocol_streams_open.set(0, labelValues = [codecs[0], dirIn])
  libp2p_protocol_streams_open.set(0, labelValues = [codecs[0], dirOut])

template assertNoLimits(p: LPProtocol) =
  # when there are no limits reserve and release will always succeed

  # this for is here to drive over any limits (default or explicit)
  for _ in 0 ..< 1000:
    check:
      p.reserveIncoming(peerId1)
      p.reserveOutgoing(peerId1)

  check:
    p.openGaugeIn() == 1000
    p.openGaugeOut() == 1000

  check: # incoming
    p.canAcceptIncoming(peerId1)
    p.canAcceptIncoming(peerId2)
    p.reserveIncoming(peerId1)
    p.reserveIncoming(peerId1)
    p.reserveIncoming(peerId2)
    p.canAcceptIncoming(peerId1)
    p.canAcceptIncoming(peerId2)

  p.releaseIncoming(peerId1)
  p.releaseIncoming(peerId2)

  check: # outgoing
    p.canOpenOutgoing(peerId1)
    p.canOpenOutgoing(peerId2)
    p.reserveOutgoing(peerId1)
    p.reserveOutgoing(peerId1)
    p.reserveOutgoing(peerId2)
    p.canOpenOutgoing(peerId1)
    p.canOpenOutgoing(peerId2)

  p.releaseOutgoing(peerId1)
  p.releaseOutgoing(peerId2)

suite "LPProtocol stream budget":
  const codecs = @["/test/1.0.0"]
  let
    peerId1 = PeerId.random()
    peerId2 = PeerId.random()
    peerId3 = PeerId.random()

  setup:
    clearGauges(codecs)

  test "LPProtocol with no limits (default values)":
    let p = LPProtocol.new(codecs, handler)
    assertNoLimits(p)

  test "LPProtocol with no limits (explicit values)":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = Opt.none(int),
      maxIncomingStreamsPerPeer = Opt.none(int),
      maxOutgoingStreamsTotal = Opt.none(int),
      maxOutgoingStreamsPerPeer = Opt.none(int),
    )
    assertNoLimits(p)

  test "LPProtocol with no limits (created with new keyword)":
    let p = new LPProtocol
    p.codecs = codecs
    assertNoLimits(p)

  test "reserveIncoming and releaseIncoming with per-peer limit":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsPerPeer = 2,
      maxIncomingStreamsTotal = Opt.none(int),
      maxOutgoingStreamsTotal = Opt.none(int),
      maxOutgoingStreamsPerPeer = Opt.none(int),
    )

    check p.canAcceptIncoming(peerId1)

    check:
      p.reserveIncoming(peerId1)
      p.openGaugeIn() == 1
      p.canAcceptIncoming(peerId1)

    check:
      p.reserveIncoming(peerId1)
      not p.canAcceptIncoming(peerId1)
      p.openGaugeIn() == 2
      p.canAcceptIncoming(peerId2) # other peer not affected

    check:
      not p.reserveIncoming(peerId1) # make rejection
      p.rejectionCounterIn(scopePerPeer) == 1
      not p.reserveIncoming(peerId1) # make rejection, again
      p.rejectionCounterIn(scopePerPeer) == 2

    p.releaseIncoming(peerId1)
    check p.canAcceptIncoming(peerId1)

    p.releaseIncoming(peerId1)
    check p.canAcceptIncoming(peerId1)

    check:
      p.openGaugeIn() == 0
      p.openGaugeOut() == 0

  test "reserveIncoming and releaseIncoming with total limit":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = 2,
      maxIncomingStreamsPerPeer = Opt.none(int),
      maxOutgoingStreamsTotal = Opt.none(int),
      maxOutgoingStreamsPerPeer = Opt.none(int),
    )

    check p.canAcceptIncoming(peerId1)

    check:
      p.reserveIncoming(peerId1)
      p.canAcceptIncoming(peerId1)

    check:
      p.reserveIncoming(peerId2)
      not p.canAcceptIncoming(peerId3)

    check:
      not p.reserveIncoming(peerId3) # make rejection
      p.rejectionCounterIn(scopeTotal) == 1
      not p.reserveIncoming(peerId3) # make rejection, again
      p.rejectionCounterIn(scopeTotal) == 2

    p.releaseIncoming(peerId1)
    check p.canAcceptIncoming(peerId3)

    p.releaseIncoming(peerId2)

    check:
      p.openGaugeIn() == 0
      p.openGaugeOut() == 0

  test "reserveOutgoing and releaseOutgoing with per-peer limit":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = Opt.none(int),
      maxIncomingStreamsPerPeer = Opt.none(int),
      maxOutgoingStreamsPerPeer = 2,
      maxOutgoingStreamsTotal = Opt.none(int),
    )

    check p.canOpenOutgoing(peerId1)

    check:
      p.reserveOutgoing(peerId1)
      p.openGaugeOut() == 1
      p.canOpenOutgoing(peerId1)

    check:
      p.reserveOutgoing(peerId1)
      not p.canOpenOutgoing(peerId1)
      p.openGaugeOut() == 2

    check:
      p.canOpenOutgoing(peerId2)
      not p.reserveOutgoing(peerId1) # make rejection
      p.rejectionCounterOut(scopePerPeer) == 1
      not p.reserveOutgoing(peerId1) # make rejection, again
      p.rejectionCounterOut(scopePerPeer) == 2
      p.openGaugeOut() == 2

    p.releaseOutgoing(peerId1)
    check p.canOpenOutgoing(peerId1)

    p.releaseOutgoing(peerId1)
    check p.canOpenOutgoing(peerId1)

    check:
      p.openGaugeIn() == 0
      p.openGaugeOut() == 0

  test "reserveOutgoing and releaseOutgoing with total limit":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = Opt.none(int),
      maxIncomingStreamsPerPeer = Opt.none(int),
      maxOutgoingStreamsTotal = 2,
      maxOutgoingStreamsPerPeer = Opt.none(int),
    )

    check:
      p.canOpenOutgoing(peerId1)

    check:
      p.reserveOutgoing(peerId1)
      p.canOpenOutgoing(peerId1)

    check:
      p.reserveOutgoing(peerId2)
      p.openGaugeOut() == 2
      not p.canOpenOutgoing(peerId3)

    check:
      not p.reserveOutgoing(peerId1) # make rejection
      p.rejectionCounterOut(scopeTotal) == 1
      not p.reserveOutgoing(peerId2) # make rejection, again
      p.rejectionCounterOut(scopeTotal) == 2
      p.openGaugeOut() == 2

    p.releaseOutgoing(peerId1)
    check p.canOpenOutgoing(peerId3)

    p.releaseOutgoing(peerId2)

    check:
      p.openGaugeIn() == 0
      p.openGaugeOut() == 0

  test "combined incoming and outgoing limits (per-peer and total)":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = 4,
      maxIncomingStreamsPerPeer = 2,
      maxOutgoingStreamsTotal = 4,
      maxOutgoingStreamsPerPeer = 2,
    )

    # Fill incoming per-peer for peerId1
    check:
      p.reserveIncoming(peerId1)
      p.reserveIncoming(peerId1)
      not p.canAcceptIncoming(peerId1) # per-peer limit hit
      p.canAcceptIncoming(peerId2) # other peer ok

    # Fill incoming total
    check:
      p.reserveIncoming(peerId2)
      p.reserveIncoming(peerId3)
      p.openGaugeIn() == 4
      not p.canAcceptIncoming(peerId2) # total limit reached
      not p.canAcceptIncoming(peerId3) # total limit reached

    # Check outgoing concurrently
    check p.canOpenOutgoing(peerId1)

    check:
      p.reserveOutgoing(peerId1)
      p.reserveOutgoing(peerId1)
      not p.canOpenOutgoing(peerId1) # per-peer limit hit

    check:
      p.reserveOutgoing(peerId2)
      p.reserveOutgoing(peerId3)
      p.openGaugeOut() == 4
      not p.canOpenOutgoing(peerId2) # total outgoing limit reached

    # Release incoming and verify
    p.releaseIncoming(peerId1)
    check p.canAcceptIncoming(peerId1)
      # peerId1 per-peer count now 1 < 2, and total 3 < 4

    # Release outgoing and verify
    p.releaseOutgoing(peerId1)
    check p.canOpenOutgoing(peerId1) # peerId1 per-peer count now 1 < 2, and total 3 < 4

    check:
      p.openGaugeIn() == 3
      p.openGaugeOut() == 3

  test "release underflow protection (release without reserve)":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = 2,
      maxIncomingStreamsPerPeer = 2,
      maxOutgoingStreamsTotal = 2,
      maxOutgoingStreamsPerPeer = 2,
    )

    # Releasing without reserving should not cause negative counts
    p.releaseIncoming(peerId1)
    check:
      p.openGaugeIn() == 0
      p.canAcceptIncoming(peerId1)

    # Reserve up to limit, then release extra should keep within limits
    check:
      p.reserveIncoming(peerId1)
      p.reserveIncoming(peerId1)
      not p.canAcceptIncoming(peerId1)

    p.releaseIncoming(peerId1)
    p.releaseIncoming(peerId1)
    check p.openGaugeIn() == 0

    # extra release for incoming
    p.releaseIncoming(peerId1)
    check:
      p.canAcceptIncoming(peerId1)
      p.openGaugeIn() == 0

    # extra release for outgoing
    p.releaseOutgoing(peerId1)
    check:
      p.canOpenOutgoing(peerId1)
      p.openGaugeOut() == 0

  test "budget with new() using int arguments directly (not Opt)":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = 2,
      maxIncomingStreamsPerPeer = 1,
      maxOutgoingStreamsTotal = 3,
      maxOutgoingStreamsPerPeer = 1,
    )

    check p.canAcceptIncoming(peerId1)

    check:
      p.reserveIncoming(peerId1)
      not p.canAcceptIncoming(peerId1) # per-peer limit 1
      p.openGaugeIn() == 1

    check:
      p.reserveIncoming(peerId2)
      not p.canAcceptIncoming(peerId3) # total limit 2 reached
      p.openGaugeIn() == 2

    p.releaseIncoming(peerId1)
    check p.canAcceptIncoming(peerId1)

    # Outgoing
    check p.canOpenOutgoing(peerId1)

    check:
      p.reserveOutgoing(peerId1)
      not p.canOpenOutgoing(peerId1) # per-peer limit 1
      p.openGaugeOut() == 1

    check:
      p.reserveOutgoing(peerId2)
      p.reserveOutgoing(peerId3)
      p.openGaugeOut() == 3
      not p.canOpenOutgoing(peerId1) # total limit 3 reached

    p.releaseOutgoing(peerId1)
    check p.canOpenOutgoing(peerId1)

    check:
      p.openGaugeIn() == 1
      p.openGaugeOut() == 2

  test "different peers share total budget correctly":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = 2,
      maxIncomingStreamsPerPeer = Opt.none(int),
      maxOutgoingStreamsTotal = 2,
      maxOutgoingStreamsPerPeer = Opt.none(int),
    )

    # Incoming
    check:
      p.reserveIncoming(peerId1)
      p.canAcceptIncoming(peerId1)
      p.reserveIncoming(peerId2)
      not p.canAcceptIncoming(peerId3)

    p.releaseIncoming(peerId1)
    check p.canAcceptIncoming(peerId3)

    # Outgoing
    check:
      p.reserveOutgoing(peerId1)
      p.canOpenOutgoing(peerId2)
      p.reserveOutgoing(peerId2)
      not p.canOpenOutgoing(peerId3)

    p.releaseOutgoing(peerId1)
    check p.canOpenOutgoing(peerId3)

    check:
      p.openGaugeIn() == 1
      p.openGaugeOut() == 1

  test "reserveIncoming and releaseIncoming with per-peer limit using Opt.some":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = Opt.none(int),
      maxIncomingStreamsPerPeer = Opt.some(1),
      maxOutgoingStreamsTotal = Opt.none(int),
      maxOutgoingStreamsPerPeer = Opt.none(int),
    )

    check p.canAcceptIncoming(peerId1)

    check:
      p.reserveIncoming(peerId1)
      not p.canAcceptIncoming(peerId1)
      p.canAcceptIncoming(peerId2) # other peer still allowed

    p.releaseIncoming(peerId1)
    check p.canAcceptIncoming(peerId1)

    check:
      p.openGaugeIn() == 0
      p.openGaugeOut() == 0

  test "reserveOutgoing and releaseOutgoing with per-peer limit using Opt.some":
    let p = LPProtocol.new(
      codecs,
      handler,
      maxIncomingStreamsTotal = Opt.none(int),
      maxIncomingStreamsPerPeer = Opt.none(int),
      maxOutgoingStreamsTotal = Opt.none(int),
      maxOutgoingStreamsPerPeer = Opt.some(1),
    )

    check p.canOpenOutgoing(peerId1)

    check:
      p.reserveOutgoing(peerId1)
      not p.canOpenOutgoing(peerId1)
      p.canOpenOutgoing(peerId2)

    p.releaseOutgoing(peerId1)
    check p.canOpenOutgoing(peerId1)

    check:
      p.openGaugeIn() == 0
      p.openGaugeOut() == 0

  test "different protocols have different gauge":
    let p1 = LPProtocol.new(@["/proto-one/1.0.0"], handler)
    let p2 = LPProtocol.new(@["/proto-two/1.0.0"], handler)

    check:
      p1.reserveOutgoing(peerId1)
      p1.reserveOutgoing(peerId1)
      p1.reserveOutgoing(peerId1)
      p1.openGaugeOut() == 3
      p2.openGaugeOut() == 0 # protocol two gauge is unchanged

    clearGauges(p1.codecs)

    check:
      p2.reserveOutgoing(peerId1)
      p2.reserveOutgoing(peerId1)
      p2.reserveOutgoing(peerId1)
      p2.openGaugeOut() == 3
      p1.openGaugeOut() == 0 # protocol one gauge is unchanged

  test "different protocols have different rejection counter":
    let p1 = LPProtocol.new(@["/proto-one/1.0.0"], handler, maxIncomingStreamsTotal = 1)
    let p2 = LPProtocol.new(@["/proto-two/1.0.0"], handler, maxIncomingStreamsTotal = 1)

    check:
      p1.reserveIncoming(peerId1)
      not p1.reserveIncoming(peerId1)
      p1.rejectionCounterIn(scopeTotal) == 1
      not p1.reserveIncoming(peerId1)
      p1.rejectionCounterIn(scopeTotal) == 2

      # other p1 counters are not changed
      p1.rejectionCounterIn(scopePerPeer) == 0
      p1.rejectionCounterOut(scopeTotal) == 0
      p1.rejectionCounterOut(scopePerPeer) == 0

      # p2 counters are not changed
      p2.rejectionCounterIn(scopeTotal) == 0
      p2.rejectionCounterIn(scopePerPeer) == 0
      p2.rejectionCounterOut(scopeTotal) == 0
      p2.rejectionCounterOut(scopePerPeer) == 0

    check:
      p2.reserveIncoming(peerId1)
      not p2.reserveIncoming(peerId1)
      p2.rejectionCounterIn(scopeTotal) == 1
      not p2.reserveIncoming(peerId1)
      p2.rejectionCounterIn(scopeTotal) == 2

      # other p2 counters are not changed
      p2.rejectionCounterIn(scopePerPeer) == 0
      p2.rejectionCounterOut(scopeTotal) == 0
      p2.rejectionCounterOut(scopePerPeer) == 0

      # p1 counters keep old state
      p1.rejectionCounterIn(scopeTotal) == 2
      p1.rejectionCounterIn(scopePerPeer) == 0
      p1.rejectionCounterOut(scopeTotal) == 0
      p1.rejectionCounterOut(scopePerPeer) == 0
