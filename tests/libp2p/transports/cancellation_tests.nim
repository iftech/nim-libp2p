# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import
  ../../../libp2p/[
    crypto/crypto,
    multiaddress,
    multistream,
    muxers/muxer,
    muxers/mplex/mplex,
    protocols/secure/noise,
    protocols/secure/secure,
    stream/connection,
    transports/transport,
    upgrademngrs/muxedupgrade,
    upgrademngrs/upgrade,
  ]
import ../../tools/[unittest, crypto, multiaddress]
import ./utils

const CancelSteps = 12 ## Poll steps to walk the cancel through, one dial per step.

proc countCancelledDials*(
    provider: TransportProvider, address: string
): Future[int] {.async: (raises: [CatchableError]).} =
  ## Dial and cancel one step later each round. Counts the dials the cancel won.

  let server = provider()
  await server.start(@[ma(address)])
  let client = provider()

  var accepted: seq[RawConn]

  proc acceptLoop() {.async: (raises: []).} =
    while true:
      try:
        let conn = await server.accept()
        if not conn.isNil():
          accepted.add(conn)
      except transport.TransportError, CancelledError:
        return

  let accepting = acceptLoop()
  defer:
    await accepting.cancelAndWait()
    await allFutures(accepted.mapIt(it.close()))
    await allFutures(client.stop(), server.stop())

  var cancelled = 0
  for steps in 0 .. CancelSteps:
    let dialFut = client.dial("", server.addrs[0])
    for _ in 0 ..< steps:
      await sleepAsync(0.milliseconds)

    await dialFut.cancelAndWait()

    # A dial that won the race with the cancel hands back a connection.
    if dialFut.completed():
      let conn = dialFut.value()
      if not conn.isNil():
        await conn.close()
    elif dialFut.cancelled():
      cancelled.inc()

  cancelled

template cancellationTransportTest*(provider: TransportProvider, address: string) =
  asyncTest "a dial cancelled at any point leaves no socket open":
    check (await countCancelledDials(provider, address)) > 0

type UpgradeStage = enum
  SecurityHandshake
  MuxerNegotiation

proc newNoiseMplexUpgrade(): MuxedUpgrade =
  proc newMuxer(conn: RawConn): Muxer =
    Mplex.new(conn)

  let key = PrivateKey.random(ECDSA, rng()).get()
  MuxedUpgrade.new(
    @[MuxerProvider.new(newMuxer, MplexCodec)],
    [Secure(Noise.new(rng(), key))],
    MultistreamSelect.new(),
  )

proc stallUpgrade(
    remote: RawConn, stage: UpgradeStage
): Future[Stream] {.async: (raises: [CatchableError]).} =
  ## Plays the remote up to `stage`, then stops answering.
  case stage
  of SecurityHandshake:
    # Reads the first Noise frame header and never replies, so the dialer waits for handshake message 2.
    check (await MultistreamSelect.tryHandle(remote, @[NoiseCodec])).get("") ==
      NoiseCodec
    var frameLen: array[2, byte]
    await remote.readExactly(addr frameLen[0], frameLen.len)
    remote
  of MuxerNegotiation:
    # Completes Noise, reads the multistream header and never replies, so the dialer waits for the muxer answer.
    let sconn = await newNoiseMplexUpgrade().secure(remote, Opt.none(PeerId))
    discard await sconn.readLp(1024)
    sconn

proc cancelUpgrade(
    provider: TransportProvider, address: string, stage: UpgradeStage
) {.async: (raises: [CatchableError]).} =
  let server = provider()
  await server.start(@[ma(address)])
  let client = provider()
  client.upgrader = newNoiseMplexUpgrade()
  defer:
    await allFutures(client.stop(), server.stop())

  let accepting = server.accept()
  let conn = await client.dial("", server.addrs[0])
  let remote = await accepting
  defer:
    await allFutures(conn.close(), remote.close())

  let upgrading = client.upgrade(conn, Opt.none(PeerId))
  let stalled = await stallUpgrade(remote, stage)
  await upgrading.cancelAndWait()
  # Callers close the raw conn after a failed upgrade, see Dialer.dialAndUpgrade.
  await allFutures(conn.close(), remote.close(), stalled.close())

  checkUntilTimeout:
    not isCounterLeaked(SecureConnTrackerName)

template upgradeCancellationTransportTest*(
    provider: TransportProvider, address: string
) =
  asyncTest "an upgrade cancelled in the security handshake leaves no connection open":
    await cancelUpgrade(provider, address, SecurityHandshake)

  asyncTest "an upgrade cancelled in muxer negotiation leaves no connection open":
    await cancelUpgrade(provider, address, MuxerNegotiation)
