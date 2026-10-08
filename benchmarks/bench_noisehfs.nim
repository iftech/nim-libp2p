# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Benchmarks for NoiseHFS (`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`)
## against the classical Noise XX handshake, plus ML-KEM-768 microbenchmarks.
##
## Methodology mirrors the JavaScript and Python benchmarks published for the
## same protocol so the three are directly comparable:
##
## * KEM operations: 10 warm-up iterations, then 1000 timed; median reported.
## * Full handshakes: 20 warm-up, then 500 timed; median reported.
##
##   The published JavaScript and Python runs used 100 KEM and 30 handshake
##   iterations. Those counts were chosen when a handshake cost ~44 ms. Here a
##   handshake costs ~3 ms and the hybrid-minus-classical difference is a few
##   hundred microseconds, so 30 samples put the effect size at the noise
##   floor. The sample count is raised rather than the protocol changed;
##   interquartile range is reported so the dispersion is visible.
## * Handshakes run over in-memory `bridgedConnections()` rather than loopback
##   TCP, so no syscall cost is attributed to the cryptography. Both sides run
##   on one event loop, so a measured handshake is the sum of initiator and
##   responder work, not the wall time of two parallel peers.
## * Ed25519 identity keys. nim-libp2p defaults to ECDSA elsewhere, but the
##   published figures for the other implementations are for a handshake that
##   verifies Ed25519 signatures, and signature cost is not negligible here.
##
## Build with -d:release. An unoptimised build is not a meaningful comparison
## against the other implementations.
##
##   nim c -d:release -r benchmarks/bench_noisehfs.nim

import std/[algorithm, monotimes, strformat, times]
import chronos
import
  ../libp2p/[
    stream/connection,
    stream/bridgestream,
    crypto/crypto,
    crypto/rng,
    crypto/mlkem768,
    peerid,
    protocols/secure/noise,
    protocols/secure/noisehfs,
    protocols/secure/secure,
  ]

const
  KemWarmup = 10
  KemIters = 1000
  HandshakeWarmup = 20
  HandshakeIters = 500

# Accumulator that keeps the optimiser from discarding benchmarked results.
var blackhole: uint64

proc consume(b: byte) {.inline.} =
  blackhole = blackhole + b.uint64

proc median(samples: seq[float]): float =
  var xs = samples
  xs.sort()
  if xs.len mod 2 == 1:
    xs[xs.len div 2]
  else:
    (xs[xs.len div 2 - 1] + xs[xs.len div 2]) / 2.0

proc msSince(t0: MonoTime): float =
  (getMonoTime() - t0).inNanoseconds.float / 1_000_000.0

proc opsPerSec(ms: float): float =
  if ms <= 0.0: 0.0 else: 1000.0 / ms

proc quantile(samples: seq[float], q: float): float =
  var xs = samples
  xs.sort()
  xs[int(q * float(xs.len - 1))]

proc row(name: string, ms: float, samples: seq[float] = @[]) =
  if samples.len == 0:
    echo &"| {name:<44} | {opsPerSec(ms):>9.0f} | {ms:>9.3f} |          |"
  else:
    let iqr = quantile(samples, 0.75) - quantile(samples, 0.25)
    echo &"| {name:<44} | {opsPerSec(ms):>9.0f} | {ms:>9.3f} | {iqr:>8.3f} |"

# ---------------------------------------------------------------------------
# ML-KEM-768 microbenchmarks
# ---------------------------------------------------------------------------

proc benchKem(): tuple[keygen, encap, decap: seq[float]] =
  let seedPair = generateKeyPair()
  let seedEncap = encapsulate(seedPair.publicKey).expect("encapsulate")

  var keygenSamples, encapSamples, decapSamples: seq[float]

  for _ in 0 ..< KemWarmup:
    consume(generateKeyPair().publicKey[0])
  for _ in 0 ..< KemIters:
    let t0 = getMonoTime()
    let kp = generateKeyPair()
    keygenSamples.add(msSince(t0))
    consume(kp.publicKey[0])

  for _ in 0 ..< KemWarmup:
    consume(encapsulate(seedPair.publicKey).expect("encapsulate").ciphertext[0])
  for _ in 0 ..< KemIters:
    let t0 = getMonoTime()
    let enc = encapsulate(seedPair.publicKey).expect("encapsulate")
    encapSamples.add(msSince(t0))
    consume(enc.ciphertext[0])

  for _ in 0 ..< KemWarmup:
    consume(decapsulate(seedEncap.ciphertext, seedPair).expect("decapsulate")[0])
  for _ in 0 ..< KemIters:
    let t0 = getMonoTime()
    let ss = decapsulate(seedEncap.ciphertext, seedPair).expect("decapsulate")
    decapSamples.add(msSince(t0))
    consume(ss[0])

  (keygenSamples, encapSamples, decapSamples)

# ---------------------------------------------------------------------------
# Handshakes
# ---------------------------------------------------------------------------

proc timeHandshake(
    initiator, responder: Secure
): Future[float] {.async: (raises: [CancelledError, LPStreamError]).} =
  let (connA, connB) =
    bridgedConnections(dirA = Direction.Out, dirB = Direction.In)

  let t0 = getMonoTime()
  let
    futInitiator = initiator.secure(connA, Opt.none(PeerId))
    futResponder = responder.secure(connB, Opt.none(PeerId))
    sconnA = await futInitiator
    sconnB = await futResponder
  let elapsed = msSince(t0)

  await sconnA.close()
  await sconnB.close()
  await connA.close()
  await connB.close()
  elapsed

proc benchHandshakesPaired(
    rng: Rng
): Future[tuple[classical, hybrid, diff: seq[float]]] {.
    async: (raises: [CancelledError, LPStreamError])
.} =
  ## Measures both protocols interleaved within one loop rather than in two
  ## consecutive phases.
  ##
  ## Measuring 500 classical handshakes and then 500 hybrid ones puts the two
  ## populations in different time windows, so any drift on the machine lands
  ## directly in the ratio between them. The added cost of the hybrid handshake
  ## is only ~0.3 ms while between-run variation in either figure is ~0.6 ms, so
  ## that arrangement is not powerful enough to resolve the effect: across nine
  ## sequential runs the ratio ranged from 0.99x to 1.27x, and 0.99x would mean
  ## the hybrid handshake is cheaper than the classical one, which cannot be
  ## true since XXhfs performs strictly more work. Alternating the two within
  ## each iteration makes drift common-mode, so it cancels in the per-iteration
  ## difference.
  let
    initiatorKey = PrivateKey.random(Ed25519, rng).expect("initiator key")
    responderKey = PrivateKey.random(Ed25519, rng).expect("responder key")

  proc classicalPair(): (Secure, Secure) =
    (Secure(Noise.new(rng, initiatorKey)), Secure(Noise.new(rng, responderKey)))

  proc hybridPair(): (Secure, Secure) =
    (
      Secure(NoiseHFS.new(rng, initiatorKey)),
      Secure(NoiseHFS.new(rng, responderKey)),
    )

  for _ in 0 ..< HandshakeWarmup:
    let (ci, cr) = classicalPair()
    discard await timeHandshake(ci, cr)
    let (hi, hr) = hybridPair()
    discard await timeHandshake(hi, hr)

  var classical, hybrid, diff: seq[float]
  for _ in 0 ..< HandshakeIters:
    let (ci, cr) = classicalPair()
    let c = await timeHandshake(ci, cr)
    let (hi, hr) = hybridPair()
    let h = await timeHandshake(hi, hr)
    classical.add(c)
    hybrid.add(h)
    diff.add(h - c)

  (classical, hybrid, diff)

proc main() {.async: (raises: [CancelledError, LPStreamError]).} =
  let rng = newRng()

  echo ""
  echo "ML-KEM-768 microbenchmarks (BoringSSL via nim-libp2p)"
  echo &"warm-up {KemWarmup}, {KemIters} timed iterations, median"
  echo ""
  echo "| Operation                                    |    ops/s |    ms/op |  IQR ms |"
  echo "|----------------------------------------------|---------:|---------:|--------:|"
  let kem = benchKem()
  row("generateKeyPair (ML-KEM-768 keygen)", median(kem.keygen), kem.keygen)
  row("encapsulate(publicKey)", median(kem.encap), kem.encap)
  row("decapsulate(cipherText, secretKey)", median(kem.decap), kem.decap)
  let kemRoundTrip = median(kem.keygen) + median(kem.encap) + median(kem.decap)
  row("Full KEM round-trip (keygen + encap + decap)", kemRoundTrip)

  echo ""
  echo "Handshake latency (in-memory connection pair, Ed25519 identity)"
  echo &"warm-up {HandshakeWarmup}, {HandshakeIters} timed iterations, median"
  echo ""
  echo "| Protocol                                     |    ops/s |ms/handshk|  IQR ms |"
  echo "|----------------------------------------------|---------:|---------:|--------:|"

  let paired = await benchHandshakesPaired(rng)
  let
    classical = median(paired.classical)
    hybrid = median(paired.hybrid)
    pairedDiff = median(paired.diff)
  row("Noise_XX_25519_ChaChaPoly_SHA256 (classical)", classical, paired.classical)
  row("Noise_XXhfs_25519+MLKEM768 (hybrid)", hybrid, paired.hybrid)

  echo ""
  echo "Derived figures"
  echo ""
  var positive = 0
  for d in paired.diff:
    if d > 0.0:
      positive += 1
  let
    overhead = hybrid / classical
    kemFraction = kemRoundTrip / hybrid * 100.0
    nonKemOverhead = hybrid - kemRoundTrip
  echo &"  classical XX median              : {classical:.3f} ms"
  echo &"  XXhfs median                     : {hybrid:.3f} ms"
  echo &"  paired difference (median)       : {pairedDiff:.3f} ms"
  echo &"  paired diff IQR                  : {quantile(paired.diff, 0.75) - quantile(paired.diff, 0.25):.3f} ms"
  echo &"  iterations where hybrid > classical: {positive}/{paired.diff.len}"
  echo &"  measured KEM round-trip          : {kemRoundTrip:.3f} ms"
  echo &"  XXhfs overhead over classical XX : {overhead:.3f}x"
  echo &"  overhead from paired difference  : {(1.0 + pairedDiff / classical):.3f}x"
  echo &"  KEM fraction of XXhfs time       : {kemFraction:.1f}%"
  echo &"  Non-KEM overhead                 : {nonKemOverhead:.2f} ms"
  echo &"  (blackhole {blackhole})"

waitFor(main())
