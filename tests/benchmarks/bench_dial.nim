# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Time to connect to a peer with N addresses. The last one answers and the others
## stall the handshake. `make bench_dial` runs it, and no CI job does.
## `-d:dialBenchRounds=N` and `-d:dialBenchTimeoutMs=N` override the defaults.

import std/[algorithm, sequtils, strformat]
import chronos
import ../../libp2p/[dialer, switch]
import ../tools/[multiaddress, stall_server, switch_builder]

const
  dialBenchRounds {.intdefine.} = 3
  dialBenchTimeoutMs {.intdefine.} = 2000
  AddressCounts = [1, 2, 4, 8, 9, 16]

static:
  doAssert dialBenchRounds > 0, "dialBenchRounds must be positive"

type
  Sample = object
    connected: bool
    elapsed: Duration

  Scenario = object
    transport: string
    address: MultiAddress

proc dialOnce(
    src: Switch, dialer: Dialer, peerId: PeerId, addrs: seq[MultiAddress]
): Future[Sample] {.async: (raises: [CancelledError]).} =
  let started = Moment.now()
  try:
    await dialer.connect(peerId, addrs)
  except DialFailedError:
    return Sample(connected: false, elapsed: Moment.now() - started)

  let sample = Sample(connected: true, elapsed: Moment.now() - started)
  await src.disconnect(peerId)
  sample

proc report(
    scenario: Scenario, addressCount: int, ranking: bool, samples: seq[Sample]
) =
  let
    elapsed = samples.mapIt(it.elapsed.milliseconds()).sorted()
    connected = samples.countIt(it.connected)
    rankingLabel = if ranking: "on" else: "off"
  echo &"| {scenario.transport:<5} | {addressCount:>3} | {rankingLabel:<7} | " &
    &"{connected}/{samples.len} | {elapsed[elapsed.len div 2]:>7} | {elapsed[^1]:>7} |"

proc bench(src: Switch, peerId: PeerId, scenario: Scenario) {.async.} =
  for addressCount in AddressCounts:
    # Fresh servers per row: each one holds every accepted socket until stop.
    let stalls = (1 ..< addressCount).mapIt(startStallServer())
    defer:
      await noCancel allFutures(stalls.mapIt(it.stop()))

    let addrs = stalls.mapIt(it.address) & scenario.address
    for ranking in [false, true]:
      let dialer = Dialer.new(
        src.peerInfo.peerId,
        src.connManager,
        src.peerStore,
        src.transports,
        src.ms,
        dialTimeout = dialBenchTimeoutMs.milliseconds,
        dialRanking = ranking,
      )
      var samples: seq[Sample]
      for _ in 0 ..< dialBenchRounds:
        samples.add(await src.dialOnce(dialer, peerId, addrs))
      report(scenario, addressCount, ranking, samples)

proc main() {.async.} =
  let
    src = makeStandardSwitch(@[TcpAutoAddress, QuicAutoAddress])
    dst = makeStandardSwitch(@[TcpAutoAddress, QuicAutoAddress])
  defer:
    await allFutures(src.stop(), dst.stop())
  await src.start()
  await dst.start()

  let scenarios = [
    Scenario(transport: "tcp", address: dst.peerInfo.addrs.filterIt(TCP.match(it))[0]),
    Scenario(
      transport: "quic", address: dst.peerInfo.addrs.filterIt(QUIC_V1.match(it))[0]
    ),
  ]

  echo &"dial timeout {dialBenchTimeoutMs} ms, {dialBenchRounds} rounds, " &
    "every address but the last one stalls the handshake\n"
  echo "| good  |   N | ranking | ok  | p50 ms  | max ms  |"
  echo "|-------|----:|---------|-----|--------:|--------:|"
  for scenario in scenarios:
    await src.bench(dst.peerInfo.peerId, scenario)

waitFor main()
