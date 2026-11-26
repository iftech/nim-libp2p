# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./autonatv2
import
  ../../libp2p/[
    peerid, switch, wire, protocols/connectivity/autonatv2/service, services/natservice
  ]
import ../../libp2p/protocols/connectivity/autonatv2/server except AutonatV2
import ../tools/[unittest, crypto, switch_builder, multiaddress]

proc createSwitch(address: string, withAutonatV2: bool = true): Switch =
  var builder = SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[ma(address)])
    .withTcpTransport()
    .withYamux()
    .withNoise()

  if withAutonatV2:
    builder = builder
      .withAutonatV2Server(AutonatV2Config.new(allowPrivateAddresses = true))
      .withNAT(
        autonatConfig(
          AutonatV2,
          v2ServiceConfig =
            Opt.some(AutonatV2ServiceConfig.new(scheduleInterval = Opt.some(1.seconds))),
        )
      )

  builder.build()

suite "Autonatv2 Interop Tests with Nim nodes":
  asyncTeardown:
    checkTrackers()

  asyncTest "Happy path":
    const peerAddress = "/ip6/::1/tcp/3030"
    let switch = createSwitch(peerAddress, withAutonatV2 = true)

    await switch.start()
    defer:
      await switch.stop()

    const ourAddress = "/ip6/::1/tcp/4040"
    check:
      await autonatInteropTest(ourAddress, peerAddress, switch.peerInfo.peerId)

  asyncTest "Timeout when peer lacks AutoNATv2 server":
    const peerAddress = "/ip6/::1/tcp/3031"
    let switch = createSwitch(peerAddress, withAutonatV2 = false)

    await switch.start()
    defer:
      await switch.stop()

    const ourAddress = "/ip6/::1/tcp/4041"
    expect AsyncTimeoutError:
      discard await autonatInteropTest(
        ourAddress, peerAddress, switch.peerInfo.peerId, timeout = 3.seconds
      )

  asyncTest "Fails gracefully on connection error":
    const unreachableAddress = "/ip6/::1/tcp/59999" # Nothing listening
    let fakePeerId = PeerId.random()

    const ourAddress = "/ip6/::1/tcp/4042"
    expect DialFailedError:
      discard await autonatInteropTest(ourAddress, unreachableAddress, fakePeerId)
