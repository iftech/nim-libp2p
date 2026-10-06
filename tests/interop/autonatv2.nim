# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import net, chronos
import ../../libp2p/utils/future
import
  ../../libp2p/[
    builders,
    peerid,
    wire,
    protocols/connectivity/autonatv2/service,
    protocols/connectivity/autonatv2/types,
    services/natservice,
  ]
import ../tools/[crypto, multiaddress]

proc autonatInteropTest*(
    ourAddr: string,
    otherAddr: string,
    otherPeerId: PeerId,
    timeout: Duration = 5.minutes,
): Future[bool] {.async.} =
  var switch = SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[ma(ourAddr)])
    .withAutonatV2Server()
    .withNAT(
      autonatConfig(
        AutonatV2,
        v2ServiceConfig =
          Opt.some(AutonatV2ServiceConfig.new(scheduleInterval = Opt.some(1.seconds))),
      )
    )
    .withTcpTransport()
    .withYamux()
    .withNoise()
    .build()

  let awaiter = newFuture[void]()

  proc reachabilityHandler(
      networkReachability: NetworkReachability,
      confidence: Opt[float],
      dialBackAddr: Opt[MultiAddress],
  ) {.async: (raises: [CancelledError]).} =
    # AutoNAT v2 reports no confidence; the summary alone decides
    if networkReachability != NetworkReachability.Unknown:
      awaiter.completeOnce()

  # NATService creates its selected AutoNAT implementation during start.
  # Start before retrieving it, then register the observer before connecting
  # the peer that triggers verification.
  await switch.start()
  defer:
    await switch.stop()

  let nat = switch.natService().valueOr:
    raiseAssert "expected NATService to be configured"
  let v2 = nat.autonatV2Service.valueOr:
    raiseAssert "expected AutonatV2 service to be configured"
  discard v2.reachabilityObservers.add(reachabilityHandler)

  await switch.connect(otherPeerId, @[ma(otherAddr)])

  # await for network reachability with some timeout,
  # to prevent waiting indefinitely
  await awaiter.wait(timeout)

  echo "Network reachability: ", v2.networkReachability

  # if awaiter has completed then autonat tests has passed.
  return awaiter.completed()
