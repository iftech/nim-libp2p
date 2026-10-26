# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../libp2p/[switch, services/hpservice, protocols/connectivity/autonat/service]

type HolePunchSwitches* = object
  sw*: Switch
  aux*: Switch
  hpService*: HPService
  autonatService*: AutonatService

proc start*(switches: HolePunchSwitches) {.async.} =
  await allFutures(switches.sw.start(), switches.aux.start())
  await switches.hpService.start(switches.sw)

proc stop*(switches: HolePunchSwitches) {.async.} =
  # Stop the externally owned service while its switch dependencies are still running.
  discard await switches.hpService.stop(switches.sw).withTimeout(5.seconds)
  # Timeout switch shutdown to avoid hanging on mplex teardown.
  discard
    await allFutures(switches.sw.stop(), switches.aux.stop()).withTimeout(5.seconds)
