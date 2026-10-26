# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../libp2p/[switch, services/hpservice, protocols/connectivity/autonat/service]

type HolePunchSwitches* = object
  sw*: Switch
  aux*: Switch
  hpService*: HPService
  autonatService*: AutonatService

proc start*(
    switches: HolePunchSwitches
) {.async: (raises: [CancelledError, LPError]).} =
  await allFutures(switches.sw.start(), switches.aux.start())
  await switches.hpService.start(switches.sw)

proc stop*(switches: HolePunchSwitches) {.async: (raises: [CancelledError, LPError]).} =
  # Stop the externally owned service while its switch dependencies are still running.
  await switches.hpService.stop(switches.sw)
  await allFutures(switches.sw.stop(), switches.aux.stop())
