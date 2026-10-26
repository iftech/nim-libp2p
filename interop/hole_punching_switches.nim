# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import
  ../libp2p/[
    builders,
    switch,
    address_manager,
    services/hpservice,
    services/autorelayservice,
    protocols/connectivity/relay/client,
    protocols/connectivity/relay/relay,
    protocols/connectivity/autonat/service,
    protocols/ping,
  ]
import ../tests/stubs/autonatclientstub
import ./unified_testing

type HolePunchSwitches* = object
  sw*: Switch
  aux*: Switch
  hpService: HPService
  autonatService*: AutonatService

proc createSwitch(config: BaseConfig, relayClient: Relay = nil): Switch =
  var sw = buildBaseSwitch(config, tcpFlags = {ServerFlags.TcpNoDelay})
    .withAddressManager(AddressManagerConfig(maxSize: 1, minCount: 1))
    .withAutonat()
    .withCircuitRelay(relayClient)
    .build()

  sw.mount(Ping.new(rng = rng()))
  sw

proc makeHolePunchSwitches*(
    config: BaseConfig
): HolePunchSwitches {.raises: [LPError].} =
  let relayClient = RelayClient.new()
  let autoRelayService = AutoRelayService.new(1, relayClient, nil, rng())

  let autonatClientStub = AutonatClientStub.new(expectedDials = 1)
  autonatClientStub.answer = NotReachable

  let autonatService = AutonatService.new(autonatClientStub, rng(), maxQueueSize = 1)
  let hpService = HPService.new(autonatService, autoRelayService)

  HolePunchSwitches(
    sw: createSwitch(config, relayClient),
    aux: createSwitch(config),
    hpService: hpService,
    autonatService: autonatService,
  )

proc start*(
    switches: HolePunchSwitches
) {.async: (raises: [CancelledError, LPError]).} =
  await allFutures(switches.sw.start(), switches.aux.start())
  await switches.hpService.start(switches.sw)

proc stop*(switches: HolePunchSwitches) {.async: (raises: [CancelledError, LPError]).} =
  # Stop the externally owned service while its switch dependencies are still running.
  await switches.hpService.stop(switches.sw)
  await allFutures(switches.sw.stop(), switches.aux.stop())
