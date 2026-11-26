# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, sequtils, tables
import
  ../../libp2p/[
    switch,
    multicodec,
    protocols/connectivity/relay/relay,
    protocols/connectivity/autonat/service,
    protocols/ping,
  ]
import ../[hole_punching_switches, unified_testing]

logScope:
  topics = "hp-interop"

proc isDirectlyConnected(switch: Switch, peerId: PeerId): bool =
  let conns = switch.connManager.getConnections()
  peerId in conns and conns[peerId].anyIt(not isRelayed(it.connection))

proc connectToRelay(
    config: BaseConfig, redisClient: Redis, switches: HolePunchSwitches
): Future[MultiAddress] {.async.} =
  # Connect to aux switch for AutoNAT stub to report NotReachable
  await switches.sw.connect(switches.aux.peerInfo.peerId, switches.aux.peerInfo.addrs)

  # Wait for autonat to report NotReachable
  pollUntil(
    switches.autonatService.networkReachability == NetworkReachability.NotReachable,
    errorMsg = "Timeout waiting for AutoNAT NotReachable",
  )
  info "AutoNAT reports NotReachable"

  # Connect to relay (triggers AutoRelay reservation)
  let relayMA = await fetchRelayMultiaddr(redisClient, config.testKey)
  info "Got relay address", relayMA

  try:
    info "Dialing relay", relayMA
    let relayId = await switches.sw.connect(relayMA).wait(30.seconds)
    info "Connected to relay", relayId
  except AsyncTimeoutError as e:
    raise newException(CatchableError, "Connection to relay timed out: " & e.msg, e)

  # Wait for our relay circuit address
  pollUntil(
    switches.sw.peerInfo.addrs.anyIt(it.contains(multiCodec("p2p-circuit")).tryGet()),
    errorMsg = "Timeout waiting for relay circuit address",
  )
  info "Got relay circuit address"
  relayMA

proc runDialer(config: BaseConfig) {.async.} =
  let
    redisClient = setupRedis(config.redisAddr)
    switches = makeHolePunchSwitches(config)

  await switches.start()
  defer:
    await switches.stop()

  let relayMA = await connectToRelay(config, redisClient, switches)

  let listenerId = await fetchListenerPeerId(redisClient, config.testKey)
  info "Got listener peer ID", listenerId

  let listenerRelayAddr = MultiAddress.init($relayMA & "/p2p-circuit").tryGet()

  # Start DCUtR timer
  let dcutrStart = Moment.now()

  info "Dialing listener via relay", listenerRelayAddr
  await switches.sw.connect(listenerId, @[listenerRelayAddr])

  # Wait for DCUtR to complete (direct connection established)
  # HPService handles DCUtR in the background when the listener receives
  # the relayed connection. Poll for a direct connection.
  pollUntil(
    switches.sw.isDirectlyConnected(listenerId),
    errorMsg = "DCUtR failed: no direct connection established within timeout",
  )

  let dcutrElapsed = Moment.now() - dcutrStart
  info "Direct connection established via DCUtR"

  # Ping over the direct connection
  let channel = await switches.sw.dial(listenerId, PingCodec)
  defer:
    await channel.close()

  let pingDelay = await Ping.new(rng = rng()).ping(channel)
  let pingRttMs = pingDelay.toMs()

  printLatencyYaml(dcutrElapsed.toMs() + pingRttMs, pingRttMs)

proc runListener(config: BaseConfig) {.async.} =
  let
    redisClient = setupRedis(config.redisAddr)
    switches = makeHolePunchSwitches(config)

  await switches.start()
  defer:
    await switches.stop()

  discard await connectToRelay(config, redisClient, switches)

  let listenerPeerId = publishListenerPeerId(redisClient, config.testKey, switches.sw)
  info "Published listener peer ID to Redis", listenerPeerId

  # Wait to be killed (docker-compose will stop us after dialer exits)
  await sleepAsync(5.minutes)

proc main() {.async.} =
  let config = readBaseConfig()
  info "Test configuration", config
  if config.isDialer:
    await runDialer(config)
  else:
    await runListener(config)

let testTimeout = parseDurationEnv("TEST_TIMEOUT_SECS", 1.seconds, DefaultTestTimeout)
runMain(main, testTimeout)
