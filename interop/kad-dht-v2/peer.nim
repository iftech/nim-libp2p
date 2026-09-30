# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Unified-testing kad-dht interop peer.
##
## One binary implements all three roles the `kad-dht/` harness wires up via the
## `ROLE` env var (bootstrap | provider | querier). The harness passes only
## `ROLE`, `REDIS_ADDR`, and `TEST_KEY`; the transport is fixed to tcp/noise/yamux.
##
## Contract:
##   - bootstrap: publish own multiaddr to Redis `{TEST_KEY}_bootstrap_addr`, stay up
##   - provider:  connect to bootstrap, addProvider + putValue, set `{TEST_KEY}_provider_done`
##   - querier:   wait for both keys, connect, getProviders + getValue, print `status: pass`

import std/[os, sets, strutils]
import chronos, chronicles, stew/byteutils
import ../../libp2p/[builders, switch, peerid]
import ../../libp2p/protocols/kademlia
import ../unified_testing

logScope:
  topics = "kad-dht interop"

const
  # Redis key suffixes
  BootstrapAddrSuffix = "_bootstrap_addr"
  ProviderDoneSuffix = "_provider_done"
  # Value announced by the provider and checked (substring) by the querier.
  ProviderValue = "hello from nim client"
  LookupAttempts = 10
  LookupDelay = 1.seconds
  RedisWaitTimeout = 60.seconds

type Role = enum
  bootstrap
  provider
  querier

type KadConfig = object
  role: Role
  redisAddr: string
  testKey: string
  bindIp: string

proc readKadConfig(): KadConfig =
  let roleStr = getEnv("ROLE")
  let role =
    case roleStr
    of "bootstrap":
      Role.bootstrap
    of "provider":
      Role.provider
    of "querier":
      Role.querier
    else:
      raise newException(CatchableError, "unknown or missing ROLE: '" & roleStr & "'")
  let testKey = getEnv("TEST_KEY")
  if testKey.len == 0:
    raise newException(CatchableError, "TEST_KEY env var is required")
  KadConfig(
    role: role,
    redisAddr: getEnv("REDIS_ADDR", "transport-redis:6379"),
    testKey: testKey,
    bindIp: resolveBindIp("0.0.0.0"),
  )

proc buildSwitch(config: KadConfig): Switch =
  ## Reuse the shared switch builder with the kad-dht fixed transport stack.
  let base = BaseConfig(
    bindIp: config.bindIp,
    redisAddr: config.redisAddr,
    testKey: config.testKey,
    transport: "tcp",
    secureChannel: "noise",
    muxer: "yamux",
    testTimeout: DefaultTestTimeout,
  )
  buildBaseSwitch(base).build()

proc provideKey(testKey: string): Key =
  Key.fromBytes(("interop-test-key-" & testKey).toBytes())

proc valueKey(testKey: string): Key =
  Key.fromBytes(("/example/data/" & testKey).toBytes())

proc newKad(switch: Switch): KadDHT =
  KadDHT.new(
    switch,
    # providerRejection makes the receiver reply to ADD_PROVIDER
    # without it dotnet blocks waiting for a reply that never comes.
    config = KadDHTConfig.new(quorum = 1, providerRejection = true),
    rng = rng(),
  )

proc connectBootstrap(
    switch: Switch, kad: KadDHT, redisClient: Redis, testKey: string
) {.async.} =
  ## Fetch the bootstrap multiaddr from Redis, dial it, and seed the routing table.
  let raw = await redisClient.fetchValue(testKey, BootstrapAddrSuffix, RedisWaitTimeout)
  let bootstrapMA = MultiAddress.init(raw).tryGet()
  let bootstrapPeerId = await switch.connect(bootstrapMA)
  kad.updatePeers(@[(bootstrapPeerId, @[bootstrapMA])])
  info "Connected to bootstrap", peerId = bootstrapPeerId

proc runBootstrap(switch: Switch, redisClient: Redis, testKey: string) {.async.} =
  let myAddr = switch.peerInfo.fullAddrs.tryGet()[0]
  redisClient.publishValue(testKey, BootstrapAddrSuffix, $myAddr)
  info "Bootstrap published multiaddr", address = $myAddr

proc runProvider(
    switch: Switch, kad: KadDHT, redisClient: Redis, testKey: string
) {.async.} =
  await connectBootstrap(switch, kad, redisClient, testKey)

  await kad.addProvider(provideKey(testKey))
  info "Provider announced key"

  let putRes =
    await kad.putValue(valueKey(testKey), Value.fromBytes(ProviderValue.toBytes()))
  if putRes.isErr:
    raise newException(ValueError, "putValue failed: " & $putRes.error)
  info "Provider stored value"

  redisClient.publishValue(testKey, ProviderDoneSuffix, "done")

proc fail(msg: string) =
  echo "error: " & msg
  echo "status: fail"
  quit(QuitFailure)

proc runQuerier(
    switch: Switch, kad: KadDHT, redisClient: Redis, testKey: string
) {.async.} =
  # Wait until the provider is done before connecting.
  discard await redisClient.fetchValue(testKey, ProviderDoneSuffix, RedisWaitTimeout)
  await connectBootstrap(switch, kad, redisClient, testKey)

  # Find the provider record.
  let pkey = provideKey(testKey)
  var providerCount = 0
  for attempt in 0 ..< LookupAttempts:
    try:
      providerCount = (await kad.getProviders(pkey)).len
    except LPStreamError as e:
      debug "getProviders attempt failed", attempt = attempt, err = e.msg
    if providerCount > 0:
      break
    await sleepAsync(LookupDelay)
  if providerCount == 0:
    fail("no providers found for key after " & $LookupAttempts & " attempts")
  info "Querier found providers", count = providerCount

  # Read the stored value.
  let vkey = valueKey(testKey)
  var value = ""
  for attempt in 0 ..< LookupAttempts:
    let getRes = await kad.getValue(vkey)
    if getRes.isOk:
      value = string.fromBytes(getRes.get().value.toBytes())
      break
    else:
      debug "getValue attempt failed", attempt = attempt, err = getRes.error
    await sleepAsync(LookupDelay)
  if "hello from" notin value:
    fail("unexpected or missing value: '" & value & "'")
  info "Querier retrieved value", value = value

  echo "status: pass"

proc main() {.async.} =
  let config = readKadConfig()
  info "Kad-dht interop peer", role = config.role, testKey = config.testKey

  let switch = buildSwitch(config)
  let kad = newKad(switch)
  switch.mount(kad)
  await switch.start()
  defer:
    await switch.stop()

  let redisClient = setupRedis(config.redisAddr)

  case config.role
  of Role.bootstrap:
    await runBootstrap(switch, redisClient, config.testKey)
    await sleepAsync(1.hours) # harness aborts the stack once the querier exits
  of Role.provider:
    await runProvider(switch, kad, redisClient, config.testKey)
    await sleepAsync(1.hours)
  of Role.querier:
    await runQuerier(switch, kad, redisClient, config.testKey)

let testTimeout = parseDurationEnv("TEST_TIMEOUT_SECS", 1.seconds, DefaultTestTimeout)
runMain(main, testTimeout)
