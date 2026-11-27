# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import stew/endians2, tables, strutils, os, redis
import chronos
import ./env
import nimcrypto/sha2
import libp2p, libp2p/multiaddress
import libp2p/protocols/[pubsub/pubsubpeer, pubsub/rpc/messages]
import libp2p/utils/heartbeat
from times import getTime, Time, toUnix, `-`, initTime, nanosecond

logScope:
  topics = "simulation"

const
  TimestampHeaderSize = sizeof(uint64)
  WarmupFlag = 0x01'u8
  WarmupFlagIndex = TimestampHeaderSize
  FragmentMarkerIndex = WarmupFlagIndex + sizeof(byte)
  ChunkMetadataSize = 2
  MinimumChunkSize = FragmentMarkerIndex + 1
  DefaultRedisPort = Port(6379)

func msgIdProvider(m: Message): Result[MessageId, ValidationResult] =
  ok(@(sha256.digest(m.data).data))

proc chunkPayloadSize(msgSize: int): Result[int, string] =
  if chunks <= 0:
    return err("FRAGMENTS must be greater than 0")
  if chunks > high(byte).int + 1:
    return err("FRAGMENTS must be 256 or fewer")
  if msgSize < 0:
    return err("msgSize must be non-negative")

  let payloadSize = msgSize div chunks
  if payloadSize < ChunkMetadataSize:
    return err("msgSize/FRAGMENTS must leave room for warm-up and fragment markers")
  ok(payloadSize)

proc parseNonNegativeEnv(name, defaultValue: string): Result[int, string] =
  let rawValue = getEnv(name, defaultValue)
  try:
    let parsed = parseInt(rawValue)
    if parsed < 0:
      return err(name & " must be non-negative")
    ok(parsed)
  except ValueError:
    err(name & " must be an integer")

proc parsePositiveEnv(name, defaultValue: string): Result[int, string] =
  let rawValue = getEnv(name, defaultValue)
  try:
    let parsed = parseInt(rawValue)
    if parsed <= 0:
      return err(name & " must be greater than 0")
    ok(parsed)
  except ValueError:
    err(name & " must be an integer")

proc parseRedisPort(portText: string): Result[Port, string] =
  if portText.len == 0:
    return err("redis_addr port cannot be empty")

  try:
    let portNumber = parseInt(portText)
    if portNumber < 0 or portNumber > 65535:
      return err("redis_addr port must be in the range 0..65535")
    ok(Port(portNumber))
  except ValueError:
    err("redis_addr port must be an integer")

proc parseRedisAddress(redisAddress: string): Result[(string, Port), string] =
  if redisAddress.len == 0:
    return err("redis_addr cannot be empty")

  if redisAddress[0] == '[':
    let closingBracket = redisAddress.find(']')
    if closingBracket < 0:
      return err("redis_addr IPv6 values must use [host]:port syntax")

    let host = redisAddress[1 ..< closingBracket]
    if host.len == 0:
      return err("redis_addr host cannot be empty")

    if closingBracket == redisAddress.high:
      return ok((host, DefaultRedisPort))

    if redisAddress[closingBracket + 1] != ':':
      return err("redis_addr bracketed hosts must be followed by :port")

    let port = parseRedisPort(redisAddress[closingBracket + 2 .. redisAddress.high]).valueOr:
      return err(error)
    return ok((host, port))

  let colonCount = redisAddress.count(':')
  if colonCount == 0 or colonCount > 1:
    return ok((redisAddress, DefaultRedisPort))

  let separator = redisAddress.rfind(':')
  let host = redisAddress[0 ..< separator]
  if host.len == 0:
    return err("redis_addr host cannot be empty")

  let port = parseRedisPort(redisAddress[separator + 1 .. redisAddress.high]).valueOr:
    return err(error)
  ok((host, port))

proc parseMessageMetadata(data: seq[byte]): Result[(uint64, bool), string] =
  if data.len < MinimumChunkSize:
    return err("message payload is too short")

  let
    sentAt = uint64.fromBytesLE(data.toOpenArray(0, TimestampHeaderSize - 1))
    isWarmup = (data[WarmupFlagIndex] and WarmupFlag) != 0
  ok((sentAt, isWarmup))

proc createMessageHandler(): proc(topic: string, data: seq[byte]) {.async, gcsafe.} =
  var messagesChunks: CountTable[(uint64, bool)]

  return proc(topic: string, data: seq[byte]) {.async, gcsafe.} =
    let (sentUint, isWarmup) = parseMessageMetadata(data).valueOr:
      warn "Ignoring truncated message payload", topic, len = data.len, err = error
      return

    let messageKey = (sentUint, isWarmup)
    messagesChunks.inc(messageKey)
    if messagesChunks[messageKey] < chunks:
      return

    messagesChunks.del(messageKey)
    if isWarmup:
      return

    let
      sentMoment = nanoseconds(int64(sentUint))
      sentNanosecs = nanoseconds(sentMoment - seconds(sentMoment.seconds))
      sentDate = initTime(sentMoment.seconds, sentNanosecs)
      diff = getTime() - sentDate
    info "Message received", latency = diff

proc messageValidator(topic: string, msg: Message): Future[ValidationResult] {.async.} =
  return ValidationResult.Accept

proc publishNewMessage(
    gossipSub: GossipSub, msgSize: int, topic: string, isWarmup = false
): Future[(Time, int)] {.async.} =
  let
    now = getTime()
    nowInt = seconds(now.toUnix()) + nanoseconds(nanosecond(now))
    payloadSize = chunkPayloadSize(msgSize).valueOr:
      raise newException(ValueError, error)
    flags = if isWarmup: WarmupFlag else: 0'u8
  var
    res = 0
    # Create a payload with a timestamp header so receivers can measure latency.
    nowBytes = @(toBytesLE(uint64(nowInt.nanoseconds))) & newSeq[byte](payloadSize)

  nowBytes[WarmupFlagIndex] = flags
  # Each fragment needs a unique payload byte so GossipSub does not deduplicate it.
  for chunk in 0 ..< chunks:
    nowBytes[FragmentMarkerIndex] = byte(chunk)
    res = await gossipSub.publish(topic, nowBytes)
  return (now, res)

proc initializeGossipsub(switch: Switch, anonymize: bool, rng: Rng): GossipSub =
  return GossipSub.init(
    switch = switch,
    triggerSelf = parseBool(getEnv("SELFTRIGGER", "true")),
    msgIdProvider = msgIdProvider,
    verifySignature = false,
    anonymize = anonymize,
    rng = rng,
  )

proc connectGossipsubPeers(
    switch: Switch, addrs: seq[string], connectTo: int, rng: Rng
): Future[Result[int, string]] {.async.} =
  var multiAddrs = addrs

  rng.shuffle(multiAddrs)

  #Make target connections
  var connected = 0
  for addrStr in multiAddrs:
    if connected >= connectTo:
      break
    let peer = MultiAddress.init(addrStr).valueOr:
      warn "Invalid multiaddress", address = addrStr
      continue
    try:
      discard await switch.connect(peer).wait(5.seconds)
      connected.inc()
      info "Connected", peer, currentConnections = $connected, target = connectTo
    except CatchableError as e:
      warn "Failed to dial", theirAddress = peer, err = e.msg

  if connected == 0:
    return err("Failed to connect any peer")
  elif connected < connectTo:
    warn "Connected to fewer peers than target",
      connected = connected, target = connectTo
  return ok(connected)

proc subscribeGossipsubTopic(gossipSub: GossipSub, topic: string) =
  gossipSub.subscribe(topic, createMessageHandler())
  gossipSub.addValidator([topic], messageValidator)

proc meshHeartbeat(hostname: string, gossipSub: GossipSub) {.async.} =
  heartbeat "mesh details", 10.seconds:
    info "Mesh details ",
      hostname,
      meshPeers = gossipSub.mesh.getOrDefault("test").len,
      gossipPeers = gossipSub.gossipsub.getOrDefault("test").len

proc main() {.async.} =
  let
    rng = libp2p.newRng()
    (hostname, connectTo, address) = getPeerDetails().valueOr:
      error "Error reading peer settings ", err = error
      return
    warmupMessages = parseNonNegativeEnv("WARMUP_MESSAGES", "3").valueOr:
      error "Invalid warm-up configuration", hostname, err = error
      return
    redisWaitTimeoutSeconds = parsePositiveEnv("REDIS_WAIT_TIMEOUT_SECONDS", "120").valueOr:
      error "Invalid Redis wait timeout", hostname, err = error
      return

  discard chunkPayloadSize(50 * 1024).valueOr:
    error "Invalid fragment configuration", hostname, err = error
    return

  let listenAddr = MultiAddress.init(address).valueOr:
    error "Invalid listen address", address
    return

  var builder = SwitchBuilder
    .new()
    .withNoise()
    .withAddress(listenAddr)
    .withMaxConnections(parseInt(getEnv("MAXCONNECTIONS", "250")))
    .withRng(rng)

  if getEnv("TRANSPORT", "QUIC") == "QUIC":
    builder = builder.withQuicTransport()
  else:
    builder = builder.withTcpTransport().withYamux()

  let
    switch = builder.build()
    gossipSub = initializeGossipsub(switch, true, rng)

  subscribeGossipsubTopic(gossipSub, "test")
  switch.mount(gossipSub)
  await switch.start()

  # Metrics
  info "Starting metrics server", hostname
  let metricsServer = startMetricsServer(parseIpAddress("0.0.0.0"), prometheusPort)
  if metricsServer.isErr:
    error "Failed to initialize metrics server", hostname, err = metricsServer.error

  info "Listening on ", hostname, address = switch.peerInfo.addrs[^1]
  info "MY PEER ID", hostname, peerId = switch.peerInfo.peerId

  # Wait for redis
  let
    redisAddr = getEnv("redis_addr", "redis:6379")
    (redisHost, redisPort) = parseRedisAddress(redisAddr).valueOr:
      error "Invalid redis address", hostname, address = redisAddr, err = error
      return
    redisWaitDeadline = Moment.now() + redisWaitTimeoutSeconds.seconds
    target = parseInt(getEnv("NUM_LIBP2P_NODES", "10"))
    redisClient = open(redisHost, redisPort)

  discard redisClient.sadd(
    "node", $switch.peerInfo.addrs[^1] & "/p2p/" & $switch.peerInfo.peerId
  )

  var members: RedisList
  while true:
    try:
      members = redisClient.smembers("node")
    except Exception as e:
      # Exception: redis library declares {.raises: [Exception].}, not CatchableError
      error "Could not obtain list of members", hostname, err = e.msg
      quit(1)

    if members.len == target:
      info "Got all members", hostname, members
      break

    if Moment.now() >= redisWaitDeadline:
      error "Timed out waiting for Redis members",
        hostname,
        len = members.len,
        target,
        timeoutSeconds = redisWaitTimeoutSeconds,
        members
      quit(1)

    error "not enough members", hostname, len = members.len, target, members

    # polling interval while waiting for all peers to register in redis
    await sleepAsync(1.seconds)

  # give nodes time to fully initialize before connecting
  info "Sleeping for 5s to make sure nim-libp2p has started"
  await sleepAsync(5.seconds)

  #connect with peers
  discard (await connectGossipsubPeers(switch, members, connectTo, rng)).valueOr:
    error "Failed to establish any connections", hostname, error = error
    return

  # allow gossipsub mesh formation via heartbeat rounds before publishing
  info "Sleeping 5s for mesh to form"
  await sleepAsync(5.seconds)

  asyncSpawn meshHeartbeat(hostname, gossipSub)

  info "Starting listening endpoint for publish controller"

  if warmupMessages > 0:
    info "Starting warm-up publishes", hostname, warmupMessages
    for warmupIdx in 0 ..< warmupMessages:
      discard await gossipSub.publishNewMessage(50 * 1024, "test", true)
      info "Warm-up publish complete",
        hostname, completed = warmupIdx + 1, total = warmupMessages
      await sleepAsync(5.seconds)

  while true:
    discard await gossipSub.publishNewMessage(50 * 1024, "test")
    # rate-limit message publishing to one message per interval
    await sleepAsync(5.seconds)

waitFor(main())
