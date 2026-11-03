# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[json, nativesockets, os, strutils, tables, times]
import chronos, stew/[byteutils, endians2]
import
  ../../../libp2p/[builders, crypto/crypto, crypto/ed25519/ed25519, protocols/waggle]

type
  BitmapMetadata = ref object of WaggleMetadata
    have: byte

  BitmapShard = ref object of WaggleShard
    id: uint64
    have: byte

proc piece(id: uint64, index: int): seq[byte] =
  for offset in 0 ..< 128:
    result.add((id + uint64(index * 128 + offset)).toBytesBE())

method clone(m: BitmapMetadata): WaggleMetadata =
  BitmapMetadata(have: m.have)

method bytes(m: BitmapMetadata): seq[byte] =
  @[m.have]

method update(m: BitmapMetadata, data: seq[byte]): Result[bool, string] =
  if data.len != 1:
    return err("invalid bitmap metadata")
  let previous = m.have
  m.have = m.have or data[0]
  ok(previous != m.have)

method objectId(s: BitmapShard): seq[byte] =
  @(s.id.toBytesBE())

method metadata(s: BitmapShard): WaggleMetadata =
  BitmapMetadata(have: s.have)

method actionFromMetadata(
    s: BitmapShard, peer: PeerId, connectionId: ConnectionId, metadata: Opt[seq[byte]]
): Result[WaggleAction, string] =
  var remote: byte
  if metadata.isSome:
    if metadata.get().len != 1:
      return err("invalid bitmap metadata")
    remote = metadata.get()[0]
  let missing = s.have and not remote
  var action = WaggleAction(need: (remote and not s.have) != 0)
  if missing != 0:
    var payload = @[missing]
    for index in 0 ..< 8:
      if (missing and (1.byte shl index)) != 0:
        payload.add(piece(s.id, index))
    action.send = Opt.some(
      PieceSend(pieces: payload, peerMetadata: BitmapMetadata(have: remote or missing))
    )
  ok(action)

proc nodeKey(id: int): PrivateKey =
  var seed: array[32, byte]
  seed[0 ..< 4] = uint32(id).toBytesLE()
  PrivateKey.init(EdPrivateKey.fromSeed(seed))

proc logEvent(message: string, fields: JsonNode) {.gcsafe, raises: [].} =
  var entry = fields
  entry["time"] = %now().utc.format("yyyy-MM-dd'T'HH:mm:sszzz")
  entry["msg"] = %message
  echo $entry

proc intValue(node: JsonNode): int =
  parseInt(node.getStr())

proc run(paramsPath: string) {.async.} =
  let
    started = Moment.now()
    hostname = getHostname()
  doAssert hostname.startsWith("node"), "Expected Shadow hostname node<N>"
  let
    nodeId = parseInt(hostname[4 .. ^1])
    script = parseJson(readFile(paramsPath), rawIntegers = true)["script"]
    random = newRng()
    switch = SwitchBuilder
      .new()
      .withRng(random)
      .withPrivateKey(nodeKey(nodeId))
      .withAddress(MultiAddress.init("/ip4/0.0.0.0/tcp/9000").get())
      .withTcpTransport()
      .withYamux()
      .withNoise()
      .build()
  var config = WaggleConfig()
  for instruction in script:
    var init = instruction
    if init["type"].getStr() == "ifNodeIDEquals":
      if init["nodeID"].intValue() != nodeId:
        continue
      init = init["instruction"]
    if init["type"].getStr() == "initWaggle":
      let params = init["waggleParams"]
      if params.hasKey("publishFanout") and params["publishFanout"].kind != JNull:
        config.defaultTopicConfig.publishFanout = params["publishFanout"].intValue()
      if params.hasKey("gossipFanout") and params["gossipFanout"].kind != JNull:
        config.defaultTopicConfig.gossipFanout = params["gossipFanout"].intValue()
      break

  var
    objects: Table[(TopicId, uint64), BitmapShard]
    waggle: Waggle

  proc getShard(topic: TopicId, id: uint64): BitmapShard {.raises: [].} =
    objects.mgetOrPut((topic, id), BitmapShard(id: id))

  proc completed(shard: BitmapShard, previous: byte) {.raises: [].} =
    if previous != 255 and shard.have == 255:
      logEvent("All parts received", %*{"object_id": $shard.id})

  proc publish(topic: TopicId, shard: BitmapShard) {.raises: [].} =
    # Waggle retains snapshots; later pieces must not mutate an admitted publish.
    doAssert waggle.publish(topic, BitmapShard(id: shard.id, have: shard.have)).isOk

  proc onEvent(event: WaggleEvent) {.gcsafe, raises: [].} =
    case event.kind
    of WaggleEventKind.Received:
      let message = event.message
      doAssert message.objectId.len == 8
      let
        id = uint64.fromBytesBE(message.objectId)
        shard = getShard(event.topicId, id)
        previous = shard.have
      if message.pieces.isSome:
        let payload = message.pieces.get()
        doAssert payload.len >= 1
        var offset = 1
        for index in 0 ..< 8:
          let mask = 1.byte shl index
          if (payload[0] and mask) == 0:
            continue
          doAssert offset + 1024 <= payload.len
          doAssert payload[offset ..< offset + 1024] == piece(id, index)
          shard.have = shard.have or mask
          offset += 1024
        doAssert offset == payload.len
      completed(shard, previous)
      if previous != shard.have or (
        message.piecesMetadata.isSome and message.piecesMetadata.get() != @[shard.have]
      ):
        publish(event.topicId, shard)
    of WaggleEventKind.InvalidData, WaggleEventKind.FullQueue,
        WaggleEventKind.OutgoingRejected:
      raiseAssert $event.kind & ": " & event.reason
    else:
      discard

  waggle = Waggle.new(switch = switch, rng = random, config = config, onEvent = onEvent)
  switch.mount(waggle)
  await switch.start()
  defer:
    await switch.stop()
  logEvent("PeerID", %*{"id": $switch.peerInfo.peerId, "node_id": nodeId})

  proc execute(instruction: JsonNode) {.async.} =
    case instruction["type"].getStr()
    of "initWaggle":
      discard # Configuration is applied before mounting the protocol.
    of "ifNodeIDEquals":
      if instruction["nodeID"].intValue() == nodeId:
        await execute(instruction["instruction"])
    of "connect":
      for target in instruction["connectTo"]:
        let
          id = target.intValue()
          ip = getHostByName("node" & $id).addrList[0]
          address = MultiAddress.init("/ip4/" & ip & "/tcp/9000").get()
        await switch.connect(PeerId.init(nodeKey(id)).get(), @[address])
    of "waitUntil":
      let deadline = started + chronos.seconds(instruction["elapsedSeconds"].intValue())
      if Moment.now() < deadline:
        await sleepAsync(deadline - Moment.now())
    of "subscribeToTopic":
      discard waggle.subscribe(instruction["topicID"].getStr().toBytes()).get()
    of "addPiece", "publish":
      let
        topic = instruction["topicID"].getStr().toBytes()
        # Preserve object IDs above high(int64) without a float conversion.
        id = parseBiggestUInt(instruction["objectID"].getStr())
        shard = getShard(topic, id)
      if instruction["type"].getStr() == "addPiece":
        let previous = shard.have
        shard.have = shard.have or byte(instruction["parts"].intValue())
        completed(shard, previous)
      else:
        publish(topic, shard)
    else:
      raise newException(ValueError, "Unknown instruction: " & $instruction)

  for instruction in script:
    await execute(instruction)

when isMainModule:
  if paramCount() != 2 or paramStr(1) != "--params":
    quit("usage: peer --params <params.json>", 1)
  waitFor run(paramStr(2))
