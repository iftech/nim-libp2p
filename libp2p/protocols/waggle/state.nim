# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [], gcsafe.}

import std/tables
import ./[shard, messages]
import ../../peerid

type
  RemoteView = ref object
    lastUsed: uint64
    raw: Opt[seq[byte]]
    tracked: WaggleMetadata
    advertised: WaggleMetadata

  ObjectViews = ref object
    entries: Table[seq[byte], RemoteView]

  CachedObject = object
    lastUsed: uint64
    shard: WaggleShard

  TopicState = ref object
    local: Table[seq[byte], CachedObject]
    remote: Table[uint64, ObjectViews]

  WaggleState* = ref object
    topics: Table[seq[byte], TopicState]
    clock: uint64
    capacity: int
    maxTopics: int

  Transmission* = object
    message*: ObjectPieces
    view: RemoteView
    tracked: WaggleMetadata
    advertised: WaggleMetadata

  ReceiveAction* = object
    active*: bool
    emit*: bool
    reply*: Opt[Transmission]

proc new*(T: type WaggleState, capacity, maxTopics: int): T =
  T(capacity: capacity, maxTopics: maxTopics)

# Keep cache hits cheap; scan recency counters only when evicting.
proc oldestKey[K, V](table: Table[K, V]): K =
  var oldest = high(uint64)
  for key, value in table:
    if value.lastUsed < oldest:
      oldest = value.lastUsed
      result = key

proc touch[K, V](state: WaggleState, table: var Table[K, V], key: K, value: V) =
  var entry = value
  inc state.clock
  entry.lastUsed = state.clock
  table[key] = entry

proc lookup[K, V](table: Table[K, V], key: K): Opt[V] =
  table.withValue(key, found):
    return Opt.some(found)
  return Opt.none(V)

proc topicState(state: WaggleState, topic: seq[byte]): Result[TopicState, string] =
  state.topics.withValue(topic, entry):
    let cache = entry[]
    return ok(cache)
  if state.topics.len >= state.maxTopics:
    return err("Waggle topic state limit reached")
  let value = TopicState()
  state.topics[topic] = value
  ok(value)

proc view(
    state: WaggleState, topic: TopicState, connectionId: uint64, objectId: seq[byte]
): RemoteView =
  let views = topic.remote.lookup(connectionId).valueOr:
    let created = ObjectViews()
    topic.remote[connectionId] = created
    created
  let remote = views.entries.lookup(objectId).valueOr:
    if views.entries.len >= state.capacity:
      views.entries.del(views.entries.oldestKey())
    RemoteView()
  state.touch(views.entries, objectId, remote)
  return remote

proc local(
    state: WaggleState, topic: TopicState, objectId: seq[byte]
): Opt[WaggleShard] =
  let entry = topic.local.lookup(objectId).valueOr:
    return Opt.none(WaggleShard)
  state.touch(topic.local, objectId, entry)
  return Opt.some(entry.shard)

proc store*(
    state: WaggleState, topic: seq[byte], shard: WaggleShard
): Result[bool, string] =
  let cache = ?state.topicState(topic)
  let objectId = shard.objectId()
  let previous = cache.local.lookup(objectId)
  var changed = true
  if previous.isSome:
    changed = ?previous.get().shard.metadata().update(shard.metadata().bytes())
  elif cache.local.len >= state.capacity:
    let evicted = cache.local.oldestKey()
    cache.local.del(evicted)
  state.touch(cache.local, objectId, CachedObject(shard: shard))
  ok(changed)

proc peerBytes(view: RemoteView): Opt[seq[byte]] =
  if view.tracked != nil:
    Opt.some(view.tracked.bytes())
  else:
    view.raw

proc prepare*(
    state: WaggleState,
    topic: seq[byte],
    connectionId: uint64,
    peer: PeerId,
    objectId: seq[byte],
    metadataOnly: bool = false,
): Result[Opt[Transmission], string] =
  let cache = state.topics.lookup(topic).valueOr:
    return ok(Opt.none(Transmission))
  let shard = state.local(cache, objectId).valueOr:
    return ok(Opt.none(Transmission))
  let view = state.view(cache, connectionId, objectId)
  let action = ?shard.actionFromMetadata(peer, connectionId, view.peerBytes())
  var tx = Transmission(view: view, message: ObjectPieces(objectId: objectId))
  if action.send.isSome and not metadataOnly:
    let sending = action.send.get()
    if sending.peerMetadata == nil:
      return err("missing peer metadata for outgoing pieces")
    tx.message.pieces = Opt.some(sending.pieces)
    tx.tracked = sending.peerMetadata.clone()
  let current = shard.metadata()
  let advertised =
    if view.advertised == nil:
      current
    else:
      view.advertised.clone()
  let changed = view.advertised == nil or (?advertised.update(current.bytes()))
  if changed:
    tx.message.piecesMetadata = Opt.some(current.bytes())
    tx.advertised = advertised
  if tx.message.pieces.isNone and tx.message.piecesMetadata.isNone:
    ok(Opt.none(Transmission))
  else:
    ok(Opt.some(tx))

proc commit*(tx: Transmission) =
  ## Advance optimistic remote views only after the message enters the queue.
  if tx.tracked != nil:
    tx.view.tracked = tx.tracked
    tx.view.raw = Opt.none(seq[byte])
  if tx.advertised != nil:
    tx.view.advertised = tx.advertised

proc received*(
    state: WaggleState,
    topic: seq[byte],
    connectionId: uint64,
    peer: PeerId,
    msg: ObjectPieces,
): Result[ReceiveAction, string] =
  let cache = ?state.topicState(topic)
  let view = state.view(cache, connectionId, msg.objectId)
  var changed = false
  if msg.piecesMetadata.isSome:
    let data = msg.piecesMetadata.get()
    if view.tracked != nil:
      let next = view.tracked.clone()
      changed = ?next.update(data)
      view.tracked = next
    else:
      changed = view.raw.isNone or view.raw.get() != data
      view.raw = Opt.some(data)
  if not changed and msg.pieces.isNone:
    return ok(ReceiveAction())
  let shard = state.local(cache, msg.objectId).valueOr:
    return ok(ReceiveAction(active: true, emit: true))
  let action = ?shard.actionFromMetadata(peer, connectionId, view.peerBytes())
  var outcome = ReceiveAction(active: true, emit: action.need)
  if action.send.isSome:
    let sending = action.send.get()
    if sending.peerMetadata == nil:
      return err("missing peer metadata for outgoing pieces")
    let current = shard.metadata()
    outcome.reply = Opt.some(
      Transmission(
        view: view,
        tracked: sending.peerMetadata.clone(),
        advertised: current,
        message: ObjectPieces(
          objectId: msg.objectId,
          pieces: Opt.some(sending.pieces),
          piecesMetadata: Opt.some(current.bytes()),
        ),
      )
    )
  ok(outcome)

proc removeSubscription*(state: WaggleState, topic: seq[byte], connectionId: uint64) =
  state.topics.withValue(topic, cache):
    cache[].remote.del(connectionId)

proc removeConnection*(state: WaggleState, connectionId: uint64) =
  for topic in state.topics.values:
    topic.remote.del(connectionId)

proc removeTopic*(state: WaggleState, topic: seq[byte]) =
  state.topics.del(topic)

proc hasLocal*(state: WaggleState, topic, objectId: seq[byte]): bool =
  let cache = state.topics.lookup(topic).valueOr:
    return false
  return cache.local.hasKey(objectId)

proc peerView*(
    state: WaggleState, topic: seq[byte], connectionId: uint64, objectId: seq[byte]
): tuple[known, advertised: bool] =
  let cache = state.topics.lookup(topic).valueOr:
    return (false, false)
  let views = cache.remote.lookup(connectionId).valueOr:
    return (false, false)
  let view = views.entries.lookup(objectId).valueOr:
    return (false, false)
  return (view.raw.isSome or view.tracked != nil, view.advertised != nil)
