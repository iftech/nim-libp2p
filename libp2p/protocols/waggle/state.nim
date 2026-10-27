# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [], gcsafe.}

import std/tables
import ./[shard, messages]
import ../../peerid

# Ordered tables keep cache touches and eviction constant-time.
type
  RemoteView = ref object
    raw: Opt[seq[byte]]
    tracked: WaggleMetadata
    advertised: WaggleMetadata

  ObjectViews = ref object
    entries: OrderedTable[seq[byte], RemoteView]

  CachedObject = object
    shard: WaggleShard

  TopicState = ref object
    local: OrderedTable[seq[byte], CachedObject]
    remote: Table[uint64, ObjectViews]

  WaggleState* = ref object
    topics: Table[seq[byte], TopicState]
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

proc firstKey[K, V](table: OrderedTable[K, V]): K =
  for key in table.keys:
    return key
  raiseAssert "empty LRU"

proc touch[K, V](table: var OrderedTable[K, V], key: K, value: V) =
  table.del(key)
  table[key] = value

proc lookup[K, V](table: Table[K, V], key: K): Opt[V] =
  table.withValue(key, found):
    return Opt.some(found)
  return Opt.none(V)

proc lookup[K, V](table: OrderedTable[K, V], key: K): Opt[V] =
  if table.hasKey(key):
    return Opt.some(table.getOrDefault(key))
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
    state: WaggleState, topic: TopicState, id: uint64, objectId: seq[byte]
): RemoteView =
  let views = topic.remote.lookup(id).valueOr:
    let created = ObjectViews()
    topic.remote[id] = created
    created
  let remote = views.entries.lookup(objectId).valueOr:
    if views.entries.len >= state.capacity:
      views.entries.del(views.entries.firstKey())
    RemoteView()
  views.entries.touch(objectId, remote)
  return remote

proc local(topic: TopicState, objectId: seq[byte]): Opt[WaggleShard] =
  let entry = topic.local.lookup(objectId).valueOr:
    return Opt.none(WaggleShard)
  topic.local.touch(objectId, entry)
  return Opt.some(entry.shard)

proc store*(
    state: WaggleState, topic: seq[byte], shard: WaggleShard
): Result[bool, string] =
  let cache = ?state.topicState(topic)
  let id = shard.objectId()
  let previous = cache.local.lookup(id)
  var changed = true
  if previous.isSome:
    changed = ?previous.get().shard.metadata().update(shard.metadata().bytes())
  elif cache.local.len >= state.capacity:
    let evicted = cache.local.firstKey()
    cache.local.del(evicted)
  cache.local.touch(id, CachedObject(shard: shard))
  ok(changed)

proc peerBytes(view: RemoteView): Opt[seq[byte]] =
  if view.tracked != nil:
    Opt.some(view.tracked.bytes())
  else:
    view.raw

proc prepare*(
    state: WaggleState,
    topic: seq[byte],
    id: uint64,
    peer: PeerId,
    objectId: seq[byte],
    metadataOnly: bool = false,
): Result[Opt[Transmission], string] =
  let cache = state.topics.lookup(topic).valueOr:
    return ok(Opt.none(Transmission))
  let shard = cache.local(objectId).valueOr:
    return ok(Opt.none(Transmission))
  let view = state.view(cache, id, objectId)
  let action = ?shard.actionFromMetadata(peer, id, view.peerBytes())
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
    state: WaggleState, topic: seq[byte], id: uint64, peer: PeerId, msg: ObjectPieces
): Result[ReceiveAction, string] =
  let cache = ?state.topicState(topic)
  let view = state.view(cache, id, msg.objectId)
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
  let shard = cache.local(msg.objectId).valueOr:
    return ok(ReceiveAction(active: true, emit: true))
  let action = ?shard.actionFromMetadata(peer, id, view.peerBytes())
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

proc removeSubscription*(state: WaggleState, topic: seq[byte], id: uint64) =
  state.topics.withValue(topic, cache):
    cache[].remote.del(id)

proc removeConnection*(state: WaggleState, id: uint64) =
  for topic in state.topics.values:
    topic.remote.del(id)

proc removeTopic*(state: WaggleState, topic: seq[byte]) =
  state.topics.del(topic)

proc peerView*(
    state: WaggleState, topic: seq[byte], id: uint64, objectId: seq[byte]
): tuple[known, advertised: bool] =
  let cache = state.topics.lookup(topic).valueOr:
    return (false, false)
  let views = cache.remote.lookup(id).valueOr:
    return (false, false)
  let view = views.entries.lookup(objectId).valueOr:
    return (false, false)
  return (view.raw.isSome or view.tracked != nil, view.advertised != nil)
