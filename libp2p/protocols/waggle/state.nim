# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [], gcsafe.}

import std/tables
import chronos
import ./[shard, messages]
import ../../peerid

# Ordered tables keep cache touches and eviction constant-time.
type
  RemoteView = ref object
    raw: Opt[seq[byte]]
    tracked: WaggleMetadata
    advertised: WaggleMetadata
    expires: Moment

  ObjectViews = ref object
    entries: OrderedTable[seq[byte], RemoteView]

  CachedObject = object
    shard: WaggleShard
    expires: Moment

  TopicState = ref object
    local: OrderedTable[seq[byte], CachedObject]
    remote: Table[uint64, ObjectViews]
    nextExpiry: Moment

  WaggleState* = ref object
    topics: Table[seq[byte], TopicState]
    capacity: int
    maxTopics: int
    lifetime: Duration

  Transmission* = object
    message*: ObjectPieces
    view: RemoteView
    tracked: WaggleMetadata
    advertised: WaggleMetadata

  ReceiveAction* = object
    active*: bool
    emit*: bool
    reply*: Opt[Transmission]

proc new*(T: type WaggleState, capacity, maxTopics: int, lifetime = 5.minutes): T =
  doAssert lifetime > ZeroDuration
  T(capacity: capacity, maxTopics: maxTopics, lifetime: lifetime)

proc expire(topic: TopicState, now: Moment, lifetime: Duration) =
  if now < topic.nextExpiry:
    return
  topic.nextExpiry = now + lifetime
  var expired: seq[seq[byte]]
  for id, entry in topic.local:
    if entry.expires <= now:
      expired.add(id)
    else:
      topic.nextExpiry = min(topic.nextExpiry, entry.expires)
  for id in expired:
    topic.local.del(id)
  for views in topic.remote.values:
    expired.setLen(0)
    for id, view in views.entries:
      if view.expires <= now:
        expired.add(id)
      else:
        topic.nextExpiry = min(topic.nextExpiry, view.expires)
    for id in expired:
      views.entries.del(id)

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

proc topicState(
    state: WaggleState, topic: seq[byte], now: Moment
): Result[TopicState, string] =
  state.topics.withValue(topic, entry):
    let cache = entry[]
    cache.expire(now, state.lifetime)
    return ok(cache)
  if state.topics.len >= state.maxTopics:
    return err("Waggle topic state limit reached")
  let value = TopicState(nextExpiry: now + state.lifetime)
  state.topics[topic] = value
  ok(value)

proc view(
    state: WaggleState, topic: TopicState, id: uint64, objectId: seq[byte], now: Moment
): RemoteView =
  let views = topic.remote.lookup(id).valueOr:
    let created = ObjectViews()
    topic.remote[id] = created
    created
  let remote = views.entries.lookup(objectId).valueOr:
    if views.entries.len >= state.capacity:
      views.entries.del(views.entries.firstKey())
    RemoteView(expires: now + state.lifetime)
  views.entries.touch(objectId, remote)
  return remote

proc local(topic: TopicState, objectId: seq[byte]): Opt[WaggleShard] =
  let entry = topic.local.lookup(objectId).valueOr:
    return Opt.none(WaggleShard)
  topic.local.touch(objectId, entry)
  return Opt.some(entry.shard)

proc store*(
    state: WaggleState, topic: seq[byte], shard: WaggleShard, now = Moment.now()
): Result[bool, string] =
  let cache = ?state.topicState(topic, now)
  let id = shard.objectId()
  let previous = cache.local.lookup(id)
  var changed = true
  if previous.isSome:
    changed = ?previous.get().shard.metadata().update(shard.metadata().bytes())
  elif cache.local.len >= state.capacity:
    let evicted = cache.local.firstKey()
    cache.local.del(evicted)
  cache.local.touch(id, CachedObject(shard: shard, expires: now + state.lifetime))
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
    now = Moment.now(),
): Result[Opt[Transmission], string] =
  let cache = state.topics.lookup(topic).valueOr:
    return ok(Opt.none(Transmission))
  cache.expire(now, state.lifetime)
  let shard = cache.local(objectId).valueOr:
    return ok(Opt.none(Transmission))
  let view = state.view(cache, id, objectId, now)
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
    state: WaggleState,
    topic: seq[byte],
    id: uint64,
    peer: PeerId,
    msg: ObjectPieces,
    now = Moment.now(),
): Result[ReceiveAction, string] =
  let cache = ?state.topicState(topic, now)
  let view = state.view(cache, id, msg.objectId, now)
  view.expires = now + state.lifetime
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

proc removeObject*(state: WaggleState, topic, objectId: seq[byte]): bool =
  ## Forget the cached snapshot and all peer views for this object.
  let cache = state.topics.lookup(topic).valueOr:
    return false
  var removed = cache.local.hasKey(objectId)
  cache.local.del(objectId)
  for views in cache.remote.values:
    removed = views.entries.hasKey(objectId) or removed
    views.entries.del(objectId)
  return removed

proc hasLocal*(
    state: WaggleState, topic, objectId: seq[byte], now = Moment.now()
): bool =
  let cache = state.topics.lookup(topic).valueOr:
    return false
  cache.expire(now, state.lifetime)
  return cache.local.hasKey(objectId)

proc peerView*(
    state: WaggleState,
    topic: seq[byte],
    id: uint64,
    objectId: seq[byte],
    now = Moment.now(),
): tuple[known, advertised: bool] =
  let cache = state.topics.lookup(topic).valueOr:
    return (false, false)
  cache.expire(now, state.lifetime)
  let views = cache.remote.lookup(id).valueOr:
    return (false, false)
  let view = views.entries.lookup(objectId).valueOr:
    return (false, false)
  return (view.raw.isSome or view.tracked != nil, view.advertised != nil)

proc cachedObjects*(state: WaggleState, topic: seq[byte]): int =
  let cache = state.topics.lookup(topic).valueOr:
    return 0
  return cache.local.len

proc trackedObjects*(state: WaggleState, topic: seq[byte], id: uint64): int =
  let cache = state.topics.lookup(topic).valueOr:
    return 0
  let views = cache.remote.lookup(id).valueOr:
    return 0
  return views.entries.len
