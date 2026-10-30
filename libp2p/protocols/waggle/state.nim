# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [], gcsafe.}

import std/tables
import chronos
import ./[shard, messages]
import ../../peerid

const DefaultObjectLifetime* = 5.minutes

type
  RemoteView = ref object
    lastUsed: uint64
    raw: Opt[seq[byte]]
    tracked: WaggleMetadata
    advertised: WaggleMetadata
    expires: Moment

  ObjectViews = ref object
    entries: Table[seq[byte], RemoteView]

  CachedObject = object
    lastUsed: uint64
    shard: WaggleShard
    expires: Moment

  TopicState = ref object
    local: Table[seq[byte], CachedObject]
    remote: Table[uint64, ObjectViews]
    nextExpiry: Moment

  WaggleState* = ref object
    topics: Table[seq[byte], TopicState]
    clock: uint64
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

proc new*(
    T: type WaggleState, capacity, maxTopics: int, lifetime = DefaultObjectLifetime
): T =
  doAssert lifetime > ZeroDuration
  T(capacity: capacity, maxTopics: maxTopics, lifetime: lifetime)

proc expire(topic: TopicState, now: Moment, lifetime: Duration) =
  if now < topic.nextExpiry:
    return
  topic.nextExpiry = now + lifetime
  var expired: seq[seq[byte]]
  for objectId, entry in topic.local:
    if entry.expires <= now:
      expired.add(objectId)
    else:
      topic.nextExpiry = min(topic.nextExpiry, entry.expires)
  for objectId in expired:
    topic.local.del(objectId)
  for views in topic.remote.values:
    expired.setLen(0)
    for objectId, view in views.entries:
      if view.expires <= now:
        expired.add(objectId)
      else:
        topic.nextExpiry = min(topic.nextExpiry, view.expires)
    for objectId in expired:
      views.entries.del(objectId)

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
    state: WaggleState,
    topic: TopicState,
    connectionId: uint64,
    objectId: seq[byte],
    now: Moment,
): RemoteView =
  let views = topic.remote.lookup(connectionId).valueOr:
    let created = ObjectViews()
    topic.remote[connectionId] = created
    created
  let remote = views.entries.lookup(objectId).valueOr:
    if views.entries.len >= state.capacity:
      views.entries.del(views.entries.oldestKey())
    RemoteView(expires: now + state.lifetime)
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
    state: WaggleState, topic: seq[byte], shard: WaggleShard, now = Moment.now()
): Result[bool, string] =
  let cache = ?state.topicState(topic, now)
  let objectId = shard.objectId()
  let previous = cache.local.lookup(objectId)
  var changed = true
  if previous.isSome:
    changed = ?previous.get().shard.metadata().update(shard.metadata().bytes())
  elif cache.local.len >= state.capacity:
    let evicted = cache.local.oldestKey()
    cache.local.del(evicted)
  state.touch(
    cache.local, objectId, CachedObject(shard: shard, expires: now + state.lifetime)
  )
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
    now = Moment.now(),
): Result[Opt[Transmission], string] =
  let cache = state.topics.lookup(topic).valueOr:
    return ok(Opt.none(Transmission))
  cache.expire(now, state.lifetime)
  let shard = state.local(cache, objectId).valueOr:
    return ok(Opt.none(Transmission))
  let view = state.view(cache, connectionId, objectId, now)
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
    now = Moment.now(),
): Result[ReceiveAction, string] =
  let cache = ?state.topicState(topic, now)
  let view = state.view(cache, connectionId, msg.objectId, now)
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
    connectionId: uint64,
    objectId: seq[byte],
    now = Moment.now(),
): tuple[known, advertised: bool] =
  let cache = state.topics.lookup(topic).valueOr:
    return (false, false)
  cache.expire(now, state.lifetime)
  let views = cache.remote.lookup(connectionId).valueOr:
    return (false, false)
  let view = views.entries.lookup(objectId).valueOr:
    return (false, false)
  return (view.raw.isSome or view.tracked != nil, view.advertised != nil)

proc cachedObjects*(state: WaggleState, topic: seq[byte], now = Moment.now()): int =
  let cache = state.topics.lookup(topic).valueOr:
    return 0
  cache.expire(now, state.lifetime)
  return cache.local.len

proc trackedObjects*(
    state: WaggleState, topic: seq[byte], connectionId: uint64, now = Moment.now()
): int =
  let cache = state.topics.lookup(topic).valueOr:
    return 0
  cache.expire(now, state.lifetime)
  let views = cache.remote.lookup(connectionId).valueOr:
    return 0
  return views.entries.len
