# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

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

  TopicState = ref object
    local: OrderedTable[seq[byte], WaggleShard]
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

proc topicState(state: WaggleState, topic: seq[byte]): Result[TopicState, string] =
  if state.topics.hasKey(topic):
    return ok(state.topics.getOrDefault(topic))
  if state.topics.len >= state.maxTopics:
    return err("Waggle topic state limit reached")
  let value = TopicState()
  state.topics[topic] = value
  ok(value)

proc view(
    state: WaggleState, topic: TopicState, id: uint64, objectId: seq[byte]
): RemoteView =
  var views = topic.remote.getOrDefault(id)
  if views == nil:
    views = ObjectViews()
    topic.remote[id] = views
  result = views.entries.getOrDefault(objectId)
  if result == nil:
    result = RemoteView()
    if views.entries.len >= state.capacity:
      views.entries.del(views.entries.firstKey())
  views.entries.touch(objectId, result)

proc local(topic: TopicState, objectId: seq[byte]): WaggleShard =
  result = topic.local.getOrDefault(objectId)
  if result != nil:
    topic.local.touch(objectId, result)

proc store*(
    state: WaggleState, topic: seq[byte], shard: WaggleShard
): Result[bool, string] =
  let cache = ?state.topicState(topic)
  let id = shard.objectId()
  let previous = cache.local.getOrDefault(id)
  var changed = true
  if previous != nil:
    changed = ?previous.metadata().update(shard.metadata().bytes())
  elif cache.local.len >= state.capacity:
    let evicted = cache.local.firstKey()
    cache.local.del(evicted)
  cache.local.touch(id, shard)
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
  let cache = state.topics.getOrDefault(topic)
  if cache == nil:
    return ok(Opt.none(Transmission))
  let shard = cache.local(objectId)
  if shard == nil:
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
  let shard = cache.local(msg.objectId)
  if shard == nil:
    return ok(ReceiveAction(active: true, emit: true))
  let action = ?shard.actionFromMetadata(peer, id, view.peerBytes())
  var outcome = ReceiveAction(active: true, emit: action.need)
  if action.send.isSome:
    let sending = action.send.get()
    if sending.peerMetadata == nil:
      return err("missing peer metadata for outgoing pieces")
    outcome.reply = Opt.some(
      Transmission(
        view: view,
        tracked: sending.peerMetadata.clone(),
        message: ObjectPieces(
          objectId: msg.objectId,
          pieces: Opt.some(sending.pieces),
          piecesMetadata: Opt.some(shard.metadata().bytes()),
        ),
      )
    )
  ok(outcome)

proc removeSubscription*(state: WaggleState, topic: seq[byte], id: uint64) =
  let cache = state.topics.getOrDefault(topic)
  if cache != nil:
    cache.remote.del(id)

proc removeConnection*(state: WaggleState, id: uint64) =
  for topic in state.topics.values:
    topic.remote.del(id)

proc removeTopic*(state: WaggleState, topic: seq[byte]) =
  state.topics.del(topic)

proc cachedObjects*(state: WaggleState, topic: seq[byte]): int =
  let cache = state.topics.getOrDefault(topic)
  if cache != nil: cache.local.len else: 0

proc trackedObjects*(state: WaggleState, topic: seq[byte], id: uint64): int =
  let cache = state.topics.getOrDefault(topic)
  if cache != nil:
    let views = cache.remote.getOrDefault(id)
    if views != nil:
      return views.entries.len
  0
