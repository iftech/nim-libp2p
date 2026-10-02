# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[hashes, sets]
import chronos/timer, results

export results

const Timeout* = 10.seconds # default timeout in ms

type
  TimedEntry*[K] = ref object of RootObj
    key: K
    addedAt: Moment
    expiresAt: Moment
    next, prev: TimedEntry[K]

  TimedCache*[K] = object of RootObj
    head, tail: TimedEntry[K] # nim linked list doesn't allow inserting at pos
    entries: HashSet[TimedEntry[K]]
    timeout: Duration
    maxSize: int # Optional max size of the cache, 0 means unlimited
    refreshOnPut: bool # If true (default), re-adding a key refreshes its expiry

func `==`*[E](a, b: TimedEntry[E]): bool =
  if isNil(a) == isNil(b):
    isNil(a) or a.key == b.key
  else:
    false

func hash*(a: TimedEntry): Hash =
  if isNil(a):
    default(Hash)
  else:
    hash(a[].key)

func expire*(t: var TimedCache, now: Moment = Moment.now()) =
  while t.head != nil and t.head.expiresAt < now:
    let removed = t.head
    t.entries.excl(removed)
    t.head = removed.next
    removed.next = nil
    removed.prev = nil
    if t.head != nil:
      t.head.prev = nil
    else:
      t.tail = nil

func del*[K](t: var TimedCache[K], key: K): Opt[TimedEntry[K]] =
  # Removes existing key from cache, returning the previous value if present
  let tmp = TimedEntry[K](key: key)
  if tmp in t.entries:
    let item =
      try:
        t.entries[tmp] # use the shared instance in the set
      except KeyError:
        raiseAssert "just checked"
    t.entries.excl(item)

    if t.head == item:
      t.head = item.next
    if t.tail == item:
      t.tail = item.prev

    if item.next != nil:
      item.next.prev = item.prev
    if item.prev != nil:
      item.prev.next = item.next
    item.next = nil
    item.prev = nil
    Opt.some(item)
  else:
    Opt.none(TimedEntry[K])

func put*[K](cache: var TimedCache[K], key: K, now = Moment.now()): bool =
  # Puts key in cache, returning true if the item was already present and false
  # otherwise. If refreshOnPut is true (default), re-adding refreshes the expiry.
  # If refreshOnPut is false, re-adding is a no-op (useful when first-seen time matters).
  func ensureSizeBound(cache: var TimedCache[K]) =
    if cache.maxSize > 0 and cache.entries.len() >= cache.maxSize and key notin cache:
      if cache.head != nil:
        let removed = cache.head
        cache.entries.excl(removed)
        cache.head = removed.next
        removed.next = nil
        removed.prev = nil
        if cache.head != nil:
          cache.head.prev = nil
        else:
          cache.tail = nil

  cache.expire(now)
  cache.ensureSizeBound()

  # If not refreshing and already present, return early
  if not cache.refreshOnPut and key in cache:
    return true

  let
    previous = cache.del(key) # Refresh existing item
    addedAt = if previous.isSome(): previous[].addedAt else: now

  let node = TimedEntry[K](key: key, addedAt: addedAt, expiresAt: now + cache.timeout)
  if cache.head == nil:
    cache.tail = node
    cache.head = cache.tail
  else:
    # search from tail because typically that's where we add when now grows
    var cur = cache.tail
    while cur != nil and node.expiresAt < cur.expiresAt:
      cur = cur.prev

    if cur == nil:
      node.next = cache.head
      cache.head.prev = node
      cache.head = node
    else:
      node.prev = cur
      node.next = cur.next
      cur.next = node
      if node.next != nil:
        node.next.prev = node
      if cur == cache.tail:
        cache.tail = node

  cache.entries.incl(node)

  previous.isSome()

func contains*[K](t: TimedCache[K], k: K): bool =
  let tmp = TimedEntry[K](key: k)
  tmp in t.entries

func len*[K](t: TimedCache[K]): int =
  ## Returns the number of entries in the cache.
  t.entries.len

func maxSize*[K](t: TimedCache[K]): int =
  ## Returns the entry limit of the cache, 0 meaning unlimited.
  t.maxSize

func addedAt*[K](t: var TimedCache[K], k: K): Moment =
  let tmp = TimedEntry[K](key: k)
  try:
    if tmp in t.entries: # raising is slow
      # Use shared instance from entries
      return t.entries[tmp][].addedAt
  except KeyError:
    raiseAssert "just checked"

  default(Moment)

func init*[K](
    T: type TimedCache[K],
    timeout: Duration = Timeout,
    maxSize: int = 0,
    refreshOnPut: bool = true,
): T =
  T(timeout: timeout, maxSize: maxSize, refreshOnPut: refreshOnPut)
