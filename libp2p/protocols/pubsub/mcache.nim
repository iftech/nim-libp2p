# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, tables]
import rpc/[messages]
import results

export sets, tables, messages, results

type
  CacheEntry* = object
    msgId*: MessageId
    topic*: string

  MCache* = object of RootObj
    msgs*: Table[MessageId, Message]
    history: seq[seq[CacheEntry]]
    pos*: int
    windowSize*: int

func get*(c: MCache, msgId: MessageId): Opt[Message] =
  if msgId in c.msgs:
    try:
      Opt.some(c.msgs[msgId])
    except KeyError:
      raiseAssert "checked"
  else:
    Opt.none(Message)

func contains*(c: MCache, msgId: MessageId): bool =
  msgId in c.msgs

func put*(c: var MCache, msgId: MessageId, msg: Message) =
  if not c.msgs.hasKeyOrPut(msgId, msg):
    # Only add cache entry if the message was not already in the cache
    c.history[c.pos].add(CacheEntry(msgId: msgId, topic: msg.topic))

func window*(c: MCache, topic: string): HashSet[MessageId] =
  let len = min(c.windowSize, c.history.len)

  var msgIds: HashSet[MessageId]
  for i in 0 ..< len:
    # Work backwards from `pos` in the circular buffer
    for entry in c.history[(c.pos + c.history.len - i) mod c.history.len]:
      if entry.topic == topic:
        msgIds.incl(entry.msgId)
  msgIds

func shift*(c: var MCache) =
  # Shift circular buffer to write to a new position, clearing it from past
  # iterations
  c.pos = (c.pos + 1) mod c.history.len

  for entry in c.history[c.pos]:
    c.msgs.del(entry.msgId)

  reset(c.history[c.pos])

func init*(T: type MCache, window, history: int): T =
  doAssert history > 0, "history must be > 0"
  doAssert window >= 0, "window must be >= 0"

  T(history: newSeq[seq[CacheEntry]](history), windowSize: window)
