# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Kademlia's typed byte domains, kept separate from the protobuf message
## definitions so both ``types`` and ``protobuf`` can depend on them.

import std/[hashes, strformat]
import chronicles, stew/arrayOps
import ../../results
import ../../utils/shortlog

const
  IdLength* = 32 # 256-bit IDs
  MaxRecordKeyLen* = 256 ## Upper bound (bytes) on a PUT_VALUE/GET_VALUE key

## Every lookup routes by XOR distance between a ``Key`` and the peer IDs of
## the routing table. ``Key`` is that lookup target: a peer ID for FIND_NODE,
## a CID for ADD_PROVIDER/GET_PROVIDERS, a record key for PUT_VALUE/GET_VALUE.
## ``RecordKey`` is the subset of keys that may name a stored value record.
## Only its constructor admits a key, so the record store, the validators and
## the selectors never see a key that ``handlePutValue`` would reject.

type
  Key* = distinct seq[byte]
    ## A Kademlia lookup target. Construct with ``Key.init`` or ``Key.fromBytes``.
  RecordKey* {.requiresInit.} = object
    ## The key of a PUT_VALUE/GET_VALUE record, 1..``MaxRecordKeyLen`` bytes.
    ## Construct with ``RecordKey.init`` or ``RecordKey.fromBytes``.
    key: Key

  Value* = distinct seq[byte]
    ## A Kademlia record value. Construct with ``Value.init`` or ``Value.fromBytes``.

func init*(T: typedesc[Key], bytes: openArray[byte]): Key =
  ## Key of `IdLength` bytes holding `bytes`, zero-padded.
  var buf: array[IdLength, byte]
  discard buf.copyFrom(bytes)
  Key(@buf)

template fromBytes*(T: typedesc[Key], bytes: sink seq[byte]): Key =
  ## Preserves raw Kademlia key bytes received from a wire message.
  Key(bytes)

template toBytes*(key: Key): seq[byte] =
  ## Returns the raw bytes used by Kademlia and its wire protocol.
  seq[byte](key)

proc len*(key: Key): int {.inline.} =
  seq[byte](key).len

proc `[]`*(key: Key, index: int): byte {.inline.} =
  seq[byte](key)[index]

proc `[]=`*(key: var Key, index: int, value: byte) {.inline.} =
  seq[byte](key)[index] = value

proc `==`*(a, b: Key): bool {.borrow.}
proc hash*(key: Key): Hash {.borrow.}

proc `$`*(key: Key): string =
  $seq[byte](key)

func default*(
  T: typedesc[RecordKey]
): RecordKey {.error: "Use RecordKey.init or RecordKey.fromBytes".}

func init*(T: typedesc[RecordKey], key: Key): LPResult[RecordKey] =
  ## The one place that admits a ``Key`` as a record key.
  if key.len == 0 or key.len > MaxRecordKeyLen:
    return err(fmt"{key.len} not in 1..{MaxRecordKeyLen}", "invalid record key length")
  ok(RecordKey(key: key))

func fromBytes*(T: typedesc[RecordKey], bytes: sink seq[byte]): LPResult[RecordKey] =
  RecordKey.init(Key.fromBytes(bytes))

func toKey*(key: RecordKey): Key =
  ## The lookup target that routes to the nodes which store the record.
  key.key

template toBytes*(key: RecordKey): seq[byte] =
  key.toKey().toBytes()

func len*(key: RecordKey): int =
  key.toKey().len

func `==`*(a, b: RecordKey): bool =
  a.toKey() == b.toKey()

func hash*(key: RecordKey): Hash =
  key.toKey().hash()

func `$`*(key: RecordKey): string =
  $key.toKey()

template init*(T: typedesc[Value], bytes: openArray[byte]): Value =
  Value(@bytes)

template fromBytes*(T: typedesc[Value], bytes: sink seq[byte]): Value =
  ## Preserves raw Kademlia value bytes received from a wire message.
  Value(bytes)

template toBytes*(value: Value): seq[byte] =
  ## Returns the raw bytes used by Kademlia and its wire protocol.
  seq[byte](value)

proc len*(value: Value): int {.inline.} =
  seq[byte](value).len

proc `[]`*(value: Value, index: int): byte {.inline.} =
  seq[byte](value)[index]

proc `[]=`*(value: var Value, index: int, byte: byte) {.inline.} =
  seq[byte](value)[index] = byte

proc `==`*(a, b: Value): bool {.borrow.}
proc hash*(value: Value): Hash {.borrow.}

proc `$`*(value: Value): string =
  $seq[byte](value)

func shortLog*(v: Value): string =
  v.toBytes().shortLog

func shortLog*(k: Key): string =
  k.toBytes().shortLog

func shortLog*(k: RecordKey): string =
  k.toBytes().shortLog

chronicles.formatIt(Value):
  it.shortLog

chronicles.formatIt(Key):
  it.shortLog

chronicles.formatIt(RecordKey):
  it.shortLog
