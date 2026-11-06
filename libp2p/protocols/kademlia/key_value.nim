# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Kademlia's typed byte domains, kept separate from the protobuf message
## definitions so both ``types`` and ``protobuf`` can depend on them.

import std/[hashes, strformat]
import chronicles, stew/arrayOps
import ../../[cid, multihash, results]
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
    data: seq[byte]

  ProvidedKey* {.requiresInit.} = object
    ## The multihash bytes of a CID that this node provides.
    data: seq[byte]

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

proc `[]`*(key: Key, index: int): byte {.inline.} =
  seq[byte](key)[index]

proc `[]=`*(key: var Key, index: int, value: byte) {.inline.} =
  seq[byte](key)[index] = value

template toKey*(mh: MultiHash): Key =
  Key.fromBytes(mh.data.buffer)

proc toKey*(c: Cid): Key =
  c.mhash().get().toKey()

template raw(key: Key): seq[byte] =
  seq[byte](key)

template raw(key: RecordKey | ProvidedKey): seq[byte] =
  key.data

func lessBytes(a, b: openArray[byte]): bool =
  ## Byte order. A key sorts before its extension.
  for i in 0 ..< min(a.len, b.len):
    if a[i] != b[i]:
      return a[i] < b[i]
  a.len < b.len

template keyOps(T: typedesc) =
  func len*(key: T): int =
    key.raw.len

  func `==`*(a, b: T): bool =
    a.raw == b.raw

  func `<`*(a, b: T): bool =
    lessBytes(a.raw, b.raw)

  func hash*(key: T): Hash =
    key.raw.hash()

  func `$`*(key: T): string =
    $key.raw

  func shortLog*(key: T): string =
    key.raw.shortLog

  chronicles.formatIt(T):
    it.shortLog

keyOps(Key)

func default*(
  T: typedesc[RecordKey]
): RecordKey {.error: "Use RecordKey.init or RecordKey.fromBytes".}

func init*(T: typedesc[RecordKey], key: Key): LPResult[RecordKey] =
  ## The one place that admits a ``Key`` as a record key.
  if key.len == 0 or key.len > MaxRecordKeyLen:
    return err(fmt"{key.len} not in 1..{MaxRecordKeyLen}", "invalid record key length")
  ok(RecordKey(data: key.toBytes()))

func fromBytes*(T: typedesc[RecordKey], bytes: sink seq[byte]): LPResult[RecordKey] =
  RecordKey.init(Key.fromBytes(bytes))

func toBytes*(key: RecordKey): seq[byte] =
  key.data

func toKey*(key: RecordKey): Key =
  ## The lookup target that routes to the nodes which store the record.
  Key.fromBytes(key.data)

keyOps(RecordKey)

func default*(
  T: typedesc[ProvidedKey]
): ProvidedKey {.error: "Use ProvidedKey.init or ProvidedKey.fromBytes".}

proc init*(T: typedesc[ProvidedKey], cid: Cid): ProvidedKey =
  ## ``mhash`` fails only on a ``Cid`` that no ``Cid.init`` made, such as ``default(Cid)``.
  ProvidedKey(data: cid.mhash().get().data.buffer)

func fromBytes*(
    T: typedesc[ProvidedKey], bytes: sink seq[byte]
): LPResult[ProvidedKey] =
  ## Reads back the bytes of ``toBytes``, for a backend that persists provided keys.
  if not MultiHash.validate(bytes):
    return
      err(fmt"{bytes.len} bytes: {bytes.shortLog}", "provided key is not a multihash")
  ok(ProvidedKey(data: bytes))

func toBytes*(key: ProvidedKey): seq[byte] =
  key.data

func toKey*(key: ProvidedKey): Key =
  Key.fromBytes(key.data)

keyOps(ProvidedKey)

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

chronicles.formatIt(Value):
  it.shortLog
