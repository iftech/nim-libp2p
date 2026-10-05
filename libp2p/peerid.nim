# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implementes API for libp2p peer.

{.push raises: [].}

{.used.}

import
  std/[hashes, strutils],
  stew/base58,
  results,
  chronicles,
  nimcrypto/utils,
  utils/[opt, shortlog, collections],
  protobuf_serialization,
  ./crypto/crypto,
  ./multicodec,
  ./multibase,
  ./multihash,
  ./vbuffer,
  ./protobuf/minprotobuf
import ./cid

export results, opt, shortlog, collections

const maxInlineKeyLength* = 42

const
  ShortPeerIdPrefixLength = 6
  ShortPeerIdSuffixLength = 6

type PeerId* = object
  data*: seq[byte]

func `$`*(pid: PeerId): string =
  ## Return base58 encoded ``pid`` representation.
  # This unusual call syntax is used to avoid a strange Nim compilation error
  base58.encode(Base58, pid.data)

func shortLog*(pid: PeerId): string =
  ## Returns compact string representation of ``pid``.
  let spid = $pid
  if spid.len <= ShortPeerIdPrefixLength + 3 + ShortPeerIdSuffixLength:
    return spid

  return
    spid[0 ..< ShortPeerIdPrefixLength] & # prefix
    "..." & # omitted
    spid[spid.len - ShortPeerIdSuffixLength .. spid.high] # suffix

chronicles.formatIt(PeerId):
  shortLog(it)

chronicles.formatIt(Opt[PeerId]):
  shortLog(it)

func toBytes*(pid: PeerId, data: var openArray[byte]): int =
  ## Store PeerId ``pid`` to array of bytes ``data``.
  ##
  ## Returns number of bytes needed to store ``pid``.
  let n = len(pid.data)
  if len(data) >= n and n > 0:
    copyMem(addr data[0], addr pid.data[0], n)
  n

template getBytes*(pid: PeerId): seq[byte] =
  ## Return PeerId ``pid`` as array of bytes.
  pid.data

func hex*(pid: PeerId): string =
  ## Returns hexadecimal string representation of ``pid``.
  toHex(pid.data)

template len*(pid: PeerId): int =
  ## Returns length of ``pid`` binary representation.
  len(pid.data)

func cmp*(a, b: PeerId): int =
  ## Compares two peer ids ``a`` and ``b``.
  ## Returns:
  ##
  ## | 0 iff a == b
  ## | < 0 iff a < b
  ## | > 0 iff a > b
  var i = 0
  var m = min(len(a.data), len(b.data))
  while i < m:
    let diff = ord(a.data[i]) - ord(b.data[i])
    if diff != 0:
      return diff
    inc(i)
  len(a.data) - len(b.data)

template `<=`*(a, b: PeerId): bool =
  (cmp(a, b) <= 0)

template `<`*(a, b: PeerId): bool =
  (cmp(a, b) < 0)

template `>=`*(a, b: PeerId): bool =
  (cmp(a, b) >= 0)

template `>`*(a, b: PeerId): bool =
  (cmp(a, b) > 0)

template `==`*(a, b: PeerId): bool =
  (cmp(a, b) == 0)

template hash*(pid: PeerId): Hash =
  hash(pid.data)

func validate*(pid: PeerId): bool =
  ## Validate check if ``pid`` is empty or not.
  len(pid.data) > 0 and MultiHash.validate(pid.data)

func hasPublicKey*(pid: PeerId): bool =
  ## Returns ``true`` if ``pid`` is small enough to hold public key inside.
  if len(pid.data) > 0:
    var mh: MultiHash
    if MultiHash.decode(pid.data, mh).isOk:
      if mh.mcodec == multiCodec("identity"):
        return true
  false

func extractPublicKey*(pid: PeerId, pubkey: var PublicKey): bool =
  ## Returns ``true`` if public key was successfully decoded from PeerId
  ## ``pid``and stored to ``pubkey``.
  ##
  ## Returns ``false`` otherwise.
  if len(pid.data) > 0:
    var mh: MultiHash
    if MultiHash.decode(pid.data, mh).isOk:
      if mh.mcodec == multiCodec("identity"):
        let length = len(mh.data.buffer)
        return pubkey.init(mh.data.buffer.toOpenArray(mh.dpos, length - 1))
  false

func getPubKey*(pid: PeerId): Opt[PublicKey] =
  ## Extract the public key embedded in `pid`, or `none` if not present.
  var pubkey: PublicKey
  if pid.extractPublicKey(pubkey):
    Opt.some(pubkey)
  else:
    Opt.none(PublicKey)

func init*(pid: var PeerId, data: openArray[byte]): bool =
  ## Initialize peer id from raw binary representation ``data``.
  ##
  ## Returns ``true`` if peer was successfully initialiazed.
  var p = PeerId(data: @data)
  if p.validate():
    pid = p
    return true
  false

func initLegacy(pid: var PeerId, data: string): bool =
  ## Initialize peer id from legacy raw base58btc multihash text.
  ##
  ## Returns ``true`` if peer was successfully initialiazed.
  var p = newSeqUninit[byte](len(data) + 4)
  var length = 0
  if Base58.decode(data, p, length) == Base58Status.Success:
    p.setLen(length)
    var opid: PeerId
    opid.data = p
    if opid.validate():
      pid = opid
      return true
  false

proc initCidV1(pid: var PeerId, data: string): bool =
  ## Initialize peer id from CIDv1 libp2p-key multibase text.
  let cid = Cid.init(data).valueOr:
    return false
  if cid.version() != CIDv1:
    return false
  let content = cid.contentType().valueOr:
    return false
  if content != multiCodec("libp2p-key"):
    return false
  let mh = cid.mhash().valueOr:
    return false
  init(pid, mh.data.buffer)

proc init*(pid: var PeerId, data: string): bool =
  ## Initialize peer id from legacy raw base58btc multihash text or CIDv1
  ## ``libp2p-key`` multibase text.
  ##
  ## Returns ``true`` if peer was successfully initialiazed.
  if len(data) == 0:
    return false
  if data.startsWith("1") or data.startsWith("Qm"):
    initLegacy(pid, data)
  else:
    initCidV1(pid, data)

func init*(t: typedesc[PeerId], data: openArray[byte]): Result[PeerId, cstring] =
  ## Create new peer id from raw binary representation ``data``.
  var res: PeerId
  if not init(res, data):
    err("peerid: incorrect PeerId binary form")
  else:
    ok(res)

proc init*(t: typedesc[PeerId], data: string): Result[PeerId, cstring] =
  ## Create new peer id from legacy raw base58btc multihash text or CIDv1
  ## ``libp2p-key`` multibase text.
  var res: PeerId
  if not init(res, data):
    err("peerid: incorrect PeerId string")
  else:
    ok(res)

proc toCid*(pid: PeerId): Result[Cid, cstring] =
  ## Return ``pid`` as a CIDv1 ``libp2p-key`` content identifier.
  let mh = ?MultiHash.init(pid.data)
  let cid = Cid.init(CIDv1, multiCodec("libp2p-key"), mh).valueOr:
    return err("peerid: could not create CID")
  ok(cid)

proc toCidString*(pid: PeerId, encoding = "base32"): Result[string, cstring] =
  ## Return ``pid`` as CIDv1 ``libp2p-key`` text using multibase ``encoding``.
  let cid = ?pid.toCid()
  let encoded = MultiBase.encode(encoding, cid.data.buffer).valueOr:
    return err("peerid: could not encode CID")
  ok(encoded)

func init*(t: typedesc[PeerId], pubkey: PublicKey): Result[PeerId, cstring] =
  ## Create new peer id from public key ``pubkey``.
  let pubraw = pubkey.getBytes().valueOr:
    return err("peerid: failed to get bytes from given key")
  var mh: MultiHash
  if len(pubraw) <= maxInlineKeyLength:
    mh = ?MultiHash.digest("identity", pubraw)
  else:
    mh = ?MultiHash.digest("sha2-256", pubraw)
  ok(PeerId(data: mh.data.buffer))

func init*(t: typedesc[PeerId], seckey: PrivateKey): Result[PeerId, cstring] =
  ## Create new peer id from private key ``seckey``.
  let pubkey = seckey.getPublicKey().valueOr:
    return err("invalid private key")
  PeerId.init(pubkey)

proc random*(t: typedesc[PeerId], rng: Rng): Result[PeerId, cstring] =
  ## Create new peer id with random public key.
  let randomKey = PrivateKey.random(Secp256k1, rng)[]
  let peerId = PeerId.init(randomKey).valueOr:
    return err("failed to generate random key")
  ok(peerId)

proc random*(t: typedesc[PeerId], count: uint, rng: Rng): Result[seq[PeerId], cstring] =
  ## Create `count` peer ids with random public keys.
  var peers = newSeqOfCap[PeerId](count)
  for _ in 0 ..< count:
    peers.add(?PeerId.random(rng))
  ok(peers)

func match*(pid: PeerId, pubkey: PublicKey): bool =
  ## Returns ``true`` if ``pid`` matches public key ``pubkey``.
  PeerId.init(pubkey) == Result[PeerId, cstring].ok(pid)

func match*(pid: PeerId, seckey: PrivateKey): bool =
  ## Returns ``true`` if ``pid`` matches private key ``seckey``.
  PeerId.init(seckey) == Result[PeerId, cstring].ok(pid)

## Serialization/Deserialization helpers

func write*(vb: var VBuffer, pid: PeerId) =
  ## Write PeerId value ``peerid`` to buffer ``vb``.
  vb.writeSeq(pid.data)

func write*(pb: var ProtoBuffer, field: int, pid: PeerId) =
  ## Write PeerId value ``peerid`` to object ``pb`` using ProtoBuf's encoding.
  write(pb, field, pid.data)

func getField*(pb: ProtoBuffer, field: int, pid: var PeerId): ProtoResult[bool] =
  ## Read ``PeerId`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ?pb.getField(field, buffer)
  if not (res):
    ok(false)
  else:
    var peerId: PeerId
    if peerId.init(buffer):
      pid = peerId
      ok(true)
    else:
      err(ProtoError.IncorrectBlob)

## protobuf_serialization extension

Protobuf.extensionDefaults(PeerId, pbytes, defaultSeq = true)

func computeFieldSize*(
    field: int, value: PeerId, ProtoType: type ProtobufExt, skipDefault: static bool
): int =
  computeFieldSize(field, value.data, pbytes, skipDefault)

proc writeField*(
    stream: OutputStream,
    field: int,
    value: PeerId,
    ProtoType: type ProtobufExt,
    skipDefault: static bool = false,
) {.raises: [IOError].} =
  writeField(stream, field, value.data, pbytes, skipDefault)

proc readFieldInto*(
    stream: InputStream,
    value: var PeerId,
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  var data = default(seq[byte])
  if readFieldInto(stream, data, header, pbytes):
    if data.len == 0:
      return false

    if value.init(data):
      true
    else:
      raise (ref ProtobufValueError)(msg: "Invalid PeerId")
  else:
    false
