# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implementes CID (Content IDentifier).

{.push raises: [].}
{.used.}

import tables, hashes
import multibase, multicodec, multihash, vbuffer, varint, results
import stew/base58

export results

type
  CidError* {.pure.} = enum
    Error
    Incorrect
    Unsupported
    Overrun

  CidVersion* = enum
    CIDvIncorrect
    CIDv0
    CIDv1
    CIDvReserved

  Cid* = object
    cidver*: CidVersion
    mcodec*: MultiCodec
    hpos*: int
    data*: VBuffer

const libp2p_contentids_exts* {.strdefine.} = ""

const ContentIdsList = [
  multiCodec("raw"),
  multiCodec("dag-pb"),
  multiCodec("dag-cbor"),
  multiCodec("dag-json"),
  multiCodec("libp2p-key"),
  multiCodec("git-raw"),
  multiCodec("eth-block"),
  multiCodec("eth-block-list"),
  multiCodec("eth-tx-trie"),
  multiCodec("eth-tx"),
  multiCodec("eth-tx-receipt-trie"),
  multiCodec("eth-tx-receipt"),
  multiCodec("eth-state-trie"),
  multiCodec("eth-account-snapshot"),
  multiCodec("eth-storage-trie"),
  multiCodec("bitcoin-block"),
  multiCodec("bitcoin-tx"),
  multiCodec("zcash-block"),
  multiCodec("zcash-tx"),
  multiCodec("stellar-block"),
  multiCodec("stellar-tx"),
  multiCodec("decred-block"),
  multiCodec("decred-tx"),
  multiCodec("dash-block"),
  multiCodec("dash-tx"),
  multiCodec("torrent-info"),
  multiCodec("torrent-file"),
  multiCodec("ed25519-pub"),
]

proc initCidCodeTable(
    codecs: openArray[MultiCodec]
): Table[int, MultiCodec] {.compileTime.} =
  var res: Table[int, MultiCodec]

  for codec in codecs:
    res[codec.int] = codec

  return res

when libp2p_contentids_exts != "":
  import utils/macroutils
  includeFile(libp2p_contentids_exts)
  const CodeContentIds = initCidCodeTable(@ContentIdsList & @ContentIdsExts)
else:
  const CodeContentIds = initCidCodeTable(@ContentIdsList)

proc decode(data: openArray[byte]): Result[Cid, CidError] =
  if len(data) == 34 and data[0] == 0x12'u8 and data[1] == 0x20'u8:
    ok(
      Cid(cidver: CIDv0, mcodec: multiCodec("dag-pb"), hpos: 0, data: initVBuffer(data))
    )
  else:
    var version, codec: uint64
    var res, offset: int
    var vb = initVBuffer(data)
    if vb.isEmpty():
      err(CidError.Incorrect)
    else:
      res = vb.readVarint(version)
      if res == -1:
        err(CidError.Incorrect)
      else:
        offset += res
        if version != 1'u64:
          err(CidError.Incorrect)
        else:
          res = vb.readVarint(codec)
          if res == -1:
            err(CidError.Incorrect)
          else:
            offset += res
            var mcodec =
              CodeContentIds.getOrDefault(cast[int](codec), InvalidMultiCodec)
            if mcodec == InvalidMultiCodec:
              err(CidError.Incorrect)
            else:
              if not MultiHash.validate(
                vb.buffer.toOpenArray(vb.offset, vb.buffer.high)
              ):
                err(CidError.Incorrect)
              else:
                vb.finish()
                ok(Cid(cidver: CIDv1, mcodec: mcodec, hpos: offset, data: vb))

proc decode(data: openArray[char]): Result[Cid, CidError] =
  var buffer: seq[byte]
  var plen = 0
  if len(data) < 2:
    return err(CidError.Incorrect)
  if len(data) == 46:
    if data[0] == 'Q' and data[1] == 'm':
      buffer = newSeqUninit[byte](BTCBase58.decodedLength(len(data)))
      if BTCBase58.decode(data, buffer, plen) != Base58Status.Success:
        return err(CidError.Incorrect)
      buffer.setLen(plen)
  if len(buffer) == 0:
    let length = MultiBase.decodedLength(data[0], len(data))
    if length == -1:
      return err(CidError.Incorrect)
    buffer = newSeqUninit[byte](length)
    if MultiBase.decode(data, buffer, plen) != MultiBaseStatus.Success:
      return err(CidError.Incorrect)
    buffer.setLen(plen)
    if buffer[0] == 0x12'u8:
      return err(CidError.Incorrect)
  decode(buffer)

proc validate*(ctype: typedesc[Cid], data: openArray[byte]): bool =
  ## Returns ``true`` is data has valid binary CID representation.
  var version, codec: uint64
  if len(data) < 2:
    return false
  let last = data.high
  if len(data) == 34:
    if data[0] == 0x12'u8 and data[1] == 0x20'u8:
      return true
  var offset = 0
  var length = 0
  LP.getUVarint(data.toOpenArray(offset, last), length, version).isOkOr:
    return false
  if version != 1'u64:
    return false
  offset += length
  if offset >= len(data):
    return false
  LP.getUVarint(data.toOpenArray(offset, last), length, codec).isOkOr:
    return false
  var mcodec = CodeContentIds.getOrDefault(cast[int](codec), InvalidMultiCodec)
  if mcodec == InvalidMultiCodec:
    return false
  offset += length
  if not MultiHash.validate(data.toOpenArray(offset, last)):
    return false
  true

proc mhash*(cid: Cid): Result[MultiHash, CidError] =
  ## Returns MultiHash part of CID.
  if cid.cidver notin {CIDv0, CIDv1}:
    return err(CidError.Incorrect)

  let mh = MultiHash.init(cid.data.buffer.toOpenArray(cid.hpos, cid.data.high)).valueOr:
    return err(CidError.Incorrect)
  ok(mh)

proc contentType*(cid: Cid): Result[MultiCodec, CidError] =
  ## Returns content type part of CID
  if cid.cidver notin {CIDv0, CIDv1}:
    err(CidError.Incorrect)
  else:
    ok(cid.mcodec)

proc version*(cid: Cid): CidVersion =
  ## Returns CID version
  cid.cidver

proc init*[T: char | byte](
    ctype: typedesc[Cid], data: openArray[T]
): Result[Cid, CidError] =
  ## Create new content identifier using array of bytes or string ``data``.
  decode(data)

proc init*(
    ctype: typedesc[Cid], version: CidVersion, content: MultiCodec, hash: MultiHash
): Result[Cid, CidError] =
  ## Create new content identifier using content type ``content`` and
  ## MultiHash ``hash`` using version ``version``.
  ##
  ## To create ``CIDv0`` you need to use:
  ## Cid.init(CIDv0, multiCodec("dag-pb"), MultiHash.digest("sha2-256", data))
  ##
  ## All other encodings and hashes are not supported by CIDv0.

  var res: Cid
  res.cidver = version

  if version == CIDv0:
    if content != multiCodec("dag-pb"):
      return err(CidError.Unsupported)
    res.data = initVBuffer()
    if hash.mcodec != multiCodec("sha2-256"):
      return err(CidError.Unsupported)
    res.mcodec = content
    res.data.write(hash)
    res.data.finish()
    return ok(res)
  elif version == CIDv1:
    let mcodec = CodeContentIds.getOrDefault(cast[int](content), InvalidMultiCodec)
    if mcodec == InvalidMultiCodec:
      return err(CidError.Incorrect)
    res.mcodec = mcodec
    res.data = initVBuffer()
    res.data.writeVarint(cast[uint64](1))
    res.data.write(mcodec)
    res.hpos = len(res.data.buffer)
    res.data.write(hash)
    res.data.finish()
    return ok(res)
  else:
    return err(CidError.Unsupported)

proc `==`*(a: Cid, b: Cid): bool =
  ## Compares content identifiers ``a`` and ``b``, returns ``true`` if hashes
  ## are equal, ``false`` otherwise.
  if a.mcodec == b.mcodec:
    var ah, bh: MultiHash
    if MultiHash.decode(a.data.buffer.toOpenArray(a.hpos, a.data.high), ah).isErr:
      return false
    if MultiHash.decode(b.data.buffer.toOpenArray(b.hpos, b.data.high), bh).isErr:
      return false
    return ah == bh
  false

proc base58*(cid: Cid): string =
  ## Get BASE58 encoded string representation of content identifier ``cid``.
  BTCBase58.encode(cid.data.buffer)

proc hex*(cid: Cid): string =
  ## Get hexadecimal string representation of content identifier ``cid``.
  $(cid.data)

proc repr*(cid: Cid): string =
  ## Get string representation of content identifier ``cid``.
  var s = $(cid.cidver)
  s.add("/")
  s.add($(cid.mcodec))
  s.add("/")
  s.add($(cid.mhash()))
  s

proc write*(vb: var VBuffer, cid: Cid) =
  ## Write CID value ``cid`` to buffer ``vb``.
  vb.writeArray(cid.data.buffer)

proc hash*(cid: Cid): Hash =
  !$(hash(cid.mcodec) !& hash(cid.data.buffer.toOpenArray(cid.hpos, cid.data.high)))

proc `$`*(cid: Cid): string =
  ## Return official string representation of content identifier ``cid``.
  if cid.cidver == CIDv0:
    BTCBase58.encode(cid.data.buffer)
  elif cid.cidver == CIDv1:
    let res = MultiBase.encode("base58btc", cid.data.buffer)
    res.get("")
  else:
    ""
