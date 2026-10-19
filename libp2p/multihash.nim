# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements MultiHash.
## Supported hashes are:
## 1. IDENTITY
## 2. SHA2-256/SHA2-512
## 3. DBL-SHA2-256
## 4. SHA3/KECCAK
## 5. SHAKE-128/SHAKE-256
## 6. BLAKE2s/BLAKE2s
## 7. SHA1
##
## Hashes which are not yet supported
## 1. SKEIN
## 2. MURMUR

{.push raises: [].}
{.used.}

import tables
import nimcrypto/[sha, sha2, keccak, blake2, hash, utils]
import varint, vbuffer, multicodec, multibase
import stew/[base58, ctops]
import results
export results
# This is workaround for Nim `import` bug.
export sha, sha2, keccak, blake2, hash, utils, vbuffer

const
  MaxHashSize* = 128
  ErrIncorrectName = "Incorrect hash name"
  ErrNotSupported = "Hash not supported"
  ErrWrongDigestSize = "Incorrect digest size"
  ErrDecodeError = "Decoding error from bytes"
  ErrParseError = "Parse error fromHex"
  libp2p_multihash_exts* {.strdefine.} = ""

type
  MHashCoderProc* = proc(data: openArray[byte], output: var openArray[byte]) {.
    nimcall, gcsafe, noSideEffect, raises: []
  .}
  MHash* = object
    mcodec*: MultiCodec
    size*: int
    coder*: MHashCoderProc

  MultiHash* = object
    data*: VBuffer
    mcodec*: MultiCodec
    size*: int
    dpos*: int

  MhResult*[T] = Result[T, cstring]

proc identhash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var length =
      if len(data) > len(output):
        len(output)
      else:
        len(data)
    copyMem(addr output[0], addr data[0], length)

proc sha1hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = sha1.digest(data)
    var length =
      if sha1.sizeDigest > len(output):
        len(output)
      else:
        sha1.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc dblsha2_256hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest1 = sha256.digest(data)
    var digest2 = sha256.digest(digest1.data)
    var length =
      if sha256.sizeDigest > len(output):
        len(output)
      else:
        sha256.sizeDigest
    copyMem(addr output[0], addr digest2.data[0], length)

proc blake2Bhash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = blake2_512.digest(data)
    var length =
      if blake2_512.sizeDigest > len(output):
        len(output)
      else:
        blake2_512.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc blake2Shash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = blake2_256.digest(data)
    var length =
      if blake2_256.sizeDigest > len(output):
        len(output)
      else:
        blake2_256.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc sha2_256hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = sha256.digest(data)
    var length =
      if sha256.sizeDigest > len(output):
        len(output)
      else:
        sha256.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc sha2_512hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = sha512.digest(data)
    var length =
      if sha512.sizeDigest > len(output):
        len(output)
      else:
        sha512.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc sha3_224hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = sha3_224.digest(data)
    var length =
      if sha3_224.sizeDigest > len(output):
        len(output)
      else:
        sha3_224.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc sha3_256hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = sha3_256.digest(data)
    var length =
      if sha3_256.sizeDigest > len(output):
        len(output)
      else:
        sha3_256.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc sha3_384hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = sha3_384.digest(data)
    var length =
      if sha3_384.sizeDigest > len(output):
        len(output)
      else:
        sha3_384.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc sha3_512hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = sha3_512.digest(data)
    var length =
      if sha3_512.sizeDigest > len(output):
        len(output)
      else:
        sha3_512.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc keccak_224hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = keccak224.digest(data)
    var length =
      if keccak224.sizeDigest > len(output):
        len(output)
      else:
        keccak224.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc keccak_256hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = keccak256.digest(data)
    var length =
      if keccak256.sizeDigest > len(output):
        len(output)
      else:
        keccak256.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc keccak_384hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = keccak384.digest(data)
    var length =
      if keccak384.sizeDigest > len(output):
        len(output)
      else:
        keccak384.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc keccak_512hash(data: openArray[byte], output: var openArray[byte]) =
  if len(output) > 0:
    var digest = keccak512.digest(data)
    var length =
      if keccak512.sizeDigest > len(output):
        len(output)
      else:
        keccak512.sizeDigest
    copyMem(addr output[0], addr digest.data[0], length)

proc shake_128hash(data: openArray[byte], output: var openArray[byte]) =
  var sctx: shake128
  if len(output) > 0:
    sctx.init()
    sctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
    sctx.xof()
    discard sctx.output(addr output[0], uint(len(output)))
    sctx.clear()

proc shake_256hash(data: openArray[byte], output: var openArray[byte]) =
  var sctx: shake256
  if len(output) > 0:
    sctx.init()
    sctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
    sctx.xof()
    discard sctx.output(addr output[0], uint(len(output)))
    sctx.clear()

const HashesList = [
  MHash(mcodec: multiCodec("identity"), size: 0, coder: identhash),
  MHash(mcodec: multiCodec("sha1"), size: sha1.sizeDigest, coder: sha1hash),
  MHash(
    mcodec: multiCodec("dbl-sha2-256"), size: sha256.sizeDigest, coder: dblsha2_256hash
  ),
  MHash(mcodec: multiCodec("sha2-256"), size: sha256.sizeDigest, coder: sha2_256hash),
  MHash(mcodec: multiCodec("sha2-512"), size: sha512.sizeDigest, coder: sha2_512hash),
  MHash(mcodec: multiCodec("sha3-224"), size: sha3_224.sizeDigest, coder: sha3_224hash),
  MHash(mcodec: multiCodec("sha3-256"), size: sha3_256.sizeDigest, coder: sha3_256hash),
  MHash(mcodec: multiCodec("sha3-384"), size: sha3_384.sizeDigest, coder: sha3_384hash),
  MHash(mcodec: multiCodec("sha3-512"), size: sha3_512.sizeDigest, coder: sha3_512hash),
  MHash(mcodec: multiCodec("shake-128"), size: 32, coder: shake_128hash),
  MHash(mcodec: multiCodec("shake-256"), size: 64, coder: shake_256hash),
  MHash(
    mcodec: multiCodec("keccak-224"), size: keccak224.sizeDigest, coder: keccak_224hash
  ),
  MHash(
    mcodec: multiCodec("keccak-256"), size: keccak256.sizeDigest, coder: keccak_256hash
  ),
  MHash(
    mcodec: multiCodec("keccak-384"), size: keccak384.sizeDigest, coder: keccak_384hash
  ),
  MHash(
    mcodec: multiCodec("keccak-512"), size: keccak512.sizeDigest, coder: keccak_512hash
  ),
  MHash(mcodec: multiCodec("blake2b-8"), size: 1, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-16"), size: 2, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-24"), size: 3, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-32"), size: 4, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-40"), size: 5, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-48"), size: 6, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-56"), size: 7, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-64"), size: 8, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-72"), size: 9, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-80"), size: 10, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-88"), size: 11, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-96"), size: 12, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-104"), size: 13, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-112"), size: 14, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-120"), size: 15, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-128"), size: 16, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-136"), size: 17, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-144"), size: 18, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-152"), size: 19, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-160"), size: 20, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-168"), size: 21, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-176"), size: 22, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-184"), size: 23, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-192"), size: 24, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-200"), size: 25, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-208"), size: 26, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-216"), size: 27, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-224"), size: 28, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-232"), size: 29, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-240"), size: 30, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-248"), size: 31, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-256"), size: 32, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-264"), size: 33, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-272"), size: 34, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-280"), size: 35, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-288"), size: 36, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-296"), size: 37, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-304"), size: 38, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-312"), size: 39, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-320"), size: 40, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-328"), size: 41, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-336"), size: 42, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-344"), size: 43, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-352"), size: 44, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-360"), size: 45, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-368"), size: 46, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-376"), size: 47, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-384"), size: 48, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-392"), size: 49, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-400"), size: 50, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-408"), size: 51, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-416"), size: 52, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-424"), size: 53, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-432"), size: 54, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-440"), size: 55, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-448"), size: 56, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-456"), size: 57, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-464"), size: 58, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-472"), size: 59, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-480"), size: 60, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-488"), size: 61, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-496"), size: 62, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-504"), size: 63, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2b-512"), size: 64, coder: blake2Bhash),
  MHash(mcodec: multiCodec("blake2s-8"), size: 1, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-16"), size: 2, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-24"), size: 3, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-32"), size: 4, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-40"), size: 5, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-48"), size: 6, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-56"), size: 7, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-64"), size: 8, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-72"), size: 9, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-80"), size: 10, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-88"), size: 11, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-96"), size: 12, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-104"), size: 13, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-112"), size: 14, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-120"), size: 15, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-128"), size: 16, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-136"), size: 17, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-144"), size: 18, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-152"), size: 19, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-160"), size: 20, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-168"), size: 21, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-176"), size: 22, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-184"), size: 23, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-192"), size: 24, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-200"), size: 25, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-208"), size: 26, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-216"), size: 27, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-224"), size: 28, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-232"), size: 29, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-240"), size: 30, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-248"), size: 31, coder: blake2Shash),
  MHash(mcodec: multiCodec("blake2s-256"), size: 32, coder: blake2Shash),
]

proc initMultiHashCodeTable(
    hashes: openArray[MHash]
): Table[MultiCodec, MHash] {.compileTime.} =
  var res: Table[MultiCodec, MHash]

  for hash in hashes:
    res[hash.mcodec] = hash

  return res

when libp2p_multihash_exts != "":
  import ./utils/macroutils
  includeFile(libp2p_multihash_exts)
  const CodeHashes = initMultiHashCodeTable(@HashesList & @HashExts)
else:
  const CodeHashes = initMultiHashCodeTable(@HashesList)

proc digestImplWithHash(hash: MHash, data: openArray[byte]): MultiHash =
  var buffer: array[MaxHashSize, byte]
  var mh: MultiHash
  mh.data = initVBuffer()
  mh.mcodec = hash.mcodec
  mh.data.write(hash.mcodec)
  if hash.size == 0:
    mh.data.writeVarint(uint(len(data)))
    mh.dpos = len(mh.data.buffer)
    mh.data.writeArray(data)
    mh.size = len(data)
  else:
    mh.data.writeVarint(uint(hash.size))
    mh.dpos = len(mh.data.buffer)
    hash.coder(data, buffer.toOpenArray(0, hash.size - 1))
    mh.data.writeArray(buffer.toOpenArray(0, hash.size - 1))
    mh.size = hash.size
  mh.data.finish()
  mh

proc digestImplWithoutHash(hash: MHash, data: openArray[byte]): MultiHash =
  var mh: MultiHash
  mh.data = initVBuffer()
  mh.mcodec = hash.mcodec
  mh.size = len(data)
  mh.data.write(hash.mcodec)
  mh.data.writeVarint(uint(len(data)))
  mh.dpos = len(mh.data.buffer)
  mh.data.writeArray(data)
  mh.data.finish()
  mh

func digestSize*(codec: MultiCodec): MhResult[int] =
  let hash = CodeHashes.getOrDefault(codec)
  if isNil(hash.coder):
    err(ErrNotSupported)
  else:
    ok(hash.size)

func digestSize*(hashname: string): MhResult[int] =
  let mc = MultiCodec.codec(hashname)
  if mc == InvalidMultiCodec:
    err(ErrIncorrectName)
  else:
    mc.digestSize

proc digest*(
    mhtype: typedesc[MultiHash], hashname: string, data: openArray[byte]
): MhResult[MultiHash] =
  ## Perform digest calculation using hash algorithm with name ``hashname`` on
  ## data array ``data``.
  let mc = MultiCodec.codec(hashname)
  if mc == InvalidMultiCodec:
    err(ErrIncorrectName)
  else:
    let hash = CodeHashes.getOrDefault(mc)
    if isNil(hash.coder):
      err(ErrNotSupported)
    else:
      ok(digestImplWithHash(hash, data))

proc digest*(
    mhtype: typedesc[MultiHash], mcodec: MultiCodec, data: openArray[byte]
): MhResult[MultiHash] =
  ## Perform digest calculation using hash algorithm with code ``hashcode`` on
  ## data array ``data``.
  let hash = CodeHashes.getOrDefault(mcodec)
  if isNil(hash.coder):
    err(ErrNotSupported)
  else:
    ok(digestImplWithHash(hash, data))

proc init*[T](
    mhtype: typedesc[MultiHash], hashname: string, mdigest: MDigest[T]
): MhResult[MultiHash] =
  ## Create MultiHash from nimcrypto's `MDigest` object and hash algorithm name
  ## ``hashname``.
  let mc = MultiCodec.codec(hashname)
  if mc == InvalidMultiCodec:
    err(ErrIncorrectName)
  else:
    let hash = CodeHashes.getOrDefault(mc)
    if isNil(hash.coder):
      err(ErrNotSupported)
    elif hash.size != len(mdigest.data):
      err(ErrWrongDigestSize)
    else:
      ok(digestImplWithoutHash(hash, mdigest.data))

proc init*[T](
    mhtype: typedesc[MultiHash], hashcode: MultiCodec, mdigest: MDigest[T]
): MhResult[MultiHash] =
  ## Create MultiHash from nimcrypto's `MDigest` and hash algorithm code
  ## ``hashcode``.
  let hash = CodeHashes.getOrDefault(hashcode)
  if isNil(hash.coder):
    err(ErrNotSupported)
  elif (hash.size != 0) and (hash.size != len(mdigest.data)):
    err(ErrWrongDigestSize)
  else:
    ok(digestImplWithoutHash(hash, mdigest.data))

proc init*(
    mhtype: typedesc[MultiHash], hashname: string, bdigest: openArray[byte]
): MhResult[MultiHash] =
  ## Create MultiHash from array of bytes ``bdigest`` and hash algorithm code
  ## ``hashcode``.
  let mc = MultiCodec.codec(hashname)
  if mc == InvalidMultiCodec:
    err(ErrIncorrectName)
  else:
    let hash = CodeHashes.getOrDefault(mc)
    if isNil(hash.coder):
      err(ErrNotSupported)
    elif (hash.size != 0) and (hash.size != len(bdigest)):
      err(ErrWrongDigestSize)
    else:
      ok(digestImplWithoutHash(hash, bdigest))

proc init*(
    mhtype: typedesc[MultiHash], hashcode: MultiCodec, bdigest: openArray[byte]
): MhResult[MultiHash] =
  ## Create MultiHash from array of bytes ``bdigest`` and hash algorithm code
  ## ``hashcode``.
  let hash = CodeHashes.getOrDefault(hashcode)
  if isNil(hash.coder):
    err(ErrNotSupported)
  elif (hash.size != 0) and (hash.size != len(bdigest)):
    err(ErrWrongDigestSize)
  else:
    ok(digestImplWithoutHash(hash, bdigest))

proc decode*(
    mhtype: typedesc[MultiHash], data: openArray[byte], mhash: var MultiHash
): MhResult[int] =
  ## Decode MultiHash value from array of bytes ``data``.
  ##
  ## On success decoded MultiHash will be stored into ``mhash`` and number of
  ## bytes consumed will be returned.
  ##
  ## On error ``-1`` will be returned.
  var code, size: uint64
  var res, dpos: int
  if len(data) < 2:
    return err(ErrDecodeError)

  var vb = initVBuffer(data)
  if vb.isEmpty():
    return err(ErrDecodeError)

  res = vb.readVarint(code)
  if res == -1:
    return err(ErrDecodeError)

  dpos += res
  res = vb.readVarint(size)
  if res == -1:
    return err(ErrDecodeError)

  dpos += res
  if size > 0x7FFF_FFFF'u64:
    return err(ErrDecodeError)

  let hash = CodeHashes.getOrDefault(MultiCodec(code))
  if isNil(hash.coder):
    return err(ErrDecodeError)

  if (hash.size != 0) and (hash.size != int(size)):
    return err(ErrDecodeError)

  if not vb.isEnough(int(size)):
    return err(ErrDecodeError)

  mhash = ?MultiHash.init(
    MultiCodec(code), vb.buffer.toOpenArray(vb.offset, vb.offset + int(size) - 1)
  )
  ok(vb.offset + int(size))

proc validate*(mhtype: typedesc[MultiHash], data: openArray[byte]): bool =
  ## Returns ``true`` if array of bytes ``data`` has correct MultiHash inside.
  var code, size: uint64
  if len(data) < 2:
    return false
  let last = data.high
  var offset = 0
  var length = 0
  LP.getUVarint(data.toOpenArray(offset, last), length, code).isOkOr:
    return false
  offset += length
  if offset >= len(data):
    return false
  LP.getUVarint(data.toOpenArray(offset, last), length, size).isOkOr:
    return false
  offset += length
  if size > 0x7FFF_FFFF'u64:
    return false
  let hash = CodeHashes.getOrDefault(cast[MultiCodec](code))
  if isNil(hash.coder):
    return false
  if (hash.size != 0) and (hash.size != int(size)):
    return false
  if size != uint64(len(data) - offset):
    return false
  true

proc init*(mhtype: typedesc[MultiHash], data: openArray[byte]): MhResult[MultiHash] =
  ## Create MultiHash from bytes array ``data``.
  var hash: MultiHash
  discard ?MultiHash.decode(data, hash)
  ok(hash)

proc init*(mhtype: typedesc[MultiHash], data: string): MhResult[MultiHash] =
  ## Create MultiHash from hexadecimal string representation ``data``.
  var hash: MultiHash
  try:
    discard ?MultiHash.decode(fromHex(data), hash)
    ok(hash)
  except ValueError:
    err(ErrParseError)

proc init58*(mhtype: typedesc[MultiHash], data: string): MultiHash =
  ## Create MultiHash from BASE58 encoded string representation ``data``.
  var hash: MultiHash
  if MultiHash.decode(Base58.decode(data), hash) == -1:
    raise newException(MultihashError, "Incorrect MultiHash binary format in init58")
  hash

proc cmp(a: openArray[byte], b: openArray[byte]): bool =
  if len(a) != len(b):
    return false
  len(a) == 0 or CT.isEqual(a, b)

proc `==`*[T](mh: MultiHash, mdigest: MDigest[T]): bool =
  ## Compares MultiHash with nimcrypto's MDigest[T], returns ``true`` if
  ## hashes are equal, ``false`` otherwise.
  if mh.dpos == 0:
    return false
  if len(mdigest.data) != mh.size:
    return false
  cmp(
    mh.data.buffer.toOpenArray(mh.dpos, mh.dpos + mh.size - 1),
    mdigest.data.toOpenArray(0, mdigest.data.high),
  )

proc `==`*[T](mdigest: MDigest[T], mh: MultiHash): bool =
  ## Compares MultiHash with nimcrypto's MDigest[T], returns ``true`` if
  ## hashes are equal, ``false`` otherwise.
  `==`(mh, mdigest)

proc `==`*(a: MultiHash, b: MultiHash): bool =
  ## Compares MultiHashes ``a`` and ``b``, returns ``true`` if hashes are equal,
  ## ``false`` otherwise.
  if a.dpos == 0 and b.dpos == 0:
    return true
  if a.mcodec != b.mcodec:
    return false
  if a.size != b.size:
    return false
  cmp(
    a.data.buffer.toOpenArray(a.dpos, a.dpos + a.size - 1),
    b.data.buffer.toOpenArray(b.dpos, b.dpos + b.size - 1),
  )

proc hex*(value: MultiHash): string =
  ## Return hexadecimal string representation of MultiHash ``value``.
  $(value.data)

proc base58*(value: MultiHash): string =
  ## Return Base58 encoded string representation of MultiHash ``value``.
  Base58.encode(value.data.buffer)

proc `$`*(mh: MultiHash): string =
  ## Return string representation of MultiHash ``value``.
  let digest = toHex(mh.data.buffer.toOpenArray(mh.dpos, mh.dpos + mh.size - 1))
  $(mh.mcodec) & "/" & digest

proc write*(vb: var VBuffer, mh: MultiHash) =
  ## Write MultiHash value ``mh`` to buffer ``vb``.
  vb.writeArray(mh.data.buffer)

proc encode*(mbtype: typedesc[MultiBase], encoding: string, mh: MultiHash): string =
  ## Get MultiBase encoded representation of ``mh`` using encoding
  ## ``encoding``.
  MultiBase.encode(encoding, mh.data.buffer)
