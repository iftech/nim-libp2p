# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements constant-time RSA PKCS#1.5 DSA.
##
## This module uses unmodified parts of code from
## BearSSL library <https://bearssl.org/>
## Copyright(C) 2018 Thomas Pornin <pornin@bolet.org>.

{.push raises: [].}

import bearssl/[rsa, rand, hash]
import minasn1
import results
import stew/[bitops2, ctops]
# We use `ncrutils` for constant-time hexadecimal encoding/decoding procedures.
import nimcrypto/utils as ncrutils
import rng
import ../utils/redact

export Asn1Error, results

const
  DefaultPublicExponent* = 65537'u32
    ## Default value for RSA public exponent.
    ## https://golang.org/src/crypto/rsa/rsa.go#226
  MinKeySize* = 2048
    ## Minimal allowed RSA key size in bits.
    ## https://github.com/libp2p/go-libp2p-core/blob/master/crypto/rsa_common.go#L13
  MaxKeySize* = 4096
    ## Maximal allowed RSA key size in bits.
    ## This matches BearSSL's BR_MAX_RSA_SIZE.
  DefaultKeySize* = 3072 ## Default RSA key size in bits.

  RsaOidSha1* = [byte 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A]
    ## RSA PKCS#1.5 SHA-1 hash object identifier.
  RsaOidSha224* = [byte 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04]
    ## RSA PKCS#1.5 SHA-224 hash object identifier.
  RsaOidSha256* = [byte 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
    ## RSA PKCS#1.5 SHA-256 hash object identifier.
  RsaOidSha384* = [byte 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]
    ## RSA PKCS#1.5 SHA-384 hash object identifier.
  RsaOidSha512* = [byte 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]
    ## RSA PKCS#1.5 SHA-512 hash object identifier.

type
  RsaPrivateKey* = ref object
    buffer*: seq[byte]
    seck*: rsa.RsaPrivateKey
    pubk*: rsa.RsaPublicKey
    pexp*: ptr byte
    pexplen*: uint

  RsaPublicKey* = ref object
    buffer*: seq[byte]
    key*: rsa.RsaPublicKey

  RsaKeyPair* = RsaPrivateKey

  RsaSignature* = ref object
    buffer*: seq[byte]

  RsaPKI* = RsaPrivateKey | RsaPublicKey | RsaSignature
  RsaKP* = RsaPrivateKey | RsaKeyPair

  RsaError* = enum
    RsaGenError
    RsaKeyIncorrectError
    RsaSignatureError
    RsaLowSecurityError
    RsaKeyTooLargeError

  RsaResult*[T] = Result[T, RsaError]

template getStart(bs, os, ls: untyped): untyped =
  let p = cast[uint](os)
  let s = cast[uint](addr bs[0])
  var so = 0
  if p >= s:
    so = cast[int](p - s)
  so

template getFinish(bs, os, ls: untyped): untyped =
  let p = cast[uint](os)
  let s = cast[uint](addr bs[0])
  var eo = -1
  if p >= s:
    let so = cast[int](p - s)
    if so + int(ls) <= len(bs):
      eo = so + int(ls) - 1
  eo

template getArray*(bs, os, ls: untyped): untyped =
  toOpenArray(bs, getStart(bs, os, ls), getFinish(bs, os, ls))

template trimZeroes(b: seq[byte], pt, ptlen: untyped) =
  var length = ptlen
  for i in 0 ..< length:
    if pt[] != byte(0x00):
      break
    pt = cast[ptr byte](cast[uint](pt) + 1)
    ptlen -= 1

proc bitLength(field: Asn1Field): int =
  if len(field) == 0:
    return 0

  let first = field.buffer[field.offset]
  ((len(field) - 1) shl 3) + bitWidth(first)

func validKeySize(bits: int): bool =
  bits >= MinKeySize and bits <= MaxKeySize

func validPublicExponent(field: Asn1Field): bool =
  const IntegerSignBit = 0x80'u8

  if len(field) == 0:
    return false

  let
    first = field.buffer[field.offset]
    last = field.buffer[field.offset + len(field) - 1]
    hadLeadingZero = field.offset > 0 and field.buffer[field.offset - 1] == 0

  if (first and IntegerSignBit) != 0 and not hadLeadingZero:
    return false
  if (last and 1) == 0:
    return false
  len(field) > 1 or first >= 3

proc random*[T: RsaKP](
    t: typedesc[T], rng: Rng, bits = DefaultKeySize, pubexp = DefaultPublicExponent
): RsaResult[T] =
  ## Generate new random RSA private key using BearSSL's HMAC-SHA256-DRBG
  ## algorithm.
  ##
  ## ``bits`` number of bits in RSA key, must be in
  ## range [2048, 4096] (default = 3072).
  ##
  ## ``pubexp`` is RSA public exponent, which must be prime (default = 65537).
  if bits < MinKeySize:
    return err(RsaLowSecurityError)
  if bits > MaxKeySize:
    return err(RsaKeyTooLargeError)

  let
    sko = 0
    pko = rsaKbufPrivSize(bits)
    eko = pko + rsaKbufPubSize(bits)
    length = eko + ((bits + 7) shr 3)

  let res = new T
  res.buffer = newSeqUninit[byte](length)

  var keygen = rsaKeygenGetDefault()

  if keygen(
    bearSslPrng(rng),
    addr res.seck,
    addr res.buffer[sko],
    addr res.pubk,
    addr res.buffer[pko],
    cuint(bits),
    pubexp,
  ) == 0:
    return err(RsaGenError)

  let
    compute = rsaComputePrivexpGetDefault()
    computed = compute(addr res.buffer[eko], addr res.seck, pubexp)
  if computed == 0:
    return err(RsaGenError)

  res.pexp = addr res.buffer[eko]
  res.pexplen = computed

  trimZeroes(res.buffer, res.seck.p, res.seck.plen)
  trimZeroes(res.buffer, res.seck.q, res.seck.qlen)
  trimZeroes(res.buffer, res.seck.dp, res.seck.dplen)
  trimZeroes(res.buffer, res.seck.dq, res.seck.dqlen)
  trimZeroes(res.buffer, res.seck.iq, res.seck.iqlen)
  trimZeroes(res.buffer, res.pubk.n, res.pubk.nlen)
  trimZeroes(res.buffer, res.pubk.e, res.pubk.elen)
  trimZeroes(res.buffer, res.pexp, res.pexplen)

  ok(res)

proc copy*[T: RsaPKI](key: T): T =
  ## Create copy of RSA private key, public key or signature.
  doAssert(not isNil(key))
  when T is RsaPrivateKey:
    if len(key.buffer) > 0:
      let length =
        key.seck.plen.uint + key.seck.qlen.uint + key.seck.dplen.uint +
        key.seck.dqlen.uint + key.seck.iqlen.uint + key.pubk.nlen.uint +
        key.pubk.elen.uint + key.pexplen.uint
      var res = new RsaPrivateKey
      res.buffer = newSeqUninit[byte](length)
      let po: uint = 0
      let qo = po + key.seck.plen
      let dpo = qo + key.seck.qlen
      let dqo = dpo + key.seck.dplen
      let iqo = dqo + key.seck.dqlen
      let no = iqo + key.seck.iqlen
      let eo = no + key.pubk.nlen
      let peo = eo + key.pubk.elen
      copyMem(addr res.buffer[po], key.seck.p, key.seck.plen)
      copyMem(addr res.buffer[qo], key.seck.q, key.seck.qlen)
      copyMem(addr res.buffer[dpo], key.seck.dp, key.seck.dplen)
      copyMem(addr res.buffer[dqo], key.seck.dq, key.seck.dqlen)
      copyMem(addr res.buffer[iqo], key.seck.iq, key.seck.iqlen)
      copyMem(addr res.buffer[no], key.pubk.n, key.pubk.nlen)
      copyMem(addr res.buffer[eo], key.pubk.e, key.pubk.elen)
      copyMem(addr res.buffer[peo], key.pexp, key.pexplen)
      res.seck.p = addr res.buffer[po]
      res.seck.q = addr res.buffer[qo]
      res.seck.dp = addr res.buffer[dpo]
      res.seck.dq = addr res.buffer[dqo]
      res.seck.iq = addr res.buffer[iqo]
      res.pubk.n = addr res.buffer[no]
      res.pubk.e = addr res.buffer[eo]
      res.pexp = addr res.buffer[peo]
      res.seck.plen = key.seck.plen
      res.seck.qlen = key.seck.qlen
      res.seck.dplen = key.seck.dplen
      res.seck.dqlen = key.seck.dqlen
      res.seck.iqlen = key.seck.iqlen
      res.pubk.nlen = key.pubk.nlen
      res.pubk.elen = key.pubk.elen
      res.pexplen = key.pexplen
      res.seck.nBitlen = key.seck.nBitlen
      return res
  elif T is RsaPublicKey:
    if len(key.buffer) > 0:
      let length = key.key.nlen + key.key.elen
      var res = new RsaPublicKey
      res.buffer = newSeqUninit[byte](length)
      let no: uint = 0
      let eo = no + key.key.nlen
      copyMem(addr res.buffer[no], key.key.n, key.key.nlen)
      copyMem(addr res.buffer[eo], key.key.e, key.key.elen)
      res.key.n = addr res.buffer[no]
      res.key.e = addr res.buffer[eo]
      res.key.nlen = key.key.nlen
      res.key.elen = key.key.elen
      return res
  elif T is RsaSignature:
    if len(key.buffer) > 0:
      var res = new RsaSignature
      res.buffer = key.buffer
      return res
  nil

proc getPublicKey*(key: RsaPrivateKey): RsaPublicKey =
  ## Get RSA public key from RSA private key.
  doAssert(not isNil(key))
  let length = key.pubk.nlen + key.pubk.elen
  var pubkey = new RsaPublicKey
  pubkey.buffer = newSeqUninit[byte](length)
  pubkey.key.n = addr pubkey.buffer[0]
  pubkey.key.e = addr pubkey.buffer[key.pubk.nlen]
  copyMem(addr pubkey.buffer[0], cast[pointer](key.pubk.n), key.pubk.nlen)
  copyMem(addr pubkey.buffer[key.pubk.nlen], cast[pointer](key.pubk.e), key.pubk.elen)
  pubkey.key.nlen = key.pubk.nlen
  pubkey.key.elen = key.pubk.elen
  pubkey

proc seckey*(pair: RsaKeyPair): RsaPrivateKey =
  ## Get RSA private key from pair ``pair``.
  cast[RsaPrivateKey](pair).copy()

proc pubkey*(pair: RsaKeyPair): RsaPublicKey =
  ## Get RSA public key from pair ``pair``.
  cast[RsaPrivateKey](pair).getPublicKey()

proc clear*[T: RsaPKI | RsaKeyPair](pki: var T) =
  ## Wipe and clear EC private key, public key or scalar object.
  doAssert(not isNil(pki))
  when T is RsaPrivateKey:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)
    pki.seckey.p = nil
    pki.seckey.q = nil
    pki.seckey.dp = nil
    pki.seckey.dq = nil
    pki.seckey.iq = nil
    pki.seckey.plen = 0
    pki.seckey.qlen = 0
    pki.seckey.dplen = 0
    pki.seckey.dqlen = 0
    pki.seckey.iqlen = 0
    pki.seckey.nBitlen = 0
    pki.pubkey.n = nil
    pki.pubkey.e = nil
    pki.pubkey.nlen = 0
    pki.pubkey.elen = 0
  elif T is RsaPublicKey:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)
    pki.key.n = nil
    pki.key.e = nil
    pki.key.nlen = 0
    pki.key.elen = 0
  elif T is RsaSignature:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)

proc toBytes*(key: RsaPrivateKey, data: var openArray[byte]): RsaResult[int] =
  ## Serialize RSA private key ``key`` to ASN.1 DER binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store RSA private key,
  ## or `0` if private key is is incorrect.
  if isNil(key):
    err(RsaKeyIncorrectError)
  elif len(key.buffer) > 0:
    var b = Asn1Buffer.init()
    var p = Asn1Composite.init(Asn1Tag.Sequence)
    p.write(0'u64)
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.pubk.n, key.pubk.nlen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.pubk.e, key.pubk.elen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.pexp, key.pexplen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.p, key.seck.plen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.q, key.seck.qlen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.dp, key.seck.dplen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.dq, key.seck.dqlen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.iq, key.seck.iqlen))
    p.finish()
    b.write(p)
    b.finish()
    var blen = len(b)
    if len(data) >= blen:
      copyMem(addr data[0], addr b.buffer[0], blen)
    ok(blen)
  else:
    err(RsaKeyIncorrectError)

proc toBytes*(key: RsaPublicKey, data: var openArray[byte]): RsaResult[int] =
  ## Serialize RSA public key ``key`` to ASN.1 DER binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store RSA public key,
  ## or `0` if public key is incorrect.
  if isNil(key):
    err(RsaKeyIncorrectError)
  elif len(key.buffer) > 0:
    var b = Asn1Buffer.init()
    var p = Asn1Composite.init(Asn1Tag.Sequence)
    var c0 = Asn1Composite.init(Asn1Tag.Sequence)
    var c1 = Asn1Composite.init(Asn1Tag.BitString)
    var c10 = Asn1Composite.init(Asn1Tag.Sequence)
    c0.write(Asn1Tag.Oid, Asn1OidRsaEncryption)
    c0.write(Asn1Tag.Null)
    c0.finish()
    c10.write(Asn1Tag.Integer, getArray(key.buffer, key.key.n, key.key.nlen))
    c10.write(Asn1Tag.Integer, getArray(key.buffer, key.key.e, key.key.elen))
    c10.finish()
    c1.write(c10)
    c1.finish()
    p.write(c0)
    p.write(c1)
    p.finish()
    b.write(p)
    b.finish()
    var blen = len(b)
    if len(data) >= blen:
      copyMem(addr data[0], addr b.buffer[0], blen)
    ok(blen)
  else:
    err(RsaKeyIncorrectError)

proc toBytes*(sig: RsaSignature, data: var openArray[byte]): RsaResult[int] =
  ## Serialize RSA signature ``sig`` to raw binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store RSA public key,
  ## or `0` if public key is incorrect.
  if isNil(sig):
    err(RsaSignatureError)
  else:
    var slen = len(sig.buffer)
    if len(data) >= slen:
      copyMem(addr data[0], addr sig.buffer[0], slen)
    ok(slen)

proc getBytes*(key: RsaPrivateKey): RsaResult[seq[byte]] =
  ## Serialize RSA private key ``key`` to ASN.1 DER binary form and
  ## return it.
  if isNil(key):
    return err(RsaKeyIncorrectError)
  var res = newSeqUninit[byte](4096)
  let length = ?key.toBytes(res)
  if length > 0:
    res.setLen(length)
    ok(res)
  else:
    err(RsaKeyIncorrectError)

proc getBytes*(key: RsaPublicKey): RsaResult[seq[byte]] =
  ## Serialize RSA public key ``key`` to ASN.1 DER binary form and
  ## return it.
  if isNil(key):
    return err(RsaKeyIncorrectError)
  var res = newSeqUninit[byte](4096)
  let length = ?key.toBytes(res)
  if length > 0:
    res.setLen(length)
    ok(res)
  else:
    err(RsaKeyIncorrectError)

proc getBytes*(sig: RsaSignature): RsaResult[seq[byte]] =
  ## Serialize RSA signature ``sig`` to raw binary form and return it.
  if isNil(sig):
    return err(RsaSignatureError)
  var res = newSeqUninit[byte](4096)
  let length = ?sig.toBytes(res)
  if length > 0:
    res.setLen(length)
    ok(res)
  else:
    err(RsaSignatureError)

proc init*(key: var RsaPrivateKey, data: openArray[byte]): Result[void, Asn1Error] =
  ## Initialize RSA private key ``key`` from ASN.1 DER binary representation
  ## ``data``.
  ##
  ## Procedure returns ``Asn1Status``.
  var field, rawn, rawpube, rawprie, rawp, rawq, rawdp, rawdq, rawiq: Asn1Field

  # Asn1Field is not trivial so avoid too much Result

  var ab = Asn1Buffer.init(data)
  field = ?ab.read()

  if field.kind != Asn1Tag.Sequence:
    return err(Asn1Error.Incorrect)

  var ib = field.getBuffer()

  field = ?ib.read()

  if field.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  if field.vint != 0'u64:
    return err(Asn1Error.Incorrect)

  rawn = ?ib.read()

  if rawn.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawpube = ?ib.read()

  if rawpube.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawprie = ?ib.read()

  if rawprie.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawp = ?ib.read()

  if rawp.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawq = ?ib.read()

  if rawq.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawdp = ?ib.read()

  if rawdp.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawdq = ?ib.read()

  if rawdq.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawiq = ?ib.read()

  if rawiq.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  let nBitlen = bitLength(rawn)
  if validKeySize(nBitlen) and len(rawp) > 0 and len(rawq) > 0 and len(rawdp) > 0 and
      len(rawdq) > 0 and len(rawiq) > 0:
    key = new RsaPrivateKey
    key.buffer = @data
    key.pubk.n = addr key.buffer[rawn.offset]
    key.pubk.e = addr key.buffer[rawpube.offset]
    key.seck.p = addr key.buffer[rawp.offset]
    key.seck.q = addr key.buffer[rawq.offset]
    key.seck.dp = addr key.buffer[rawdp.offset]
    key.seck.dq = addr key.buffer[rawdq.offset]
    key.seck.iq = addr key.buffer[rawiq.offset]
    key.pexp = addr key.buffer[rawprie.offset]
    key.pubk.nlen = uint(len(rawn))
    key.pubk.elen = uint(len(rawpube))
    key.seck.plen = uint(len(rawp))
    key.seck.qlen = uint(len(rawq))
    key.seck.dplen = uint(len(rawdp))
    key.seck.dqlen = uint(len(rawdq))
    key.seck.iqlen = uint(len(rawiq))
    key.pexplen = uint(len(rawprie))
    key.seck.nBitlen = cast[uint32](nBitlen)
    ok()
  else:
    err(Asn1Error.Incorrect)

proc init*(key: var RsaPublicKey, data: openArray[byte]): Result[void, Asn1Error] =
  ## Initialize RSA public key ``key`` from ASN.1 DER binary representation
  ## ``data``.
  ##
  ## Procedure returns ``Asn1Status``.
  var field, rawn, rawe: Asn1Field
  var ab = Asn1Buffer.init(data)

  field = ?ab.read()

  if field.kind != Asn1Tag.Sequence:
    return err(Asn1Error.Incorrect)

  var ib = field.getBuffer()

  field = ?ib.read()

  if field.kind != Asn1Tag.Sequence:
    return err(Asn1Error.Incorrect)

  var ob = field.getBuffer()

  field = ?ob.read()

  if field.kind != Asn1Tag.Oid:
    return err(Asn1Error.Incorrect)
  elif field != Asn1OidRsaEncryption:
    return err(Asn1Error.Incorrect)

  field = ?ob.read()

  if field.kind != Asn1Tag.Null:
    return err(Asn1Error.Incorrect)

  field = ?ib.read()

  if field.kind != Asn1Tag.BitString:
    return err(Asn1Error.Incorrect)

  var vb = field.getBuffer()

  field = ?vb.read()

  if field.kind != Asn1Tag.Sequence:
    return err(Asn1Error.Incorrect)

  var sb = field.getBuffer()

  rawn = ?sb.read()

  if rawn.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  rawe = ?sb.read()

  if rawe.kind != Asn1Tag.Integer:
    return err(Asn1Error.Incorrect)

  if validKeySize(bitLength(rawn)) and validPublicExponent(rawe):
    key = new RsaPublicKey
    key.buffer = @data
    key.key.n = addr key.buffer[rawn.offset]
    key.key.e = addr key.buffer[rawe.offset]
    key.key.nlen = uint(len(rawn))
    key.key.elen = uint(len(rawe))
    ok()
  else:
    err(Asn1Error.Incorrect)

proc init*(sig: var RsaSignature, data: openArray[byte]): Result[void, Asn1Error] =
  ## Initialize RSA signature ``sig`` from ASN.1 DER binary representation
  ## ``data``.
  ##
  ## Procedure returns ``Result[void, Asn1Status]``.
  if len(data) > 0:
    sig = new RsaSignature
    sig.buffer = @data
    ok()
  else:
    err(Asn1Error.Incorrect)

proc init*[T: RsaPKI](sospk: var T, data: string): Result[void, Asn1Error] =
  ## Initialize EC `private key`, `public key` or `scalar` ``sospk`` from
  ## hexadecimal string representation ``data``.
  ##
  ## Procedure returns ``Result[void, Asn1Status]``.
  sospk.init(ncrutils.fromHex(data))

proc init*(
    t: typedesc[RsaPrivateKey], data: openArray[byte]
): RsaResult[RsaPrivateKey] =
  ## Initialize RSA private key from ASN.1 DER binary representation ``data``
  ## and return constructed object.
  var res: RsaPrivateKey
  if res.init(data).isErr:
    err(RsaKeyIncorrectError)
  else:
    ok(res)

proc init*(t: typedesc[RsaPublicKey], data: openArray[byte]): RsaResult[RsaPublicKey] =
  ## Initialize RSA public key from ASN.1 DER binary representation ``data``
  ## and return constructed object.
  var res: RsaPublicKey
  if res.init(data).isErr:
    err(RsaKeyIncorrectError)
  else:
    ok(res)

proc init*(t: typedesc[RsaSignature], data: openArray[byte]): RsaResult[RsaSignature] =
  ## Initialize RSA signature from raw binary representation ``data`` and
  ## return constructed object.
  var res: RsaSignature
  if res.init(data).isErr:
    err(RsaSignatureError)
  else:
    ok(res)

redactType(RsaPrivateKey)

proc `$`*(key: RsaPublicKey): string =
  ## Return string representation of RSA public key.
  if isNil(key) or len(key.buffer) == 0:
    return "Empty or uninitialized RSA key"
  let nbitlen = key.key.nlen shl 3
  var s = "RSA key ("
  s.add($nbitlen)
  s.add(" bits)\nn = ")
  s.add(ncrutils.toHex(getArray(key.buffer, key.key.n, key.key.nlen)))
  s.add("\ne = ")
  s.add(ncrutils.toHex(getArray(key.buffer, key.key.e, key.key.elen)))
  s.add("\n")
  s

proc `$`*(sig: RsaSignature): string =
  ## Return string representation of RSA signature.
  if isNil(sig) or len(sig.buffer) == 0:
    return "Empty or uninitialized RSA signature"
  var s = "RSA signature ("
  s.add(ncrutils.toHex(sig.buffer))
  s.add(")")
  s

proc `==`*(a, b: RsaPrivateKey): bool =
  ## Compare two RSA private keys for equality.
  ##
  ## Result is true if ``a`` and ``b`` are both ``nil`` or ``a`` and ``b`` are
  ## equal by value.
  if isNil(a) and isNil(b):
    true
  elif isNil(a) and (not isNil(b)):
    false
  elif isNil(b) and (not isNil(a)):
    false
  else:
    if a.seck.nBitlen == b.seck.nBitlen:
      if a.seck.nBitlen > 0'u:
        let r1 = CT.isEqual(
          getArray(a.buffer, a.seck.p, a.seck.plen),
          getArray(b.buffer, b.seck.p, b.seck.plen),
        )
        let r2 = CT.isEqual(
          getArray(a.buffer, a.seck.q, a.seck.qlen),
          getArray(b.buffer, b.seck.q, b.seck.qlen),
        )
        let r3 = CT.isEqual(
          getArray(a.buffer, a.seck.dp, a.seck.dplen),
          getArray(b.buffer, b.seck.dp, b.seck.dplen),
        )
        let r4 = CT.isEqual(
          getArray(a.buffer, a.seck.dq, a.seck.dqlen),
          getArray(b.buffer, b.seck.dq, b.seck.dqlen),
        )
        let r5 = CT.isEqual(
          getArray(a.buffer, a.seck.iq, a.seck.iqlen),
          getArray(b.buffer, b.seck.iq, b.seck.iqlen),
        )
        let r6 = CT.isEqual(
          getArray(a.buffer, a.pexp, a.pexplen), getArray(b.buffer, b.pexp, b.pexplen)
        )
        let r7 = CT.isEqual(
          getArray(a.buffer, a.pubk.n, a.pubk.nlen),
          getArray(b.buffer, b.pubk.n, b.pubk.nlen),
        )
        let r8 = CT.isEqual(
          getArray(a.buffer, a.pubk.e, a.pubk.elen),
          getArray(b.buffer, b.pubk.e, b.pubk.elen),
        )
        r1 and r2 and r3 and r4 and r5 and r6 and r7 and r8
      else:
        true
    else:
      false

proc `==`*(a, b: RsaSignature): bool =
  ## Compare two RSA signatures for equality.
  if isNil(a) and isNil(b):
    true
  elif isNil(a) and (not isNil(b)):
    false
  elif isNil(b) and (not isNil(a)):
    false
  else:
    # We need to cover all the cases because Signature initialization procedure
    # do not perform any checks.
    if len(a.buffer) == 0 and len(b.buffer) == 0:
      true
    elif len(a.buffer) == 0 and len(b.buffer) != 0:
      false
    elif len(b.buffer) == 0 and len(a.buffer) != 0:
      false
    elif len(a.buffer) != len(b.buffer):
      false
    else:
      CT.isEqual(a.buffer, b.buffer)

proc `==`*(a, b: RsaPublicKey): bool =
  ## Compare two RSA public keys for equality.
  if isNil(a) and isNil(b):
    true
  elif isNil(a) and (not isNil(b)):
    false
  elif isNil(b) and (not isNil(a)):
    false
  else:
    let r1 = CT.isEqual(
      getArray(a.buffer, a.key.n, a.key.nlen), getArray(b.buffer, b.key.n, b.key.nlen)
    )
    let r2 = CT.isEqual(
      getArray(a.buffer, a.key.e, a.key.elen), getArray(b.buffer, b.key.e, b.key.elen)
    )
    (r1 and r2)

proc sign*[T: byte | char](
    key: RsaPrivateKey, message: openArray[T]
): RsaResult[RsaSignature] {.gcsafe.} =
  ## Get RSA PKCS1.5 signature of data ``message`` using SHA256 and private
  ## key ``key``.
  if isNil(key):
    return err(RsaKeyIncorrectError)

  var hc: HashCompatContext
  var hash: array[32, byte]
  let impl = rsaPkcs1SignGetDefault()
  var res = new RsaSignature
  res.buffer = newSeqUninit[byte]((key.seck.nBitlen + 7) shr 3)
  var kv = addr sha256Vtable
  kv.init(addr hc.vtable)
  if len(message) > 0:
    kv.update(addr hc.vtable, addr message[0], uint(len(message)))
  else:
    kv.update(addr hc.vtable, nil, 0)
  kv.out(addr hc.vtable, addr hash[0])
  var oid = RsaOidSha256
  let implRes =
    impl(addr oid[0], addr hash[0], uint(len(hash)), addr key.seck, addr res.buffer[0])
  if implRes == 0:
    err(RsaSignatureError)
  else:
    ok(res)

proc verify*[T: byte | char](
    sig: RsaSignature, message: openArray[T], pubkey: RsaPublicKey
): bool =
  ## Verify RSA signature ``sig`` using public key ``pubkey`` and data
  ## ``message``.
  ##
  ## Return ``true`` if message verification succeeded, ``false`` if
  ## verification failed.
  doAssert((not isNil(sig)) and (not isNil(pubkey)))
  if len(sig.buffer) > 0:
    var hc: HashCompatContext
    var hash: array[32, byte]
    var check: array[32, byte]
    var impl = rsaPkcs1VrfyGetDefault()
    var kv = addr sha256Vtable
    kv.init(addr hc.vtable)
    if len(message) > 0:
      kv.update(addr hc.vtable, addr message[0], uint(len(message)))
    else:
      kv.update(addr hc.vtable, nil, 0)
    kv.out(addr hc.vtable, addr hash[0])
    var oid = RsaOidSha256
    let res = impl(
      addr sig.buffer[0],
      uint(len(sig.buffer)),
      addr oid[0],
      uint(len(check)),
      addr pubkey.key,
      addr check[0],
    )
    if res == 1:
      return equalMem(addr check[0], addr hash[0], len(hash))
  false
