# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements Public Key and Private Key interface for libp2p.
{.push raises: [].}

from strutils import split, strip, cmpIgnoreCase
import protobuf_serialization, chronicles

const libp2p_pki_schemes* {.strdefine.} = "rsa,ed25519,secp256k1,ecnist"

type PKScheme* = enum
  RSA = 0
  Ed25519
  Secp256k1
  ECDSA

proc initSupportedSchemes(list: static string): set[PKScheme] =
  var res: set[PKScheme]

  let schemes = split(list, {',', ';', '|'})
  for item in schemes:
    if cmpIgnoreCase(strip(item), "rsa") == 0:
      res.incl(PKScheme.RSA)
    elif cmpIgnoreCase(strip(item), "ed25519") == 0:
      res.incl(PKScheme.Ed25519)
    elif cmpIgnoreCase(strip(item), "secp256k1") == 0:
      res.incl(PKScheme.Secp256k1)
    elif cmpIgnoreCase(strip(item), "ecnist") == 0:
      res.incl(PKScheme.ECDSA)
  if len(res) == 0:
    res = {PKScheme.RSA, PKScheme.Ed25519, PKScheme.Secp256k1, PKScheme.ECDSA}
  res

proc initSupportedSchemes(schemes: static set[PKScheme]): set[int8] =
  var res: set[int8]
  if PKScheme.RSA in schemes:
    res.incl(int8(PKScheme.RSA))
  if PKScheme.Ed25519 in schemes:
    res.incl(int8(PKScheme.Ed25519))
  if PKScheme.Secp256k1 in schemes:
    res.incl(int8(PKScheme.Secp256k1))
  if PKScheme.ECDSA in schemes:
    res.incl(int8(PKScheme.ECDSA))
  res

const
  SupportedSchemes* = initSupportedSchemes(libp2p_pki_schemes)
  SupportedSchemesInt* = initSupportedSchemes(SupportedSchemes)
  RsaDefaultKeySize* = 3072

template supported*(scheme: PKScheme): bool =
  ## Returns true if specified ``scheme`` is currently available.
  scheme in SupportedSchemes

when supported(PKScheme.RSA):
  import rsa
when supported(PKScheme.Ed25519):
  import ed25519/ed25519
when supported(PKScheme.Secp256k1):
  import secp
when supported(PKScheme.ECDSA):
  import ecnist

  # These used to be declared in `crypto` itself
  export ecnist.ephemeral, ecnist.ECDHEScheme

import ../vbuffer, ../multihash, ../multicodec
import nimcrypto/[rijndael, twofish, sha2, hash, hmac]
# We use `ncrutils` for constant-time hexadecimal encoding/decoding procedures.
import nimcrypto/utils as ncrutils
import ../utils/[opt, shortlog, collections, redact]
import rng
import results
export results, opt, shortlog, collections
export rng except bearSslDrbg, bearSslDrbgRef, bearSslPrng

# This is workaround for Nim's `import` bug
export rijndael, twofish, sha2, hash, hmac, ncrutils

type
  DigestSheme* = enum
    Sha256
    Sha512

  PublicKey* = object
    case scheme*: PKScheme
    of PKScheme.RSA:
      when PKScheme.RSA in SupportedSchemes:
        rsakey*: rsa.RsaPublicKey
      else:
        discard
    of PKScheme.Ed25519:
      when supported(PKScheme.Ed25519):
        edkey*: EdPublicKey
      else:
        discard
    of PKScheme.Secp256k1:
      when supported(PKScheme.Secp256k1):
        skkey*: SkPublicKey
      else:
        discard
    of PKScheme.ECDSA:
      when supported(PKScheme.ECDSA):
        eckey*: ecnist.EcPublicKey
      else:
        discard

  PrivateKey* = object
    case scheme*: PKScheme
    of PKScheme.RSA:
      when supported(PKScheme.RSA):
        rsakey*: rsa.RsaPrivateKey
      else:
        discard
    of PKScheme.Ed25519:
      when supported(PKScheme.Ed25519):
        edkey*: EdPrivateKey
      else:
        discard
    of PKScheme.Secp256k1:
      when supported(PKScheme.Secp256k1):
        skkey*: SkPrivateKey
      else:
        discard
    of PKScheme.ECDSA:
      when supported(PKScheme.ECDSA):
        eckey*: ecnist.EcPrivateKey
      else:
        discard

  KeyPair* = object
    seckey*: PrivateKey
    pubkey*: PublicKey

  Secret* = object
    ivsize*: int
    keysize*: int
    macsize*: int
    data*: seq[byte]

  Signature* = object
    data*: seq[byte]

  CryptoError* = enum
    KeyError
    SigError
    HashError
    SchemeError

  CryptoResult*[T] = Result[T, CryptoError]

func orError*[T, E, F](res: Result[T, E], e: F): Result[T, F] =
  if res.isErr():
    return err(e)
  when T is void:
    ok()
  else:
    ok(res.get())

proc random*(
    T: typedesc[PrivateKey], scheme: PKScheme, rng: Rng, bits = RsaDefaultKeySize
): CryptoResult[PrivateKey] =
  ## Generate random private key for scheme ``scheme``.
  ##
  ## ``bits`` is number of bits for RSA key, ``bits`` value must be in
  ## [2048, 4096], default value is 3072 bits.
  case scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      let rsakey = ?RsaPrivateKey.random(rng, bits).orError(CryptoError.KeyError)
      ok(PrivateKey(scheme: scheme, rsakey: rsakey))
    else:
      err(SchemeError)
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      let edkey = EdPrivateKey.random(rng)
      ok(PrivateKey(scheme: scheme, edkey: edkey))
    else:
      err(SchemeError)
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      let eckey =
        ?ecnist.EcPrivateKey.random(Secp256r1, rng).orError(CryptoError.KeyError)
      ok(PrivateKey(scheme: scheme, eckey: eckey))
    else:
      err(SchemeError)
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      let skkey = SkPrivateKey.random(rng)
      ok(PrivateKey(scheme: scheme, skkey: skkey))
    else:
      err(SchemeError)

proc random*(
    T: typedesc[PrivateKey], rng: Rng, bits = RsaDefaultKeySize
): CryptoResult[PrivateKey] =
  ## Generate random private key using default public-key cryptography scheme.
  ##
  ## Default public-key cryptography schemes are following order:
  ## ed25519, secp256k1, RSA, secp256r1.
  ##
  ## So will be used first available (supported) method.
  when supported(PKScheme.Ed25519):
    let edkey = EdPrivateKey.random(rng)
    ok(PrivateKey(scheme: PKScheme.Ed25519, edkey: edkey))
  elif supported(PKScheme.Secp256k1):
    let skkey = SkPrivateKey.random(rng)
    ok(PrivateKey(scheme: PKScheme.Secp256k1, skkey: skkey))
  elif supported(PKScheme.RSA):
    let rsakey = ?RsaPrivateKey.random(rng, bits).orError(CryptoError.KeyError)
    ok(PrivateKey(scheme: PKScheme.RSA, rsakey: rsakey))
  elif supported(PKScheme.ECDSA):
    let eckey =
      ?ecnist.EcPrivateKey.random(Secp256r1, rng).orError(CryptoError.KeyError)
    ok(PrivateKey(scheme: PKScheme.ECDSA, eckey: eckey))
  else:
    err(SchemeError)

proc random*(
    T: typedesc[KeyPair], scheme: PKScheme, rng: Rng, bits = RsaDefaultKeySize
): CryptoResult[KeyPair] =
  ## Generate random key pair for scheme ``scheme``.
  ##
  ## ``bits`` is number of bits for RSA key, ``bits`` value must be in
  ## [2048, 4096], default value is 3072 bits.
  case scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      let pair = ?RsaKeyPair.random(rng, bits).orError(CryptoError.KeyError)
      ok(
        KeyPair(
          seckey: PrivateKey(scheme: scheme, rsakey: pair.seckey),
          pubkey: PublicKey(scheme: scheme, rsakey: pair.pubkey),
        )
      )
    else:
      err(SchemeError)
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      let pair = EdKeyPair.random(rng)
      ok(
        KeyPair(
          seckey: PrivateKey(scheme: scheme, edkey: pair.seckey),
          pubkey: PublicKey(scheme: scheme, edkey: pair.pubkey),
        )
      )
    else:
      err(SchemeError)
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      let pair = ?EcKeyPair.random(Secp256r1, rng).orError(CryptoError.KeyError)
      ok(
        KeyPair(
          seckey: PrivateKey(scheme: scheme, eckey: pair.seckey),
          pubkey: PublicKey(scheme: scheme, eckey: pair.pubkey),
        )
      )
    else:
      err(SchemeError)
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      let pair = SkKeyPair.random(rng)
      ok(
        KeyPair(
          seckey: PrivateKey(scheme: scheme, skkey: pair.seckey),
          pubkey: PublicKey(scheme: scheme, skkey: pair.pubkey),
        )
      )
    else:
      err(SchemeError)

proc random*(
    T: typedesc[KeyPair], rng: Rng, bits = RsaDefaultKeySize
): CryptoResult[KeyPair] =
  ## Generate random private pair of keys using default public-key cryptography
  ## scheme.
  ##
  ## Default public-key cryptography schemes are following order:
  ## ed25519, secp256k1, RSA, secp256r1.
  ##
  ## So will be used first available (supported) method.
  when supported(PKScheme.Ed25519):
    let pair = EdKeyPair.random(rng)
    ok(
      KeyPair(
        seckey: PrivateKey(scheme: PKScheme.Ed25519, edkey: pair.seckey),
        pubkey: PublicKey(scheme: PKScheme.Ed25519, edkey: pair.pubkey),
      )
    )
  elif supported(PKScheme.Secp256k1):
    let pair = SkKeyPair.random(rng)
    ok(
      KeyPair(
        seckey: PrivateKey(scheme: PKScheme.Secp256k1, skkey: pair.seckey),
        pubkey: PublicKey(scheme: PKScheme.Secp256k1, skkey: pair.pubkey),
      )
    )
  elif supported(PKScheme.RSA):
    let pair = ?RsaKeyPair.random(rng, bits).orError(KeyError)
    ok(
      KeyPair(
        seckey: PrivateKey(scheme: PKScheme.RSA, rsakey: pair.seckey),
        pubkey: PublicKey(scheme: PKScheme.RSA, rsakey: pair.pubkey),
      )
    )
  elif supported(PKScheme.ECDSA):
    let pair = ?EcKeyPair.random(Secp256r1, rng).orError(KeyError)
    ok(
      KeyPair(
        seckey: PrivateKey(scheme: PKScheme.ECDSA, eckey: pair.seckey),
        pubkey: PublicKey(scheme: PKScheme.ECDSA, eckey: pair.pubkey),
      )
    )
  else:
    err(SchemeError)

proc getPublicKey*(key: PrivateKey): CryptoResult[PublicKey] =
  ## Get public key from corresponding private key ``key``.
  case key.scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      let rsakey = key.rsakey.getPublicKey()
      ok(PublicKey(scheme: RSA, rsakey: rsakey))
    else:
      err(SchemeError)
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      let edkey = key.edkey.getPublicKey()
      ok(PublicKey(scheme: Ed25519, edkey: edkey))
    else:
      err(SchemeError)
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      let eckey = ?key.eckey.getPublicKey().orError(KeyError)
      ok(PublicKey(scheme: ECDSA, eckey: eckey))
    else:
      err(SchemeError)
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      let skkey = key.skkey.getPublicKey()
      ok(PublicKey(scheme: Secp256k1, skkey: skkey))
    else:
      err(SchemeError)

proc toRawBytes*(
    key: PrivateKey | PublicKey, data: var openArray[byte]
): CryptoResult[int] =
  ## Serialize private key ``key`` (using scheme's own serialization) and store
  ## it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store private key ``key``.
  case key.scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      key.rsakey.toBytes(data).orError(KeyError)
    else:
      err(SchemeError)
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      ok(key.edkey.toBytes(data))
    else:
      err(SchemeError)
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      key.eckey.toBytes(data).orError(KeyError)
    else:
      err(SchemeError)
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      key.skkey.toBytes(data).orError(KeyError)
    else:
      err(SchemeError)

proc getRawBytes*(key: PrivateKey | PublicKey): CryptoResult[seq[byte]] =
  ## Return private key ``key`` in binary form (using scheme's own
  ## serialization).
  case key.scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      key.rsakey.getBytes().orError(KeyError)
    else:
      err(SchemeError)
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      ok(key.edkey.getBytes())
    else:
      err(SchemeError)
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      key.eckey.getBytes().orError(KeyError)
    else:
      err(SchemeError)
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      ok(key.skkey.getBytes())
    else:
      err(SchemeError)

proc getBytes*(key: PrivateKey): CryptoResult[seq[byte]] =
  ## Return private key ``key`` in binary form (using libp2p's protobuf
  ## serialization).
  let rawBytes = ?key.getRawBytes()
  var encoded: seq[byte]
  try:
    var stream = memoryOutput()
    stream.writeField(1, puint64(key.scheme))
    stream.writeField(2, pbytes(rawBytes))
    encoded = stream.getOutput(seq[byte])
  except IOError:
    return err(CryptoError.KeyError)
  ok(encoded)

proc getBytes*(key: PublicKey): CryptoResult[seq[byte]] =
  ## Return public key ``key`` in binary form (using libp2p's protobuf
  ## serialization).
  let rawBytes = ?key.getRawBytes()
  var encoded: seq[byte]
  {.cast(noSideEffect).}:
    try:
      var stream = memoryOutput()
      stream.writeField(1, puint64(key.scheme))
      stream.writeField(2, pbytes(rawBytes))
      encoded = stream.getOutput(seq[byte])
    except IOError:
      return err(CryptoError.KeyError)
  ok(encoded)

proc getBytes*(sig: Signature): seq[byte] =
  ## Return signature ``sig`` in binary form.
  sig.data

proc toBytes*(key: PrivateKey, data: var openArray[byte]): CryptoResult[int] =
  ## Serialize private key ``key`` (using libp2p protobuf scheme) and store
  ## it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store private key ``key``.
  let encoded = ?key.getBytes()
  let blen = len(encoded)
  if len(data) >= blen and blen > 0:
    copyMem(addr data[0], addr encoded[0], blen)
  ok(blen)

proc toBytes*(key: PublicKey, data: var openArray[byte]): CryptoResult[int] =
  ## Serialize public key ``key`` (using libp2p protobuf scheme) and store
  ## it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store public key ``key``.
  let encoded = ?key.getBytes()
  let blen = len(encoded)
  if len(data) >= blen and blen > 0:
    copyMem(addr data[0], addr encoded[0], blen)
  ok(blen)

proc toBytes*(sig: Signature, data: var openArray[byte]): int =
  ## Serialize signature ``sig`` and store it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store signature ``sig``.
  let encoded = sig.getBytes()
  let blen = len(encoded)
  if len(data) >= blen and blen > 0:
    copyMem(addr data[0], addr encoded[0], blen)
  blen

template initImpl[T: PrivateKey | PublicKey](key: var T, data: openArray[byte]): bool =
  var id: uint64
  var buffer: seq[byte]
  var gotId = false
  var gotBuffer = false
  var parseOk = false
  block parseBlock:
    if len(data) <= 0:
      break parseBlock
    {.cast(noSideEffect).}:
      try:
        var handle = memoryInput(data)
        let stream: InputStream = handle.s
        while stream.readable():
          let header = stream.readHeader()
          case header.number()
          of 1:
            id = uint64(readValue(stream, puint64))
            gotId = true
          of 2:
            buffer = seq[byte](readValue(stream, pbytes))
            gotBuffer = true
          else:
            case header.kind()
            of WireKind.Varint:
              skipValue(stream, puint64)
            of WireKind.Fixed64:
              skipValue(stream, fixed64)
            of WireKind.LengthDelim:
              skipValue(stream, pbytes)
            of WireKind.Fixed32:
              skipValue(stream, fixed32)
        parseOk = true
      except SerializationError, IOError:
        discard
  if not parseOk or not (gotId and gotBuffer) or cast[int8](id) notin SupportedSchemesInt or
      len(buffer) <= 0:
    false
  else:
    var scheme = cast[PKScheme](cast[int8](id))
    when key is PrivateKey:
      var nkey = PrivateKey(scheme: scheme)
    else:
      var nkey = PublicKey(scheme: scheme)
    case scheme
    of PKScheme.RSA:
      when supported(PKScheme.RSA):
        if init(nkey.rsakey, buffer).isOk:
          key = nkey
          true
        else:
          false
      else:
        false
    of PKScheme.Ed25519:
      when supported(PKScheme.Ed25519):
        if init(nkey.edkey, buffer):
          key = nkey
          true
        else:
          false
      else:
        false
    of PKScheme.ECDSA:
      when supported(PKScheme.ECDSA):
        if init(nkey.eckey, buffer).isOk:
          key = nkey
          true
        else:
          false
      else:
        false
    of PKScheme.Secp256k1:
      when supported(PKScheme.Secp256k1):
        if init(nkey.skkey, buffer).isOk:
          key = nkey
          true
        else:
          false
      else:
        false

proc init*(key: var PrivateKey, data: openArray[byte]): bool =
  initImpl(key, data)

proc init*(key: var PublicKey, data: openArray[byte]): bool =
  initImpl(key, data)

proc init*(sig: var Signature, data: openArray[byte]): bool =
  ## Initialize signature ``sig`` from raw binary form.
  ##
  ## Returns ``true`` on success.
  if len(data) > 0:
    sig.data = @data
    return true
  false

proc init*[T: PrivateKey | PublicKey](key: var T, data: string): bool =
  ## Initialize private/public key ``key`` from libp2p's protobuf serialized
  ## hexadecimal string representation.
  ##
  ## Returns ``true`` on success.
  key.init(ncrutils.fromHex(data))

proc init*(sig: var Signature, data: string): bool =
  ## Initialize signature ``sig`` from serialized hexadecimal string
  ## representation.
  ##
  ## Returns ``true`` on success.
  sig.init(ncrutils.fromHex(data))

proc init*(t: typedesc[PrivateKey], data: openArray[byte]): CryptoResult[PrivateKey] =
  ## Create new private key from libp2p's protobuf serialized binary form.
  var res: t
  if not res.init(data):
    err(CryptoError.KeyError)
  else:
    ok(res)

proc init*(t: typedesc[PublicKey], data: openArray[byte]): CryptoResult[PublicKey] =
  ## Create new public key from libp2p's protobuf serialized binary form.
  var res: t
  if not res.init(data):
    err(CryptoError.KeyError)
  else:
    ok(res)

proc init*(t: typedesc[Signature], data: openArray[byte]): CryptoResult[Signature] =
  ## Create new public key from libp2p's protobuf serialized binary form.
  var res: t
  if not res.init(data):
    err(SigError)
  else:
    ok(res)

proc init*(t: typedesc[PrivateKey], data: string): CryptoResult[PrivateKey] =
  ## Create new private key from libp2p's protobuf serialized hexadecimal string
  ## form.
  t.init(ncrutils.fromHex(data))

when supported(PKScheme.RSA):
  proc init*(t: typedesc[PrivateKey], key: rsa.RsaPrivateKey): PrivateKey =
    PrivateKey(scheme: RSA, rsakey: key)

  proc init*(t: typedesc[PublicKey], key: rsa.RsaPublicKey): PublicKey =
    PublicKey(scheme: RSA, rsakey: key)

when supported(PKScheme.Ed25519):
  proc init*(t: typedesc[PrivateKey], key: EdPrivateKey): PrivateKey =
    PrivateKey(scheme: Ed25519, edkey: key)

  proc init*(t: typedesc[PublicKey], key: EdPublicKey): PublicKey =
    PublicKey(scheme: Ed25519, edkey: key)

when supported(PKScheme.Secp256k1):
  proc init*(t: typedesc[PrivateKey], key: SkPrivateKey): PrivateKey =
    PrivateKey(scheme: Secp256k1, skkey: key)

  proc init*(t: typedesc[PublicKey], key: SkPublicKey): PublicKey =
    PublicKey(scheme: Secp256k1, skkey: key)

when supported(PKScheme.ECDSA):
  proc init*(t: typedesc[PrivateKey], key: ecnist.EcPrivateKey): PrivateKey =
    PrivateKey(scheme: ECDSA, eckey: key)

  proc init*(t: typedesc[PublicKey], key: ecnist.EcPublicKey): PublicKey =
    PublicKey(scheme: ECDSA, eckey: key)

proc init*(t: typedesc[PublicKey], data: string): CryptoResult[PublicKey] =
  ## Create new public key from libp2p's protobuf serialized hexadecimal string
  ## form.
  t.init(ncrutils.fromHex(data))

proc init*(t: typedesc[Signature], data: string): CryptoResult[Signature] =
  ## Create new signature from serialized hexadecimal string form.
  t.init(ncrutils.fromHex(data))

proc `==`*(key1, key2: PublicKey): bool =
  ## Return ``true`` if two public keys ``key1`` and ``key2`` of the same
  ## scheme and equal.
  if key1.scheme == key2.scheme:
    case key1.scheme
    of PKScheme.RSA:
      when supported(PKScheme.RSA):
        (key1.rsakey == key2.rsakey)
      else:
        false
    of PKScheme.Ed25519:
      when supported(PKScheme.Ed25519):
        (key1.edkey == key2.edkey)
      else:
        false
    of PKScheme.ECDSA:
      when supported(PKScheme.ECDSA):
        (key1.eckey == key2.eckey)
      else:
        false
    of PKScheme.Secp256k1:
      when supported(PKScheme.Secp256k1):
        (key1.skkey == key2.skkey)
      else:
        false
  else:
    false

proc `==`*(key1, key2: PrivateKey): bool =
  ## Return ``true`` if two private keys ``key1`` and ``key2`` of the same
  ## scheme and equal.
  if key1.scheme == key2.scheme:
    case key1.scheme
    of PKScheme.RSA:
      when supported(PKScheme.RSA):
        (key1.rsakey == key2.rsakey)
      else:
        false
    of PKScheme.Ed25519:
      when supported(PKScheme.Ed25519):
        (key1.edkey == key2.edkey)
      else:
        false
    of PKScheme.ECDSA:
      when supported(PKScheme.ECDSA):
        (key1.eckey == key2.eckey)
      else:
        false
    of PKScheme.Secp256k1:
      when supported(PKScheme.Secp256k1):
        (key1.skkey == key2.skkey)
      else:
        false
  else:
    false

proc `$`*(key: PublicKey): string =
  ## Get string representation of public key ``key``.
  case key.scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      $(key.rsakey)
    else:
      "unsupported RSA key"
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      "ed25519 key (" & $key.edkey & ")"
    else:
      "unsupported ed25519 key"
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      "secp256r1 key (" & $key.eckey & ")"
    else:
      "unsupported secp256r1 key"
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      "secp256k1 key (" & $key.skkey & ")"
    else:
      "unsupported secp256k1 key"

func shortLog*(key: PublicKey): string =
  ## Get short string representation of public key ``key``.
  case key.scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      ($key.rsakey).shortLog
    else:
      "unsupported RSA key"
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      "ed25519 key (" & ($key.edkey).shortLog & ")"
    else:
      "unsupported ed25519 key"
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      "secp256r1 key (" & ($key.eckey).shortLog & ")"
    else:
      "unsupported secp256r1 key"
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      "secp256k1 key (" & ($key.skkey).shortLog & ")"
    else:
      "unsupported secp256k1 key"

redactType(PrivateKey)
redactType(KeyPair)
redactType(Secret)

proc `$`*(sig: Signature): string =
  ## Get string representation of signature ``sig``.
  ncrutils.toHex(sig.data)

proc sign*(key: PrivateKey, data: openArray[byte]): CryptoResult[Signature] {.gcsafe.} =
  ## Sign message ``data`` using private key ``key`` and return generated
  ## signature in raw binary form.
  var res: Signature
  case key.scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      let sig = ?key.rsakey.sign(data).orError(SigError)
      res.data = ?sig.getBytes().orError(SigError)
      ok(res)
    else:
      err(SchemeError)
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      let sig = key.edkey.sign(data)
      res.data = sig.getBytes()
      ok(res)
    else:
      err(SchemeError)
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      let sig = ?key.eckey.sign(data).orError(SigError)
      res.data = ?sig.getBytes().orError(SigError)
      ok(res)
    else:
      err(SchemeError)
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      let sig = key.skkey.sign(data)
      res.data = sig.getBytes()
      ok(res)
    else:
      err(SchemeError)

proc verify*(sig: Signature, message: openArray[byte], key: PublicKey): bool =
  ## Verify signature ``sig`` using message ``message`` and public key ``key``.
  ## Return ``true`` if message signature is valid.
  case key.scheme
  of PKScheme.RSA:
    when supported(PKScheme.RSA):
      var signature: RsaSignature
      if signature.init(sig.data).isOk:
        signature.verify(message, key.rsakey)
      else:
        false
    else:
      false
  of PKScheme.Ed25519:
    when supported(PKScheme.Ed25519):
      var signature: EdSignature
      if signature.init(sig.data):
        signature.verify(message, key.edkey)
      else:
        false
    else:
      false
  of PKScheme.ECDSA:
    when supported(PKScheme.ECDSA):
      var signature: EcSignature
      if signature.init(sig.data).isOk:
        signature.verify(message, key.eckey)
      else:
        false
    else:
      false
  of PKScheme.Secp256k1:
    when supported(PKScheme.Secp256k1):
      var signature: SkSignature
      if signature.init(sig.data).isOk:
        signature.verify(message, key.skkey)
      else:
        false
    else:
      false

template makeSecret(buffer, hmactype, secret, seed: untyped) {.dirty.} =
  var ctx: hmactype
  var j = 0
  # We need to strip leading zeros, because Go bigint serialization do it.
  var offset = 0
  for i in 0 ..< len(secret):
    if secret[i] != 0x00'u8:
      break
    inc(offset)
  ctx.init(secret.toOpenArray(offset, secret.high))
  ctx.update(seed)
  var a = ctx.finish()
  while j < len(buffer):
    ctx.init(secret.toOpenArray(offset, secret.high))
    ctx.update(a.data)
    ctx.update(seed)
    var b = ctx.finish()
    var todo = len(b.data)
    if j + todo > len(buffer):
      todo = len(buffer) - j
    copyMem(addr buffer[j], addr b.data[0], todo)
    j += todo
    ctx.init(secret.toOpenArray(offset, secret.high))
    ctx.update(a.data)
    a = ctx.finish()

proc stretchKeys*(
    cipherType: string, hashType: string, sharedSecret: seq[byte]
): Secret =
  ## Expand shared secret to cryptographic keys.
  var secret: Secret
  if cipherType == "AES-128":
    secret.ivsize = aes128.sizeBlock
    secret.keysize = aes128.sizeKey
  elif cipherType == "AES-256":
    secret.ivsize = aes256.sizeBlock
    secret.keysize = aes256.sizeKey
  elif cipherType == "TwofishCTR":
    secret.ivsize = twofish256.sizeBlock
    secret.keysize = twofish256.sizeKey

  var seed = "key expansion"
  secret.macsize = 20
  let length = secret.ivsize + secret.keysize + secret.macsize
  secret.data = newSeqUninit[byte](2 * length)

  if hashType == "SHA256":
    makeSecret(secret.data, HMAC[sha256], sharedSecret, seed)
  elif hashType == "SHA512":
    makeSecret(secret.data, HMAC[sha512], sharedSecret, seed)
  secret

template goffset*(secret, id, o: untyped): untyped =
  id * (len(secret.data) shr 1) + o

template ivOpenArray*(secret: Secret, id: int): untyped =
  toOpenArray(
    secret.data, goffset(secret, id, 0), goffset(secret, id, secret.ivsize - 1)
  )

template keyOpenArray*(secret: Secret, id: int): untyped =
  toOpenArray(
    secret.data,
    goffset(secret, id, secret.ivsize),
    goffset(secret, id, secret.ivsize + secret.keysize - 1),
  )

template macOpenArray*(secret: Secret, id: int): untyped =
  toOpenArray(
    secret.data,
    goffset(secret, id, secret.ivsize + secret.keysize),
    goffset(secret, id, secret.ivsize + secret.keysize + secret.macsize - 1),
  )

proc iv*(secret: Secret, id: int): seq[byte] =
  ## Get array of bytes with with initial vector.
  var buf = newSeqUninit[byte](secret.ivsize)
  var offset =
    if id == 0:
      0
    else:
      (len(secret.data) div 2)
  copyMem(addr buf[0], addr secret.data[offset], secret.ivsize)
  buf

proc key*(secret: Secret, id: int): seq[byte] =
  var buf = newSeqUninit[byte](secret.keysize)
  var offset =
    if id == 0:
      0
    else:
      (len(secret.data) div 2)
  offset += secret.ivsize
  copyMem(addr buf[0], addr secret.data[offset], secret.keysize)
  buf

proc mac*(secret: Secret, id: int): seq[byte] =
  var buf = newSeqUninit[byte](secret.macsize)
  var offset =
    if id == 0:
      0
    else:
      (len(secret.data) div 2)
  offset += secret.ivsize + secret.keysize
  copyMem(addr buf[0], addr secret.data[offset], secret.macsize)
  buf

proc getOrder*(
    remotePubkey, localNonce: openArray[byte], localPubkey, remoteNonce: openArray[byte]
): CryptoResult[int] =
  ## Compare values and calculate `order` parameter.
  var ctx: sha256
  ctx.init()
  ctx.update(remotePubkey)
  ctx.update(localNonce)
  var digest1 = ctx.finish()
  ctx.init()
  ctx.update(localPubkey)
  ctx.update(remoteNonce)
  var digest2 = ctx.finish()
  var mh1 = ?MultiHash.init(multiCodec("sha2-256"), digest1).orError(HashError)
  var mh2 = ?MultiHash.init(multiCodec("sha2-256"), digest2).orError(HashError)
  var res = 0
  for i in 0 ..< len(mh1.data.buffer):
    res = int(mh1.data.buffer[i]) - int(mh2.data.buffer[i])
    if res != 0:
      if res < 0:
        res = -1
      elif res > 0:
        res = 1
      break
  ok(res)

proc selectBest*(order: int, p1, p2: string): string =
  ## Determines which algorithm to use from list `p1` and `p2`.
  ##
  ## Returns empty string if there no algorithms in common.
  var f, s: seq[string]
  if order < 0:
    f = strutils.split(p2, ",")
    s = strutils.split(p1, ",")
  elif order > 0:
    f = strutils.split(p1, ",")
    s = strutils.split(p2, ",")
  else:
    var p = strutils.split(p1, ",")
    return p[0]

  for felement in f:
    for selement in s:
      if felement == selement:
        return felement

## Serialization/Deserialization helpers

proc write*(vb: var VBuffer, pubkey: PublicKey) {.raises: [ResultError[CryptoError]].} =
  ## Write PublicKey value ``pubkey`` to buffer ``vb``.
  vb.writeSeq(pubkey.getBytes().tryGet())

proc write*(
    vb: var VBuffer, seckey: PrivateKey
) {.raises: [ResultError[CryptoError]].} =
  ## Write PrivateKey value ``seckey`` to buffer ``vb``.
  vb.writeSeq(seckey.getBytes().tryGet())

proc write*(vb: var VBuffer, sig: PrivateKey) {.raises: [ResultError[CryptoError]].} =
  ## Write Signature value ``sig`` to buffer ``vb``.
  vb.writeSeq(sig.getBytes().tryGet())

## protobuf_serialization extension

Protobuf.extensionDefaults(PublicKey, pbytes)

func computeFieldSize*(
    field: int, value: PublicKey, ProtoType: type ProtobufExt, skipDefault: static bool
): int =
  let bytes = value.getBytes().expect("failed to get key bytes")
  computeFieldSize(field, bytes, pbytes, skipDefault)

proc writeField*(
    stream: OutputStream,
    field: int,
    value: PublicKey,
    ProtoType: type ProtobufExt,
    skipDefault: static bool = false,
) {.raises: [IOError].} =
  let bytes = value.getBytes().expect("failed to get key bytes")
  writeField(stream, field, bytes, pbytes, skipDefault)

proc readFieldInto*(
    stream: InputStream,
    value: var PublicKey,
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  var data = default(seq[byte])

  if readFieldInto(stream, data, header, pbytes):
    if data.len == 0:
      return false

    var key = PublicKey()
    if key.init(data):
      value = key
      return true
    raise newException(ProtobufValueError, "Invalid PublicKey")

  false

Protobuf.extensionDefaults(Signature, pbytes)

func computeFieldSize*(
    field: int, value: Signature, ProtoType: type ProtobufExt, skipDefault: static bool
): int =
  let bytes = value.getBytes()
  computeFieldSize(field, bytes, pbytes, skipDefault)

proc writeField*(
    stream: OutputStream,
    field: int,
    value: Signature,
    ProtoType: type ProtobufExt,
    skipDefault: static bool = false,
) {.raises: [IOError].} =
  let bytes = value.getBytes()
  writeField(stream, field, bytes, pbytes, skipDefault)

proc readFieldInto*(
    stream: InputStream,
    value: var Signature,
    header: FieldHeader,
    ProtoType: type ProtobufExt,
): bool {.raises: [SerializationError, IOError].} =
  var data = default(seq[byte])

  if readFieldInto(stream, data, header, pbytes):
    if data.len == 0:
      return false

    var sig = Signature()
    if sig.init(data):
      value = sig
      return true
    raise newException(ProtobufValueError, "Invalid Signature")

  false
