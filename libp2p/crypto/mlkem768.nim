# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Raw ML-KEM-768 (FIPS 203) key encapsulation.
##
## This wraps the `MLKEM768_*` C API already vendored into nim-libp2p through
## its `boringssl` dependency (`crypto/mlkem/mlkem.cc`), rather than pulling in
## a separate, unaudited PQC library. BoringSSL's ML-KEM-768 implementation is
## the same one shipped in Chrome's TLS stack.
##
## https://csrc.nist.gov/pubs/fips/203/final

{.push raises: [].}

import boringssl
import results
import ./mlkem768layout
export results

const
  MLKEM768PublicKeyLen* = 1184
    ## Encoded ML-KEM-768 encapsulation (public) key size, in bytes.
  MLKEM768CiphertextLen* = 1088
    ## ML-KEM-768 ciphertext size, in bytes.
  MLKEM768SharedSecretLen* = 32
    ## ML-KEM-768 shared secret size, in bytes.

type
  MLKEM768PublicKeyBytes* = array[MLKEM768PublicKeyLen, byte]
  MLKEM768CiphertextBytes* = array[MLKEM768CiphertextLen, byte]
  MLKEM768SharedSecret* = array[MLKEM768SharedSecretLen, byte]

  MLKEM768ParsedPublicKey = array[mlkem768PublicKeyOpaqueLen, byte]
  MLKEM768PrivateKeyImpl = array[mlkem768PrivateKeyOpaqueLen, byte]

  MLKEM768KeyPair* = object
    publicKey*: MLKEM768PublicKeyBytes ## wire-ready encoded public key
    privateKey: MLKEM768PrivateKeyImpl

  MLKEM768EncapResult* = object
    ciphertext*: MLKEM768CiphertextBytes
    sharedSecret*: MLKEM768SharedSecret

  MLKEM768Error* = enum
    MLKEM768InvalidPublicKey
    MLKEM768InvalidCiphertextLength

  # Mirrors BoringSSL's `struct cbs_st` (a {data, len} byte-string view) from
  # `include/openssl/bytestring.h`, so a view can be built without calling
  # the header-only inline `CBS_init`.
  CbsView {.pure, bycopy.} = object
    data: ptr byte
    len: csize_t

{.push cdecl.}
proc mlkem768GenerateKeyC(
  outEncodedPublicKey: ptr byte, outSeed: pointer, outPrivateKey: ptr byte
) {.importc: "MLKEM768_generate_key".}

proc mlkem768ParsePublicKeyC(
  outPublicKey: ptr byte, inCbs: ptr CbsView
): cint {.importc: "MLKEM768_parse_public_key".}

proc mlkem768EncapC(
  outCiphertext: ptr byte, outSharedSecret: ptr byte, publicKey: ptr byte
) {.importc: "MLKEM768_encap".}

proc mlkem768DecapC(
  outSharedSecret: ptr byte,
  ciphertext: ptr byte,
  ciphertextLen: csize_t,
  privateKey: ptr byte,
): cint {.importc: "MLKEM768_decap".}

{.pop.} # cdecl

proc generateKeyPair*(): MLKEM768KeyPair =
  ## Generates a fresh ML-KEM-768 keypair. `result.publicKey` is the
  ## wire-format encapsulation key ready to be sent to a peer.
  mlkem768GenerateKeyC(
    addr result.publicKey[0], nil, addr result.privateKey[0]
  )

proc encapsulate*(
    remotePublicKey: openArray[byte]
): Result[MLKEM768EncapResult, MLKEM768Error] =
  ## Encapsulates a fresh shared secret for `remotePublicKey`, which must be
  ## the `MLKEM768PublicKeyLen`-byte encoded public key received from a peer.
  if remotePublicKey.len != MLKEM768PublicKeyLen:
    return err(MLKEM768InvalidPublicKey)

  var cbs = CbsView(data: unsafeAddr remotePublicKey[0], len: remotePublicKey.len.csize_t)
  var parsed: MLKEM768ParsedPublicKey
  if mlkem768ParsePublicKeyC(addr parsed[0], addr cbs) != 1:
    return err(MLKEM768InvalidPublicKey)

  var res: MLKEM768EncapResult
  mlkem768EncapC(addr res.ciphertext[0], addr res.sharedSecret[0], addr parsed[0])
  ok(res)

proc decapsulate*(
    ciphertext: openArray[byte], keyPair: MLKEM768KeyPair
): Result[MLKEM768SharedSecret, MLKEM768Error] =
  ## Recovers the shared secret from `ciphertext` using `keyPair`'s private
  ## key. Per FIPS 203 6.4 implicit rejection, a `ciphertext` of the correct
  ## length that was not produced for this key does not fail here - it
  ## silently yields a pseudorandom shared secret, so the handshake's AEAD
  ## authentication (not this call) is what detects tampering or a mismatched
  ## key. Only a wrong-length ciphertext is rejected outright.
  if ciphertext.len != MLKEM768CiphertextLen:
    return err(MLKEM768InvalidCiphertextLength)

  var secret: MLKEM768SharedSecret
  if mlkem768DecapC(
    addr secret[0], unsafeAddr ciphertext[0], ciphertext.len.csize_t,
    unsafeAddr keyPair.privateKey[0],
  ) != 1:
    return err(MLKEM768InvalidCiphertextLength)
  ok(secret)
