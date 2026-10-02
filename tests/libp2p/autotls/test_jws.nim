# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import json, base64, strutils
import stew/byteutils
import ../../../libp2p/crypto/rsa
import ../../../libp2p/autotls/acme/jws
import ../../tools/[unittest, crypto]

proc b64UrlDecode(s: string): seq[byte] {.raises: [ValueError].} =
  var padded = s.replace('-', '+').replace('_', '/')
  while padded.len mod 4 != 0:
    padded &= "="
  base64.decode(padded).toBytes()

suite "ACME JWS":
  let key = RsaPrivateKey.random(rng()).get()

  test "produces a valid RS256 flattened JWS":
    let header = %*{"alg": "RS256", "typ": "JWT", "nonce": "abc", "url": "https://e"}
    let payload = %*{"termsOfServiceAgreed": true}

    let jws = toFlattenedJws(header, payload, key).get()

    # Flattened JWS has exactly the three members (no unprotected header).
    check jws.kind == JObject
    check jws.len == 3
    for field in ["protected", "payload", "signature"]:
      check jws.hasKey(field)

    # protected/payload base64url-decode back to the original JSON inputs.
    check parseJson(string.fromBytes(b64UrlDecode(jws["protected"].getStr))) == header
    check parseJson(string.fromBytes(b64UrlDecode(jws["payload"].getStr))) == payload

    # The signature verifies as RS256 over `protected.payload`.
    let signingInput = jws["protected"].getStr & "." & jws["payload"].getStr
    let sig = RsaSignature.init(b64UrlDecode(jws["signature"].getStr)).get()
    check rsa.verify(sig, signingInput, key.getPublicKey())

  test "base64url members carry no padding":
    let jws = toFlattenedJws(%*{"alg": "RS256"}, %*{"a": 1}, key).get()
    for field in ["protected", "payload", "signature"]:
      check not jws[field].getStr.contains('=')
      check not jws[field].getStr.contains('+')
      check not jws[field].getStr.contains('/')

  test "an empty JSON payload still signs and verifies":
    let jws = toFlattenedJws(%*{"alg": "RS256"}, %*{}, key).get()
    let signingInput = jws["protected"].getStr & "." & jws["payload"].getStr
    let sig = RsaSignature.init(b64UrlDecode(jws["signature"].getStr)).get()
    check rsa.verify(sig, signingInput, key.getPublicKey())

  test "a zero-length payload still signs and verifies":
    let jws = toFlattenedJws(%*{"alg": "RS256"}, "", key).get()
    check jws["payload"].getStr == ""
    let signingInput = jws["protected"].getStr & "." & jws["payload"].getStr
    let sig = RsaSignature.init(b64UrlDecode(jws["signature"].getStr)).get()
    check rsa.verify(sig, signingInput, key.getPublicKey())

  test "rejects an unsupported algorithm":
    check toFlattenedJws(%*{"alg": "ES256"}, %*{"a": 1}, key).error ==
      "Unsupported JWS algorithm: ES256"
    check toFlattenedJws(%*{"typ": "JWT"}, %*{"a": 1}, key).error ==
      "Unsupported JWS algorithm: "
