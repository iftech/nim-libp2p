# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Minimal JSON Web Signature (JWS) producer for the ACME client.
##
## libp2p only ever needs to *issue* RS256-signed requests to the ACME server,
## so this module implements just the flattened JWS JSON serialization
## (RFC 7515, section 7.2.2) using RSASSA-PKCS1-v1_5 with SHA-256. The signing
## reuses `crypto/rsa`, whose `sign` is already exactly an RS256 signer (same
## PKCS#1 v1.5 padding, SHA-256 digest and DigestInfo OID), so no signing code
## is vendored. This replaces the former `nim-jwt` dependency, of which only
## this slice was ever used.

import json
import results
import stew/byteutils
import ./utils
import ../../crypto/rsa

const SupportedAlg = "RS256"

proc toFlattenedJws*(
    protectedHeader: JsonNode, payload: string, key: rsa.RsaPrivateKey
): Result[JsonNode, string] {.raises: [].} =
  ## Signs `protectedHeader` and the already-serialized `payload` with `key` (RS256)
  ## and returns the flattened JWS JSON serialization: the base64url-encoded
  ## `protected`, `payload` and `signature` members.
  ##
  ## The signature covers `BASE64URL(protected) || '.' || BASE64URL(payload)`
  ## exactly as transmitted, so the JSON key ordering of the inputs does not
  ## affect verification.
  let alg = protectedHeader{"alg"}.getStr()
  if alg != SupportedAlg:
    return err("Unsupported JWS algorithm: " & alg)

  let
    protectedB64 = base64UrlEncode(($protectedHeader).toBytes)
    payloadB64 = base64UrlEncode(payload.toBytes)
    signingInput = protectedB64 & "." & payloadB64

  let signature = key.sign(signingInput).valueOr:
    return err("Failed to create JWS signature")
  let signatureBytes = signature.getBytes().valueOr:
    return err("Failed to encode JWS signature bytes")

  ok(
    %*{
      "payload": payloadB64,
      "protected": protectedB64,
      "signature": base64UrlEncode(signatureBytes),
    }
  )

proc toFlattenedJws*(
    protectedHeader: JsonNode, payload: JsonNode, key: rsa.RsaPrivateKey
): Result[JsonNode, string] {.raises: [].} =
  toFlattenedJws(protectedHeader, $payload, key)
