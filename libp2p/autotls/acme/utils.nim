# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import base64, strformat, strutils, json
import chronos/apps/http/httpclient, json_serialization
import nimcrypto/sha2
import ../../transports/tls/certificate_ffi
import ../../crypto/rsa
import ../../results

func header*(
    table: HttpTable, key: string
): Result[string, LPResultError] {.raises: [].} =
  if not table.contains(key):
    return err(key, "key not present in headers")
  ok(table.getString(key))

func tryGetStr*(node: JsonNode, key: string): Result[string, LPResultError] =
  let field = node{key}
  if field.isNil() or field.kind != JString:
    return err(key, "missing string field")
  ok(field.getStr())

proc tryTo*[T](node: JsonNode, _: typedesc[T]): Result[T, LPResultError] =
  try:
    ok(node.to(T))
  except CatchableError as e:
    err(e, fmt"failed to decode {$T}")

func tryParseEnum*[T: enum](s: string): Result[T, LPResultError] =
  for v in T:
    if $v == s:
      return ok(v)
  err(s, fmt"invalid {$T}")

proc base64UrlEncode*(data: seq[byte]): string =
  ## Encodes data using base64url (RFC 4648 §5) — no padding, URL-safe
  var encoded = base64.encode(data, safe = true)
  encoded.removeSuffix("=")
  encoded.removeSuffix("=")
  return encoded

proc thumbprint*(key: RsaPrivateKey): string =
  let pubkey = key.getPublicKey()
  let nArray = @(getArray(pubkey.buffer, pubkey.key.n, pubkey.key.nlen))
  let eArray = @(getArray(pubkey.buffer, pubkey.key.e, pubkey.key.elen))

  let n = base64UrlEncode(nArray)
  let e = base64UrlEncode(eArray)
  let keyJson = %*{"e": e, "kty": "RSA", "n": n}
  let digest = sha256.digest($keyJson)
  return base64UrlEncode(@(digest.data))

proc getResponseBody*(
    response: HttpClientResponseRef
): Future[Result[JsonNode, LPResultError]] {.async: (raises: [CancelledError]).} =
  try:
    let bodyBytes = await response.getBodyBytes()
    if bodyBytes.len == 0:
      return ok(%*{})
    ok(Json.decode(bodyBytes, JsonNode))
  except CancelledError as e:
    raise e
  except CatchableError as e:
    err(e, "Failed to read response body")

proc createCSR*(
    domain: string, certKeyPair: RsaPrivateKey
): Result[string, LPResultError] =
  let rawSeckey = certKeyPair.getBytes().valueOr:
    return err(error, "Failed to get RSA private key bytes (DER)")
  let certKey = cert_new_key_t(rawSeckey).valueOr:
    return err(error, "Failed to convert key pair to cert_key_t")
  defer:
    cert_free_key(certKey)

  let derCSR = cert_signing_req(domain, certKey).valueOr:
    return err(error, "Failed to create CSR")

  ok(base64UrlEncode(derCSR))
