# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import base64, strutils, json
import chronos/apps/http/httpclient, results, json_serialization
import nimcrypto/sha2
import ../../transports/tls/certificate_ffi
import ../../crypto/rsa

func header*(table: HttpTable, key: string): Result[string, string] {.raises: [].} =
  if not table.contains(key):
    return err("key " & key & " not present in headers")
  ok(table.getString(key))

func tryGetStr*(node: JsonNode, key: string): Result[string, string] =
  let field = node{key}
  if field.isNil() or field.kind != JString:
    return err("missing string field: " & key)
  ok(field.getStr())

proc tryTo*[T](node: JsonNode, _: typedesc[T]): Result[T, string] =
  try:
    ok(node.to(T))
  except CatchableError as e:
    err("failed to decode " & $T & ": " & e.msg)

func tryParseEnum*[T: enum](s: string): Result[T, string] =
  for v in T:
    if $v == s:
      return ok(v)
  err("invalid " & $T & ": " & s)

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
): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
  try:
    let bodyBytes = await response.getBodyBytes()
    if bodyBytes.len == 0:
      return ok(%*{})
    ok(Json.decode(bodyBytes, JsonNode))
  except CancelledError as e:
    raise e
  except CatchableError as e:
    err("Failed to read response body: " & e.msg)

proc createCSR*(domain: string, certKeyPair: RsaPrivateKey): Result[string, string] =
  let rawSeckey = certKeyPair.getBytes().valueOr:
    return err("Failed to get RSA private key bytes (DER)")
  let certKey = cert_new_key_t(rawSeckey).valueOr:
    return err("Failed to convert key pair to cert_key_t")
  defer:
    cert_free_key(certKey)

  let derCSR = cert_signing_req(domain, certKey).valueOr:
    return err("Failed to create CSR")

  ok(base64UrlEncode(derCSR))
