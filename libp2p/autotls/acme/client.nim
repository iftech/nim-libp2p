# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import uri
import nimcrypto/sha2
import chronos, chronicles, results, stew/byteutils
import ../../crypto/rsa
import ../../crypto/rng
import ../../utils/opt
import ./api
import ./utils

export api

type KeyAuthorization* = string

type ACMEClient* = ref object
  api: ACMEApi
  key*: RsaPrivateKey
  kid*: Kid

logScope:
  topics = "libp2p auto-tls"

proc new*(
    T: typedesc[ACMEClient],
    rng: Rng,
    api: ACMEApi = ACMEApi.new(),
    key: Opt[RsaPrivateKey] = Opt.none(RsaPrivateKey),
    kid: Kid = Kid(""),
): T {.raises: [].} =
  let key = key.valueOr:
    RsaPrivateKey.random(rng).get()
  T(api: api, key: key, kid: kid)

proc getOrInitKid*(
    self: ACMEClient
): Future[Result[Kid, string]] {.async: (raises: [CancelledError]).} =
  if self.kid.len == 0:
    let registerResponse = ?(await self.api.requestRegister(self.key))
    self.kid = registerResponse.kid
  ok(self.kid)

proc genKeyAuthorization*(self: ACMEClient, token: string): KeyAuthorization =
  base64UrlEncode(@(sha256.digest((token & "." & thumbprint(self.key)).toBytes).data))

proc getChallenge*(
    self: ACMEClient, domains: seq[api.Domain]
): Future[Result[ACMEChallengeDns01Response, string]] {.
    async: (raises: [CancelledError])
.} =
  let kid = ?(await self.getOrInitKid())
  await self.api.requestChallenge(domains, self.key, kid)

proc getCertificate*(
    self: ACMEClient,
    domain: api.Domain,
    certKeyPair: RsaPrivateKey,
    challenge: ACMEChallengeDns01Response,
    acmeRetries: int = 10,
    finalizeRetries: int = 10,
): Future[Result[ACMECertificateResponse, string]] {.async: (raises: [CancelledError]).} =
  let chalURL = parseUri(challenge.dns01.url)
  let orderURL = parseUri(challenge.order)
  let finalizeURL = parseUri(challenge.finalize)
  let kid = ?(await self.getOrInitKid())

  trace "Sending challenge completed notification"
  discard ?(await self.api.sendChallengeCompleted(chalURL, self.key, kid))

  trace "Checking for completed challenge"
  let completed =
    ?(await self.api.checkChallengeCompleted(chalURL, self.key, kid, acmeRetries))
  if not completed:
    return err("Failed to signal ACME server about challenge completion")

  trace "Waiting for certificate to be finalized"
  let finalized = ?(
    await self.api.certificateFinalized(
      domain, finalizeURL, orderURL, certKeyPair, self.key, kid, finalizeRetries
    )
  )
  if not finalized:
    return err("Failed to finalize certificate for domain " & domain)

  trace "Downloading certificate"
  await self.api.downloadCertificate(orderURL, self.key, kid)

proc close*(self: ACMEClient) {.async: (raises: [CancelledError]).} =
  await self.api.close()
