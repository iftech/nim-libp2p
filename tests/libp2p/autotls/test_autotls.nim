# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import base64, sequtils, json, strutils, uri, chronos, chronos/apps/http/httpclient
from times import dateTime, format, initDuration, mNov, timezone, utc, `-`, `==`
import
  ../../../libp2p/
    [stream/connection, upgrademngrs/upgrade, autotls/acme/client, crypto/rsa, wire]
import ../../tools/[unittest, http_server, crypto]
import ../../stubs/acme_api_stub
import ./rfc_vectors

suite "AutoTLS ACME API":
  const WildcardDomain = "*.example.libp2p.direct"

  # RSA generation dominates the runtime of every test here, so one pair for all.
  let
    key = RsaPrivateKey.random(rng()).get()
    certKey = RsaPrivateKey.random(rng()).get()
    certPem = tlsCertPemGenerator()

  var api {.threadvar.}: ACMEApiStub

  asyncTeardown:
    await api.close()
    checkTrackers()

  asyncSetup:
    api = ACMEApiStub.new()

  asyncTest "register to acme server":
    api.queueRegister()

    let registerResponse = (await api.requestRegister(key)).get()
    check registerResponse.kid == AccountURL

  asyncTest "request challenge for a domain":
    api.queueOrder("pending", %*[AuthorizationsURL])

    let challengeResponse =
      (await api.requestNewOrder(@["some.dummy.domain.com"], key, "kid")).get()
    check challengeResponse.status == ACMEOrderStatus.PENDING
    check challengeResponse.authorizations == [AuthorizationsURL]
    check challengeResponse.finalize == FinalizeURL
    check challengeResponse.order == OrderURL

    api.queueChallenges(
      %*[
        {
          "url": ChallengeURL,
          "type": "dns-01",
          "status": "pending",
          "token": "expected-dns01-token",
        }
      ]
    )

    let authorizationsResponse = (
      await api.requestAuthorizations(challengeResponse.authorizations, key, "kid")
    ).get()
    check authorizationsResponse.challenges.len > 0

    let dns01 = authorizationsResponse.challenges.filterIt(
      it.`type` == ACMEChallengeType.DNS01
    )[0]
    check dns01.url == ChallengeURL
    check dns01.`type` == ACMEChallengeType.DNS01
    check dns01.token == ACMEChallengeToken("expected-dns01-token")
    check dns01.status == ACMEChallengeStatus.PENDING

  asyncTest "challenge completed successful":
    api.queueChallengeCompleted()
    check (await api.sendChallengeCompleted(parseUri(ChallengeURL), key, "kid")).isOk()

    api.queueStatus("valid")
    let completed =
      (await api.checkChallengeCompleted(parseUri(ChallengeURL), key, "kid")).get()

    check:
      completed == true
      api.requestedUris == @[parseUri(ChallengeURL), parseUri(ChallengeURL)]

  asyncTest "challenge processing is polled until valid":
    api.queueStatus("processing")
    api.queueStatus("valid")
    let completed =
      await api.checkChallengeCompleted(parseUri(ChallengeURL), key, "kid", retries = 1)
    check completed.get()
    check api.requestedUris == @[parseUri(ChallengeURL), parseUri(ChallengeURL)]

  asyncTest "challenge completed max retries reached":
    api.queueChallengeCompleted()
    check (await api.sendChallengeCompleted(parseUri(ChallengeURL), key, "kid")).isOk()

    # retries is the number of checks after the first one, so two polls
    api.queueStatus("pending")
    api.queueStatus("pending")
    let completed = (
      await api.checkChallengeCompleted(parseUri(ChallengeURL), key, "kid", retries = 1)
    ).get()

    check:
      completed == false
      api.requestedUris ==
        @[parseUri(ChallengeURL), parseUri(ChallengeURL), parseUri(ChallengeURL)]

  asyncTest "challenge completed invalid":
    api.queueChallengeCompleted()
    check (await api.sendChallengeCompleted(parseUri(ChallengeURL), key, "kid")).isOk()

    api.queueStatus("invalid")
    check (await api.checkChallengeCompleted(parseUri(ChallengeURL), key, "kid")).isErr()

    # an invalid challenge raises on the first check instead of polling on
    check api.requestedUris == @[parseUri(ChallengeURL), parseUri(ChallengeURL)]

  asyncTest "finalize certificate successful":
    api.queueStatus("valid") # requestFinalize
    api.queueStatus("valid") # checkCertFinalized

    let finalized = await api.certificateFinalized(
      "some-domain", parseUri(FinalizeURL), parseUri(OrderURL), certKey, key, "kid"
    )

    check:
      finalized.get() == true
      api.requestedUris == @[parseUri(FinalizeURL), parseUri(OrderURL)]

  asyncTest "finalize certificate processing then valid":
    api.queueStatus("valid") # requestFinalize
    api.queueStatus("processing")
    api.queueStatus("valid")

    let finalized = await api.certificateFinalized(
      "some-domain", parseUri(FinalizeURL), parseUri(OrderURL), certKey, key, "kid"
    )

    check:
      finalized.get() == true
      api.requestedUris ==
        @[parseUri(FinalizeURL), parseUri(OrderURL), parseUri(OrderURL)]

  asyncTest "finalize certificate max retries reached":
    api.queueStatus("valid") # requestFinalize
    # retries is the number of checks after the first one, so two polls
    api.queueStatus("processing")
    api.queueStatus("processing")

    let finalized = await api.certificateFinalized(
      "some-domain",
      parseUri(FinalizeURL),
      parseUri(OrderURL),
      certKey,
      key,
      "kid",
      retries = 1,
    )

    check:
      finalized.get() == false
      api.requestedUris ==
        @[parseUri(FinalizeURL), parseUri(OrderURL), parseUri(OrderURL)]

  asyncTest "finalize certificate invalid":
    api.queueStatus("valid") # requestFinalize
    api.queueStatus("invalid")

    let finalized = await api.certificateFinalized(
      "some-domain", parseUri(FinalizeURL), parseUri(OrderURL), certKey, key, "kid"
    )

    check:
      finalized.isErr()
      # an invalid order ends the poll instead of retrying
      api.requestedUris == @[parseUri(FinalizeURL), parseUri(OrderURL)]

  asyncTest "expect error on invalid JSON response":
    # One response per call below
    api.queueInvalidBody(10)

    # The stub overrides requestNonce, so procCall reaches the real one.
    check (await procCall requestNonce(ACMEApi(api))).isErr()

    check (await api.requestRegister(key)).isErr()

    check (await api.requestNewOrder(@["some-domain"], key, "kid")).isErr()

    check (await api.requestAuthorizations(@[AuthorizationsURL], key, "kid")).isErr()

    check (await api.requestChallenge(@["domain-1", "domain-2"], key, "kid")).isErr()

    check (
      await api.requestCheck(
        parseUri(OrderURL), ACMECheckKind.ACMEOrderCheck, key, "kid"
      )
    ).isErr()

    check (
      await api.requestCheck(
        parseUri(ChallengeURL), ACMECheckKind.ACMEChallengeCheck, key, "kid"
      )
    ).isErr()

    check (await api.sendChallengeCompleted(parseUri(ChallengeURL), key, "kid")).isErr()

    check (
      await api.requestFinalize(
        "some-domain", parseUri(FinalizeURL), certKey, key, "kid"
      )
    ).isErr()

    check (await api.requestGetOrder(parseUri(OrderURL), key, "kid")).isErr()

    check api.requestedUris.len == 10

  asyncTest "the directory URL is used as given":
    let acmeApi = ACMEApi.new(parseUri("http://acme.example/dir"))
    defer:
      await acmeApi.close()

    check acmeApi.directoryURL == parseUri("http://acme.example/dir")

  asyncTest "the directory is fetched once and cached":
    # The cache is only observable on a stub that was not handed a directory.
    await api.close()
    api = ACMEApiStub.new(directory = Opt.none(ACMEDirectory))
    api.mockedResponses.add(
      HTTPResponse(
        body: %*{
          "newNonce": StubDirectory.newNonce,
          "newOrder": StubDirectory.newOrder,
          "newAccount": StubDirectory.newAccount,
        },
        headers: HttpTable.init(),
      )
    )
    for _ in 0 ..< 2:
      api.mockedResponses.add(
        HTTPResponse(
          body: %*{}, headers: HttpTable.init(@[("Replay-Nonce", "some-nonce")])
        )
      )

    # The stub overrides requestNonce, so call the real one that consults the directory.
    check (await procCall requestNonce(ACMEApi(api))).isOk()
    check (await procCall requestNonce(ACMEApi(api))).isOk()

    check api.requestedUris ==
      @[
        parseUri(DirectoryURL),
        parseUri(StubDirectory.newNonce),
        parseUri(StubDirectory.newNonce),
      ]

  asyncTest "the replay nonce is read from the response header":
    const nonce = "some-replay-nonce"
    api.mockedResponses.add(
      HTTPResponse(body: %*{}, headers: HttpTable.init(@[("Replay-Nonce", nonce)]))
    )

    check (await procCall requestNonce(ACMEApi(api))).get() == nonce

  asyncTest "the register request is signed with a jwk":
    api.queueRegister()

    check (await api.requestRegister(key)).isOk()

    check api.protectedHeader(0).hasKey("jwk")

  asyncTest "the register request agrees to the terms of service":
    api.queueRegister()

    check (await api.requestRegister(key)).isOk()

    check api.signedPayload(0)["termsOfServiceAgreed"].getBool

  asyncTest "an order request is signed with the account kid":
    api.queueOrder("pending", %*[AuthorizationsURL])

    check (await api.requestNewOrder(@[WildcardDomain], key, AccountURL)).isOk()

    check api.protectedHeader(0)["kid"].getStr == AccountURL

  asyncTest "the order payload names the domain as a dns identifier":
    api.queueOrder("pending", %*[AuthorizationsURL])

    check (await api.requestNewOrder(@[WildcardDomain], key, AccountURL)).isOk()

    check api.signedPayload(0)["identifiers"] ==
      %*[{"type": "dns", "value": WildcardDomain}]

  asyncTest "successive signed requests carry different nonces":
    api.queueRegister()
    api.queueOrder("pending", %*[AuthorizationsURL])

    check (await api.requestRegister(key)).isOk()
    check (await api.requestNewOrder(@[WildcardDomain], key, AccountURL)).isOk()

    check api.protectedHeader(0)["nonce"] != api.protectedHeader(1)["nonce"]

  asyncTest "an order with no authorizations is refused":
    api.queueOrder("pending", %*[])

    check (await api.requestNewOrder(@[WildcardDomain], key, AccountURL)).isErr()

  asyncTest "an order that is neither pending nor ready is refused":
    api.queueOrder("invalid", %*[AuthorizationsURL])
    # The authorization is in place, so only the status can stop the call.
    api.queueChallenges(
      %*[{"type": "dns-01", "url": ChallengeURL, "status": "pending", "token": "t"}]
    )

    check (await api.requestChallenge(@[WildcardDomain], key, AccountURL)).isErr()

  asyncTest "an authorization offering no dns-01 challenge is refused":
    api.queueOrder("pending", %*[AuthorizationsURL])
    api.queueChallenges(
      %*[
        {"type": "http-01", "url": ChallengeURL, "status": "pending", "token": "t"},
        {"type": "tls-alpn-01", "url": ChallengeURL, "status": "pending", "token": "t"},
      ]
    )

    check (await api.requestChallenge(@[WildcardDomain], key, AccountURL)).isErr()

  asyncTest "a register response with no location header is refused":
    api.mockedResponses.add(
      HTTPResponse(body: %*{"status": "valid"}, headers: HttpTable.init())
    )

    check (await api.requestRegister(key)).isErr()

  asyncTest "the finalize payload carries a csr naming the domain":
    api.queueStatus("valid")

    check (
      await api.requestFinalize(
        WildcardDomain, parseUri(FinalizeURL), rfc7517Key(), key, AccountURL
      )
    ).isOk()

    check base64.decode(api.signedPayload(0)["csr"].getStr).contains(WildcardDomain)

  asyncTest "the csr is sent as base64url without padding":
    api.queueStatus("valid")

    check (
      await api.requestFinalize(
        WildcardDomain, parseUri(FinalizeURL), rfc7517Key(), key, AccountURL
      )
    ).isOk()

    check not api.signedPayload(0)["csr"].getStr.endsWith('=')

  asyncTest "an unrecognized challenge type does not discard the dns-01 beside it":
    api.queueChallenges(
      %*[
        {
          "type": "dns-account-01",
          "url": "https://acme.example/chal/2",
          "status": "pending",
          "token": "t",
        },
        {"type": "dns-01", "url": ChallengeURL, "status": "pending", "token": "t"},
      ]
    )

    let authorizations =
      (await api.requestAuthorizations(@[AuthorizationsURL], key, AccountURL)).get()

    check authorizations.challenges.len == 1
    check authorizations.challenges[0].`type` == ACMEChallengeType.DNS01
    check authorizations.challenges[0].url == ChallengeURL

  asyncTest "authorization, status and order resources are read with POST-as-GET":
    api.queueChallenges(
      %*[{"type": "dns-01", "url": ChallengeURL, "status": "pending", "token": "t"}]
    )
    api.queueStatus("valid")
    api.queueGetOrder("https://acme.example/cert/1", "2099-01-01T00:00:00Z")

    check (await api.requestAuthorizations(@[AuthorizationsURL], key, AccountURL)).isOk()
    check (await api.requestCheck(parseUri(OrderURL), ACMEOrderCheck, key, AccountURL)).isOk()
    check (await api.requestGetOrder(parseUri(OrderURL), key, AccountURL)).isOk()

    check api.payloads.len == 3
    for index in 0 ..< api.payloads.len:
      check api.encodedPayload(index) == ""

  proc downloadWithExpires(
      expires: string
  ): Future[Result[ACMECertificateResponse, string]] {.async.} =
    let certServer = startTestHttpServer(certPem)
    defer:
      await certServer.stop()

    api.directoryURL = parseUri(certServer.url)
    api.queueGetOrder(certServer.url, expires)
    # A tail `await` is freed by the deferred `await` before its value is read.
    let response = await api.downloadCertificate(parseUri(OrderURL), key, AccountURL)
    response

  asyncTest "the order's expires is parsed in UTC":
    let expiry =
      (await downloadWithExpires("2026-11-02T14:30:00Z")).get().certificateExpiry

    check expiry.timezone == utc()
    check expiry.format("yyyy-MM-dd'T'HH:mm:ss") == "2026-11-02T14:30:00"

  asyncTest "an expires with a fractional second is accepted":
    let expiry =
      (await downloadWithExpires("2026-11-02T14:30:00.125Z")).get().certificateExpiry

    check expiry - dateTime(2026, mNov, 2, 14, 30, zone = utc()) ==
      initDuration(milliseconds = 125)

  asyncTest "an expires with a numeric UTC offset is accepted":
    let expiry =
      (await downloadWithExpires("2026-11-02T16:30:00+02:00")).get().certificateExpiry

    check expiry == dateTime(2026, mNov, 2, 14, 30, zone = utc())

  asyncTest "an order whose certificate url is off the directory origin is refused":
    api.queueGetOrder("", "2026-11-02T14:30:00Z")
    api.queueGetOrder("https://elsewhere.example/cert/1", "2026-11-02T14:30:00Z")

    check (await api.downloadCertificate(parseUri(OrderURL), key, AccountURL)).isErr()

    check (await api.downloadCertificate(parseUri(OrderURL), key, AccountURL)).isErr()

suite "AutoTLS ACME API over HTTP":
  # The stub overrides get and post, so these drive the real ones.

  asyncTeardown:
    checkTrackers()

  asyncTest "a url the session cannot turn into an address is an http error":
    # an empty directory URL keeps the empty request URL on its origin
    let api = ACMEApi.new(directoryURL = parseUri(""))
    defer:
      await api.close()

    check (await api.get(parseUri(""))).isErr()

    check (await api.post(parseUri(""), "{}")).isErr()

  asyncTest "a post carries the server's response body back":
    let server = startTestHttpServer($ %*{"status": "valid"})
    let api = ACMEApi.new(directoryURL = parseUri(server.url))
    defer:
      await api.close()
      await server.stop()

    check (await api.post(parseUri(server.url), "{}")).get().body ==
      %*{"status": "valid"}

  asyncTest "a request off the directory origin is refused":
    let api = ACMEApi.new(parseUri("https://acme.example/directory"))
    defer:
      await api.close()

    check (await api.get(parseUri("https://elsewhere.example/new-nonce"))).isErr()

    check (await api.post(parseUri("http://127.0.0.1:8080/new-order"), "{}")).isErr()

    # same host, other scheme and port
    check (await api.get(parseUri("http://acme.example/new-nonce"))).isErr()

  asyncTest "a request on the directory origin is sent":
    let server = startTestHttpServer($ %*{"status": "valid"})
    let api = ACMEApi.new(directoryURL = parseUri(server.url))
    defer:
      await api.close()
      await server.stop()

    check (await api.get(parseUri(server.url & "acme/new-nonce"))).get().body ==
      %*{"status": "valid"}

  asyncTest "a directory naming a resource off its origin is refused":
    let server = startTestHttpServer(
      $ %*{"newNonce": "", "newOrder": OrderURL, "newAccount": AccountURL}
    )
    let api = ACMEApi.new(directoryURL = parseUri(server.url))
    defer:
      await api.close()
      await server.stop()

    check (await api.requestNonce()).isErr()

suite "AutoTLS ACME Client":
  const
    CertDomain = "some.domain"
    ChallengeToken = "some-token"
    # Not an RFC value. RFC 8555 §8.4 applied to ChallengeToken and the RFC 7638
    # thumbprint, computed independently of libp2p with:
    #   printf '%s' 'some-token.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs' |
    #     openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
    Dns01Digest = "XChHH-xniF3XvbGZZSwSaim3CTuk885yHgQU3qHVdeY"

  # RSA generation dominates the runtime of every test here, so one pair for all.
  let
    key = RsaPrivateKey.random(rng()).get()
    certKey = RsaPrivateKey.random(rng()).get()

  var acmeApi {.threadvar.}: ACMEApiStub
  var acme {.threadvar.}: ACMEClient

  proc dns01Challenge(): ACMEChallengeDns01Response =
    ACMEChallengeDns01Response(
      finalize: FinalizeURL,
      order: OrderURL,
      dns01: ACMEChallenge(
        url: ChallengeURL,
        `type`: ACMEChallengeType.DNS01,
        status: ACMEChallengeStatus.PENDING,
        token: ACMEChallengeToken(ChallengeToken),
      ),
    )

  asyncSetup:
    acmeApi = ACMEApiStub.new()

  asyncTeardown:
    await acme.close()
    checkTrackers()

  asyncTest "the key authorization is the dns-01 digest of token and thumbprint":
    acme =
      ACMEClient.new(rng = rng(), api = ACMEApi(acmeApi), key = Opt.some(rfc7517Key()))

    check acme.genKeyAuthorization(ChallengeToken) == Dns01Digest

  asyncTest "the account is registered once and its kid reused":
    acmeApi.queueRegister()

    acme = ACMEClient.new(rng = rng(), api = ACMEApi(acmeApi), key = Opt.some(key))

    check:
      (await acme.getOrInitKid()).get() == AccountURL
      (await acme.getOrInitKid()).get() == AccountURL
      acmeApi.requestedUris == @[parseUri(StubDirectory.newAccount)]

  asyncTest "getCertificate fails before finalization when the challenge never validates":
    acmeApi.queueRegister()
    acmeApi.queueChallengeCompleted()
    acmeApi.queueStatus("pending") # checkChallengeCompleted

    acme = ACMEClient.new(rng = rng(), api = ACMEApi(acmeApi), key = Opt.some(key))

    let certificate = await acme.getCertificate(
      api.Domain(CertDomain), certKey, dns01Challenge(), acmeRetries = 0
    )
    check certificate.isErr()

    check acmeApi.requestedUris ==
      @[
        parseUri(StubDirectory.newAccount),
        parseUri(ChallengeURL),
        parseUri(ChallengeURL),
      ]

  asyncTest "getCertificate fails at finalization when the order turns invalid":
    acmeApi.queueRegister()
    acmeApi.queueChallengeCompleted()
    acmeApi.queueStatus("valid") # checkChallengeCompleted
    acmeApi.queueStatus("valid") # requestFinalize
    acmeApi.queueStatus("invalid") # checkCertFinalized

    acme = ACMEClient.new(rng = rng(), api = ACMEApi(acmeApi), key = Opt.some(key))

    let certificate =
      await acme.getCertificate(api.Domain(CertDomain), certKey, dns01Challenge())
    check certificate.isErr()

    check acmeApi.requestedUris ==
      @[
        parseUri(StubDirectory.newAccount),
        parseUri(ChallengeURL),
        parseUri(ChallengeURL),
        parseUri(FinalizeURL),
        parseUri(OrderURL),
      ]
