# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import json, parseutils, sequtils, strformat, strutils, uri
from times import DateTime, utc
import chronos/apps/http/httpclient

import ./jws
import ./utils
import ../../crypto/rsa
import ../../utils/opt
import ../../results
import ../../transports/tls/certificate

export results

const
  LetsEncryptDirectoryURL* = parseUri("https://acme-v02.api.letsencrypt.org/directory")
  LetsEncryptStagingDirectoryURL* =
    parseUri("https://acme-staging-v02.api.letsencrypt.org/directory")

type Authorization* = string
type Domain* = string
type Kid* = string
type Nonce* = string

type ACMEDirectory* = object
  newNonce*: string
  newOrder*: string
  newAccount*: string

type ACMEApi* = ref object of RootObj
  directory: Opt[ACMEDirectory]
  session: HttpSessionRef
  directoryURL*: Uri

type HTTPResponse* = object
  body*: JsonNode
  headers*: HttpTable

type ACMEChallengeStatus* {.pure.} = enum
  PENDING = "pending"
  PROCESSING = "processing"
  VALID = "valid"
  INVALID = "invalid"

type ACMEOrderStatus* {.pure.} = enum
  PENDING = "pending"
  READY = "ready"
  PROCESSING = "processing"
  VALID = "valid"
  INVALID = "invalid"

type ACMEChallengeType* {.pure.} = enum
  DNS01 = "dns-01"
  HTTP01 = "http-01"
  TLSALPN01 = "tls-alpn-01"
  DNSPersist01 = "dns-persist-01"

type ACMEChallengeToken* = string

type ACMEChallenge* = object
  url*: string
  `type`*: ACMEChallengeType
  status*: ACMEChallengeStatus
  token*: ACMEChallengeToken

type ACMEChallengeResponse* = object
  status*: ACMEOrderStatus
  authorizations*: seq[Authorization]
  finalize*: string
  order*: string

type ACMEChallengeDns01Response* = object
  finalize*: string
  order*: string
  dns01*: ACMEChallenge

type ACMEAuthorizationsResponse* = object
  challenges*: seq[ACMEChallenge]

type ACMECompletedResponse* = object
  url: string

type ACMECheckKind* = enum
  ACMEOrderCheck
  ACMEChallengeCheck

type ACMECheckResponse* = object
  case kind: ACMECheckKind
  of ACMEOrderCheck:
    orderStatus: ACMEOrderStatus
  of ACMEChallengeCheck:
    chalStatus: ACMEChallengeStatus
  retryAfter: Duration

type ACMEFinalizeResponse* = object
  status: ACMEOrderStatus

type ACMEOrderResponse* = object
  certificate: string

type ACMECertificateResponse* = object
  rawCertificate*: string
  certificateExpiry*: DateTime

type ACMECertificate* = object
  rawCertificate*: string
  certificateExpiry*: DateTime
  certKeyPair*: RsaPrivateKey

const
  Alg = "RS256"
  DefaultChalCompletedRetries = 10
  DefaultChalCompletedRetryTime = 1.seconds
  MaxRetryAfter = 1.hours
  DefaultFinalizeRetries = 10
  ACMEHttpHeaders = [("Content-Type", "application/jose+json")]

type JWK = object
  kty: string
  n: string
  e: string

# whether the request uses Kid or not
type ACMERequestType = enum
  ACMEJwkRequest
  ACMEKidRequest

type ACMERequestHeader = object
  alg: string
  typ: string
  nonce: Nonce
  url: string
  case kind: ACMERequestType
  of ACMEJwkRequest:
    jwk: JWK
  of ACMEKidRequest:
    kid: Kid

type Email = string

type ACMERegisterRequest* = object
  termsOfServiceAgreed: bool
  contact: seq[Email]

type ACMEAccountStatus = enum
  valid = "valid"
  deactivated = "deactivated"
  revoked = "revoked"

type ACMERegisterResponseBody = object
  status*: ACMEAccountStatus

type ACMERegisterResponse* = object
  kid*: Kid
  status*: ACMEAccountStatus

type ACMEChallengeIdentifier = object
  `type`: string
  value: string

type ACMEChallengeRequest = object
  identifiers: seq[ACMEChallengeIdentifier]

type ACMEChallengeResponseBody = object
  status: ACMEOrderStatus
  authorizations: seq[Authorization]
  finalize: string

func origin(uri: Uri): string =
  let scheme = uri.scheme.toLowerAscii()
  let port =
    if uri.port.len > 0:
      uri.port
    elif scheme == "http":
      "80"
    else:
      "443"
  scheme & "://" & uri.hostname.toLowerAscii() & ":" & port

func checkOrigin*(self: ACMEApi, uri: Uri): Result[void, LPResultError] =
  ## The directory is the only URL the caller chooses; the rest come from the server.
  if uri.origin != self.directoryURL.origin:
    return err(
      fmt"{uri}, origin {self.directoryURL.origin}",
      "ACME URL is not on the directory origin",
    )
  ok()

func checkAPIError(resp: HTTPResponse): Result[void, LPResultError] =
  let respType = resp.body{"type"}.getStr()
  if not respType.contains("acme:error"):
    return ok()

  let detail = resp.body{"detail"}.getStr()
  err(fmt"type: {respType}, detail: {detail}", "API request failed")

proc toHTTPResponse(
    raw: HttpClientResponseRef
): Future[Result[HTTPResponse, LPResultError]] {.async: (raises: [CancelledError]).} =
  let body = ?(await raw.getResponseBody())
  let resp = HTTPResponse(body: body, headers: raw.headers)
  ?resp.checkAPIError()
  ok(resp)

proc trySend(
    request: HttpClientRequestRef
): Future[Result[HttpClientResponseRef, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  try:
    ok(await request.send())
  except HttpError as e:
    err(e, "Failed to connect to ACME server")

proc tryGetBodyBytes(
    response: HttpClientResponseRef
): Future[Result[seq[byte], LPResultError]] {.async: (raises: [CancelledError]).} =
  try:
    ok(await response.getBodyBytes())
  except HttpError as e:
    err(e, "Failed to read response from ACME server")

method post*(
  self: ACMEApi, uri: Uri, payload: string
): Future[Result[HTTPResponse, LPResultError]] {.
  async: (raises: [CancelledError]), base
.}

method get*(
  self: ACMEApi, uri: Uri
): Future[Result[HTTPResponse, LPResultError]] {.
  async: (raises: [CancelledError]), base
.}

proc new*(
    T: typedesc[ACMEApi],
    directoryURL: Uri = LetsEncryptDirectoryURL,
    flags: HttpClientFlags = {},
): ACMEApi =
  let session = HttpSessionRef.new(flags)

  ACMEApi(
    session: session, directory: Opt.none(ACMEDirectory), directoryURL: directoryURL
  )

proc getDirectory(
    self: ACMEApi
): Future[Result[ACMEDirectory, LPResultError]] {.async: (raises: [CancelledError]).} =
  if self.directory.isSome():
    return ok(self.directory.get())

  let acmeResponse = ?(await self.get(self.directoryURL))
  let directory = ?acmeResponse.body.tryTo(ACMEDirectory)
  self.directory = Opt.some(directory)
  ok(directory)

method requestNonce*(
    self: ACMEApi
): Future[Result[Nonce, LPResultError]] {.async: (raises: [CancelledError]), base.} =
  let directory = ?(await self.getDirectory())
  let acmeResponse = ?(await self.get(parseUri(directory.newNonce)))
  acmeResponse.headers.header("Replay-Nonce")

# TODO: save n and e in account so we don't have to recalculate every time
func acmeHeader(
    uri: Uri, key: RsaPrivateKey, nonce: Nonce, kid: Opt[Kid]
): ACMERequestHeader =
  if kid.isSome():
    return ACMERequestHeader(
      kind: ACMEKidRequest,
      alg: Alg,
      typ: "JWT",
      nonce: nonce,
      url: $uri,
      kid: kid.get(),
    )

  let pubkey = key.getPublicKey()
  let nArray = @(getArray(pubkey.buffer, pubkey.key.n, pubkey.key.nlen))
  let eArray = @(getArray(pubkey.buffer, pubkey.key.e, pubkey.key.elen))
  ACMERequestHeader(
    kind: ACMEJwkRequest,
    alg: Alg,
    typ: "JWT",
    nonce: nonce,
    url: $uri,
    jwk: JWK(kty: "RSA", n: base64UrlEncode(nArray), e: base64UrlEncode(eArray)),
  )

proc sendPost(
    self: ACMEApi, uri: Uri, payload: string
): Future[Result[HttpClientResponseRef, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  ?self.checkOrigin(uri)
  let request = ?HttpClientRequestRef.post(
    self.session, $uri, body = payload, headers = ACMEHttpHeaders
  )
  await request.trySend()

method post*(
    self: ACMEApi, uri: Uri, payload: string
): Future[Result[HTTPResponse, LPResultError]] {.
    async: (raises: [CancelledError]), base
.} =
  let rawResponse = ?(await self.sendPost(uri, payload))
  await rawResponse.toHTTPResponse()

method get*(
    self: ACMEApi, uri: Uri
): Future[Result[HTTPResponse, LPResultError]] {.
    async: (raises: [CancelledError]), base
.} =
  ?self.checkOrigin(uri)
  let request = ?HttpClientRequestRef.get(self.session, $uri)
  let rawResponse = ?(await request.trySend())
  await rawResponse.toHTTPResponse()

proc createSignedAcmeRequest(
    self: ACMEApi, uri: Uri, payload: string, key: RsaPrivateKey, kid: Opt[Kid]
): Future[Result[string, LPResultError]] {.async: (raises: [CancelledError]).} =
  let nonce = ?(await self.requestNonce())
  let header = acmeHeader(uri, key, nonce, kid)
  ok($(?toFlattenedJws(%*header, payload, key)))

proc createPostAsGetRequest(
    self: ACMEApi, uri: Uri, key: RsaPrivateKey, kid: Kid
): Future[Result[string, LPResultError]] {.async: (raises: [CancelledError]).} =
  ## RFC 8555 section 6.3: a POST-as-GET is a signed POST with a zero-length payload.
  await self.createSignedAcmeRequest(uri, "", key, Opt.some(kid))

proc postAsGet(
    self: ACMEApi, uri: Uri, key: RsaPrivateKey, kid: Kid
): Future[Result[HTTPResponse, LPResultError]] {.async: (raises: [CancelledError]).} =
  let payload = ?(await self.createPostAsGetRequest(uri, key, kid))
  await self.post(uri, payload)

proc postSigned(
    self: ACMEApi, uri: Uri, payload: string, key: RsaPrivateKey, kid: Opt[Kid]
): Future[Result[HTTPResponse, LPResultError]] {.async: (raises: [CancelledError]).} =
  let signed = ?(await self.createSignedAcmeRequest(uri, payload, key, kid))
  await self.post(uri, signed)

func parseRegister(resp: HTTPResponse): Result[ACMERegisterResponse, LPResultError] =
  let body = ?resp.body.tryTo(ACMERegisterResponseBody)
  let kid = ?resp.headers.header("location")
  ok(ACMERegisterResponse(status: body.status, kid: kid))

func parseNewOrder(resp: HTTPResponse): Result[ACMEChallengeResponse, LPResultError] =
  let body = ?resp.body.tryTo(ACMEChallengeResponseBody)
  if body.authorizations.len == 0:
    return err("Authorizations field is empty")

  let order = ?resp.headers.header("location")
  ok(
    ACMEChallengeResponse(
      status: body.status,
      authorizations: body.authorizations,
      finalize: body.finalize,
      order: order,
    )
  )

func parseAuthorizations(
    resp: HTTPResponse
): Result[ACMEAuthorizationsResponse, LPResultError] =
  var challenges: seq[ACMEChallenge]
  var decodeErrors: seq[LPResultError]
  for node in resp.body.getOrDefault("challenges").getElems():
    let challenge = node.tryTo(ACMEChallenge).valueOr:
      decodeErrors.add(error)
      continue
    challenges.add(challenge)

  if challenges.len > 0:
    return ok(ACMEAuthorizationsResponse(challenges: challenges))
  if decodeErrors.len > 0:
    return err(decodeErrors.join("; "), "Failed to decode challenges")
  err("No challenges received")

func dns01Challenge(
    order: ACMEChallengeResponse, auth: ACMEAuthorizationsResponse
): Result[ACMEChallengeDns01Response, LPResultError] =
  let challenges = auth.challenges.filterIt(it.`type` == ACMEChallengeType.DNS01)
  if challenges.len == 0:
    return err("Could not find supported DNS challenge type (dns-01)")

  ok(
    ACMEChallengeDns01Response(
      finalize: order.finalize, order: order.order, dns01: challenges[0]
    )
  )

func retryAfter(headers: HttpTable): Duration =
  let raw = headers.getString("Retry-After")
  var secs: int
  if raw.len == 0 or parseSaturatedNatural(raw, secs) != raw.len:
    return DefaultChalCompletedRetryTime
  min(secs, MaxRetryAfter.seconds.int).seconds

func parseCheck(
    resp: HTTPResponse, checkKind: ACMECheckKind
): Result[ACMECheckResponse, LPResultError] =
  let status = ?resp.body.tryGetStr("status")
  let retryAfter = resp.headers.retryAfter()
  case checkKind
  of ACMEOrderCheck:
    ok(
      ACMECheckResponse(
        kind: checkKind,
        orderStatus: ?tryParseEnum[ACMEOrderStatus](status),
        retryAfter: retryAfter,
      )
    )
  of ACMEChallengeCheck:
    ok(
      ACMECheckResponse(
        kind: checkKind,
        chalStatus: ?tryParseEnum[ACMEChallengeStatus](status),
        retryAfter: retryAfter,
      )
    )

const InvalidCertificateExpiry* = "Invalid certificate expiry"

proc parseCertificateExpiry(certificate: seq[byte]): Result[DateTime, LPResultError] =
  let certificateValidTo = validTo(certificate, PEM).valueOr:
    return err(error, InvalidCertificateExpiry)
  ok(certificateValidTo.utc)

proc requestRegister*(
    self: ACMEApi, key: RsaPrivateKey
): Future[Result[ACMERegisterResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let registerRequest = ACMERegisterRequest(termsOfServiceAgreed: true)
  let directory = ?(await self.getDirectory())
  let acmeResponse = ?(
    await self.postSigned(
      parseUri(directory.newAccount), $(%*registerRequest), key, Opt.none(Kid)
    )
  )
  acmeResponse.parseRegister()

proc requestNewOrder*(
    self: ACMEApi, domains: seq[Domain], key: RsaPrivateKey, kid: Kid
): Future[Result[ACMEChallengeResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let orderRequest = ACMEChallengeRequest(
    identifiers: domains.mapIt(ACMEChallengeIdentifier(`type`: "dns", value: it))
  )
  let directory = ?(await self.getDirectory())
  let acmeResponse = ?(
    await self.postSigned(
      parseUri(directory.newOrder), $(%*orderRequest), key, Opt.some(kid)
    )
  )
  acmeResponse.parseNewOrder()

proc requestAuthorizations*(
    self: ACMEApi, authorizations: seq[Authorization], key: RsaPrivateKey, kid: Kid
): Future[Result[ACMEAuthorizationsResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  if authorizations.len == 0:
    return err("No authorizations to request")

  let acmeResponse = ?(await self.postAsGet(parseUri(authorizations[0]), key, kid))
  acmeResponse.parseAuthorizations()

proc requestChallenge*(
    self: ACMEApi, domains: seq[Domain], key: RsaPrivateKey, kid: Kid
): Future[Result[ACMEChallengeDns01Response, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let orderResp = ?(await self.requestNewOrder(domains, key, kid))
  if orderResp.status notin [ACMEOrderStatus.PENDING, ACMEOrderStatus.READY]:
    return err($orderResp.status, "Invalid new order status")

  let authResp = ?(await self.requestAuthorizations(orderResp.authorizations, key, kid))
  dns01Challenge(orderResp, authResp)

proc requestCheck*(
    self: ACMEApi, checkURL: Uri, checkKind: ACMECheckKind, key: RsaPrivateKey, kid: Kid
): Future[Result[ACMECheckResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let acmeResponse = ?(await self.postAsGet(checkURL, key, kid))
  acmeResponse.parseCheck(checkKind)

proc sendChallengeCompleted*(
    self: ACMEApi, chalURL: Uri, key: RsaPrivateKey, kid: Kid
): Future[Result[ACMECompletedResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let acmeResponse = ?(await self.postSigned(chalURL, "{}", key, Opt.some(kid)))
  acmeResponse.body.tryTo(ACMECompletedResponse)

proc checkChallengeCompleted*(
    self: ACMEApi,
    checkURL: Uri,
    key: RsaPrivateKey,
    kid: Kid,
    retries: int = DefaultChalCompletedRetries,
): Future[Result[bool, LPResultError]] {.async: (raises: [CancelledError]).} =
  for i in 0 .. retries:
    let checkResponse =
      ?(await self.requestCheck(checkURL, ACMEChallengeCheck, key, kid))
    case checkResponse.chalStatus
    of ACMEChallengeStatus.PENDING, ACMEChallengeStatus.PROCESSING:
      await sleepAsync(checkResponse.retryAfter) # try again after some delay
    of ACMEChallengeStatus.VALID:
      return ok(true)
    else:
      return err($checkResponse.chalStatus, "Failed challenge completion")
  ok(false)

proc completeChallenge*(
    self: ACMEApi,
    chalURL: Uri,
    key: RsaPrivateKey,
    kid: Kid,
    retries: int = DefaultChalCompletedRetries,
): Future[Result[bool, LPResultError]] {.async: (raises: [CancelledError]).} =
  discard ?(await self.sendChallengeCompleted(chalURL, key, kid))
  # check until acme server is done (poll validation)
  await self.checkChallengeCompleted(chalURL, key, kid, retries = retries)

proc requestFinalize*(
    self: ACMEApi,
    domain: Domain,
    finalize: Uri,
    certKeyPair: RsaPrivateKey,
    key: RsaPrivateKey,
    kid: Kid,
): Future[Result[ACMEFinalizeResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let csr = ?createCSR(domain, certKeyPair)
  let acmeResponse =
    ?(await self.postSigned(finalize, $(%*{"csr": csr}), key, Opt.some(kid)))
  # server responds with updated order response
  acmeResponse.body.tryTo(ACMEFinalizeResponse)

proc checkCertFinalized*(
    self: ACMEApi,
    order: Uri,
    key: RsaPrivateKey,
    kid: Kid,
    retries: int = DefaultChalCompletedRetries,
): Future[Result[bool, LPResultError]] {.async: (raises: [CancelledError]).} =
  for i in 0 .. retries:
    let checkResponse = ?(await self.requestCheck(order, ACMEOrderCheck, key, kid))
    case checkResponse.orderStatus
    of ACMEOrderStatus.VALID:
      return ok(true)
    of ACMEOrderStatus.PROCESSING:
      await sleepAsync(checkResponse.retryAfter) # try again after some delay
    else:
      return err($checkResponse.orderStatus, "Failed certificate finalization")
  ok(false)

proc certificateFinalized*(
    self: ACMEApi,
    domain: Domain,
    finalize: Uri,
    order: Uri,
    certKeyPair: RsaPrivateKey,
    key: RsaPrivateKey,
    kid: Kid,
    retries: int = DefaultFinalizeRetries,
): Future[Result[bool, LPResultError]] {.async: (raises: [CancelledError]).} =
  discard ?(await self.requestFinalize(domain, finalize, certKeyPair, key, kid))
  # keep checking order until cert is valid (done)
  await self.checkCertFinalized(order, key, kid, retries = retries)

proc requestGetOrder*(
    self: ACMEApi, order: Uri, key: RsaPrivateKey, kid: Kid
): Future[Result[ACMEOrderResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let acmeResponse = ?(await self.postAsGet(order, key, kid))
  acmeResponse.body.tryTo(ACMEOrderResponse)

proc downloadCertificate*(
    self: ACMEApi, order: Uri, key: RsaPrivateKey, kid: Kid
): Future[Result[ACMECertificateResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
  let orderResponse = ?(await self.requestGetOrder(order, key, kid))

  let certificateURL = parseUri(orderResponse.certificate)
  let payload = ?(await self.createPostAsGetRequest(certificateURL, key, kid))
  # not `self.post` as it reads the response as JSON, and a certificate is PEM
  let rawResponse = ?(await self.sendPost(certificateURL, payload))
  let certificate = ?(await rawResponse.tryGetBodyBytes())
  let expiry = ?parseCertificateExpiry(certificate)
  ok(
    ACMECertificateResponse(
      rawCertificate: bytesToString(certificate), certificateExpiry: expiry
    )
  )

proc close*(self: ACMEApi) {.async: (raises: [CancelledError]).} =
  await self.session.closeWait()
