# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

{.push raises: [].}

import base64, json, uri
import chronos, chronos/apps/http/httpclient, results
import ../../libp2p/autotls/acme/api

export api

const
  DirectoryURL* = "https://acme.example/directory"
  AccountURL* = "https://acme.example/acct/1"
  OrderURL* = "https://acme.example/order/1"
  FinalizeURL* = "https://acme.example/finalize/1"
  AuthorizationsURL* = "https://acme.example/authz/1"
  ChallengeURL* = "https://acme.example/chal/1"

const StubDirectory* = ACMEDirectory(
  newNonce: "https://acme.example/new-nonce",
  newOrder: "https://acme.example/new-order",
  newAccount: "https://acme.example/new-account",
)

type ACMEApiStub* = ref object of ACMEApi
  ## Answers ACME requests from `mockedResponses`, recording what was requested
  ## and the flattened JWS each POST carried. An empty queue refuses the request
  ## instead. While `stalls` is set the request stays pending, until it is cancelled.
  mockedResponses*: seq[HTTPResponse]
  requestedUris*: seq[Uri]
  payloads*: seq[string]
  nonces: int
  stalls*: bool

proc new*(
    T: typedesc[ACMEApiStub], directory: Opt[ACMEDirectory] = Opt.some(StubDirectory)
): ACMEApiStub =
  ACMEApiStub(
    session: HttpSessionRef.new(),
    directory: directory,
    directoryURL: parseUri(DirectoryURL),
  )

proc jwsMember(self: ACMEApiStub, index: int, member: string): JsonNode =
  try:
    parseJson(base64.decode(parseJson(self.payloads[index])[member].getStr))
  except CatchableError as exc:
    raiseAssert "stub could not read the JWS " & member & ": " & exc.msg

proc protectedHeader*(self: ACMEApiStub, index: int): JsonNode =
  ## The protected header of the `index`-th signed request.
  self.jwsMember(index, "protected")

proc signedPayload*(self: ACMEApiStub, index: int): JsonNode =
  ## The payload of the `index`-th signed request.
  self.jwsMember(index, "payload")

proc encodedPayload*(self: ACMEApiStub, index: int): string =
  ## The payload of the `index`-th signed request, still base64url-encoded.
  try:
    parseJson(self.payloads[index])["payload"].getStr
  except CatchableError as exc:
    raiseAssert "stub could not read the JWS payload: " & exc.msg

proc queueRegister*(self: ACMEApiStub) =
  ## Queues the response `requestRegister` consumes.
  self.mockedResponses.add(
    HTTPResponse(
      body: %*{"status": "valid"}, headers: HttpTable.init(@[("location", AccountURL)])
    )
  )

proc queueOrder*(self: ACMEApiStub, status: string, authorizations: JsonNode) =
  ## Queues the response `requestNewOrder` consumes.
  self.mockedResponses.add(
    HTTPResponse(
      body:
        %*{"status": status, "authorizations": authorizations, "finalize": FinalizeURL},
      headers: HttpTable.init(@[("location", OrderURL)]),
    )
  )

proc queueChallenges*(self: ACMEApiStub, challenges: JsonNode) =
  ## Queues the response `requestAuthorizations` consumes.
  self.mockedResponses.add(
    HTTPResponse(body: %*{"challenges": challenges}, headers: HttpTable.init())
  )

proc queueChallengeCompleted*(self: ACMEApiStub) =
  ## Queues the response `sendChallengeCompleted` consumes.
  self.mockedResponses.add(
    HTTPResponse(body: %*{"url": ChallengeURL}, headers: HttpTable.init())
  )

proc queueStatus*(self: ACMEApiStub, status: string) =
  ## Queues the status-only response `requestCheck` and `requestFinalize` consume.
  self.mockedResponses.add(
    HTTPResponse(
      body: %*{"status": status}, headers: HttpTable.init(@[("Retry-After", "0")])
    )
  )

proc queueGetOrder*(self: ACMEApiStub, certificateURL: string, expires: string) =
  ## Queues the response `requestGetOrder` consumes.
  self.mockedResponses.add(
    HTTPResponse(
      body: %*{"certificate": certificateURL, "expires": expires},
      headers: HttpTable.init(),
    )
  )

proc queueInvalidBody*(self: ACMEApiStub, count: int) =
  ## Queues `count` responses whose body is well-formed JSON but not the shape
  ## the caller decodes.
  for _ in 0 ..< count:
    self.mockedResponses.add(
      HTTPResponse(
        body: %*{"invalid field": "invalid value"}, headers: HttpTable.init()
      )
    )

proc scriptChallenge*(self: ACMEApiStub, token: string) =
  ## Queues the three responses `getChallenge` consumes, carrying `token` in the challenge.
  self.queueRegister()
  self.queueOrder("pending", %*[AuthorizationsURL])
  self.queueChallenges(
    %*[{"url": ChallengeURL, "type": "dns-01", "status": "pending", "token": token}]
  )

proc scriptCertificate*(self: ACMEApiStub, certificateURL: string, expires: string) =
  ## Queues the five responses `getCertificate` consumes, ending in an order whose
  ## certificate is served from `certificateURL`.
  self.queueChallengeCompleted()
  self.queueStatus("valid") # checkChallengeCompleted
  self.queueStatus("valid") # requestFinalize
  self.queueStatus("valid") # checkCertFinalized
  self.queueGetOrder(certificateURL, expires)

proc respond(
    self: ACMEApiStub, uri: Uri
): Future[Result[HTTPResponse, string]] {.async: (raises: [CancelledError]).} =
  self.requestedUris.add(uri)
  if self.stalls:
    await Future[void].Raising([CancelledError]).init("ACMEApiStub.stall")
  if self.mockedResponses.len == 0:
    return err("ACMEApiStub refused " & $uri)

  let response = self.mockedResponses[0]
  self.mockedResponses.delete(0)
  ok(response)

method requestNonce*(
    self: ACMEApiStub
): Future[Result[Nonce, string]] {.async: (raises: [CancelledError]).} =
  self.nonces += 1
  ok($self.directoryURL & "/acme/" & $self.nonces)

method post*(
    self: ACMEApiStub, uri: Uri, payload: string
): Future[Result[HTTPResponse, string]] {.async: (raises: [CancelledError]).} =
  self.payloads.add(payload)
  await self.respond(uri)

method get*(
    self: ACMEApiStub, uri: Uri
): Future[Result[HTTPResponse, string]] {.async: (raises: [CancelledError]).} =
  await self.respond(uri)
