# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import base64, json, strutils, uri, times, stew/byteutils
import chronos, chronos/apps/http/httpclient, results, chronicles
import ../peerinfo, ../crypto/crypto, ../varint.nim
import ../utils/rfc3339

logScope:
  topics = "libp2p peer-id-auth"

const
  NimLibp2pUserAgent = "nim-libp2p"
  PeerIDAuthPrefix* = "libp2p-PeerID"
  ChallengeCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  ChallengeDefaultLen = 48

export Domain

type PeerIDAuthClient* = ref object of RootObj
  session: HttpSessionRef
  rng: Rng

type PeerIDAuthError* = object of LPError

type PeerIDAuthResponse* = object
  status*: int
  headers*: HttpTable
  body*: seq[byte]

type BearerToken* = object
  token*: string
  expires*: Opt[DateTime]

type PeerIDAuthOpaque* = string
type PeerIDAuthSignature* = string
type PeerIDAuthChallenge* = string

type PeerIDAuthAuthenticationResponse* = object
  challengeClient*: PeerIDAuthChallenge
  opaque*: PeerIDAuthOpaque
  serverPubkey*: PublicKey

type PeerIDAuthAuthorizationResponse* = object
  sig*: PeerIDAuthSignature
  bearer*: BearerToken
  response*: PeerIDAuthResponse

type SigParam = object
  k: string
  v: seq[byte]

proc new*(T: typedesc[PeerIDAuthClient], rng: Rng): PeerIDAuthClient =
  PeerIDAuthClient(session: HttpSessionRef.new(), rng: rng)

proc randomChallenge(
    rng: Rng, challengeLen: int = ChallengeDefaultLen
): PeerIDAuthChallenge =
  var challenge = newString(challengeLen)
  for c in challenge.mitems:
    c = ChallengeCharset[rng.rand(0, ChallengeCharset.high)]
  PeerIDAuthChallenge(challenge)

proc tryDecode(encoded: string): LPResult[seq[byte]] =
  catch(base64.decode(encoded).toBytes()).mapErr(
    proc(e: ref CatchableError): string =
      e.msg
  )

func extractField(data, key: string): LPResult[string] =
  var fields = data
  fields.removePrefix(PeerIDAuthPrefix & " ")
  for segment in fields.split(","):
    let parts = segment.split("=", 1)
    if parts.len == 2 and parts[0].strip() == key:
      return ok(parts[1].strip(chars = {' ', '"'}))
  err("Failed to find " & key & " in PeerID Auth header")

func genDataToSign(
    parts: seq[SigParam], prefix: string = PeerIDAuthPrefix
): LPResult[seq[byte]] =
  var buf: seq[byte] = prefix.toBytes()
  for p in parts:
    let varintLen = PB.encodeVarint(hint(p.k.len + p.v.len + 1)).valueOr:
      return err("could not encode fields length to varint")
    buf.add varintLen
    buf.add (p.k & "=").toBytes()
    buf.add p.v
  ok(buf)

proc getSigParams(
    clientSender: bool, hostname: string, challenge: string, publicKey: PublicKey
): LPResult[seq[SigParam]] =
  let keyBytes = publicKey.getBytes().valueOr:
    return err("Failed to get public key bytes: " & $error)
  if clientSender:
    ok(
      @[
        SigParam(k: "challenge-client", v: challenge.toBytes()),
        SigParam(k: "hostname", v: hostname.toBytes()),
        SigParam(k: "server-public-key", v: keyBytes),
      ]
    )
  else:
    ok(
      @[
        SigParam(k: "challenge-server", v: challenge.toBytes()),
        SigParam(k: "client-public-key", v: keyBytes),
        SigParam(k: "hostname", v: hostname.toBytes()),
      ]
    )

proc sign(
    privateKey: PrivateKey,
    challenge: PeerIDAuthChallenge,
    publicKey: PublicKey,
    hostname: string,
    clientSender: bool = true,
): LPResult[PeerIDAuthSignature] =
  let params = ?getSigParams(clientSender, hostname, challenge, publicKey)
  let bytesToSign = ?params.genDataToSign()
  let sig = privateKey.sign(bytesToSign).valueOr:
    return err("Failed to sign: " & $error)
  ok(PeerIDAuthSignature(base64.encode(sig.getBytes(), safe = true)))

proc tryCheckSignature*(
    serverSig: PeerIDAuthSignature,
    serverPublicKey: PublicKey,
    challengeServer: PeerIDAuthChallenge,
    clientPublicKey: PublicKey,
    hostname: string,
): LPResult[bool] =
  let params = ?getSigParams(false, hostname, challengeServer, clientPublicKey)
  let bytesToSign = ?params.genDataToSign()
  let sigBytes = serverSig.tryDecode().valueOr:
    return err("Failed to decode server's signature: " & error)

  var serverSignature: Signature
  if not serverSignature.init(sigBytes):
    return err("Failed to initialize Signature from base64 encoded sig")

  ok(serverSignature.verify(bytesToSign, serverPublicKey))

proc checkSignature*(
    serverSig: PeerIDAuthSignature,
    serverPublicKey: PublicKey,
    challengeServer: PeerIDAuthChallenge,
    clientPublicKey: PublicKey,
    hostname: string,
): bool {.raises: [PeerIDAuthError].} =
  tryCheckSignature(
    serverSig, serverPublicKey, challengeServer, clientPublicKey, hostname
  )
    .valueOrRaise(PeerIDAuthError)

method post*(
    self: PeerIDAuthClient, uri: Uri, payload: string, authHeader: string
): Future[PeerIDAuthResponse] {.async: (raises: [HttpError, CancelledError]), base.} =
  let request = HttpClientRequestRef.post(
    self.session,
    $uri,
    body = payload,
    headers = [
      ("Content-Type", "application/json"),
      ("User-Agent", NimLibp2pUserAgent),
      ("Authorization", authHeader),
    ],
  ).valueOr:
    raiseHttpAddressError(error)
  let rawResponse = await request.send()

  PeerIDAuthResponse(
    status: rawResponse.status,
    headers: rawResponse.headers,
    body: await rawResponse.getBodyBytes(),
  )

method get*(
    self: PeerIDAuthClient, uri: Uri
): Future[PeerIDAuthResponse] {.
    async: (raises: [PeerIDAuthError, HttpError, CancelledError]), base
.} =
  if self.session.isNil():
    raise newException(PeerIDAuthError, "Session is nil")
  let req = HttpClientRequestRef.get(self.session, $uri).valueOr:
    raise newException(PeerIDAuthError, "Could not get request obj")
  let rawResponse = await req.send()
  PeerIDAuthResponse(
    status: rawResponse.status,
    headers: rawResponse.headers,
    body: await rawResponse.getBodyBytes(),
  )

proc tryGet(
    self: PeerIDAuthClient, uri: Uri
): Future[LPResult[PeerIDAuthResponse]] {.async: (raises: [CancelledError]).} =
  try:
    ok(await self.get(uri))
  except HttpError as e:
    err(e.msg)
  except PeerIDAuthError as e:
    err(e.msg)

proc tryPost(
    self: PeerIDAuthClient, uri: Uri, payload: string, authHeader: string
): Future[LPResult[PeerIDAuthResponse]] {.async: (raises: [CancelledError]).} =
  try:
    ok(await self.post(uri, payload, authHeader))
  except HttpError as e:
    err(e.msg)

proc tryRequestAuthentication*(
    self: PeerIDAuthClient, uri: Uri
): Future[LPResult[PeerIDAuthAuthenticationResponse]] {.
    async: (raises: [CancelledError])
.} =
  let response = (await self.tryGet(uri)).valueOr:
    return err("Failed to start PeerID Auth: " & error)

  let wwwAuthenticate = response.headers.getString("WWW-Authenticate")
  if wwwAuthenticate == "":
    return err("WWW-authenticate not present in response")

  let encodedPubkey = ?wwwAuthenticate.extractField("public-key")
  let pubkeyBytes = encodedPubkey.tryDecode().valueOr:
    return err("Failed to decode server public-key: " & error)
  let serverPubkey = PublicKey.init(pubkeyBytes).valueOr:
    return err("Failed to initialize server public-key")

  ok(
    PeerIDAuthAuthenticationResponse(
      challengeClient: ?wwwAuthenticate.extractField("challenge-client"),
      opaque: ?wwwAuthenticate.extractField("opaque"),
      serverPubkey: serverPubkey,
    )
  )

proc requestAuthentication*(
    self: PeerIDAuthClient, uri: Uri
): Future[PeerIDAuthAuthenticationResponse] {.
    async: (raises: [PeerIDAuthError, CancelledError])
.} =
  let authentication = await self.tryRequestAuthentication(uri)
  authentication.valueOrRaise(PeerIDAuthError)

proc pubkeyBytes*(pubkey: PublicKey): seq[byte] {.raises: [PeerIDAuthError].} =
  pubkey.getBytes().valueOr:
    raise newException(
      PeerIDAuthError, "Failed to get bytes from PeerInfo's publicKey: " & $error
    )

proc parseBearerExpiry(value: string): Opt[DateTime] =
  let expires = parseRfc3339DateTime(value).valueOr:
    if value.len > 0:
      debug "Ignoring invalid bearer expiry", expiry = value
    return Opt.none(DateTime)
  Opt.some(expires)

proc tryRequestAuthorization*(
    self: PeerIDAuthClient,
    peerInfo: PeerInfo,
    uri: Uri,
    challengeClient: PeerIDAuthChallenge,
    challengeServer: PeerIDAuthChallenge,
    serverPubkey: PublicKey,
    opaque: PeerIDAuthOpaque,
    payload: auto,
): Future[LPResult[PeerIDAuthAuthorizationResponse]] {.
    async: (raises: [CancelledError])
.} =
  let clientPubkey = peerInfo.publicKey.getBytes().valueOr:
    return err("Failed to get bytes from PeerInfo's publicKey: " & $error)
  let sig = ?peerInfo.privateKey.sign(challengeClient, serverPubkey, uri.hostname)
  let authHeader =
    PeerIDAuthPrefix & " public-key=\"" & clientPubkey.encode(safe = true) & "\"" &
    ", opaque=\"" & opaque & "\"" & ", challenge-server=\"" & challengeServer & "\"" &
    ", sig=\"" & sig & "\""
  let response = (await self.tryPost(uri, $payload, authHeader)).valueOr:
    return err("Failed to send Authorization for PeerID Auth: " & error)

  let authenticationInfo = response.headers.getString("authentication-info")
  let bearerExpires = authenticationInfo.extractField("expires").valueOr("")
  let expires = parseBearerExpiry(bearerExpires)

  ok(
    PeerIDAuthAuthorizationResponse(
      sig: PeerIDAuthSignature(?authenticationInfo.extractField("sig")),
      bearer:
        BearerToken(token: ?authenticationInfo.extractField("bearer"), expires: expires),
      response: response,
    )
  )

proc requestAuthorization*(
    self: PeerIDAuthClient,
    peerInfo: PeerInfo,
    uri: Uri,
    challengeClient: PeerIDAuthChallenge,
    challengeServer: PeerIDAuthChallenge,
    serverPubkey: PublicKey,
    opaque: PeerIDAuthOpaque,
    payload: auto,
): Future[PeerIDAuthAuthorizationResponse] {.
    async: (raises: [PeerIDAuthError, CancelledError])
.} =
  let authorization = await self.tryRequestAuthorization(
    peerInfo, uri, challengeClient, challengeServer, serverPubkey, opaque, payload
  )
  authorization.valueOrRaise(PeerIDAuthError)

proc sendWithoutBearer(
    self: PeerIDAuthClient, uri: Uri, peerInfo: PeerInfo, payload: auto
): Future[LPResult[(BearerToken, PeerIDAuthResponse)]] {.
    async: (raises: [CancelledError])
.} =
  # Authenticate in three ways as per the PeerID Auth spec
  # https://github.com/libp2p/specs/blob/master/http/peer-id-auth.md

  let authentication = ?(await self.tryRequestAuthentication(uri))

  let challengeServer = self.rng.randomChallenge()
  let authorization = ?(
    await self.tryRequestAuthorization(
      peerInfo, uri, authentication.challengeClient, challengeServer,
      authentication.serverPubkey, authentication.opaque, payload,
    )
  )

  let validSig = ?tryCheckSignature(
    authorization.sig, authentication.serverPubkey, challengeServer, peerInfo.publicKey,
    uri.hostname,
  )
  if not validSig:
    return err("Failed to validate server's signature")

  ok((authorization.bearer, authorization.response))

proc sendWithBearer(
    self: PeerIDAuthClient, uri: Uri, payload: auto, bearer: BearerToken
): Future[LPResult[(BearerToken, PeerIDAuthResponse)]] {.
    async: (raises: [CancelledError])
.} =
  if bearer.expires.isSome() and bearer.expires.get() <= now():
    return err("Bearer expired")

  let authHeader = PeerIDAuthPrefix & " bearer=\"" & bearer.token & "\""
  let response = (await self.tryPost(uri, $payload, authHeader)).valueOr:
    return err("Failed to send request with bearer token for PeerID Auth: " & error)

  ok((bearer, response))

proc trySend*(
    self: PeerIDAuthClient,
    uri: Uri,
    peerInfo: PeerInfo,
    payload: auto,
    bearer: Opt[BearerToken] = Opt.none(BearerToken),
): Future[LPResult[(BearerToken, PeerIDAuthResponse)]] {.
    async: (raises: [CancelledError])
.} =
  if bearer.isSome():
    await self.sendWithBearer(uri, payload, bearer.get())
  else:
    await self.sendWithoutBearer(uri, peerInfo, payload)

proc send*(
    self: PeerIDAuthClient,
    uri: Uri,
    peerInfo: PeerInfo,
    payload: auto,
    bearer: Opt[BearerToken] = Opt.none(BearerToken),
): Future[(BearerToken, PeerIDAuthResponse)] {.
    async: (raises: [PeerIDAuthError, CancelledError])
.} =
  let sent = await self.trySend(uri, peerInfo, payload, bearer)
  sent.valueOrRaise(PeerIDAuthError)

proc close*(
    self: PeerIDAuthClient
): Future[void] {.async: (raises: [CancelledError]).} =
  await self.session.closeWait()
