# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

{.push raises: [].}

import base64, strutils, times, uri
import chronos, chronos/apps/http/httpclient, stew/byteutils
import ../../libp2p/[crypto/crypto, peeridauth/client, varint]
import ../tools/crypto

const
  ChallengeClient = "somechallengeclient"
  Opaque = "someopaque"

type PeerIDAuthClientStub* = ref object of PeerIDAuthClient
  ## Answers the PeerID Auth handshake as a server would, recording what was sent.
  ## Either header can be replaced to serve a malformed or absent one instead, and
  ## `challengeServer` signs over a challenge other than the one the client sent.
  serverKey: PrivateKey
  status*: int
  statuses*: seq[int]
  body*: seq[byte]
  token*: string
  expires*: Opt[DateTime]
  wwwAuthenticate*: Opt[string]
  authenticationInfo*: Opt[string]
  challengeServer*: Opt[string]
  requestedUris*: seq[Uri]
  payloads*: seq[string]
  authHeaders*: seq[string]

proc new*(T: typedesc[PeerIDAuthClientStub]): PeerIDAuthClientStub =
  PeerIDAuthClientStub(
    session: HttpSessionRef.new(),
    rng: rng(),
    serverKey: PrivateKey.random(PKScheme.Ed25519, rng()).get(),
    status: 200,
    token: "somebearer",
    expires: Opt.none(DateTime),
    wwwAuthenticate: Opt.none(string),
    authenticationInfo: Opt.none(string),
    challengeServer: Opt.none(string),
  )

proc extractField(data, key: string): string =
  for segment in data.split(","):
    if key in segment:
      return segment.split("=", 1)[1].strip(chars = {' ', '"'})
  ""

proc authField*(self: PeerIDAuthClientStub, index: int, key: string): string =
  ## Reads one field back out of the Authorization header of the index'th request.
  self.authHeaders[index].extractField(key)

proc signAsServer(
    self: PeerIDAuthClientStub,
    challengeServer, hostname: string,
    clientPubkey: PublicKey,
): string =
  var buf = PeerIDAuthPrefix.toBytes()
  for (k, v) in [
    ("challenge-server", challengeServer.toBytes()),
    ("client-public-key", clientPubkey.getBytes().get()),
    ("hostname", hostname.toBytes()),
  ]:
    buf.add PB.encodeVarint(hint(k.len + v.len + 1)).get()
    buf.add (k & "=").toBytes()
    buf.add v
  base64.encode(self.serverKey.sign(buf).get().getBytes(), safe = true)

method get*(
    self: PeerIDAuthClientStub, uri: Uri
): Future[PeerIDAuthResponse] {.
    async: (raises: [PeerIDAuthError, HttpError, CancelledError])
.} =
  self.requestedUris.add(uri)

  var wwwAuthenticate = self.wwwAuthenticate.valueOr:
    let serverPubkey =
      self.serverKey.getPublicKey().get().pubkeyBytes().encode(safe = true)
    PeerIDAuthPrefix & " challenge-client=\"" & ChallengeClient & "\", public-key=\"" &
      serverPubkey & "\", opaque=\"" & Opaque & "\""

  var headers = HttpTable.init()
  headers.add("WWW-Authenticate", wwwAuthenticate)
  PeerIDAuthResponse(status: 200, headers: headers, body: @[])

method post*(
    self: PeerIDAuthClientStub, uri: Uri, payload: string, authHeader: string
): Future[PeerIDAuthResponse] {.async: (raises: [HttpError, CancelledError]).} =
  self.requestedUris.add(uri)
  self.payloads.add(payload)
  self.authHeaders.add(authHeader)
  let status =
    if self.statuses.len >= self.authHeaders.len:
      self.statuses[self.authHeaders.len - 1]
    else:
      self.status

  # a bearer-authenticated request carries no challenge to answer
  if authHeader.extractField("bearer") != "":
    return
      PeerIDAuthResponse(status: status, headers: HttpTable.init(), body: self.body)

  var authenticationInfo = self.authenticationInfo.valueOr:
    var clientPubkey: PublicKey
    try:
      clientPubkey =
        PublicKey.init(decode(authHeader.extractField("public-key")).toBytes()).get()
    except ValueError as exc:
      raiseAssert "stub could not read the client public key: " & exc.msg

    let challengeServer =
      self.challengeServer.valueOr(authHeader.extractField("challenge-server"))
    let sig = self.signAsServer(challengeServer, uri.hostname, clientPubkey)
    var expires = ""
    if self.expires.isSome():
      expires =
        ", expires=\"" & self.expires.get().utc.format("yyyy-MM-dd'T'HH:mm:ss") &
        ".000Z\""

    PeerIDAuthPrefix & " sig=\"" & sig & "\", bearer=\"" & self.token & "\"" & expires

  var headers = HttpTable.init()
  headers.add("Authentication-Info", authenticationInfo)
  PeerIDAuthResponse(status: status, headers: headers, body: self.body)
