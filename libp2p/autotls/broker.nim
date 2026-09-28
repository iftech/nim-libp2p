# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import json, sequtils, times, uri
import chronos, chronicles, results
import chronos/apps/http/httpcommon
import
  ../crypto/crypto,
  ../multiaddress,
  ../peerinfo,
  ../peeridauth/client,
  ./acme/client,
  ./utils

export PeerIDAuthError

logScope:
  topics = "libp2p auto-tls"

const
  DefaultRegistrationURL* =
    parseUri("https://registration.libp2p.direct/v1/_acme-challenge")
  HttpOk = 200
  HttpUnauthorized = 401

type AutotlsBroker* = ref object
  registrationURL: Uri
  peerIdAuthClient: PeerIDAuthClient
  bearer: Opt[BearerToken]

proc new*(
    T: typedesc[AutotlsBroker],
    rng: Rng,
    registrationURL: Uri = DefaultRegistrationURL,
    peerIdAuthClient: PeerIDAuthClient = PeerIDAuthClient.new(rng),
): T =
  T(
    registrationURL: registrationURL,
    peerIdAuthClient: peerIdAuthClient,
    bearer: Opt.none(BearerToken),
  )

proc sendChallenge*(
    self: AutotlsBroker,
    peerInfo: PeerInfo,
    addrs: seq[MultiAddress],
    keyAuth: KeyAuthorization,
): Future[void] {.async: (raises: [AutoTLSError, PeerIDAuthError, CancelledError]).} =
  ## Authenticates with the AutoTLS broker and registers the ACME DNS-01
  ## challenge for the given addresses. All request construction, the broker
  ## URL, bearer-token handling and response validation are kept internal: the
  ## caller only learns whether the challenge was accepted (no error) or not
  ## (an exception).
  if addrs.len == 0:
    raise newException(AutoTLSError, "Unable to authenticate with broker: no addresses")

  let strMultiaddresses = addrs.mapIt($it)
  let payload = %*{"value": keyAuth, "addresses": strMultiaddresses}

  # drop a bearer we already know to be expired so we re-authenticate
  # instead of looping on `PeerIDAuthError("Bearer expired")`
  if self.bearer.isSome():
    let cached = self.bearer.get()
    if cached.expires.isSome() and cached.expires.get() <= now():
      self.bearer = Opt.none(BearerToken)

  trace "Sending challenge to AutoTLS broker", registrationURL = $self.registrationURL
  var (bearer, response) = await self.peerIdAuthClient.send(
    self.registrationURL, peerInfo, payload, self.bearer
  )

  # If broker returns 401, it is a signal that bearer is no loger accepted.
  if response.status == HttpUnauthorized and self.bearer.isSome():
    # Retry this registration once without bearer, which runs the mutual-auth handshake and
    # obtains a replacement bearer. 
    # Do not retry a 401 from that fresh handshake.
    self.bearer = Opt.none(BearerToken)
    (bearer, response) =
      await self.peerIdAuthClient.send(self.registrationURL, peerInfo, payload)

  # remember the latest bearer in case the broker rotated it
  self.bearer =
    if response.status == HttpUnauthorized:
      Opt.none(BearerToken)
    else:
      Opt.some(bearer)

  if response.status != HttpOk:
    raise newException(
      AutoTLSError,
      "Failed to authenticate with AutoTLS broker " & $self.registrationURL & " (status " &
        $response.status & "): " & bytesToString(response.body),
    )

proc close*(self: AutotlsBroker) {.async: (raises: [CancelledError]).} =
  await self.peerIdAuthClient.close()
