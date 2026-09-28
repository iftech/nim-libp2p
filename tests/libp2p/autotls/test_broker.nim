# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import json, sequtils, strutils, times, uri
import chronos, stew/byteutils
import
  ../../../libp2p/[
    autotls/broker,
    autotls/utils,
    autotls/acme/client,
    crypto/crypto,
    multiaddress,
    peeridauth/client,
    peerinfo,
  ]
import ../../tools/[unittest, crypto, multiaddress]
import ../../stubs/peer_id_auth_client_stub

suite "AutoTLS broker":
  const
    RegistrationURL = "https://broker.example/v1/_acme-challenge"
    KeyAuth = KeyAuthorization("expected-key-authorization")
    Addresses = ["/ip4/1.2.3.4/tcp/4001", "/ip4/1.2.3.4/tcp/4002/ws"]

  var client {.threadvar.}: PeerIDAuthClientStub
  var broker {.threadvar.}: AutotlsBroker
  var peerInfo {.threadvar.}: PeerInfo
  var addrs {.threadvar.}: seq[MultiAddress]

  asyncTeardown:
    await broker.close()
    checkTrackers()

  asyncSetup:
    client = PeerIDAuthClientStub.new()
    broker = AutotlsBroker.new(rng(), parseUri(RegistrationURL), client)
    peerInfo = PeerInfo.new(PrivateKey.random(PKScheme.Ed25519, rng()).get())
    addrs = Addresses.mapIt(ma(it))

  asyncTest "an empty address set is refused before the broker is contacted":
    expect(AutoTLSError):
      await broker.sendChallenge(peerInfo, @[], KeyAuth)

    check client.requestedUris.len == 0

  asyncTest "the payload carries the key authorization and every address in order":
    await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check:
      client.payloads.len == 1
      parseJson(client.payloads[0]) == %*{"value": KeyAuth, "addresses": Addresses}

  asyncTest "the challenge is sent to the registration URL as given":
    await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check client.requestedUris.mapIt($it) == @[RegistrationURL, RegistrationURL]

  asyncTest "a rejected registration raises":
    client.status = 403
    client.body = "peer not authorized".toBytes()

    expect(AutoTLSError):
      await broker.sendChallenge(peerInfo, addrs, KeyAuth)

  asyncTest "a live bearer authenticates the next registration without a handshake":
    client.expires = Opt.some(now() + initDuration(hours = 1))

    await broker.sendChallenge(peerInfo, addrs, KeyAuth)
    await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check:
      client.requestedUris.len == 3
      client.authHeaders.len == 2
      client.authHeaders[1] == PeerIDAuthPrefix & " bearer=\"" & client.token & "\""

  asyncTest "an expired bearer is dropped and the handshake runs again":
    client.expires = Opt.some(now() - initDuration(hours = 1))

    await broker.sendChallenge(peerInfo, addrs, KeyAuth)
    await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check:
      client.requestedUris.len == 4
      client.authHeaders.len == 2
      client.authHeaders[1].startsWith(PeerIDAuthPrefix & " public-key=")

  asyncTest "a bearer without an expiry is reused, not dropped":
    await broker.sendChallenge(peerInfo, addrs, KeyAuth)
    await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check:
      client.requestedUris.len == 3
      client.authHeaders.len == 2
      client.authHeaders[1] == PeerIDAuthPrefix & " bearer=\"" & client.token & "\""

  asyncTest "a 401 bearer response re-authenticates and retries the registration":
    # The first call obtains the bearer. The next call rejects it, then accepts
    # the retried request after the mutual-auth handshake.
    client.statuses = @[200, 401, 200]

    await broker.sendChallenge(peerInfo, addrs, KeyAuth)
    await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check:
      client.requestedUris.len == 5
      client.authHeaders.len == 3
      client.authHeaders[1] == PeerIDAuthPrefix & " bearer=\"" & client.token & "\""
      client.authHeaders[2].startsWith(PeerIDAuthPrefix & " public-key=")

  asyncTest "a bearer obtained during a rejected registration is kept":
    client.status = 500

    expect AutoTLSError:
      await broker.sendChallenge(peerInfo, addrs, KeyAuth)
    expect AutoTLSError:
      await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check client.authHeaders[1] == PeerIDAuthPrefix & " bearer=\"" & client.token & "\""

  asyncTest "a 401 clears the bearer for the next registration":
    client.status = 401

    expect AutoTLSError:
      await broker.sendChallenge(peerInfo, addrs, KeyAuth)
    expect AutoTLSError:
      await broker.sendChallenge(peerInfo, addrs, KeyAuth)

    check:
      client.requestedUris.len == 4
      client.authHeaders.len == 2
      client.authHeaders[1].startsWith(PeerIDAuthPrefix & " public-key=")
