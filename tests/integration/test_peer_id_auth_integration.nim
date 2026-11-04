# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import json, chronos, chronos/apps/http/httpclient
import ../../libp2p/[stream/connection, upgrademngrs/upgrade, peeridauth/client, wire]
from ../../libp2p/autotls/broker import DefaultRegistrationURL
import ../tools/[unittest, crypto]

when defined(linux) and defined(amd64):
  {.used.}

const HttpPeerAuthFailed = 401

suite "PeerID Auth":
  var client {.threadvar.}: PeerIDAuthClient
  var peerInfo {.threadvar.}: PeerInfo

  asyncTeardown:
    await client.close()
    checkTrackers()

  asyncSetup:
    client = PeerIDAuthClient.new(rng())
    peerInfo = PeerInfo.new(PrivateKey.random(PKScheme.RSA, rng()).get())

  asyncTest "test peerID send":
    let payload = %*{
      "identifiers": [
        {
          "type": "dns",
          "value":
            "*.k51qzi5uqu5dj8c5nhiw2oceam0uebustsj7s36kjxwtscngp0y126o3b95mh9.libp2p.direct",
        }
      ]
    }

    let (bearer, responseWithoutBearer) =
      await client.send(DefaultRegistrationURL, peerInfo, payload)
    check responseWithoutBearer.status != HttpPeerAuthFailed
    doAssert bearer.token.len > 0

    let (_, responseWithBearer) =
      await client.send(DefaultRegistrationURL, peerInfo, payload, Opt.some(bearer))
    check responseWithBearer.status != HttpPeerAuthFailed
