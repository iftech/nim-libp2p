# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import net, strutils, uri
from times import now, initDuration, `-`, `<`
import chronos, chronos/apps/http/httpclient
import
  ../../../libp2p/[
    autotls/acme/api,
    autotls/acme/client,
    autotls/broker,
    autotls/service,
    autotls/utils,
    nameresolving/dnsresolver,
    transports/wstransport,
    wire,
  ]
import ../../tools/[unittest, crypto, lifecycle, multiaddress, switch_builder]

const
  PebbleDirectoryURL = "https://127.0.0.1/dir"
  ForgeRegistrationURL = "http://127.0.0.1:5380/v1/_acme-challenge"
  ForgeNameServer = "127.0.0.1:5354"
  NodeIP = "127.0.0.1"
  RenewCheckTime = 1.seconds
  IssueTimeout = 60.seconds

proc newAutotlsService(): AutotlsService =
  AutotlsService(
    acmeClient: ACMEClient.new(
      rng(),
      api = ACMEApi.new(
        directoryURL = parseUri(PebbleDirectoryURL),
        # Pebble presents a self-signed certificate and chronos cannot be handed a
        # trust anchor.
        flags = {HttpClientFlag.NoVerifyHost, HttpClientFlag.NoVerifyServerName},
      ),
    ),
    broker: AutotlsBroker.new(rng(), parseUri(ForgeRegistrationURL)),
    cert: Opt.none(AutotlsCert),
    certReady: newAsyncEvent(),
    running: newAsyncEvent(),
    config: AutotlsConfig.new(
      ipAddress = Opt.some(parseIpAddress(NodeIP)),
      nameServers = @[initTAddress(ForgeNameServer)],
      acmeDirectoryURL = parseUri(PebbleDirectoryURL),
      registrationURL = parseUri(ForgeRegistrationURL),
      renewCheckTime = RenewCheckTime,
    ),
    rng: rng(),
  )

suite "AutoTLS against a local ACME server and broker":
  asyncTeardown:
    checkTrackers()

  asyncTest "a certificate is issued end to end":
    let service = newAutotlsService()
    let switch = makeStandardSwitchBuilder(TcpAutoAddress).withYamux().build()
    switch.services.add(service)
    startAndDeferStop(@[switch])

    let cert = await service.getCertWhenReady().wait(IssueTimeout)
    check cert.expiry > now()

  asyncTest "the certificate is renewed once it is about to expire":
    let service = newAutotlsService()
    let switch = makeStandardSwitchBuilder(TcpAutoAddress).withYamux().build()
    switch.services.add(service)
    startAndDeferStop(@[switch])

    let certBefore = await service.getCertWhenReady().wait(IssueTimeout)
    service.certReady.clear()
    service.cert = Opt.some(
      AutotlsCert.new(
        certBefore.cert, certBefore.privkey, now() - initDuration(hours = 2)
      )
    )

    let certAfter = await service.getCertWhenReady().wait(IssueTimeout)
    check:
      certAfter.cert != certBefore.cert
      certAfter.expiry > now()

  asyncTest "a switch dials over wss with the issued certificate":
    let service = newAutotlsService()
    let issuer = makeStandardSwitchBuilder(TcpAutoAddress).withYamux().build()
    issuer.services.add(service)
    startAndDeferStop(@[issuer])

    discard await service.getCertWhenReady().wait(IssueTimeout)

    let server = SwitchBuilder
      .new()
      .withRng(rng())
      .withPrivateKey(issuer.peerInfo.privateKey)
      .withAddress(ma("/ip4/127.0.0.1/tcp/0/wss"))
      .withTransport(
        proc(config: TransportConfig): Transport =
          WsTransport.new(config.upgr, nil, nil, Opt.some(service), rng = config.rng)
      )
      .withYamux()
      .withNoise()
      .build()

    let client = SwitchBuilder
      .new()
      .withRng(rng())
      .withAddress(WsAutoAddress)
      .withNameResolver(DnsResolver.new(@[initTAddress(ForgeNameServer)]))
      # NoVerifyHost drops the trust anchor check only, the dialed name is still matched
      .withWsTransport(tlsFlags = {TLSFlags.NoVerifyHost})
      .withYamux()
      .withNoise()
      .build()

    startAndDeferStop(@[server, client])

    let port = server.peerInfo.listenAddrs[0].initTAddress().tryGet().port
    let serverDomain =
      NodeIP.replace('.', '-') & "." & encodePeerId(server.peerInfo.peerId).get() & "." &
      DefaultDomainSuffix

    await client.connect(
      server.peerInfo.peerId, @[ma("/dns4/" & serverDomain & "/tcp/" & $port & "/wss")]
    )
    check client.isConnected(server.peerInfo.peerId)
    checkUntilTimeout:
      server.isConnected(client.peerInfo.peerId)
