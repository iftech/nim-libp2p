# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import net, sequtils, strutils, uri
from times import now, initDuration, `-`, `<`
import chronos, chronos/apps/http/httpclient
import ../../../libp2p/[autotls/service, autotls/utils, nameresolving/dnsresolver, wire]
import ../../tools/[unittest, crypto, lifecycle, multiaddress, switch_builder]

const
  PebbleDirectoryURL = "https://127.0.0.1/dir"
  ForgeRegistrationURL = "http://127.0.0.1:5380/v1/_acme-challenge"
  ForgeNameServer = "127.0.0.1:5354"
  NodeIP = "127.0.0.1"
  RenewCheckTime = 1.seconds
  IssueTimeout = 60.seconds

proc newAutotlsConfig(): AutotlsConfig =
  AutotlsConfig.new(
    ipAddress = Opt.some(parseIpAddress(NodeIP)),
    nameServers = @[initTAddress(ForgeNameServer)],
    acmeDirectoryURL = parseUri(PebbleDirectoryURL),
    # Pebble presents a self-signed certificate and chronos cannot be handed a
    # trust anchor.
    acmeHttpFlags = {HttpClientFlag.NoVerifyHost, HttpClientFlag.NoVerifyServerName},
    registrationURL = parseUri(ForgeRegistrationURL),
    renewCheckTime = RenewCheckTime,
  )

proc getAutotlsService(switch: Switch): AutotlsService =
  for service in switch.services:
    if service of AutotlsService:
      return AutotlsService(service)
  raiseAssert "switch has no AutoTLS service"

suite "AutoTLS against a local ACME server and broker", timeout = 3 * IssueTimeout:
  asyncTeardown:
    checkTrackers()

  asyncTest "a certificate is issued end to end":
    let switch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withYamux()
      .withAutotls(newAutotlsConfig())
      .build()
    let service = switch.getAutotlsService()
    startAndDeferStop(@[switch])

    let cert = (await service.getCertWhenReady().wait(IssueTimeout)).get()
    check cert.expiry > now()

  asyncTest "the certificate is renewed once it is about to expire":
    let switch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withYamux()
      .withAutotls(newAutotlsConfig())
      .build()
    let service = switch.getAutotlsService()
    startAndDeferStop(@[switch])

    let certBefore = (await service.getCertWhenReady().wait(IssueTimeout)).get()
    service.certReady.clear()
    service.cert = Opt.some(
      AutotlsCert.new(
        certBefore.cert, certBefore.privkey, now() - initDuration(hours = 2)
      )
    )

    let certAfter = (await service.getCertWhenReady().wait(IssueTimeout)).get()
    check:
      certAfter.cert != certBefore.cert
      certAfter.expiry > now()

  asyncTest "a switch dials over wss with the issued certificate":
    # Keep issuance and serving on separate switches: WsTransport.start waits
    # for the certificate during the switch start window. The server reuses
    # the issuer's key because the issued certificate names that peer.
    let issuer = makeStandardSwitchBuilder(TcpAutoAddress)
      .withYamux()
      .withAutotls(newAutotlsConfig())
      .build()
    let issuerService = issuer.getAutotlsService()
    startAndDeferStop(@[issuer])

    let cert = (await issuerService.getCertWhenReady().wait(IssueTimeout)).get()

    let server = makeStandardSwitchBuilder(
        @[TcpAutoAddress, WssAutoAddress]
      )
      .withPrivateKey(issuer.peerInfo.privateKey)
      .withAutotls(newAutotlsConfig())
      .withYamux()
      .build()
    let serverService = server.getAutotlsService()
    serverService.cert = Opt.some(cert)
    serverService.certReady.fire()

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

    let port = server.peerInfo.listenAddrs.filterIt(WSS.match(it))[0]
      .initTAddress()
      .tryGet().port
    let serverDomain =
      NodeIP.replace('.', '-') & "." & encodePeerId(server.peerInfo.peerId).get() & "." &
      DefaultDomainSuffix

    await client.connect(
      server.peerInfo.peerId, @[ma("/dns4/" & serverDomain & "/tcp/" & $port & "/wss")]
    )
    check client.isConnected(server.peerInfo.peerId)
    checkUntilTimeout:
      server.isConnected(client.peerInfo.peerId)
