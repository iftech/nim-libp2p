# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, json, net, results, sequtils, uri
from times import fromUnix, now, initDuration, utc, `+`, `==`
import
  ../../../libp2p/[
    autotls/service,
    autotls/broker,
    autotls/utils,
    autotls/acme/client,
    crypto/rsa,
    switch,
    wire,
  ]
import
  ../../tools/
    [unittest, http_server, crypto, lifecycle, multiaddress, resolver, switch_builder]
import ../../stubs/[acme_api_stub, peer_id_auth_client_stub]

suite "AutoTLS certificate issuance and renewal":
  const
    RenewCheckTime = 20.milliseconds
    RenewBufferTime = 1.hours
    ChallengeToken = "some-token"
    NodeIP = "127.0.0.1"
    DomainSuffix = "example.test"

  # RSA generation dominates the runtime of every test here, so one key pair each.
  let
    accountKey = RsaPrivateKey.random(rng()).get()
    (certKey, cert) = tlsCertGenerator()

  var acmeApi {.threadvar.}: ACMEApiStub
  var authClient {.threadvar.}: PeerIDAuthClientStub
  var service {.threadvar.}: AutotlsService
  var switch {.threadvar.}: Switch

  proc newService(
      config: AutotlsConfig = AutotlsConfig.new(
        ipAddress = Opt.some(parseIpAddress(NodeIP)),
        renewCheckTime = RenewCheckTime,
        renewBufferTime = RenewBufferTime,
      )
  ): AutotlsService =
    AutotlsService(
      acmeClient:
        ACMEClient.new(rng(), api = ACMEApi(acmeApi), key = Opt.some(accountKey)),
      broker: AutotlsBroker.new(rng(), DefaultRegistrationURL, authClient),
      cert: Opt.none(AutotlsCert),
      certReady: newAsyncEvent(),
      running: newAsyncEvent(),
      config: config,
      rng: rng(),
    )

  proc installCert(service: AutotlsService, expiresIn: times.Duration) =
    service.installCertificate(AutotlsCert.new(cert, certKey, now() + expiresIn))

  asyncSetup:
    acmeApi = ACMEApiStub.new()
    authClient = PeerIDAuthClientStub.new()
    switch = makeStandardSwitch(TcpAutoAddress)
    await switch.start()

  asyncTeardown:
    await service.stop(switch)
    await switch.stop()
    checkTrackers()

  asyncTest "a certificate expiring in 5 minutes is renewed":
    service = newService()
    service.installCert(initDuration(minutes = 5))
    await service.start(switch)

    # A renewal attempt fails on its first ACME request, which is enough to see it.
    checkUntilTimeout:
      acmeApi.requestedUris.len > 0

  asyncTest "a certificate expiring in 90 minutes is not renewed under a 1 hour buffer":
    service = newService()
    service.installCert(initDuration(minutes = 90))
    await service.start(switch)

    # Nothing signals a heartbeat that decided against renewing, so wait out several.
    await sleepAsync(10 * RenewCheckTime)

    check acmeApi.requestedUris.len == 0

  asyncTest "issuance is retried issueRetries times":
    # renewCheckTime is left at its 1 hour default, so a second round won't start
    service = newService(
      AutotlsConfig.new(
        ipAddress = Opt.some(parseIpAddress(NodeIP)),
        issueRetries = 3,
        issueRetryTime = 1.milliseconds,
      )
    )
    await service.start(switch)

    # Every attempt fails on its first ACME request, so a request is an attempt.
    checkUntilTimeoutCustom(15.seconds, 500.milliseconds):
      acmeApi.requestedUris.len >= 4

    let certResult = await service.getCertWhenReady()
    check:
      certResult.isErr()
      certResult.error == "ACMEApiStub refused https://acme.example/new-account"

  asyncTest "a failed round is retried on the next heartbeat":
    # No retries, so a round is one request.
    service = newService(
      AutotlsConfig.new(
        ipAddress = Opt.some(parseIpAddress(NodeIP)),
        issueRetries = 0,
        renewCheckTime = RenewCheckTime,
      )
    )
    await service.start(switch)

    checkUntilTimeout:
      acmeApi.requestedUris.len >= 2

  asyncTest "a service stopped during issuance makes no further attempt":
    acmeApi.stalls = true
    service = newService(
      AutotlsConfig.new(ipAddress = Opt.some(parseIpAddress(NodeIP)), issueRetries = 3)
    )
    await service.start(switch)

    check acmeApi.requestedUris.len == 1

    await service.stop(switch)

    check acmeApi.requestedUris.len == 1

  asyncTest "the certificate is handed over once issuance fires":
    service = newService()

    let certFut = service.getCertWhenReady()
    check not certFut.finished

    service.installCert(initDuration(hours = 2))

    let autotlsCert = (await certFut).get()
    check:
      autotlsCert.cert == cert
      autotlsCert.privkey == certKey

  asyncTest "certificate updates are delivered only to current subscribers":
    service = newService()
    let currentSubscriber = service.subscribeCertificateUpdates()
    defer:
      currentSubscriber.unsubscribe()

    service.installCert(initDuration(hours = 2))

    let updates = await currentSubscriber.waitUpdates()
    check:
      updates.len == 1
      updates[0].cert == cert
      updates[0].privkey == certKey

    let lateSubscriber = service.subscribeCertificateUpdates()
    defer:
      lateSubscriber.unsubscribe()

    let staleUpdates = lateSubscriber.waitUpdates()
    check not staleUpdates.finished
    lateSubscriber.unsubscribe()
    check (await staleUpdates).len == 0

  asyncTest "certificate update subscribers are unblocked when the service stops":
    service = newService()
    let subscriber = service.subscribeCertificateUpdates()
    defer:
      subscriber.unsubscribe()

    let updates = subscriber.waitUpdates()
    check not updates.finished

    await service.stop(switch)

    check (await updates).len == 0

  asyncTest "certificate update subscribers survive a service restart":
    service = newService()
    service.installCert(initDuration(hours = 2))
    let subscriber = service.subscribeCertificateUpdates()
    defer:
      subscriber.unsubscribe()

    await service.start(switch)
    let stopped = subscriber.waitUpdates()
    await service.stop(switch)
    check (await stopped).len == 0

    await service.start(switch)
    let updates = subscriber.waitUpdates()
    service.installCert(initDuration(hours = 3))

    check (await updates).len == 1

  asyncTest "the certificate in place is handed over while its renewal is in flight":
    acmeApi.stalls = true
    service = newService()
    service.installCert(initDuration(minutes = 5))
    await service.start(switch)

    check acmeApi.requestedUris.len == 1

    let autotlsCert = (await service.getCertWhenReady()).get()
    check autotlsCert.cert == cert

  asyncTest "the broker is sent the addresses the peer announces":
    const AnnouncedAddrs =
      ["/ip4/" & NodeIP & "/tcp/9000", "/ip4/" & NodeIP & "/tcp/9001/ws"]
    switch.peerInfo.announcedAddrs = AnnouncedAddrs.mapIt(ma(it))

    acmeApi.scriptChallenge(ChallengeToken)

    var config = AutotlsConfig.new(
      ipAddress = Opt.some(parseIpAddress(NodeIP)), issueRetries = 0, dnsRetries = 0
    )
    config.nameResolver = StubNameResolver.new()
    service = newService(config)
    await service.start(switch)

    check parseJson(authClient.payloads[0])["addresses"] == %AnnouncedAddrs

  asyncTest "a certificate is issued, installed, and not issued again":
    const OrderExpires = "2099-01-01T00:00:00Z"
    let certPem = tlsCertPemGenerator()
    let certServer = startTestHttpServer(certPem)
    defer:
      await certServer.stop()

    # the certificate download is a real request, so it has to be on the directory origin
    acmeApi.directoryURL = parseUri(certServer.url)
    acmeApi.scriptChallenge(ChallengeToken)
    acmeApi.scriptCertificate(certServer.url, OrderExpires)

    # issueRetries must be higher than zero to prove it's done only once
    service = newService(
      AutotlsConfig.new(
        ipAddress = Opt.some(parseIpAddress(NodeIP)),
        domainSuffix = DomainSuffix,
        renewCheckTime = RenewCheckTime,
        issueRetries = 3,
        issueRetryTime = 1.milliseconds,
      )
    )
    let keyAuth = service.acmeClient.genKeyAuthorization(ChallengeToken)
    let resolver =
      StubNameResolver.new(txtRecords = @[keyAuth], ipAddresses = @[NodeIP])
    service.config.nameResolver = resolver

    await service.start(switch)
    let autotlsCert = (await service.getCertWhenReady()).get()
    # Nothing signals a round that ended, so wait out a three retries window.
    await sleepAsync(50.milliseconds)

    let baseDomain = encodePeerId(switch.peerInfo.peerId).get() & "." & DomainSuffix
    check:
      # One round is 8 requests, so more would be a second attempt.
      acmeApi.requestedUris.len == 8
      autotlsCert.expiry == fromUnix(DefaultTlsCertValidToUnix).utc
      resolver.txtQueries == @["_acme-challenge." & baseDomain]
      resolver.ipQueries == @["127-0-0-1." & baseDomain]
      parseJson(authClient.payloads[0])["value"].getStr == keyAuth

  asyncTest "persisted state prevents issuance after a process restart":
    const OrderExpires = "2099-01-01T00:00:00Z"
    let certPem = tlsCertPemGenerator()
    let certServer = startTestHttpServer(certPem)
    defer:
      await certServer.stop()

    let storage = AutotlsMemoryStorage.new()
    var config = AutotlsConfig.new(
      ipAddress = Opt.some(parseIpAddress(NodeIP)),
      domainSuffix = DomainSuffix,
      renewCheckTime = RenewCheckTime,
      issueRetries = 0,
      dnsRetries = 0,
      storage = Opt.some(AutotlsStorage(storage)),
    )
    acmeApi.directoryURL = parseUri(certServer.url)
    acmeApi.scriptChallenge(ChallengeToken)
    acmeApi.scriptCertificate(certServer.url, OrderExpires)

    # The first service stands in for the original process and uses the stub
    # API to issue the certificate. Its account and certificate are saved.
    service = newService(config)
    let keyAuth = service.acmeClient.genKeyAuthorization(ChallengeToken)
    service.config.nameResolver =
      StubNameResolver.new(txtRecords = @[keyAuth], ipAddresses = @[NodeIP])
    await service.start(switch)
    let issued = (await service.getCertWhenReady()).get()
    await service.stop(switch)
    let requestCount = acmeApi.requestedUris.len

    # A fresh service has no injected ACME client. It must restore both the
    # certificate and account from storage before it could contact ACME.
    service = AutotlsService.new(rng(), config)
    await service.start(switch)
    let restored = (await service.getCertWhenReady()).get()
    await sleepAsync(3 * RenewCheckTime)

    check:
      restored.expiry == issued.expiry
      service.acmeClient.key == accountKey
      service.acmeClient.kid == AccountURL
      acmeApi.requestedUris.len == requestCount

  asyncTest "the certificate is not requested until the DNS records are published":
    acmeApi.scriptChallenge(ChallengeToken)

    var config = AutotlsConfig.new(
      ipAddress = Opt.some(parseIpAddress(NodeIP)), issueRetries = 0, dnsRetries = 0
    )
    # The A record resolves, so only the missing TXT record holds issuance back.
    config.nameResolver = StubNameResolver.new(ipAddresses = @[NodeIP])
    service = newService(config)
    await service.start(switch)

    check acmeApi.requestedUris.len == 3

  asyncTest "certificate wait fails when the switch has no TcpTransport":
    let memSwitch = makeStandardSwitch(MemoryAutoAddress())
    startAndDeferStop(@[memSwitch])

    service = newService()
    await service.start(memSwitch)
    let certResult = await service.getCertWhenReady()

    check:
      acmeApi.requestedUris.len == 0
      service.running.isSet
      certResult.isErr()
      certResult.error == "Could not find a TcpTransport in switch"

  asyncTest "issuance aborts when no public IP address can be determined":
    acmeApi.scriptChallenge(ChallengeToken)
    service = newService(AutotlsConfig.new(issueRetries = 0))
    await service.start(switch)

    let issued = await service.issueCertificate(switch)
    check:
      issued.isErr
      acmeApi.requestedUris.len == 0
      authClient.payloads.len == 0
      service.cert.isNone
      service.running.isSet

suite "AutoTLS on a switch":
  asyncTeardown:
    checkTrackers()

  asyncTest "issuance publishes a bound TCP address while wss waits for its certificate":
    let acmeApi = ACMEApiStub.new()
    let authClient = PeerIDAuthClientStub.new()
    acmeApi.scriptChallenge("some-token")

    var config = AutotlsConfig.new(
      ipAddress = Opt.some(parseIpAddress("127.0.0.1")),
      issueRetries = 0,
      dnsRetries = 0,
    )
    config.nameResolver = StubNameResolver.new()
    let switch = makeStandardSwitchBuilder(@[TcpAutoAddress, WssAutoAddress])
      .withAutotls(config)
      .build()
    let service = AutotlsService(switch.services.filterIt(it of AutotlsService)[0])
    service.acmeClient = ACMEClient.new(rng(), api = ACMEApi(acmeApi))
    service.broker = AutotlsBroker.new(rng(), DefaultRegistrationURL, authClient)
    defer:
      await switch.stop()

    let startFut = switch.start()
    defer:
      await startFut.cancelAndWait()

    checkUntilTimeout:
      authClient.payloads.len == 1

    let addrs = parseJson(authClient.payloads[0])["addresses"]
    check addrs.len > 0
    for addr in addrs:
      check ma(addr.getStr()).initTAddress().tryGet().port != Port(0)

  asyncTest "certificate renewal preserves non-TCP address candidates":
    let acmeApi = ACMEApiStub.new()
    let authClient = PeerIDAuthClientStub.new()
    let (certKey, cert) = tlsCertGenerator()
    let switch = makeStandardSwitchBuilder(@[TcpAutoAddress, WsAutoAddress])
      .withAutotls(
        AutotlsConfig.new(
          ipAddress = Opt.some(parseIpAddress("127.0.0.1")),
          renewCheckTime = 20.milliseconds,
          issueRetries = 0,
        )
      )
      .build()
    let service = AutotlsService(switch.services.filterIt(it of AutotlsService)[0])
    service.acmeClient = ACMEClient.new(rng(), api = ACMEApi(acmeApi))
    service.broker = AutotlsBroker.new(rng(), DefaultRegistrationURL, authClient)
    let installedCert = AutotlsCert.new(cert, certKey, now() + initDuration(hours = 2))
    service.cert = Opt.some(installedCert)
    service.certReady.fire()
    defer:
      await switch.stop()

    await switch.start()

    let wsAddr = switch.peerInfo.listenAddrs.filterIt(WS.match(it))[0]
    check switch.addressManager.candidates.anyIt(it.address == wsAddr)

    installedCert.expiry = now()
    checkUntilTimeout:
      acmeApi.requestedUris.len > 0

    check switch.addressManager.candidates.anyIt(it.address == wsAddr)

  asyncTest "a switch listening on wss fails to start without a certificate":
    let acmeApi = ACMEApiStub.new()
    let switch = makeStandardSwitchBuilder(@[TcpAutoAddress, WssAutoAddress])
      .withAutotls(
        AutotlsConfig.new(
          ipAddress = Opt.some(parseIpAddress("127.0.0.1")),
          issueRetries = 0,
          initialCertTimeout = 10.seconds,
        )
      )
      .build()
    let service = AutotlsService(switch.services.filterIt(it of AutotlsService)[0])
    service.acmeClient = ACMEClient.new(rng(), api = ACMEApi(acmeApi))
    defer:
      await switch.stop()

    expectMsgContains LPError, "ACMEApiStub refused https://acme.example/new-account":
      await switch.start()

  asyncTest "a switch listening on wss fails when autotls has no TcpTransport":
    let switch = makeStandardSwitchBuilder(@[WssAutoAddress])
      .withAutotls(AutotlsConfig.new(initialCertTimeout = 10.seconds))
      .build()
    defer:
      await switch.stop()

    expectMsgContains LPError, "Could not find a TcpTransport in switch":
      await switch.start()

  asyncTest "a switch listening only on ws starts without an autotls certificate":
    let switch = makeStandardSwitchBuilder(@[WsAutoAddress])
      .withAutotls(
        AutotlsConfig.new(
          ipAddress = Opt.some(parseIpAddress("127.0.0.1")),
          acmeDirectoryURL = parseUri("http://127.0.0.1:1"),
          initialCertTimeout = 100.milliseconds,
        )
      )
      .build()
    defer:
      await switch.stop()

    await switch.start()
