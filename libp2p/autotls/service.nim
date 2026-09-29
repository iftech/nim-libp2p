# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import sequtils
import chronos, chronicles, net, results, uri
import chronos/apps/http/httpclient
import chronos/streams/tlsstream
from times import DateTime, now, toTime, toUnix

import
  ./acme/client,
  ./broker,
  ./utils,
  ../crypto/rsa,
  ../crypto/rng,
  ../nameresolving/nameresolver,
  ../nameresolving/dnsresolver,
  ../switch,
  ../peerinfo,
  ../transports/transport,
  ../transports/tcptransport,
  ../utils/heartbeat,
  ../utils/ipaddr,
  ../utils/tlsredact,
  ../wire

logScope:
  topics = "libp2p auto-tls"

export
  LetsEncryptDirectoryURL, AutoTLSError, DefaultDnsServers, DefaultRegistrationURL,
  AutotlsBroker, tlsredact

const
  DefaultRenewCheckTime* = 1.hours
  DefaultRenewBufferTime* = 1.hours
  DefaultInitialCertTimeout* = 2.minutes
  DefaultIssueRetries = 3
  DefaultIssueRetryTime = 1.seconds

  DefaultDomainSuffix* = "libp2p.direct"

type AutotlsCert* = ref object
  cert*: TLSCertificate
  privkey*: TLSPrivateKey
  expiry*: DateTime

type AutotlsConfig* = object
  acmeDirectoryURL*: Uri
  acmeHttpFlags*: HttpClientFlags
  nameResolver*: NameResolver
  ipAddress: Opt[IpAddress]
  renewCheckTime*: Duration
  renewBufferTime*: Duration
  initialCertTimeout*: Duration
  issueRetries*: int
  issueRetryTime*: Duration
  registrationURL*: Uri
  domainSuffix*: string
  dnsRetries*: int
  dnsRetryTime*: Duration
  acmeRetries*: int
  acmeRetryTime*: Duration
  finalizeRetries*: int
  finalizeRetryTime*: Duration

type AutotlsService* = ref object of Service
  acmeClient*: ACMEClient
  broker*: AutotlsBroker
  cert*: Opt[AutotlsCert]
  certReady*: AsyncEvent
  running*: AsyncEvent
  config*: AutotlsConfig
  managerFut: Future[void]
  peerInfo: PeerInfo
  rng*: Rng

proc new*(
    T: typedesc[AutotlsCert],
    cert: TLSCertificate,
    privkey: TLSPrivateKey,
    expiry: DateTime,
): T =
  T(cert: cert, privkey: privkey, expiry: expiry)

method getCertWhenReady*(
    self: AutotlsService
): Future[AutotlsCert] {.base, async: (raises: [AutoTLSError, CancelledError]).} =
  await self.certReady.wait()
  return self.cert.get

proc new*(
    T: typedesc[AutotlsConfig],
    ipAddress: Opt[IpAddress] = Opt.none(IpAddress),
    nameServers: seq[TransportAddress] = DefaultDnsServers,
    acmeDirectoryURL: Uri = LetsEncryptDirectoryURL,
    acmeHttpFlags: HttpClientFlags = {},
    renewCheckTime: Duration = DefaultRenewCheckTime,
    renewBufferTime: Duration = DefaultRenewBufferTime,
    initialCertTimeout: Duration = DefaultInitialCertTimeout,
    issueRetries: int = DefaultIssueRetries,
    issueRetryTime: Duration = DefaultIssueRetryTime,
    registrationURL: Uri = DefaultRegistrationURL,
    domainSuffix: string = DefaultDomainSuffix,
    dnsRetries: int = 10,
    dnsRetryTime: Duration = 1.seconds,
    acmeRetries: int = 10,
    acmeRetryTime: Duration = 1.seconds,
    finalizeRetries: int = 10,
    finalizeRetryTime: Duration = 1.seconds,
): T =
  T(
    nameResolver: DnsResolver.new(nameServers),
    acmeDirectoryURL: acmeDirectoryURL,
    acmeHttpFlags: acmeHttpFlags,
    ipAddress: ipAddress,
    renewCheckTime: renewCheckTime,
    renewBufferTime: renewBufferTime,
    initialCertTimeout: initialCertTimeout,
    issueRetries: issueRetries,
    issueRetryTime: issueRetryTime,
    registrationURL: registrationURL,
    domainSuffix: domainSuffix,
    dnsRetries: dnsRetries,
    dnsRetryTime: dnsRetryTime,
    acmeRetries: acmeRetries,
    acmeRetryTime: acmeRetryTime,
    finalizeRetries: finalizeRetries,
    finalizeRetryTime: finalizeRetryTime,
  )

proc new*(
    T: typedesc[AutotlsService], rng: Rng, config: AutotlsConfig = AutotlsConfig.new()
): T =
  T(
    acmeClient: ACMEClient.new(
      api = ACMEApi.new(config.acmeDirectoryURL, config.acmeHttpFlags), rng = rng
    ),
    broker: AutotlsBroker.new(rng, config.registrationURL),
    cert: Opt.none(AutotlsCert),
    certReady: newAsyncEvent(),
    running: newAsyncEvent(),
    config: config,
    managerFut: nil,
    peerInfo: nil,
    rng: rng,
  )

method setup*(self: AutotlsService, switch: Switch) {.raises: [ServiceSetupError].} =
  if self.config.ipAddress.isSome():
    return
  let ip = getPublicIPAddress().valueOr:
    raise newException(ServiceSetupError, "Host does not have a public IP address")
  self.config.ipAddress = Opt.some(ip)

proc newAutotlsCert(
    certificate: ACMECertificateResponse, certKeyPair: RsaPrivateKey
): Result[AutotlsCert, string] =
  let derPrivKey = certKeyPair.getBytes().valueOr:
    return err("Unable to get TLS private key")

  try:
    ok(
      AutotlsCert.new(
        TLSCertificate.init(certificate.rawCertificate),
        TLSPrivateKey.init(derPrivKey.pemEncode("PRIVATE KEY")),
        certificate.certificateExpiry,
      )
    )
  except TLSStreamProtocolError as e:
    err("Could not parse downloaded certificates: " & e.msg)

proc publishChallenge(
    self: AutotlsService,
    baseDomain: api.Domain,
    keyAuth: KeyAuthorization,
    addrs: seq[MultiAddress],
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  # broker encapsulates request construction, bearer handling and response
  # validation: it either registers the challenge or raises on failure
  let dnsSet =
    try:
      await self.broker.sendChallenge(self.peerInfo, addrs, keyAuth)
      await checkDNSRecords(
        self.config.nameResolver,
        self.config.ipAddress.get(),
        baseDomain,
        keyAuth,
        self.config.dnsRetries,
        self.config.dnsRetryTime,
      )
    except LPError as e:
      return err($e.name & ": " & e.msg)
  if not dnsSet:
    return err("DNS records not set")
  ok()

proc requestCertificate(
    self: AutotlsService,
    baseDomain: api.Domain,
    certKeyPair: RsaPrivateKey,
    addrs: seq[MultiAddress],
): Future[Result[ACMECertificateResponse, string]] {.async: (raises: [CancelledError]).} =
  trace "Requesting ACME challenge"
  let dns01Challenge =
    ?(await self.acmeClient.getChallenge(@[api.Domain("*." & baseDomain)]))
  trace "Generating key authorization"
  let keyAuth = self.acmeClient.genKeyAuthorization(dns01Challenge.dns01.token)

  ?(await self.publishChallenge(baseDomain, keyAuth, addrs))

  trace "Notifying challenge completion to ACME and downloading cert"
  await self.acmeClient.getCertificate(
    api.Domain("*." & baseDomain),
    certKeyPair,
    dns01Challenge,
    self.config.acmeRetries,
    self.config.finalizeRetries,
  )

proc brokerAddrs(
    self: AutotlsService, switch: Switch
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  ## Wait for a TCP listener to bind, then use its concrete addresses instead
  ## of Switch.peerInfo.listenAddrs, which is populated only after every
  ## transport has started.
  let tcpTransports = switch.transports.filterIt(it of TcpTransport)

  while true:
    var started: seq[Transport]
    for transport in tcpTransports:
      if transport.running:
        started.add(transport)
        let addrs = await self.peerInfo.expandAddrs(transport.addrs)
        if addrs.len > 0:
          return addrs

    # A started TCP transport with no dialable addresses is a dial-only
    # transport (or its addresses were filtered). It cannot bootstrap AutoTLS.
    # Wait for another listener, or retry expansion in case an address mapper is
    # still becoming ready.
    let pending = tcpTransports.filterIt(not it.running)
    if pending.len > 0:
      try:
        discard await one(pending.mapIt(it.onRunning.wait()))
      except ValueError:
        # The list cannot normally be empty after the check above; retain the
        # guard because a future combinator rejects an empty sequence.
        discard
    elif started.len > 0:
      await sleepAsync(max(self.config.issueRetryTime, 1.milliseconds))

proc issueCertificate(
    self: AutotlsService, switch: Switch
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  trace "Issuing certificate"

  if self.peerInfo.isNil():
    return err("Cannot issue new certificate: peerInfo not set")

  if self.config.ipAddress.isNone():
    return err("Cannot issue new certificate: IP address not configured")

  let addrs = await self.brokerAddrs(switch)

  let peerLabel = ?encodePeerId(self.peerInfo.peerId)
  let baseDomain = api.Domain(peerLabel & "." & self.config.domainSuffix)

  let certKeyPair = RsaPrivateKey.random(self.rng).valueOr:
    return err("Unable to generate certificate key pair")

  let certificate = ?(await self.requestCertificate(baseDomain, certKeyPair, addrs))

  trace "Installing certificate"
  self.cert = Opt.some(?newAutotlsCert(certificate, certKeyPair))
  self.certReady.fire()
  info "AutoTLS successfully renewed certificate"
  ok()

proc hasTcpTransport(switch: Switch): bool =
  switch.transports.anyIt(it of TcpTransport)

proc tryIssueCertificate(
    self: AutotlsService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  var lastError = ""
  let operation = if self.cert.isSome(): "renewal" else: "initial issuance"
  var attempts = 0
  var outcome = "cancelled"
  defer:
    debug "Certificate issuance finished",
      operation, outcome, attempts, hasCertificate = self.cert.isSome()

  for attempt in 0 .. self.config.issueRetries:
    if attempt > 0:
      await sleepAsync(self.config.issueRetryTime)
    attempts.inc()
    let issued = await self.issueCertificate(switch)
    if issued.isOk():
      outcome = "issued"
      return

    outcome = "failed"
    lastError = issued.error
    trace "Certificate issuance failed", err = lastError, attempt = attempt + 1

  error "Failed to issue certificate",
    err = lastError,
    operation,
    maxAttempts = self.config.issueRetries + 1,
    hasCertificate = self.cert.isSome(),
    expiry = (if self.cert.isSome: $self.cert.get().expiry else: "none")

method start*(
    self: AutotlsService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  self.running.fire()
  self.peerInfo = switch.peerInfo

  # The switch starts services concurrently with transports. Requiring the TCP
  # transport to be running here could fail when the service starts first, so
  # AutotlsService should only check whether a transport exists.
  if not switch.hasTcpTransport():
    error "Could not find a TcpTransport in switch"
    return

  proc manageCert() {.async: (raises: []).} =
    try:
      heartbeat "Certificate Management", self.config.renewCheckTime:
        if self.cert.isNone():
          await self.tryIssueCertificate(switch)

        self.cert.ifValue(cert):
          let timeUntilExpiry = seconds(cert.expiry.toTime.toUnix - now().toTime.toUnix)
          if timeUntilExpiry <= self.config.renewBufferTime:
            await self.tryIssueCertificate(switch)
    except CancelledError:
      trace "Autotls management cancelled"

  self.managerFut = manageCert()
  info "AutoTLS management started"

method stop*(
    self: AutotlsService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  if not self.acmeClient.isNil():
    await self.acmeClient.close()
  if not self.broker.isNil():
    await self.broker.close()
  if not self.managerFut.isNil():
    await self.managerFut.cancelAndWait()
    self.managerFut = nil

when defined(libp2p_testing):
  func ipAddress*(config: AutotlsConfig): Opt[IpAddress] =
    config.ipAddress
