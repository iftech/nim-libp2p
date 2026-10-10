# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import sequtils
import chronos, chronicles, net, uri
import chronos/apps/http/httpclient
import chronos/streams/tlsstream
from times import DateTime, now, toTime, toUnix, utc
import stew/byteutils

import
  ./acme/client,
  ./broker,
  ./storage,
  ./utils,
  ../crypto/rsa,
  ../crypto/rng,
  ../logging,
  ../nameresolving/nameresolver,
  ../nameresolving/dnsresolver,
  ../switch,
  ../peerinfo,
  ../transports/transport,
  ../transports/tcptransport,
  ../transports/tls/certificate,
  ../utils/heartbeat,
  ../utils/ipaddr,
  ../utils/tlsredact,
  ../utils/future,
  ../wire

logScope:
  topics = "libp2p auto-tls"

export
  LetsEncryptDirectoryURL, AutoTLSError, DefaultDnsServers, DefaultRegistrationURL,
  AutotlsBroker, storage, tlsredact

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

type CertSubscription* = ref object
  ## A subscription to certificates issued after it is created.
  updates: AsyncEventQueue[Opt[AutotlsCert]]
  key: EventQueueKey

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
  storage*: Opt[AutotlsStorage]

type AutotlsService* = ref object of Service
  acmeClient*: ACMEClient
  broker*: AutotlsBroker
  cert*: Opt[AutotlsCert]
  certFailure: Opt[string]
  certReady*: AsyncEvent
  certUpdates: AsyncEventQueue[Opt[AutotlsCert]]
  running*: AsyncEvent
  config*: AutotlsConfig
  managerFut: Future[void]
  peerInfo: PeerInfo
  rng*: Rng
  publicIpWarnings: LogRateLimit
  storageKey: Opt[AutotlsStorageKey]

proc new*(
    T: typedesc[AutotlsCert],
    cert: TLSCertificate,
    privkey: TLSPrivateKey,
    expiry: DateTime,
): T =
  T(cert: cert, privkey: privkey, expiry: expiry)

method getCertWhenReady*(
    self: AutotlsService
): Future[LPResult[AutotlsCert]] {.base, async: (raises: [CancelledError]).} =
  if self.cert.isSome():
    return ok(self.cert.get())
  await self.certReady.wait()
  if self.cert.isSome():
    return ok(self.cert.get())
  err(self.certFailure.get("certificate issuance failed without an error"))

proc resetCertWait(self: AutotlsService) =
  self.certFailure = Opt.none(string)
  self.certReady.clear()

proc installCertificate(self: AutotlsService, cert: AutotlsCert) =
  ## Install a certificate and notify listeners that terminate TLS themselves.
  self.cert = Opt.some(cert)
  self.certFailure = Opt.none(string)
  self.certReady.fire()
  if not self.certUpdates.isNil:
    self.certUpdates.emit(Opt.some(cert))

proc waitUpdates*(
    self: CertSubscription
): Future[seq[AutotlsCert]] {.async: (raises: [CancelledError]).} =
  ## Wait for certificates issued since the previous call to this procedure.
  ## Returns an empty sequence when the service stops. The subscription remains
  ## active and will receive certificates issued after the service restarts.
  if self.updates.isNil: # The subscription was already unsubscribed
    return @[]

  try:
    (await self.updates.waitEvents(self.key)).filterIt(it.isSome()).mapIt(it.get())
  except AsyncEventQueueFullError:
    # Certificate update queues are always unbounded, so this is unreachable.
    return @[]

proc unsubscribe*(self: CertSubscription) =
  ## Stop receiving certificate updates. This procedure is idempotent.
  if not self.updates.isNil:
    self.updates.unregister(self.key)
    self.updates = nil

proc subscribeCertificateUpdates*(self: AutotlsService): CertSubscription =
  ## Subscribe to certificates issued after this call.
  if self.certUpdates.isNil:
    self.certUpdates = newAsyncEventQueue[Opt[AutotlsCert]]()
  CertSubscription(updates: self.certUpdates, key: self.certUpdates.register())

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
    storage: Opt[AutotlsStorage] = Opt.none(AutotlsStorage),
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
    storage: storage,
  )

proc new*(
    T: typedesc[AutotlsService], rng: Rng, config: AutotlsConfig = AutotlsConfig.new()
): T =
  T(
    acmeClient: nil,
    broker: AutotlsBroker.new(rng, config.registrationURL),
    cert: Opt.none(AutotlsCert),
    certFailure: Opt.none(string),
    certReady: newAsyncEvent(),
    certUpdates: newAsyncEventQueue[Opt[AutotlsCert]](),
    running: newAsyncEvent(),
    config: config,
    managerFut: nil,
    peerInfo: nil,
    rng: rng,
    storageKey: Opt.none(AutotlsStorageKey),
  )

proc isRunning*(self: AutotlsService): bool =
  self.running.isSet()

proc newStorageKey(self: AutotlsService): LPResult[AutotlsStorageKey] =
  ok(
    AutotlsStorageKey(
      peerLabel: ?encodePeerId(self.peerInfo.peerId),
      acmeDirectoryURL: self.config.acmeDirectoryURL,
      domainSuffix: self.config.domainSuffix,
    )
  )

proc restoreState(self: AutotlsService): Future[LPResult[void]] {.
    async: (raises: [CancelledError])
.} =
  ## Restore state before creating the ACME client so its account identity is
  ## retained across process restarts.
  self.storageKey = Opt.some(?self.newStorageKey())

  var accountKey = Opt.none(RsaPrivateKey)
  var accountKid = Kid("")
  self.config.storage.ifValue(storage):
    let state = ?(await storage.load(self.storageKey.get()))
    state.ifValue(state):
      if state.accountKey.len == 0 and state.accountKid.len > 0:
        return err("AutoTLS storage has an account URL without an account key")
      if state.accountKey.len > 0:
        let key = RsaPrivateKey.init(state.accountKey).valueOr:
          return err("AutoTLS storage contains an invalid account key")
        accountKey = Opt.some(key)
        accountKid = state.accountKid

      let hasCertificate = state.certificatePem.len > 0
      let hasCertificateKey = state.certificateKeyPem.len > 0
      if hasCertificate xor hasCertificateKey:
        return err("AutoTLS storage contains an incomplete certificate")
      if hasCertificate:
        let expiry = validTo(state.certificatePem.toBytes, PEM).valueOr:
          return err("AutoTLS storage contains a certificate with an invalid expiry")
        if expiry.toUnix > now().toTime.toUnix:
          try:
            let certificate = TLSCertificate.init(state.certificatePem)
            let privateKey = TLSPrivateKey.init(state.certificateKeyPem)
            self.installCertificate(AutotlsCert.new(certificate, privateKey, expiry.utc))
            info "Restored AutoTLS certificate from storage"
          except TLSStreamProtocolError:
            return err("AutoTLS storage contains an invalid certificate or private key")
        else:
          info "Stored AutoTLS certificate is expired; a replacement will be requested"

  # Keeping this conditional makes tests and advanced callers that inject a
  # custom ACME API continue to work, while normal construction happens only
  # after persistence has been read.
  if self.acmeClient.isNil:
    self.acmeClient = ACMEClient.new(
      api = ACMEApi.new(self.config.acmeDirectoryURL, self.config.acmeHttpFlags),
      rng = self.rng,
      key = accountKey,
      kid = accountKid,
    )
  ok()

proc saveState(
    self: AutotlsService, certificate: ACMECertificateResponse, certKeyPair: RsaPrivateKey
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  ## Save state only after ACME completed issuance. A save failure does not
  ## invalidate the usable in-memory certificate, but is reported to callers.
  if self.config.storage.isNone():
    return ok()
  if self.storageKey.isNone():
    return err("AutoTLS storage key was not initialized")

  let accountKey = self.acmeClient.key.getBytes().valueOr:
    return err("Unable to serialize AutoTLS account key")
  let certificateKey = certKeyPair.getBytes().valueOr:
    return err("Unable to serialize AutoTLS certificate key")
  let state = AutotlsStoredState(
    accountKey: accountKey,
    accountKid: self.acmeClient.kid,
    certificatePem: certificate.rawCertificate,
    certificateKeyPem: certificateKey.pemEncode("PRIVATE KEY"),
  )
  await self.config.storage.get().save(self.storageKey.get(), state)

proc newAutotlsCert(
    certificate: ACMECertificateResponse, certKeyPair: RsaPrivateKey
): Result[AutotlsCert, LPResultError] =
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
    err(e, "Could not parse downloaded certificates")

proc publishChallenge(
    self: AutotlsService,
    baseDomain: api.Domain,
    keyAuth: KeyAuthorization,
    addrs: seq[MultiAddress],
): Future[Result[void, LPResultError]] {.async: (raises: [CancelledError]).} =
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
      return err(e, $e.name)
  if not dnsSet:
    return err("DNS records not set")
  ok()

proc requestCertificate(
    self: AutotlsService,
    baseDomain: api.Domain,
    certKeyPair: RsaPrivateKey,
    addrs: seq[MultiAddress],
): Future[Result[ACMECertificateResponse, LPResultError]] {.
    async: (raises: [CancelledError])
.} =
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

proc boundAddrs(switch: Switch): seq[MultiAddress] =
  var boundAddrs: seq[MultiAddress]
  for transport in switch.transports:
    if transport.running:
      boundAddrs &= transport.addrs
  return boundAddrs

proc brokerAddrs(
    self: AutotlsService, switch: Switch
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  ## Wait for a TCP listener to bind, then use its concrete addresses instead
  ## of Switch.peerInfo.listenAddrs, which is populated only after every
  ## transport has started.
  let tcpTransports = switch.transports.filterIt(it of TcpTransport)
  if tcpTransports.len == 0:
    return @[]

  proc discoverAddrs(): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    proc isTcpAddress(address: MultiAddress): bool =
      for transport in tcpTransports:
        if transport.handles(address):
          return true
      false

    while true:
      var started: seq[Transport]
      for transport in tcpTransports:
        if transport.running:
          started.add(transport)

      if started.len > 0:
        # Address mappers maintain state for the complete set of bound
        # addresses. In particular, passing only one TCP transport would make
        # them withdraw mappings and candidates belonging to other transports.
        let boundAddrs = switch.boundAddrs()
        if boundAddrs.len > 0:
          let addrs = await self.peerInfo.expandAddrs(boundAddrs)
          # Explicit announcements are an operator-selected broker payload and
          # historically were forwarded as a whole, even when they include a
          # non-TCP address.
          if self.peerInfo.announcedAddrs.len > 0 and addrs.len > 0:
            return addrs
          let tcpAddrs = addrs.filterIt(isTcpAddress(it))
          if tcpAddrs.len > 0:
            return tcpAddrs

      let pending = tcpTransports.filterIt(not it.running)
      if pending.len > 0:
        let notStarted = pending.filterIt(not it.onRunning.isSet)
        if notStarted.len > 0:
          let waits = notStarted.mapIt(it.onRunning.wait())
          try:
            discard await one(waits)
          except ValueError:
            # The list cannot normally be empty after the check above; retain the
            # guard because a future combinator rejects an empty sequence.
            discard
          finally:
            waits.cancelSoon()
        else:
          # AsyncEvent is sticky: a stopped transport's onRunning event remains
          # set from an earlier start, so awaiting it would spin immediately.
          await sleepAsync(self.config.issueRetryTime)
      else:
        # Every TCP transport has started. If none bound a listener, they are all
        # dial-only (or their listen addresses were filtered before startup), so
        # no future address discovery can make this issuance attempt viable.
        if tcpTransports.allIt(it.addrs.len == 0):
          return @[]

        # At least one transport has a bound address, but its mapper may still
        # be becoming ready. Keep retrying until the discovery deadline.
        await sleepAsync(self.config.issueRetryTime)

  try:
    return await discoverAddrs().wait(self.config.initialCertTimeout)
  except AsyncTimeoutError:
    warn "TCP address discovery timed out", timeout = self.config.initialCertTimeout
    return @[]

proc issueCertificate(
    self: AutotlsService, switch: Switch
): Future[Result[void, LPResultError]] {.async: (raises: [CancelledError]).} =
  trace "Issuing certificate"

  if self.peerInfo.isNil():
    return err("Cannot issue new certificate: peerInfo not set")

  if self.config.ipAddress.isNone():
    let ip = getPublicIPAddress().valueOr:
      let ipLookupError = error
      if self.publicIpWarnings.allowLog():
        warn "Certificate issuance failed: unable to determine public IP address",
          err = ipLookupError,
          hint =
            "Set AutotlsConfig.ipAddress or ensure the node is reachable from the public internet"
      return err("Unable to determine public IP address: " & ipLookupError)
    self.config.ipAddress = Opt.some(ip)

  let addrs = await self.brokerAddrs(switch)
  if addrs.len == 0:
    return
      err("No dialable TCP address available before the address discovery deadline")

  let peerLabel = ?encodePeerId(self.peerInfo.peerId)
  let baseDomain = api.Domain(peerLabel & "." & self.config.domainSuffix)

  let certKeyPair = RsaPrivateKey.random(self.rng).valueOr:
    return err("Unable to generate certificate key pair")

  let certificate = ?(await self.requestCertificate(baseDomain, certKeyPair, addrs))

  trace "Installing certificate"
  self.installCertificate(?newAutotlsCert(certificate, certKeyPair))
  let saved = await self.saveState(certificate, certKeyPair)
  if saved.isErr:
    # The certificate remains valid in this process. Returning success avoids
    # immediately ordering another one solely because persistence failed.
    error "Issued AutoTLS certificate could not be persisted", err = saved.error
  info "AutoTLS successfully renewed certificate"
  ok()

proc hasTcpTransport(switch: Switch): bool =
  switch.transports.anyIt(it of TcpTransport)

proc tryIssueCertificate(
    self: AutotlsService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  if self.cert.isNone():
    self.resetCertWait()

  var lastError: LPResultError
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

  if self.cert.isNone():
    self.certFailure = Opt.some($lastError)
    self.certReady.fire()

proc needsRenewal(expiry: DateTime, renewBufferTime: Duration): bool =
  ## Compare absolute times to avoid overflowing Chronos's nanosecond Duration
  ## for certificates that expire far in the future.
  expiry.toTime.toUnix <= now().toTime.toUnix + renewBufferTime.seconds

method start*(
    self: AutotlsService, switch: Switch
) {.async: (raises: [CancelledError, LPError]).} =
  self.running.fire()
  self.peerInfo = switch.peerInfo

  let restored = await self.restoreState()
  if restored.isErr:
    let failure = "Could not restore AutoTLS state: " & $restored.error
    error "Could not restore AutoTLS state", err = restored.error
    self.certFailure = Opt.some(failure)
    self.certReady.fire()
    raise newException(LPError, failure)

  # The switch starts services concurrently with transports. Requiring the TCP
  # transport to be running here could fail when the service starts first, so
  # AutotlsService should only check whether a transport exists.
  if not switch.hasTcpTransport():
    const failure = "Could not find a TcpTransport in switch"
    error failure
    self.certFailure = Opt.some(failure)
    self.certReady.fire()
    return

  if self.cert.isNone():
    self.resetCertWait()

  proc manageCert() {.async: (raises: []).} =
    try:
      heartbeat "Certificate Management", self.config.renewCheckTime:
        if self.cert.isNone():
          await self.tryIssueCertificate(switch)

        self.cert.ifValue(cert):
          if needsRenewal(cert.expiry, self.config.renewBufferTime):
            await self.tryIssueCertificate(switch)
    except CancelledError:
      trace "Autotls management cancelled"

  self.managerFut = manageCert()
  info "AutoTLS management started"

method stop*(
    self: AutotlsService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  self.running.clear()
  if not self.certUpdates.isNil():
    self.certUpdates.emit(Opt.none(AutotlsCert))
  if not self.acmeClient.isNil():
    await self.acmeClient.close()
  if not self.broker.isNil():
    await self.broker.close()
  if not self.managerFut.isNil():
    await self.managerFut.cancelAndWait()
    self.managerFut = nil

when defined(libp2p_testing):
  export installCertificate, issueCertificate

  func ipAddress*(config: AutotlsConfig): Opt[IpAddress] =
    config.ipAddress
