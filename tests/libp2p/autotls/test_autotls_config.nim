# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, net, uri
import
  ../../../libp2p/[
    autotls/service,
    autotls/acme/api,
    autotls/acme/client,
    nameresolving/dnsresolver,
    wire,
  ]
import ../../tools/unittest

suite "AutoTLS Configuration Tests":
  teardown:
    checkTrackers()

  test "AutotlsConfig constructor with default values":
    let config = AutotlsConfig.new()

    check:
      config.acmeDirectoryURL == LetsEncryptDirectoryURL
      config.ipAddress == Opt.none(IpAddress)
      DnsResolver(config.nameResolver).nameServers == DefaultDnsServers
      config.renewCheckTime == DefaultRenewCheckTime
      config.renewBufferTime == DefaultRenewBufferTime
      config.initialCertTimeout == DefaultInitialCertTimeout
      config.issueRetries == 3
      config.issueRetryTime == 1.seconds
      config.registrationURL == DefaultRegistrationURL
      config.domainSuffix == DefaultDomainSuffix
      config.dnsRetries == 10
      config.dnsRetryTime == 1.seconds
      config.acmeRetries == 10
      config.acmeRetryTime == 1.seconds
      config.finalizeRetries == 10
      config.finalizeRetryTime == 1.seconds

  test "AutotlsConfig constructor with custom values":
    let customIpAddress = parseIpAddress("203.0.113.7")
    let customNameServers =
      @[initTAddress("192.0.2.53:53"), initTAddress("198.51.100.53:53")]
    let customAcmeDirectoryURL = parseUri("https://acme.example.com/dir")
    let customRenewCheckTime = 7.minutes
    let customRenewBufferTime = 8.minutes
    let customInitialCertTimeout = 9.minutes
    let customIssueRetries = 7
    let customIssueRetryTime = 5.seconds
    let customRegistrationURL =
      parseUri("https://custom-broker.example.com/v1/_acme-challenge")
    let customDomainSuffix = "custom.example.test"
    let customDnsRetries = 5
    let customDnsRetryTime = 2.seconds
    let customAcmeRetries = 15
    let customAcmeRetryTime = 3.seconds
    let customFinalizeRetries = 20
    let customFinalizeRetryTime = 4.seconds

    let config = AutotlsConfig.new(
      ipAddress = Opt.some(customIpAddress),
      nameServers = customNameServers,
      acmeDirectoryURL = customAcmeDirectoryURL,
      renewCheckTime = customRenewCheckTime,
      renewBufferTime = customRenewBufferTime,
      initialCertTimeout = customInitialCertTimeout,
      issueRetries = customIssueRetries,
      issueRetryTime = customIssueRetryTime,
      registrationURL = customRegistrationURL,
      domainSuffix = customDomainSuffix,
      dnsRetries = customDnsRetries,
      dnsRetryTime = customDnsRetryTime,
      acmeRetries = customAcmeRetries,
      acmeRetryTime = customAcmeRetryTime,
      finalizeRetries = customFinalizeRetries,
      finalizeRetryTime = customFinalizeRetryTime,
    )

    check:
      config.ipAddress == Opt.some(customIpAddress)
      # nameServers reaches the config as the DnsResolver built out of it.
      DnsResolver(config.nameResolver).nameServers == customNameServers
      config.acmeDirectoryURL == customAcmeDirectoryURL
      config.renewCheckTime == customRenewCheckTime
      config.renewBufferTime == customRenewBufferTime
      config.initialCertTimeout == customInitialCertTimeout
      config.issueRetries == customIssueRetries
      config.issueRetryTime == customIssueRetryTime
      config.registrationURL == customRegistrationURL
      config.domainSuffix == customDomainSuffix
      config.dnsRetries == customDnsRetries
      config.dnsRetryTime == customDnsRetryTime
      config.acmeRetries == customAcmeRetries
      config.acmeRetryTime == customAcmeRetryTime
      config.finalizeRetries == customFinalizeRetries
      config.finalizeRetryTime == customFinalizeRetryTime
