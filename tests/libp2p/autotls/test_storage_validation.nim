# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, times
import stew/byteutils
from ../../../libp2p/results import isOfError
import
  ../../../libp2p/[
    autotls/service,
    autotls/acme/api,
    crypto/crypto,
    crypto/rsa,
    transports/tls/certificate,
  ]
import ../../tools/[unittest, crypto]

suite "AutoTLS stored state validation":
  let accountKey = RsaPrivateKey.random(rng()).get()
  let accountBytes = accountKey.getBytes().get()
  let keyPair = KeyPair.random(PKScheme.RSA, rng()).get()
  let pem = generateX509(keyPair, encodingFormat = EncodingFormat.PEM)
  let certificate = string.fromBytes(pem.certificate)
  let privateKey = string.fromBytes(pem.privateKey)

  test "empty and valid account states":
    let empty = AutotlsStoredState().validate().get()
    check:
      empty.accountKey.isNone()
      empty.certificate.isNone()
      not empty.certificateExpired
    let valid = AutotlsStoredState(
        accountKey: accountBytes, accountKid: Kid("account-url")
      )
      .validate()
      .get()
    check:
      valid.accountKey.get() == accountKey
      valid.accountKid == Kid("account-url")

  test "rejects account URL without a key and invalid keys":
    check AutotlsStoredState(accountKid: Kid("url")).validate().error ==
      "AutoTLS storage has an account URL without an account key"
    check AutotlsStoredState(accountKey: @[1.byte]).validate().error ==
      "AutoTLS storage contains an invalid account key"

  test "rejects incomplete and malformed certificates":
    for state in [
      AutotlsStoredState(certificatePem: certificate),
      AutotlsStoredState(certificateKeyPem: privateKey),
    ]:
      check state.validate().error ==
        "AutoTLS storage contains an incomplete certificate"
    check:
      AutotlsStoredState(certificatePem: "invalid", certificateKeyPem: privateKey).validate().error ==
        "AutoTLS storage contains a certificate with an invalid expiry"
    check:
      AutotlsStoredState(certificatePem: certificate, certificateKeyPem: "invalid")
        .validate()
        .isOfError("AutoTLS storage contains an invalid certificate or private key")

  test "returns a usable certificate":
    let valid = AutotlsStoredState(
        certificatePem: certificate, certificateKeyPem: privateKey
      )
      .validate()
      .get()
    check:
      valid.certificate.isSome()
      not valid.certificateExpired
      valid.certificate.get().expiry == fromUnix(67090165200).utc

  test "rejects a certificate and private key from different keypairs":
    let otherPem = generateX509(keyPair, encodingFormat = EncodingFormat.PEM)
    let chain = certificate & string.fromBytes(otherPem.certificate)
    check:
      AutotlsStoredState(certificatePem: chain, certificateKeyPem: privateKey)
        .validate()
        .isOk()
      AutotlsStoredState(
        certificatePem: chain, certificateKeyPem: string.fromBytes(otherPem.privateKey)
      ).validate().error ==
        "AutoTLS storage contains a certificate and private key that do not match"

  test "expired certificate is ignored":
    let expired = tlsCertPemGenerator(fromUnix(1600000000))
    let valid = AutotlsStoredState(certificatePem: expired, certificateKeyPem: "unused")
      .validate()
      .get()
    check:
      valid.certificate.isNone()
      valid.certificateExpired
