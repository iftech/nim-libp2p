# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, times
import stew/byteutils
import ../../../libp2p/[autotls/service, autotls/acme/api, crypto/crypto, crypto/rsa,
  transports/tls/certificate]
import ../../tools/[unittest, crypto]

suite "AutoTLS stored state validation":
  let accountKey = RsaPrivateKey.random(rng()).get()
  let accountBytes = accountKey.getBytes().get()
  let keyPair = KeyPair.random(PKScheme.RSA, rng()).get()
  let pem = generateX509(keyPair, encodingFormat = EncodingFormat.PEM)
  let certificate = string.fromBytes(pem.certificate)
  let privateKey = string.fromBytes(pem.privateKey)

  test "empty and valid account states":
    let empty = validateStoredState(AutotlsStoredState()).get()
    check:
      empty.accountKey.isNone()
      empty.certificate.isNone()
      not empty.certificateExpired
    let valid = validateStoredState(AutotlsStoredState(
      accountKey: accountBytes, accountKid: Kid("account-url")
    )).get()
    check:
      valid.accountKey.get() == accountKey
      valid.accountKid == Kid("account-url")

  test "rejects account URL without a key and invalid keys":
    check validateStoredState(AutotlsStoredState(accountKid: Kid("url"))).error ==
      "AutoTLS storage has an account URL without an account key"
    check validateStoredState(AutotlsStoredState(accountKey: @[1.byte])).error ==
      "AutoTLS storage contains an invalid account key"

  test "rejects incomplete and malformed certificates":
    for state in [AutotlsStoredState(certificatePem: certificate),
                  AutotlsStoredState(certificateKeyPem: privateKey)]:
      check validateStoredState(state).error ==
        "AutoTLS storage contains an incomplete certificate"
    check validateStoredState(AutotlsStoredState(
      certificatePem: "invalid", certificateKeyPem: privateKey
    )).error == "AutoTLS storage contains a certificate with an invalid expiry"
    check validateStoredState(AutotlsStoredState(
      certificatePem: certificate, certificateKeyPem: "invalid"
    )).error == "AutoTLS storage contains an invalid certificate or private key"

  test "returns a usable certificate":
    let valid = validateStoredState(AutotlsStoredState(
      certificatePem: certificate, certificateKeyPem: privateKey
    )).get()
    check:
      valid.certificate.isSome()
      not valid.certificateExpired
      valid.certificate.get().expiry == fromUnix(67090165200).utc

  test "expired certificate is ignored":
    let expired = tlsCertPemGenerator(fromUnix(1600000000))
    let valid = validateStoredState(AutotlsStoredState(
      certificatePem: expired, certificateKeyPem: "unused"
    )).get()
    check:
      valid.certificate.isNone()
      valid.certificateExpired
