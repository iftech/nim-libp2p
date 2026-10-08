# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos/streams/tlsstream, stew/byteutils, times
import ../../libp2p/[crypto/crypto, peerid, transports/tls/certificate]

var rngSingleton {.threadvar.}: Rng
rngSingleton = newRng()

const DefaultTlsCertValidToUnix* = 67090165200
  ## The default `validTo` used by `generateX509` (4096-01-01T13:00:00Z).

proc getRng(): Rng =
  rngSingleton

template rng*(): Rng =
  getRng()

proc randomPeerId*(r: Rng = rng()): PeerId =
  PeerId.random(r).expect("the rng produces a valid peer id")

proc tlsCertGenerator*(
    kp: Opt[KeyPair] = Opt.none(KeyPair)
): (TLSPrivateKey, TLSCertificate) {.gcsafe, raises: [].} =
  try:
    let keyPair = kp.valueOr:
      KeyPair.random(PKScheme.RSA, rng()).get()
    let certX509 = generateX509(keyPair, encodingFormat = EncodingFormat.PEM)

    let secureKey = TLSPrivateKey.init(string.fromBytes(certX509.privateKey))
    let secureCert = TLSCertificate.init(string.fromBytes(certX509.certificate))

    (secureKey, secureCert)
  except TLSStreamProtocolError, TLSCertificateError:
    raiseAssert "should not happen"

proc tlsCertPemGenerator*(
    validTo: Time = fromUnix(DefaultTlsCertValidToUnix)
): string {.gcsafe, raises: [].} =
  ## The certificate as a server hands it over, before `TLSCertificate.init`.
  try:
    let keyPair = KeyPair.random(PKScheme.RSA, rng()).get()
    let certX509 = generateX509(
      keyPair, validTo = validTo, encodingFormat = EncodingFormat.PEM
    ).certificate

    string.fromBytes(certX509)
  except TLSCertificateError:
    raiseAssert "should not happen"
