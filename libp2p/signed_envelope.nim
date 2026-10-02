# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements Signed Envelope.

{.push raises: [].}

import pkg/stew/byteutils, pkg/results
import multicodec, crypto/crypto, vbuffer
import protobuf_serialization

export crypto

type
  EnvelopeError* = enum
    EnvelopeInvalidProtobuf
    EnvelopeFieldMissing
    EnvelopeInvalidSignature
    EnvelopeWrongType

  Envelope* {.proto3.} = object
    publicKey* {.fieldNumber: 1, ext.}: PublicKey
    payloadType* {.fieldNumber: 2.}: seq[byte]
    payload {.fieldNumber: 3.}: seq[byte]
    signature* {.fieldNumber: 5, ext.}: Signature

proc getSignatureBuffer(e: Envelope, domain: string): seq[byte] =
  var buffer = initVBuffer()

  buffer.writeSeq(domain.toBytes())
  buffer.writeSeq(e.payloadType)
  buffer.writeSeq(e.payload)

  buffer.buffer

proc init*(
    T: typedesc[Envelope],
    privateKey: PrivateKey,
    payloadType: sink seq[byte],
    payload: sink seq[byte],
    domain: string,
): Result[Envelope, CryptoError] =
  var envelope = Envelope(
    publicKey: ?privateKey.getPublicKey(),
    payloadType: move(payloadType),
    payload: move(payload),
  )

  envelope.signature = ?privateKey.sign(envelope.getSignatureBuffer(domain))

  ok(envelope)

proc verify*(envelope: Envelope, domain: string): bool =
  envelope.signature.verify(envelope.getSignatureBuffer(domain), envelope.publicKey)

proc encode*(envelope: Envelope): seq[byte] =
  Protobuf.encode(envelope)

proc decode*(
    _: type Envelope, buf: seq[byte], domain: string
): Result[Envelope, EnvelopeError] =
  let envelope =
    try:
      Protobuf.decode(buf, Envelope)
    except SerializationError:
      return err(EnvelopeInvalidProtobuf)

  if envelope.publicKey.getBytes().isErr:
    return err(EnvelopeFieldMissing)

  if envelope.signature.data.len == 0:
    return err(EnvelopeFieldMissing)

  if not envelope.verify(domain):
    return err(EnvelopeInvalidSignature)

  ok(envelope)

proc payload*(envelope: Envelope): seq[byte] =
  # Payload is readonly
  envelope.payload

type SignedPayload*[T] = object
  # T needs to have .encode(), .decode(), .payloadType(), .payloadDomain()
  envelope*: Envelope
  data*: T

proc init*[T](
    _: typedesc[SignedPayload[T]], privateKey: PrivateKey, data: T
): Result[SignedPayload[T], CryptoError] =
  mixin encode

  let envelope =
    ?Envelope.init(privateKey, T.payloadType(), data.encode(), T.payloadDomain)

  ok(SignedPayload[T](data: data, envelope: envelope))

proc decode*[T](
    _: typedesc[SignedPayload[T]], envelope: Envelope
): Result[SignedPayload[T], EnvelopeError] =
  mixin decode

  if envelope.payloadType != T.payloadType:
    return err(EnvelopeWrongType)
  if not envelope.verify(T.payloadDomain):
    return err(EnvelopeInvalidSignature)

  let data = T.decode(envelope.payload).valueOr:
    return err(EnvelopeInvalidProtobuf)
  let signedPayload = SignedPayload[T](envelope: envelope, data: data)

  when compiles(?signedPayload.checkValid()):
    ?signedPayload.checkValid()

  ok(signedPayload)

proc decode*[T](
    _: typedesc[SignedPayload[T]], buffer: sink seq[byte]
): Result[SignedPayload[T], EnvelopeError] =
  let envelope = ?Envelope.decode(move(buffer), T.payloadDomain)
  SignedPayload[T].decode(envelope)

proc encode*[T](msg: SignedPayload[T]): seq[byte] =
  msg.envelope.encode()
