# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements Signed Envelope.

{.push raises: [].}

import pkg/stew/byteutils, pkg/results
import multicodec, crypto/crypto, vbuffer
import protobuf_serialization

export crypto

type
  EnvelopeErrorKind* = enum
    EnvelopeInvalidProtobuf
    EnvelopeFieldMissing
    EnvelopeInvalidSignature
    EnvelopeWrongType

  EnvelopeError* = object
    kind*: EnvelopeErrorKind
    msg*: string

  Envelope* {.proto3.} = object
    publicKey* {.fieldNumber: 1, ext.}: PublicKey
    payloadType* {.fieldNumber: 2.}: seq[byte]
    payload {.fieldNumber: 3.}: seq[byte]
    signature* {.fieldNumber: 5, ext.}: Signature

func init*(T: type EnvelopeError, kind: EnvelopeErrorKind, msg = ""): EnvelopeError =
  EnvelopeError(kind: kind, msg: msg)

func `==`*(e: EnvelopeError, kind: EnvelopeErrorKind): bool =
  e.kind == kind

func `$`*(e: EnvelopeError): string =
  if e.msg.len == 0:
    return $e.kind

  $e.kind & ": " & e.msg

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
    except SerializationError as e:
      return err(EnvelopeError.init(EnvelopeInvalidProtobuf, e.msg))

  if envelope.publicKey.getBytes().isErr:
    return err(EnvelopeError.init(EnvelopeFieldMissing, "publicKey"))

  if envelope.signature.data.len == 0:
    return err(EnvelopeError.init(EnvelopeFieldMissing, "signature"))

  if not envelope.verify(domain):
    return err(EnvelopeError.init(EnvelopeInvalidSignature))

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

proc fromVerifiedEnvelope[T](
    _: typedesc[SignedPayload[T]], envelope: Envelope
): Result[SignedPayload[T], EnvelopeError] =
  mixin decode

  if envelope.payloadType != T.payloadType:
    return err(EnvelopeError.init(EnvelopeWrongType))

  let data = T.decode(envelope.payload).valueOr:
    return err(EnvelopeError.init(EnvelopeInvalidProtobuf, $error))
  let signedPayload = SignedPayload[T](envelope: envelope, data: data)

  when compiles(?signedPayload.checkValid()):
    ?signedPayload.checkValid()

  ok(signedPayload)

proc decode*[T](
    _: typedesc[SignedPayload[T]], envelope: Envelope
): Result[SignedPayload[T], EnvelopeError] =
  if not envelope.verify(T.payloadDomain):
    return err(EnvelopeError.init(EnvelopeInvalidSignature))

  SignedPayload[T].fromVerifiedEnvelope(envelope)

proc decode*[T](
    _: typedesc[SignedPayload[T]], buffer: sink seq[byte]
): Result[SignedPayload[T], EnvelopeError] =
  let envelope = ?Envelope.decode(move(buffer), T.payloadDomain)
  SignedPayload[T].fromVerifiedEnvelope(envelope)

proc encode*[T](msg: SignedPayload[T]): seq[byte] =
  msg.envelope.encode()
