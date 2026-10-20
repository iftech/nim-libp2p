# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import stew/byteutils
import ../../libp2p/[signed_envelope]
import ../tools/[unittest, crypto]

suite "Signed envelope":
  test "Encode -> decode -> encode -> decode test":
    let
      privKey = PrivateKey.random(rng()).tryGet()
      envelope =
        Envelope.init(privKey, @[byte 12, 0], "payload".toBytes(), "domain").tryGet()
      buffer = envelope.encode()
      decodedEnvelope = Envelope.decode(buffer, "domain").tryGet()
      wrongDomain = Envelope.decode(buffer, "wdomain")

      reencodedEnvelope = decodedEnvelope.encode()
      redecodedEnvelope = Envelope.decode(reencodedEnvelope, "domain").tryGet()

    check:
      decodedEnvelope == envelope
      wrongDomain.error == EnvelopeInvalidSignature

      reencodedEnvelope == buffer
      redecodedEnvelope == envelope

  test "Interop decode test":
    # from https://github.com/libp2p/go-libp2p-core/blob/b18a4c9c5629870bde2cd85ab3b87a507600d411/record/envelope_test.go#L68
    let inputData = "0a24080112206f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f812102f6c69627032702f74657374646174611a0c68656c6c6f20776f726c64212a401178673b51dfa842aad17e465e25d646ad16628916b964c3fb10c711fee87872bdd4e4646f58c277cdff09704913d8be1aec6322de8d3d0bb852120374aece08".hexToSeqByte()
    let decodedEnvelope = Envelope.decode(inputData, "libp2p-testing").tryGet()
    check:
      decodedEnvelope.payloadType == "/libp2p/testdata".toBytes()
      decodedEnvelope.payload == "hello world!".toBytes()

  test "Signature validation":
    # same as above, but payload altered
    let inputData = "0a24080112206f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f812102f6c69627032702f74657374646174611a0c00006c6c6f20776f726c64212a401178673b51dfa842aad17e465e25d646ad16628916b964c3fb10c711fee87872bdd4e4646f58c277cdff09704913d8be1aec6322de8d3d0bb852120374aece08".hexToSeqByte()
    check Envelope.decode(inputData, "libp2p-testing").error == EnvelopeInvalidSignature

  test "Garbage key bytes in field 1":
    let inputData = @[0x0A'u8, 0x05, 0x08, 0x01, 0x12, 0x01, 0x00]
    check Envelope.decode(inputData, "domain").error == EnvelopeInvalidProtobuf

  test "Empty signature":
    let privKey = PrivateKey.random(rng()).tryGet()
    var envelope =
      Envelope.init(privKey, @[byte 12, 0], "payload".toBytes(), "domain").tryGet()
    envelope.signature = Signature()
    check Envelope.decode(envelope.encode(), "domain").error == EnvelopeFieldMissing

# needs to be exported to work
type
  DummyPayload* = object
    awesome: byte

  SignedDummy = SignedPayload[DummyPayload]

proc decode*(
    T: typedesc[DummyPayload], buffer: seq[byte]
): Result[DummyPayload, cstring] =
  ok(DummyPayload(awesome: buffer[0]))

proc encode*(pd: DummyPayload): seq[byte] =
  @[pd.awesome]

proc checkValid*(pd: SignedDummy): Result[void, EnvelopeError] =
  if pd.data.awesome == 12.byte:
    ok()
  else:
    err(EnvelopeInvalidSignature)

proc payloadDomain*(T: typedesc[DummyPayload]): string =
  "dummy"

proc payloadType*(T: typedesc[DummyPayload]): seq[byte] =
  @[(byte) 0x00, (byte) 0x00]

suite "Signed payload":
  test "Simple encode -> decode":
    let
      privKey = PrivateKey.random(rng()).tryGet()
      dummyPayload = DummyPayload(awesome: 12.byte)
      signed = SignedDummy.init(privKey, dummyPayload).tryGet()
      encoded = signed.encode()
      decoded = SignedDummy.decode(encoded).tryGet()

    check:
      dummyPayload.awesome == decoded.data.awesome
      decoded.envelope.publicKey == privKey.getPublicKey().tryGet()

  test "Invalid payload":
    let
      privKey = PrivateKey.random(rng()).tryGet()
      dummyPayload = DummyPayload(awesome: 30.byte)
      signed = SignedDummy.init(privKey, dummyPayload).tryGet()
      encoded = signed.encode()

    check SignedDummy.decode(encoded).error == EnvelopeInvalidSignature

  test "Invalid payload type":
    let
      privKey = PrivateKey.random(rng()).tryGet()
      dummyPayload = DummyPayload(awesome: 30.byte)
      signed = Envelope
        .init(privKey, @[55.byte], dummyPayload.encode(), DummyPayload.payloadDomain)
        .tryGet()
      encoded = signed.encode()

    check SignedDummy.decode(encoded).error == EnvelopeWrongType
