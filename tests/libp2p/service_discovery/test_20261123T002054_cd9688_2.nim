# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

# Proof for finding 20261123T002054-cd9688/2.
#
# logos-service-discovery.md, "Advertisement Signature Verification":
#
#   envelope = DECODE_SIGNED_ENVELOPE(encoded_ad_bytes)
#   assert(envelope.payload_type == "/libp2p/extensible-peer-record/")
#
# An XPR advertisement carries the payload type
# "/libp2p/extensible-peer-record/", and a verifier asserts it.

import results
import stew/byteutils
import
  ../../../libp2p/
    [crypto/crypto, extended_peer_record, peerid, routing_record, signed_envelope]
import ../../../libp2p/protocols/service_discovery/types
import ../../tools/[unittest]
import ./utils

const SpecPayloadType = "/libp2p/extensible-peer-record/"

suite "Spec proof 20261123T002054-cd9688/2 - XPR envelope payload type":
  test "the XPR payload type is /libp2p/extensible-peer-record/":
    check ExtendedPeerRecord.payloadType() == SpecPayloadType.toBytes()

  test "an advertisement built by this node carries the spec's payload type":
    let ad = makeAdvertisement("/waku/store/1.0.0")
    check ad.envelope.payloadType == SpecPayloadType.toBytes()

  test "an advertisement carrying the spec's payload type is accepted":
    let
      privateKey = randomKey()
      record = ExtendedPeerRecord(
        peerId: PeerId.init(privateKey).get(),
        seqNo: 1,
        services: @[ServiceInfo(id: "/waku/store/1.0.0")],
      )
      # Same payload and signing domain as this implementation; only the
      # payload type is the one the spec names.
      envelope = Envelope
        .init(
          privateKey,
          SpecPayloadType.toBytes(),
          record.encode(),
          ExtendedPeerRecord.payloadDomain(),
        )
        .get()

    check Advertisement.decode(envelope.encode()).isOk()

  test "an envelope that is not an extensible peer record is not an advertisement":
    # A plain routing record (payload type 0x0301) fails the spec's
    # payload_type assert, so it must not decode as an advertisement.
    let
      privateKey = randomKey()
      ordinary = SignedPeerRecord
        .init(privateKey, PeerRecord.init(PeerId.init(privateKey).get(), @[]))
        .get()

    check ordinary.envelope.payloadType != SpecPayloadType.toBytes()
    check Advertisement.decode(ordinary.encode().get()).isErr()
