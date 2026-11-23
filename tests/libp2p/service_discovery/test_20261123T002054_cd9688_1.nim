# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

# Proof for finding 20261123T002054-cd9688/1.
#
# logos-service-discovery.md, "Advertisement Signature Verification":
#
#   envelope = DECODE_SIGNED_ENVELOPE(encoded_ad_bytes)
#   assert(envelope.domain == "libp2p-routing-state")
#
# An XPR advertisement is signed, and verified, in the envelope domain
# "libp2p-routing-state".

import results
import ../../../libp2p/[crypto/crypto, extended_peer_record, peerid, signed_envelope]
import ../../../libp2p/protocols/service_discovery/types
import ../../tools/[unittest]
import ./utils

const SpecEnvelopeDomain = "libp2p-routing-state"

suite "Spec proof 20261123T002054-cd9688/1 - XPR envelope domain":
  test "the XPR envelope domain is libp2p-routing-state":
    check ExtendedPeerRecord.payloadDomain() == SpecEnvelopeDomain

  test "an advertisement built by this node verifies in the spec's domain":
    let ad = makeAdvertisement("/waku/store/1.0.0")
    check ad.envelope.verify(SpecEnvelopeDomain)

  test "an advertisement signed in the spec's domain is accepted":
    let
      privateKey = randomKey()
      record = ExtendedPeerRecord(
        peerId: PeerId.init(privateKey).get(),
        seqNo: 1,
        services: @[ServiceInfo(id: "/waku/store/1.0.0")],
      )
      # The envelope a spec-following advertiser produces: same payload and
      # payload type as this implementation, signed in the spec's domain.
      envelope = Envelope
        .init(
          privateKey,
          ExtendedPeerRecord.payloadType(),
          record.encode(),
          SpecEnvelopeDomain,
        )
        .get()

    check envelope.verify(SpecEnvelopeDomain)
    check Advertisement.decode(envelope.encode()).isOk()
