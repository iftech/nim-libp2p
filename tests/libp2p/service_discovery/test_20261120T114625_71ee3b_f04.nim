# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/4.
# Spec, Advertisement Signature Verification (XPR-encoded advertisements):
#   assert(envelope.domain == "libp2p-routing-state")
#   assert(envelope.payload_type == "/libp2p/extensible-peer-record/")

import results
import ../../../libp2p/[extended_peer_record, peerid, routing_record, signed_envelope]
import ../../tools/unittest
import ./utils

suite "Proof 20261120T114625-71ee3b/4 - XPR envelope domain and payload type":
  test "advertisement envelope is signed under the domain the spec names":
    check ExtendedPeerRecord.payloadDomain() == "libp2p-routing-state"

  test "an XPR envelope signed under the spec domain verifies as an advertisement":
    let ad = makeAdvertisement("proof-domain")
    let key = randomKey()
    let envelope = Envelope
      .init(
        key,
        ExtendedPeerRecord.payloadType(),
        ExtendedPeerRecord
        .init(PeerId.init(key).get(), @[], services = ad.data.services)
        .encode(),
        "libp2p-routing-state",
      )
      .get()

    check Advertisement.decode(envelope.encode().get()).isOk()

  test "XPR payload type differs from the plain peer record payload type":
    check ExtendedPeerRecord.payloadType() != PeerRecord.payloadType()
