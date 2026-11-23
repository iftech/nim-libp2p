# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import results
import ../../../libp2p/[extended_peer_record, signed_envelope]
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/9 - unrelated signed ServiceInfo":
  test "registrar treats data for the other service as opaque":
    let key = randomKey()
    let requested = "/example/requested/1.0.0"
    let record = ExtendedPeerRecord.init(
      PeerId.init(key).get(),
      @[],
      services = @[
        makeServiceInfo(requested),
        ServiceInfo(
          id: "/example/other/1.0.0",
          data: Opt.some(newSeq[byte](MaxServiceDataSize + 1)),
        ),
      ],
    )
    let ad = SignedExtendedPeerRecord.init(key, record).get()
    let bytes = ad.encode().get()
    check bytes.len <= MaxXPRSize
    let msg = RegisterMessage(advertisement: Opt.some(bytes))
    check isValidAdvertisement(msg, requested.hashServiceId()).isOk()
