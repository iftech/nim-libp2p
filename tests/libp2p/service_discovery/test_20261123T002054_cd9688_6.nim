# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results
import ../../../libp2p/[extended_peer_record, protocols/service_discovery/types]
import ../../tools/unittest
import ./utils

suite "Service discovery advertisement binding":
  test "unrelated service metadata does not affect the requested service":
    const
      Requested = "/example/service/1.0.0"
      Other = "/example/other/1.0.0"

    let key = randomKey()
    var record = makeAdvertisement(Requested, key).data
    let baseline = SignedExtendedPeerRecord.init(key, record).get()
    let serviceId = Requested.hashServiceId()
    check isValidAdvertisement(
      RegisterMessage(advertisement: Opt.some(baseline.encode().get())), serviceId
    ).isOk()

    record.services.add(
      ServiceInfo(id: Other, data: Opt.some(newSeq[byte](MaxServiceDataSize + 1)))
    )
    let ad = SignedExtendedPeerRecord.init(key, record).get()
    let encoded = ad.encode().get()
    check encoded.len <= MaxXPRSize
    check Advertisement.decode(encoded).isOk()
    check ad.advertisesService(serviceId)
    check isValidAdvertisement(
      RegisterMessage(advertisement: Opt.some(encoded)), serviceId
    ).isOk()
