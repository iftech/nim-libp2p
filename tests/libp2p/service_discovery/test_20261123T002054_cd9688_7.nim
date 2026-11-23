# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import
  ../../../libp2p/[
    extended_peer_record, protocols/service_discovery/advertiser,
    protocols/service_discovery/types,
  ]
import ../../tools/unittest
import ./utils

suite "Service discovery client mode":
  test "a configured service is omitted from records published by clients":
    let service = makeServiceInfo("/example/client-mode/1.0.0")
    let client = setupServiceDiscoveryNode(client = true, services = @[service])
    for candidate in client.xprsToPublish():
      let decoded = SignedExtendedPeerRecord.decode(candidate.bytes)
      check decoded.isOk()
      if decoded.isOk():
        check not decoded.get().advertisesService(service.id.hashServiceId())
