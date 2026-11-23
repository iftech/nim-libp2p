# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos
import ../../../../libp2p/protocols/kademlia
import ../../../tools/[lifecycle, unittest]
import ../../kademlia/utils as kad_utils
import ../utils

suite "Service Discovery Component - Add Provider":
  teardown:
    checkTrackers()

  asyncTest "provide a key from a service discovery node":
    let nodes = setupServiceDiscoveryNodes(2)
    startAndDeferStop(nodes)
    await connect(nodes[0], nodes[1])

    await nodes[0].startProviding(nodes[1].rtable.selfId.toCid())

    checkUntilTimeout:
      nodes[1].providerCount() == 1
      nodes[0].providedCount() == 1
