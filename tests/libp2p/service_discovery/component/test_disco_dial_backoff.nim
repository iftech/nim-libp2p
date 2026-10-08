# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results
import
  ../../../../libp2p/[
    peerstore,
    protocols/kademlia,
    protocols/service_discovery/advertiser,
    protocols/service_discovery/connection,
    protocols/service_discovery/dial_backoff,
    protocols/service_discovery/types,
    switch,
  ]
import ../../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../../tools/[lifecycle, multiaddress, unittest]
import ../utils

suite "Service Discovery Component - Dial Backoff":
  teardown:
    checkTrackers()

  asyncTest "an unreachable peer backs off, then leaves the service table":
    # A backoff no test run can outlive keeps the assertions off the scheduler.
    let discoConfig = ServiceDiscoveryConfig.new(
      dialBackoffBase = 1.hours, dialBackoffMax = 1.hours, maxDialFailures = 3
    )
    let disco = setupServiceDiscoveryNode(discoConfig = discoConfig)
    startAndDeferStop(@[disco])

    let service = makeServiceInfo()
    check disco.addProvidedService(service)
    let table = disco.rtManager.getTable(service.id.hashServiceId()).get()

    let deadPeerId = randomPeerId()
    let deadAddrs = @[ma("/ip4/127.0.0.1/tcp/1")]
    disco.switch.peerStore[AddressBook].set(
      deadPeerId, deadAddrs, AddressConfidence.Low
    )
    check table.insert(deadPeerId)

    let msg = kad_protobuf.Message(msgType: kad_protobuf.MessageType.ping)

    check (await disco.send(deadPeerId, msg)).isErr()

    let backedOff = await disco.send(deadPeerId, msg)
    check:
      backedOff.isErr()
      backedOff.error == makeDialBackoffError(deadPeerId)
      table.contains(deadPeerId.toKey())

    # The gate blocks further dials, so the rest is recorded without a wait.
    for _ in 1 .. 2:
      disco.recordDialFailure(deadPeerId, deadAddrs)

    check not table.contains(deadPeerId.toKey())

    # A re-admitted peer must stay backed off, or the eviction only restarts the loop.
    check table.insert(deadPeerId)
    let reAdmitted = await disco.send(deadPeerId, msg)
    check:
      reAdmitted.isErr()
      reAdmitted.error == makeDialBackoffError(deadPeerId)
