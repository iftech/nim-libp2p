# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils, tables
import ../../../libp2p/[protocols/kademlia, switch, builders]
import ../../../libp2p/utils/future
import ../../tools/[lifecycle, unittest, multiaddress]
import ./utils.nim

proc deadAddrs(port: int): seq[MultiAddress] =
  @[ma("/ip4/127.0.0.1/tcp/" & $port)]

suite "KadDHT - Probe backoff":
  teardown:
    checkTrackers()

  test "probe failure cache stays within maxProbeFailures":
    ## The keys are remote-supplied peer ids, so the cap is what bounds memory.
    let kad = setupKad()
    kad.config.limits.maxProbeFailures = 8

    for i in 0 ..< 100:
      kad.probeRecordFailure(randomPeerId(), deadAddrs(40000 + i))

    check kad.probeFailures.len <= 8

  test "a flood of one-shot failures does not evict a repeat offender":
    let kad = setupKad()
    kad.config.limits.maxProbeFailures = 8
    let offender = randomPeerId()
    let offenderAddrs = deadAddrs(59999)

    for _ in 0 ..< 3:
      kad.probeRecordFailure(offender, offenderAddrs)
    for i in 0 ..< 100:
      kad.probeRecordFailure(randomPeerId(), deadAddrs(40000 + i))

    check kad.probeBackedOff(offender, offenderAddrs)

  test "a peer whose backoff elapsed keeps its count":
    let kad = setupKad()
    kad.config.limits.maxProbeFailures = 1
    kad.config.timeout = 1.nanoseconds
    let peerId = randomPeerId()
    let addrs = deadAddrs(59999)

    kad.probeRecordFailure(peerId, addrs)
    kad.probeRecordFailure(peerId, addrs)

    check kad.probeFailures.getOrDefault(peerId).count == 2

  test "a full cache drops elapsed entries before it records a new failure":
    var failures: Table[PeerId, ProbeFailure]
    for _ in 0 ..< 4:
      failures[randomPeerId()] = ProbeFailure(count: 1, until: Moment.now() - 1.seconds)
    let peerId = randomPeerId()

    failures.recordFailure(peerId, deadAddrs(59999), 1.seconds, 1.minutes, 4)

    check:
      failures.len == 1
      failures.getOrDefault(peerId).count == 1

  test "backoff doubles per failure and stops at the cap":
    check:
      probeBackoff(1, 1.seconds, 4.seconds) == 1.seconds
      probeBackoff(2, 1.seconds, 4.seconds) == 2.seconds
      probeBackoff(3, 1.seconds, 4.seconds) == 4.seconds
      probeBackoff(9, 1.seconds, 4.seconds) == 4.seconds
      # a cap below the base still bounds the backoff
      probeBackoff(1, 6.minutes, 5.minutes) == 5.minutes

  test "each failure pushes the peer's next probe further out":
    let kad = setupKad()
    kad.config.timeout = 1.seconds
    kad.config.probeBackoffMax = 1.hours
    let peerId = randomPeerId()
    let addrs = deadAddrs(59999)

    var untils: seq[Moment]
    for _ in 0 ..< 3:
      kad.probeRecordFailure(peerId, addrs)
      untils.add(kad.probeFailures.getOrDefault(peerId).until)

    check:
      kad.probeFailures.getOrDefault(peerId).count == 3
      untils[0] < untils[1]
      untils[1] < untils[2]

  asyncTest "a peer whose probe failed is not probed again while backed off":
    let kad = setupKad()
    let peer = PeerInfo(peerId: randomPeerId(), addrs: deadAddrs(59999))

    kad.admitPeers(@[peer])
    checkUntilTimeout:
      kad.admissionProbes.len == 0
    check kad.probeFailures.getOrDefault(peer.peerId).count == 1

    kad.admitPeers(@[peer])
    check:
      kad.admissionProbes.len == 0
      kad.admissionSem.availableSlots == kad.config.limits.maxConcurrentProbes

  asyncTest "a backed-off peer named with other addresses is probed again":
    ## A bogus address must not keep the peer's working address out of the table.
    let kad = setupKad()
    let peerId = randomPeerId()

    kad.admitPeers(@[PeerInfo(peerId: peerId, addrs: deadAddrs(59999))])
    checkUntilTimeout:
      kad.admissionProbes.len == 0

    kad.admitPeers(@[PeerInfo(peerId: peerId, addrs: deadAddrs(59998))])
    check kad.admissionProbes.len == 1

    let probes = move kad.admissionProbes
    await noCancel probes.values.toSeq().cancelAndWait()

  asyncTest "a successful probe clears the peer's recorded failures":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    let peerId = kads[1].switch.peerInfo.peerId
    kads[0].probeFailures[peerId] =
      ProbeFailure(count: 2, until: Moment.now() - 1.seconds)
    kads[0].admitPeers(
      @[PeerInfo(peerId: peerId, addrs: kads[1].switch.peerInfo.addrs)]
    )

    checkUntilTimeout:
      kads[0].hasKey(peerId.toKey())
      not kads[0].probeFailures.hasKey(peerId)

  asyncTest "an admission probe for a detached table does not insert the peer":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    let peerId = kads[1].switch.peerInfo.peerId
    let serviceTable =
      RoutingTable.new(randomServiceId(), registry = kads[0].rtable.registry)
    kads[0].admitPeers(
      serviceTable, @[PeerInfo(peerId: peerId, addrs: kads[1].switch.peerInfo.addrs)]
    )
    check kads[0].admissionProbes.len == 1

    serviceTable.detachAll()
    checkUntilTimeout:
      kads[0].admissionProbes.len == 0

    check:
      not serviceTable.contains(peerId.toKey())
      not kads[0].probeFailures.hasKey(peerId)

  asyncTest "a probe that fails without suspending is not tracked":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    let peerId = kads[1].switch.peerInfo.peerId
    await kads[0].msgSender.stop()
    kads[0].admitPeers(
      @[PeerInfo(peerId: peerId, addrs: kads[1].switch.peerInfo.addrs)]
    )

    check:
      kads[0].admissionProbes.len == 0
      kads[0].probeFailures.getOrDefault(peerId).count == 1
      not kads[0].hasKey(peerId.toKey())
    checkUntilTimeout:
      kads[0].admissionSem.availableSlots == kads[0].config.limits.maxConcurrentProbes
