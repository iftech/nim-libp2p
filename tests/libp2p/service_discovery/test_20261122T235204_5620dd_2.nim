# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261122T235204-5620dd/2.
#
# Spec, "Error Handling":
#   | Timeout | Close stream, retry with exponential backoff |
# Spec, "Distributing ads across registrars": ongoing registrations include
# registrars "for which there is an ongoing registration attempt", and
# K_register caps active registrations + ongoing attempts per bucket.

import std/sequtils
import chronos, results, sets
import
  ../../../libp2p/[
    peerid,
    peerstore,
    protocols/kademlia,
    protocols/service_discovery,
    protocols/service_discovery/advertiser,
    stream/connection,
    switch,
  ]
import ../../tools/[fault_stream, unittest]
import ./utils

const RequestTimeout = 200.milliseconds

suite "Proof 20261122T235204-5620dd/2 - REGISTER timeout":
  asyncTest "a REGISTER whose registrar never answers times out and frees its slot":
    let disco = setupServiceDiscoveryNode(
      kadConfig = KadDHTConfig.new(
        ExtEntryValidator(),
        ExtEntrySelector(),
        timeout = RequestTimeout,
        disableBootstrapping = true,
      )
    )
    # the registrar accepts the stream and the request, and never replies
    let stream = FaultStream.new(onRead = Fault.Hang)
    disco.switch = FaultSwitch.new(disco.switch, stream)
    defer:
      await disco.stopRegistrations()
      await stream.close()

    let registrar = PeerId.random()
    check disco.rtable.insert(registrar)
    disco.switch.peerStore[AddressBook][registrar] = @[makeMultiAddress("127.0.0.1")]

    let service = makeServiceInfo()
    check disco.addProvidedService(service).isOk()
    require disco.advertiser.running.len == 1
    let task = toSeq(disco.advertiser.running)[0]

    await stream.hung.wait().wait(5.seconds)

    # 25 request timeouts later, and a maintenance round in between
    await sleepAsync(RequestTimeout * 10)
    await disco.maintainRegistrations()
    await sleepAsync(RequestTimeout * 15)

    # Timeout: close stream
    check stream.closed()
    # the attempt ended, so the registrar left the ongoing registrations
    check task.fut.finished()
