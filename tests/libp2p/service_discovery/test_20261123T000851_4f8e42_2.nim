# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for audit finding 20261123T000851-4f8e42/2.
# Spec, Error Handling: Timeout -> close stream, retry with exponential backoff.

import std/tables
import chronos, results
import
  ../../../libp2p/[
    multiaddress,
    peerid,
    protocols/kademlia,
    protocols/service_discovery,
    protocols/service_discovery/dial_backoff,
    protocols/service_discovery/discoverer,
    protocols/service_discovery/types,
    stream/connection,
    switch,
  ]
import ../../tools/[fault_stream, unittest]
import ./utils

proc addRegistrar(
    disco: ServiceDiscovery, serviceName: string, stream: FaultStream
): PeerId =
  ## One registrar in DiscT(service); every dial to it is answered by `stream`.
  doAssert disco.registerInterest(serviceName)
  let table = disco.rtManager.getTable(serviceName.hashServiceId()).get()
  let registrar = PeerId.random()
  doAssert table.insert(registrar)
  disco.switch.peerStore[AddressBook][registrar] = @[makeMultiAddress("127.0.0.1")]
  disco.switch = FaultSwitch.new(disco.switch, stream)
  registrar

suite "Proof 20261123T000851-4f8e42/2 - GET_ADS timeout backs the registrar off":
  teardown:
    checkTrackers()

  asyncTest "a registrar that never answers GET_ADS is backed off":
    let kadConfig = KadDHTConfig.new(
      ExtEntryValidator(),
      ExtEntrySelector(),
      timeout = 300.millis,
      disableBootstrapping = true,
    )
    let disco = setupServiceDiscoveryNode(kadConfig = kadConfig)
    let serviceName = "silent-registrar"
    let serviceId = serviceName.hashServiceId()

    let stream = FaultStream.new(onRead = Fault.Hang)
    defer:
      await stream.close()
    let registrar = disco.addRegistrar(serviceName, stream)
    let addrs = disco.switch.peerStore[AddressBook][registrar]

    let found = await disco.lookup(serviceId)
    # lookup cancels the timed-out query without waiting for it to unwind
    await sleepAsync(100.millis)

    check:
      found.isOk()
      found.get().len == 0
      # the request was really sent and timed out waiting for the reply
      stream.reads == 1
      stream.cancels == 1
      # "Close stream": holds
      stream.wasResetLocally()
    check:
      # "retry with exponential backoff": the timeout must count as a failure
      # so that the next attempt at this registrar is delayed
      registrar in disco.dialFailures
      disco.dialBackedOff(registrar, addrs)
