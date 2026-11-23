# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/sequtils
import chronos, results, sets, tables
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

proc confirmedReply(): seq[byte] =
  let reply = Message(
    msgType: Opt.some(MessageType.register),
    register: Opt.some(RegisterMessage(status: Opt.some(RegistrationStatus.Confirmed))),
  ).encode()
  doAssert reply.len < 128
  @[reply.len.byte] & reply

suite "Proof 20261122T235204-5620dd/3 - confirmed registration lifetime":
  asyncTest "eviction from the candidate table preserves a confirmed registration slot":
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(kRegister = 1)
    )
    let stream = FaultStream.new(reply = confirmedReply())
    disco.switch = FaultSwitch.new(disco.switch, stream)
    defer:
      await disco.stopRegistrations()
      await stream.close()

    let registrar = PeerId.random()
    require disco.rtable.insert(registrar)
    disco.switch.peerStore[AddressBook][registrar] = @[makeMultiAddress("127.0.0.1")]
    let service = makeServiceInfo()
    let sid = service.id.hashServiceId()
    require disco.addProvidedService(service).isOk()
    require disco.advertiser.running.len == 1
    let confirmed = toSeq(disco.advertiser.running)[0]
    for step in 0 ..< 20:
      if stream.closed():
        break
      await stepsAsync(1)
    require stream.closed()
    require not confirmed.fut.finished()

    let table = disco.rtManager.getTable(sid).get()
    var replacement = PeerId.random()
    while table.bucketIndex(replacement.toKey()) != confirmed.bucketIdx:
      replacement = PeerId.random()
    require table.removePeer(registrar, "test eviction")
    require table.insert(replacement)

    await disco.maintainRegistrations()

    check confirmed in disco.advertiser.running
    check toSeq(disco.advertiser.running).allIt(it.registrar != replacement)
