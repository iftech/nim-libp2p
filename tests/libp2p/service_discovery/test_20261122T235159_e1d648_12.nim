# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/[net, tables]
import chronos, results
import ../../../libp2p/signed_envelope
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/12 - independent lower bound updates":
  test "a service bound does not get copied into the address bound":
    let config = ServiceDiscoveryConfig.new(safetyParam = 0.01)
    let disco = setupServiceDiscoveryNode(discoConfig = config)
    let protocolId = "/example/bounds/1.0.0"
    let serviceId = protocolId.hashServiceId()
    let ip = parseIpAddress("192.0.2.10")
    let now = Moment.init(Moment.now().epochSeconds, Second)
    disco.registrar.updateLowerBounds(serviceId, @[], 100.secs, now)
    let ad = makeAdvertisement(protocolId)
    let request = Message(
      msgType: MessageType.register,
      key: serviceId,
      register: Opt.some(RegisterMessage(advertisement: Opt.some(ad.encode().get()))),
    )
    let reply = disco.registration(ad.data.peerId, request, @[ip]).register.get()
    check reply.status == RegistrationStatus.Wait
    check reply.ticket.get().tWaitFor.get() > 9.secs
    let addressBound = disco.registrar.boundIp.getOrDefault($ip) -
      disco.registrar.timestampIp.getOrDefault($ip)
    check addressBound == 9.secs
