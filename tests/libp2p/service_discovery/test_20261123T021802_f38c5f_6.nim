# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021802-f38c5f/6.
# Spec, "Lower Bound Enforcement": "The same logic is applied for each IP
# associated with the advertisement: remaining_ip_bound = bound(IP) -
# elapsed_ip_time; w_ip = max(w_base, remaining_ip_bound); if w_base >
# remaining_ip_bound: bound(IP) = w_ip", and "When an IP first enters the
# registrar state, the registrar sets: bound(IP) = 0".

import std/[net, tables]
import chronos, results
import ../../../libp2p/signed_envelope
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/unittest
import ./utils

suite "Proof 20261123T021802-f38c5f/6 - IP bound is the IP-level waiting time":
  test "a service bound is not written into the bound of a first-seen IP":
    # w_base = E * 1 * (0 + 0 + G) = 900 * 0.01 = 9 s on an empty cache.
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.01)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceName = "proof-6-service"
    let serviceId = serviceName.hashServiceId()
    let ip = parseIpAddress("192.0.2.10")
    let now = Moment.init(Moment.now().epochSeconds, Second)

    # The service already carries a bound of 300 s issued to someone else.
    disco.registrar.updateLowerBounds(serviceId, @[], 300.secs, now)

    let ad = makeAdvertisement(serviceName)
    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: ad.encode().get(),
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )
    let reply = disco.registration(ad.data.peerId, inMsg, @[ip]).register.get()
    check reply.status == kadprotobuf.RegistrationStatus.Wait
    # w_final = max(w_service, w_ip) is driven by the service bound.
    check reply.ticket.get().tWaitFor.get() > 250.secs

    # bound(IP) = w_ip = max(w_base, 0 - 0) = 9 s.
    let ipBound =
      disco.registrar.boundIp.getOrDefault($ip) -
      disco.registrar.timestampIp.getOrDefault($ip)
    checkpoint "bound(IP) stored = " & $ipBound & ", w_ip per spec = 9s"
    check ipBound == 9.secs

    # The same IP now asks for an unrelated, never seen service.
    let other = makeServiceId(77)
    let wOther = disco.registrar.waitingTime(conf, other, @[ip], now + 1.secs)
    checkpoint "wait for an unrelated service from that IP = " & $wOther
    check wOther <= 9.secs
