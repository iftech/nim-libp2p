# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261122T235159-e1d648/3.
# Spec, "Lower Bound Enforcement": "a newly issued waiting time at time
# `t_current` MUST NOT be smaller than a previously issued waiting time by more
# than the elapsed time since that waiting time was issued:
# w_new >= w_previous - (t_current - t_previous)", with
# "w_service = max(w_base, remaining_service_bound)" and
# "bound(service_id_hash) = w_service".

import std/[net, tables]
import chronos, results
import ../../../libp2p/signed_envelope
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/3 - service lower bound keeps the waiting time":
  test "a waiting time above E still bounds the next waiting time for the service":
    let advertExpiry = 100.secs
    let conf = ServiceDiscoveryConfig.new(advertExpiry = advertExpiry, advertCacheCap = 10)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceName = "proof-3-service"
    let serviceId = serviceName.hashServiceId()
    let now = Moment.init(Moment.now().epochSeconds, Second)

    # Five cached ads from one /24, under other services: occupancy = 2^10.
    for i in 1 .. 5:
      let sid = makeServiceId(byte(i))
      disco.registrar.seedAd(
        sid, makeAdvertisement($sid), now, ips = @[parseIpAddress("10.0.0." & $i)]
      )

    # Advertiser A registers `serviceId` from the same /24: high IP similarity.
    let ipA = @[parseIpAddress("10.0.0.77")]
    let wPrevious = disco.registrar.waitingTime(conf, serviceId, ipA, now)
    check wPrevious > advertExpiry

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
    let reply = disco.registration(ad.data.peerId, inMsg, ipA).register.get()
    check reply.status == kadprotobuf.RegistrationStatus.Wait

    # bound(service_id_hash) = w_service, the waiting time that was calculated.
    let stored =
      disco.registrar.boundService[serviceId] -
      disco.registrar.timestampService[serviceId]
    checkpoint "w issued = " & $wPrevious & ", bound stored = " & $stored
    check stored == wPrevious

    # 50 s later the same service is requested from an unrelated IP (w_base ~ 0).
    let elapsed = 50.secs
    let wNew = disco.registrar.waitingTime(
      conf, serviceId, @[parseIpAddress("200.0.0.1")], now + elapsed
    )
    checkpoint "w_new = " & $wNew & ", w_previous - elapsed = " & $(wPrevious - elapsed)
    check wNew >= wPrevious - elapsed
