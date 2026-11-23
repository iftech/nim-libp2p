# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261122T235159-e1d648/1.
# Spec, "Safety Parameter": "The safety parameter `G` ensures waiting times
# never reach zero even when service similarity is zero (new service) [and]
# IP similarity is zero (completely distinct IP)".
# Spec, "Handling REGISTER requests" step 2: "If no `ticket` is provided ...
# Create a new signed `ticket` based on `t_wait`, and return the signed
# `ticket` in a response with status `Wait`."

import std/net
import chronos, results
import ../../../libp2p/signed_envelope
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/1 - safety parameter G keeps the wait above zero":
  test "waitingTime is non-zero for a new service from a distinct IP (spec defaults)":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()
    let ips = @[parseIpAddress("198.51.100.7")]

    let w = registrar.waitingTime(discoConfig, makeServiceId(), ips, Moment.now())

    # E * 1 * (0 + 0 + G) = 900 * 1e-7 > 0
    check w > ZeroDuration

  test "first REGISTER without a ticket is answered with Wait and a ticket":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "proof-1-service"
    let serviceId = serviceName.hashServiceId()
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

    let reply = disco
      .registration(ad.data.peerId, inMsg, @[parseIpAddress("198.51.100.7")]).register
      .get()

    check:
      reply.status == kadprotobuf.RegistrationStatus.Wait
      reply.ticket.isSome()
      disco.countAdsInCache(serviceId) == 0
