# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/1.
# Spec, Safety Parameter: "The safety parameter G ensures waiting times never
# reach zero even when service similarity is zero (new service) [and] IP
# similarity is zero (completely distinct IP)".
# Spec, Handling REGISTER requests, step 2: "If no ticket is provided in the
# REGISTER request this is the advertiser's first registration attempt for the
# ad. Create a new signed ticket based on t_wait, and return the signed ticket
# in a response with status Wait."

import chronos, results, net
import ../../../libp2p/[extended_peer_record, peerid]
import ../../tools/unittest
import ./utils

suite "Proof 20261120T114625-71ee3b/1 - safety parameter G":
  test "waiting time never reaches zero for a new service and a distinct IP":
    let registrar = Registrar.new()
    let discoConfig = ServiceDiscoveryConfig.new()

    let w = registrar.waitingTime(
      discoConfig, makeServiceId(), @[parseIpAddress("10.0.0.1")], Moment.now()
    )

    check w > ZeroDuration

  test "first REGISTER without a ticket is answered with Wait and a signed ticket":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "proof-first-register"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName, addrs = @[makeMultiAddress("10.0.0.1")])

    let inMsg = Message(
      msgType: MessageType.register,
      key: serviceId,
      register: Opt.some(
        RegisterMessage(
          advertisement: ad.encode().get(),
          status: Opt.none(RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply =
      disco.registration(ad.data.peerId, inMsg, @[parseIpAddress("10.0.0.1")])
    let register = reply.register.get()

    check register.status.get() == RegistrationStatus.Wait
    check register.ticket.isSome()
    check disco.countAdsInCache(serviceId) == 0
