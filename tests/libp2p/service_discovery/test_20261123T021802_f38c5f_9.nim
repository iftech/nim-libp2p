# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021802-f38c5f/9.
# Spec, "Handling REGISTER requests" step 5: "If `t_remaining <= 0`, add the
# `ad` to the `ad_cache` ... If an entry for this `peer_id` and `service_id`
# already exists, this replaces it." Spec, "REGISTER Response": "`REJECTED`:
# Invalid signature, invalid ticket, or error".

import std/net
import chronos, results
import ../../../libp2p/[crypto/crypto, peerid, signed_envelope]
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/unittest
import ./utils

suite "Proof 20261123T021802-f38c5f/9 - re-registration replaces the cached entry":
  test "a valid ad for an existing peer and service is not rejected":
    let disco = setupServiceDiscoveryNode()
    let serviceName = "proof-9-service"
    let serviceId = serviceName.hashServiceId()
    let advertiserKey = randomKey()
    let advertiser = PeerId.init(advertiserKey).get()
    let cached = makeAdvertisement(serviceName, advertiserKey, seqNo = 20)
    let resent = makeAdvertisement(serviceName, advertiserKey, seqNo = 10)
    let ip = @[parseIpAddress("198.51.100.7")]

    disco.acceptAdvertisement(Moment.now(), serviceId, advertiser, cached, ip)
    check disco.registrar.ads.contains(serviceId, advertiser)

    # Validly signed, right service, no ticket: per the spec the answer is a
    # ticket (Wait) or, once the wait is served, a replacement (Confirmed).
    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: resent.encode().get(),
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )
    let reply = disco.registration(advertiser, inMsg, ip).register.get()

    checkpoint "status = " & $reply.status
    check reply.status != Opt.some(kadprotobuf.RegistrationStatus.Rejected)
