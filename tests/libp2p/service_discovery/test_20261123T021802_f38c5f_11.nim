# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021802-f38c5f/11.
# Spec, "Formula": "`getIP(advertiser.addrs)` is a function to get the IP
# addresses from the multiaddresses of the advertiser's connection
# information." Spec, "IP Similarity Score": "The IP being refered to here is
# NOT the ad's but the one from the advertiser connection information." and
# "Registrars MUST use an IP similarity score to limit the number of requests
# coming from the same subnetwork by increasing their waiting time."
#
# When the stream carries no observed address, registration() scores the
# addresses the peerstore holds for the sender. Those are the listen addresses
# the sender announced about itself, so the sender picks its own score.

import std/net
import chronos, results
import ../../../libp2p/[multiaddress, peerid, peerstore, signed_envelope, switch]
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/unittest
import ./utils

proc registerWithoutConnectionIp(
    disco: ServiceDiscovery, serviceName: string, declaredIp: string
): kadprotobuf.RegisterMessage =
  ## One REGISTER, no ticket, from a sender whose stream has no observed
  ## address and who announced `declaredIp` as its listen address.
  let ad = makeAdvertisement(serviceName)
  let sender = ad.data.peerId
  disco.switch.peerStore[AddressBook][sender] = @[makeMultiAddress(declaredIp)]
  let inMsg = kadprotobuf.Message(
    msgType: kadprotobuf.MessageType.register,
    key: serviceName.hashServiceId(),
    register: Opt.some(
      kadprotobuf.RegisterMessage(
        advertisement: ad.encode().get(),
        status: Opt.none(kadprotobuf.RegistrationStatus),
        ticket: Opt.none(Ticket),
      )
    ),
  )
  # connectionIps left empty: what handleMessage passes when
  # stream.observedAddr is not set.
  disco.registration(sender, inMsg).register.get()

suite "Proof 20261123T021802-f38c5f/11 - IP score comes from connection information":
  test "a sender without a connection IP cannot pick its score through announced addresses":
    # w_base = 900 * ~1 * (0 + score + 0.01): 9 s at score 0.
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.01)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let now = Moment.init(Moment.now().epochSeconds, Second)

    # Five cached entries whose advertisers connected from 10.0.0.0/24.
    for i in 1 .. 5:
      let sid = makeServiceId(byte(i))
      disco.registrar.seedAd(
        sid, makeAdvertisement($sid), now, ips = @[parseIpAddress("10.0.0." & $i)]
      )

    # Two senders with the same connection information (none). They differ
    # only in the address each announced about itself.
    let far =
      disco.registerWithoutConnectionIp("proof-11-service-far", "200.1.2.3")
    let near =
      disco.registerWithoutConnectionIp("proof-11-service-near", "10.0.0.77")

    check far.status == kadprotobuf.RegistrationStatus.Wait
    check near.status == kadprotobuf.RegistrationStatus.Wait
    let waitFar = far.ticket.get().tWaitFor.get()
    let waitNear = near.ticket.get().tWaitFor.get()

    checkpoint "announced 200.1.2.3 -> wait " & $waitFar &
      "; announced 10.0.0.77 -> wait " & $waitNear
    # The score is a function of connection information, which is the same
    # for both, so the waiting times must not differ by announced address.
    check waitFar == waitNear
