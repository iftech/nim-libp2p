# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261122T235159-e1d648/2.
# Spec, "Occupancy Score": "occupancy_score = 1 / (1 - c/C)^P_occ ... The
# occupancy score increases progressively as the cache fills ... As `c -> C`:
# Score -> infinity (prevents overflow)".
# Spec, "Error Handling": "Cache full (registrar) | Issue ticket with waiting time".

from std/times import getTime, toUnix
import std/[net, sequtils, tables]
import chronos, results
import ../../../libp2p/[crypto/crypto, peerid, signed_envelope]
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/2 - occupancy score at a full cache":
  test "waiting time does not drop when the cache goes from C-1 to C entries":
    let registrar = Registrar.new(10)
    let discoConfig = ServiceDiscoveryConfig.new(advertCacheCap = 10)
    let serviceId = makeServiceId(1)
    let ips = @[parseIpAddress("198.51.100.7")]
    let now = Moment.now()

    # 9 ads under 9 distinct services, one of them `serviceId`; no IPs tracked.
    registrar.ads.seedOccupancy(9, now)
    check registrar.ads.len == 9
    let wAlmostFull = registrar.waitingTime(discoConfig, serviceId, ips, now)

    let extra = makeServiceId(200)
    registrar.seedAd(extra, makeAdvertisement($extra), now)
    check registrar.ads.len == 10
    let wFull = registrar.waitingTime(discoConfig, serviceId, ips, now)

    checkpoint "w(c = C-1) = " & $wAlmostFull & ", w(c = C) = " & $wFull
    check wFull >= wAlmostFull

  test "a full cache issues a ticket instead of evicting an unexpired ad":
    let conf =
      ServiceDiscoveryConfig.new(advertCacheCap = 10, registrationWindow = 10.secs)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let serviceName = "proof-2-service"
    let serviceId = serviceName.hashServiceId()
    let advertiserKey = PrivateKey.random(rng()).get()
    let advertiserId = PeerId.init(advertiserKey).get()
    let adBytes = makeAdvertisement(serviceName, advertiserKey).encode().get()

    # Full cache of fresh (unexpired) ads.
    disco.registrar.ads.seedOccupancy(10)
    check disco.registrar.ads.len == 10
    var before: seq[PeerId]
    for peers in disco.registrar.ads.byService.values:
      for advertiser in peers.keys:
        before.add(advertiser)

    # A ticket this registrar signed 10 days ago, retried inside its window.
    let nowUnix = getTime().toUnix()
    var ticket = Ticket(
      advertisement: adBytes,
      tInit: nowUnix - 864_000,
      tMod: nowUnix - 1,
      tWaitFor: 1.secs,
      signature: Opt.none(seq[byte]),
    )
    check ticket.sign(disco.switch.peerInfo.privateKey).isOk()

    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.some(ticket),
        )
      ),
    )

    let reply = disco
      .registration(advertiserId, inMsg, @[parseIpAddress("198.51.100.7")]).register
      .get()

    var after: seq[PeerId]
    for peers in disco.registrar.ads.byService.values:
      for advertiser in peers.keys:
        after.add(advertiser)

    check:
      reply.status == kadprotobuf.RegistrationStatus.Wait
      reply.ticket.isSome()
      before.allIt(it in after)
