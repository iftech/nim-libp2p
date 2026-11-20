# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/2.
# Spec, Occupancy Score: "As c -> C: Score -> infinity (prevents overflow)".
# Spec, Error Handling: "Cache full (registrar) | Issue ticket with waiting time".

import chronos, results, net
import ../../../libp2p/[extended_peer_record, peerid]
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../tools/unittest
import ./utils

const Capacity = 4

proc fillCache(ads: AdvertisementCache, n: int, now: Moment): seq[(ServiceId, PeerId)] =
  ## `n` ads under distinct services, from IPs whose first bit is 0.
  var entries: seq[(ServiceId, PeerId)]
  for i in 0 ..< n:
    let sid = makeServiceId(byte(i + 1))
    let ad = makeAdvertisement($sid)
    ads.put(sid, ad.data.peerId, ad, @[parseIpAddress("10.0.0." & $(i + 1))], now)
    entries.add((sid, ad.data.peerId))
  entries

suite "Proof 20261120T114625-71ee3b/2 - full advertisement cache":
  test "waiting time does not drop when the cache goes from nearly full to full":
    let discoConfig = ServiceDiscoveryConfig.new(advertCacheCap = Capacity)
    let now = Moment.init(Moment.now().epochSeconds, Second)
    # A new service from an IP that shares no prefix with any cached one.
    let newService = makeServiceId(200)
    let newIp = @[parseIpAddress("200.0.0.1")]

    let nearlyFull = Registrar.new(Capacity)
    discard nearlyFull.ads.fillCache(Capacity - 1, now)
    let wNearlyFull = nearlyFull.waitingTime(discoConfig, newService, newIp, now)

    let full = Registrar.new(Capacity)
    discard full.ads.fillCache(Capacity, now)
    let wFull = full.waitingTime(discoConfig, newService, newIp, now)

    checkpoint "waiting time at c = C-1: " & $wNearlyFull & ", at c = C: " & $wFull
    check wFull >= wNearlyFull
    check wFull > ZeroDuration

  test "REGISTER on a full cache gets a ticket and evicts no unexpired ad":
    let conf = ServiceDiscoveryConfig.new(advertCacheCap = Capacity)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    let now = Moment.init(Moment.now().epochSeconds, Second)
    let entries = disco.registrar.ads.fillCache(Capacity, now)
    check disco.registrar.ads.len == Capacity

    let serviceName = "proof-full-cache"
    let serviceId = serviceName.hashServiceId()
    let ad = makeAdvertisement(serviceName)
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
      disco.registration(ad.data.peerId, inMsg, @[parseIpAddress("200.0.0.1")])
    let register = reply.register.get()

    check register.status.get() == RegistrationStatus.Wait
    check register.ticket.isSome()
    for (sid, advertiser) in entries:
      check disco.registrar.ads.contains(sid, advertiser)
