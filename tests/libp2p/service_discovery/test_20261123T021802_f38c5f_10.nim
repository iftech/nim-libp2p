# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021802-f38c5f/10.
# Spec, "Lower Bound Enforcement": "Service-level entries are bounded by the
# number of distinct `service_id_hash` values currently tracked in the
# registrar state. IP-level entries are bounded by the number of distinct `IPs`
# present in advertisements currently tracked in the registrar state." and
# "For each `IP` in the IP tree, the registrar MUST maintain: bound(IP) ...".

import std/[net, tables]
import chronos, results
import ../../../libp2p/signed_envelope
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../../libp2p/utils/iptree
import ../../tools/unittest
import ./utils

suite "Proof 20261123T021802-f38c5f/10 - lower-bound state is bounded by the cache":
  test "requests that are not admitted leave no per-service or per-IP state":
    # w_base = 900 * 1 * (0 + 0 + 0.01) = 9 s, so every first request gets Wait.
    let conf = ServiceDiscoveryConfig.new(safetyParam = 0.01)
    let disco = setupServiceDiscoveryNode(discoConfig = conf)
    const Requests = 50

    for i in 0 ..< Requests:
      let serviceName = "proof-10-service-" & $i
      let ad = makeAdvertisement(serviceName)
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
      let ip = parseIpAddress("198.51." & $i & ".7")
      let reply = disco.registration(ad.data.peerId, inMsg, @[ip]).register.get()
      check reply.status == kadprotobuf.RegistrationStatus.Wait

    # Nothing was admitted: no service and no IP is tracked by the ad cache.
    check disco.registrar.ads.len == 0
    checkpoint "services in cache = " & $disco.registrar.ads.serviceLen &
      ", service bounds held = " & $disco.registrar.boundService.len &
      "; IPs in tree = " & $disco.registrar.ads.ipTree.ipsLen & ", IP bounds held = " &
      $disco.registrar.boundIp.len
    check disco.registrar.boundService.len <= disco.registrar.ads.serviceLen
    check disco.registrar.timestampService.len <= disco.registrar.ads.serviceLen
    check disco.registrar.boundIp.len <= disco.registrar.ads.ipTree.ipsLen
    check disco.registrar.timestampIp.len <= disco.registrar.ads.ipTree.ipsLen
