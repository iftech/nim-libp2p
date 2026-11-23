# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021802-f38c5f/7.
# Spec, "IP Similarity Score": "Track IP addresses as a multiset: each IP is
# counted once per `ad_cache` entry that uses it"; "A new entry is admitted to
# the `ad_cache`: MUST increment the count for that IP"; "MUST update the count
# once per `ad_cache` entry".

import std/net
import chronos
import ../../../libp2p/[multiaddress, peerid, peerstore, switch]
import ../../../libp2p/protocols/service_discovery/advertisement_cache
import ../../../libp2p/utils/iptree
import ../../tools/[unittest, multiaddress]
import ./utils

suite "Proof 20261123T021802-f38c5f/7 - one IP count per cache entry":
  test "an advertiser known by two addresses on one IP adds one count":
    let disco = setupServiceDiscoveryNode()
    let ad = makeAdvertisement("proof-7-service")
    let serviceId = "proof-7-service".hashServiceId()
    let advertiser = ad.data.peerId

    # No connection IP is known, so the registrar reads the peerstore: the
    # advertiser listens on two ports of one host.
    disco.switch.peerStore[AddressBook][advertiser] =
      @[ma("/ip4/203.0.113.5/tcp/9000"), ma("/ip4/203.0.113.5/tcp/9001")]
    let ips = disco.advertiserIps(advertiser)

    disco.acceptAdvertisement(Moment.now(), serviceId, advertiser, ad, ips)

    checkpoint "entries = " & $disco.registrar.ads.len & ", IP count = " &
      $disco.registrar.ads.ipTree.ipsLen
    check disco.registrar.ads.len == 1
    check disco.registrar.ads.ipTree.ipsLen == 1
