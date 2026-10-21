# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sets
import chronos
import
  ../../../libp2p/[
    builders,
    peeraddrpolicy,
    switch,
    multiaddress,
    peerid,
    peerstore,
    protocols/identify,
    protocols/kademlia,
  ]
import ../../tools/[unittest, crypto, switch_builder, multiaddress]

suite "PeerStore addressPolicy":
  test "updatePeerInfo stores all addresses with default policy":
    let peerId = PeerId.random()
    let peerStore = PeerStore.new(nil)

    peerStore.updatePeerInfo(
      IdentifyInfo(
        peerId: peerId,
        addrs: @[ma("/ip4/192.168.1.5/tcp/4001"), ma("/ip4/1.1.1.1/tcp/4001")],
      )
    )

    # updatePeerInfo does a direct assignment (not extend), so order is preserved
    check peerStore[AddressBook][peerId] ==
      @[ma("/ip4/192.168.1.5/tcp/4001"), ma("/ip4/1.1.1.1/tcp/4001")]

  test "updatePeerInfo filters private addresses when addressPolicy is set":
    let peerId = PeerId.random()
    let peerStore = PeerStore.new(nil)
    peerStore.addressPolicy = publicRoutableAddressPolicy

    peerStore.updatePeerInfo(
      IdentifyInfo(
        peerId: peerId,
        addrs: @[
          ma("/ip4/192.168.1.5/tcp/4001"),
          ma("/ip4/1.1.1.1/tcp/4001"),
          ma("/ip4/10.0.0.1/tcp/4001"),
        ],
      )
    )

    check peerStore[AddressBook][peerId] == @[ma("/ip4/1.1.1.1/tcp/4001")]

  test "updatePeerInfo skips storage when all addresses are filtered":
    let peerId = PeerId.random()
    let peerStore = PeerStore.new(nil)
    peerStore.addressPolicy = publicRoutableAddressPolicy

    peerStore.updatePeerInfo(
      IdentifyInfo(
        peerId: peerId,
        addrs: @[ma("/ip4/192.168.1.5/tcp/4001"), ma("/ip4/127.0.0.1/tcp/4001")],
      )
    )

    # Peer should not have any addresses stored
    check peerStore[AddressBook][peerId].len == 0

  test "updatePeerInfo clears stale addresses when a later update filters everything":
    let peerId = PeerId.random()
    let peerStore = PeerStore.new(nil)
    peerStore.addressPolicy = publicRoutableAddressPolicy

    peerStore.updatePeerInfo(
      IdentifyInfo(peerId: peerId, addrs: @[ma("/ip4/1.1.1.1/tcp/4001")])
    )
    check peerStore[AddressBook][peerId] == @[ma("/ip4/1.1.1.1/tcp/4001")]

    peerStore.updatePeerInfo(
      IdentifyInfo(peerId: peerId, addrs: @[ma("/ip4/192.168.1.5/tcp/4001")])
    )
    check peerStore[AddressBook][peerId].len == 0

  test "circuit relay addresses pass through the filter":
    let peerId = PeerId.random()
    let peerStore = PeerStore.new(nil)
    peerStore.addressPolicy = publicRoutableAddressPolicy

    let relayAddr = ma(
      "/ip4/192.168.1.5/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit"
    )
    peerStore.updatePeerInfo(IdentifyInfo(peerId: peerId, addrs: @[relayAddr]))

    check peerStore[AddressBook][peerId] == @[relayAddr]

suite "KadDHT updatePeers address policy":
  test "updatePeers stores all addresses with default policy":
    let switch = makeStandardSwitch(TcpAutoAddress)

    let config = KadDHTConfig.new()
    let kad = KadDHT.new(switch, @[], config, rng = rng())
    switch.mount(kad)

    let remotePeer = PeerId.random()
    kad.updatePeers(
      @[
        PeerInfo(
          peerId: remotePeer,
          addrs: @[ma("/ip4/192.168.1.5/tcp/4001"), ma("/ip4/1.1.1.1/tcp/4001")],
        )
      ]
    )

    # Use set comparison: extend() uses HashSet internally so order is not guaranteed
    check switch.peerStore[AddressBook][remotePeer].toHashSet() ==
      @[ma("/ip4/192.168.1.5/tcp/4001"), ma("/ip4/1.1.1.1/tcp/4001")].toHashSet()

  test "updatePeers filters private addresses when addressPolicy is set":
    let switch = makeStandardSwitch(TcpAutoAddress)

    let config = KadDHTConfig.new(addressPolicy = publicRoutableAddressPolicy)
    let kad = KadDHT.new(switch, @[], config, rng = rng())
    switch.mount(kad)

    let remotePeer = PeerId.random()
    kad.updatePeers(
      @[
        PeerInfo(
          peerId: remotePeer,
          addrs: @[ma("/ip4/192.168.1.5/tcp/4001"), ma("/ip4/1.1.1.1/tcp/4001")],
        )
      ]
    )

    check switch.peerStore[AddressBook][remotePeer] == @[ma("/ip4/1.1.1.1/tcp/4001")]

  test "updatePeers does not add peer to AddressBook when all addresses filtered":
    let switch = makeStandardSwitch(TcpAutoAddress)

    let config = KadDHTConfig.new(addressPolicy = publicRoutableAddressPolicy)
    let kad = KadDHT.new(switch, @[], config, rng = rng())
    switch.mount(kad)

    let remotePeer = PeerId.random()
    kad.updatePeers(
      @[PeerInfo(peerId: remotePeer, addrs: @[ma("/ip4/192.168.1.5/tcp/4001")])]
    )

    check switch.peerStore[AddressBook][remotePeer].len == 0
    check kad.rtable.findClosestPeerIds(remotePeer.toKey(), 1).len == 0

  test "updatePeers enforces IP diversity limits":
    let switch = makeStandardSwitch(TcpAutoAddress)

    var limits = KadDHTLimits.new(DefaultReplication, DefaultQuorum)
    limits.maxPeersPerIp = 1
    limits.maxPeersPerIpv4Subnet = 2
    limits.maxPeersPerIpv6Subnet = 2
    let config = KadDHTConfig.new(limits = Opt.some(limits))
    let kad = KadDHT.new(switch, @[], config, rng = rng())
    switch.mount(kad)

    let
      v4PeerA = PeerId.random()
      v4PeerB = PeerId.random()
      v4PeerC = PeerId.random()
      v4PeerD = PeerId.random()
      v4PeerE = PeerId.random()
      v6PeerA = PeerId.random()
      v6PeerB = PeerId.random()
      v6PeerC = PeerId.random()
      v6PeerD = PeerId.random()
      v6PeerE = PeerId.random()

    kad.updatePeers(
      @[
        PeerInfo(peerId: v4PeerA, addrs: @[ma("/ip4/8.8.8.1/tcp/4001")]),
        PeerInfo(peerId: v4PeerB, addrs: @[ma("/ip4/8.8.8.2/tcp/4001")]),
        PeerInfo(peerId: v4PeerC, addrs: @[ma("/ip4/8.8.8.3/tcp/4001")]),
        PeerInfo(peerId: v4PeerD, addrs: @[ma("/ip4/1.1.1.1/tcp/4001")]),
        PeerInfo(peerId: v4PeerE, addrs: @[ma("/ip4/1.1.1.1/tcp/4002")]),
        PeerInfo(peerId: v6PeerA, addrs: @[ma("/ip6/2001:4860:4860::1/tcp/4001")]),
        PeerInfo(peerId: v6PeerB, addrs: @[ma("/ip6/2001:4860:4860::2/tcp/4001")]),
        PeerInfo(peerId: v6PeerC, addrs: @[ma("/ip6/2001:4860:4860::3/tcp/4001")]),
        PeerInfo(peerId: v6PeerD, addrs: @[ma("/ip6/2606:4700:4700::1111/tcp/4001")]),
        PeerInfo(peerId: v6PeerE, addrs: @[ma("/ip6/2606:4700:4700::1111/tcp/4002")]),
      ]
    )

    let keys = kad.rtable.allKeys()
    check:
      v4PeerA.toKey() in keys
      v4PeerB.toKey() in keys
      v4PeerC.toKey() notin keys
      v4PeerD.toKey() in keys
      v4PeerE.toKey() notin keys
      v6PeerA.toKey() in keys
      v6PeerB.toKey() in keys
      v6PeerC.toKey() notin keys
      v6PeerD.toKey() in keys
      v6PeerE.toKey() notin keys
      switch.peerStore[AddressBook][v4PeerC].len == 0
      switch.peerStore[AddressBook][v4PeerD].len == 1
      switch.peerStore[AddressBook][v4PeerE].len == 0
      switch.peerStore[AddressBook][v6PeerC].len == 0
      switch.peerStore[AddressBook][v6PeerD].len == 1
      switch.peerStore[AddressBook][v6PeerE].len == 0

suite "SwitchBuilder withPrivateAddressFilter outbound":
  teardown:
    checkTrackers()

  asyncTest "private addresses are removed from peerInfo.addrs when filter is enabled":
    # Listen on loopback — a non-public address that is always available.
    # The filter should remove it, leaving no announced addresses.
    let switch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withWildcardResolver(false)
      .withPrivateAddressFilter()
      .build()

    await switch.start()
    check switch.peerInfo.addrs.len == 0
    await switch.stop()

  asyncTest "public addresses are kept when filter is enabled":
    # Listen on loopback (always available) but use a stubbed address mapper
    # to surface a routable address to the announcement pipeline. The filter
    # must keep the public address while dropping the private listen address.
    let publicAddr = ma("/ip4/1.2.3.4/tcp/4001")
    let switch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withWildcardResolver(false)
      .withPrivateAddressFilter()
      .build()

    proc stubMapper(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      return input & @[publicAddr]

    switch.peerInfo.addressMappers.add(stubMapper)

    await switch.start()
    # Filter removes loopback but keeps the mapper-injected public address.
    check switch.peerInfo.addrs == @[publicAddr]
    await switch.stop()

  asyncTest "withPrivateAddressFilter default is off":
    # Without calling withPrivateAddressFilter, private addresses pass through
    let switch =
      makeStandardSwitchBuilder(TcpAutoAddress).withWildcardResolver(false).build()

    await switch.start()
    check switch.peerInfo.addrs.len > 0
    await switch.stop()
