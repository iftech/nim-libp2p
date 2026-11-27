# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/[builders, multiaddress, peerid, results, switch]
import ../tools/[crypto, unittest]
import ./mdns

suite "mDNS interoperability":
  teardown:
    checkTrackers()

  asyncTest "two distinct remote peers complete discovery":
    let
      discovery = MdnsDiscovery.new(2).get()
      local = PeerId.random()
      first = PeerId.random()
      second = PeerId.random()

    let outcome = discovery.waitForPeers(10.seconds)
    discovery.observe(local, first)
    discovery.observe(local, second)
    check (await outcome).isOk

  asyncTest "duplicate announcements and the local peer do not count":
    let
      discovery = MdnsDiscovery.new(2).get()
      local = PeerId.random()
      remote = PeerId.random()

    discovery.observe(local, local)
    discovery.observe(local, remote)
    discovery.observe(local, remote)
    let outcome = await discovery.waitForPeers(20.milliseconds)
    require outcome.isErr
    check outcome.error == "mDNS discovery timed out; discovered 1 of 2 peers"

  asyncTest "a timed-out wait leaves discovery available to other waits":
    let
      discovery = MdnsDiscovery.new(1).get()
      local = PeerId.random()
      remote = PeerId.random()
      pending = discovery.waitForPeers(10.seconds)

    check (await discovery.waitForPeers(0.milliseconds)).isErr
    let timedOut = await discovery.waitForPeers(20.milliseconds)
    require timedOut.isErr
    let retry = discovery.waitForPeers(10.seconds)
    discovery.observe(local, remote)
    check:
      (await pending).isOk
      (await retry).isOk
      (await discovery.waitForPeers(0.milliseconds)).isOk

  asyncTest "interop node discovers two running mDNS peers":
    proc newPeer(): Switch =
      SwitchBuilder
        .new()
        .withAddress(MultiAddress.init("/ip4/0.0.0.0/tcp/0").get())
        .withTcpTransport()
        .withYamux()
        .withNoise()
        .withMdns()
        .build()

    let
      first = newPeer()
      second = newPeer()

    await first.start()
    await second.start()
    defer:
      await first.stop()
      await second.stop()

    let outcome = await mdnsInteropTest(2, 15.seconds)
    if outcome.isErr:
      checkpoint $outcome.error
    check outcome.isOk
