# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/[peerid, results]
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

  test "invalid expected peer count returns an error":
    check:
      runMdnsInterop(@[], 1.seconds).isErr
      runMdnsInterop(@["0"], 1.seconds).isErr
      runMdnsInterop(@["-1"], 1.seconds).isErr
      runMdnsInterop(@["abc"], 1.seconds).isErr
