# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils, tables]
import chronos, chronos/threadsync
import ../../libp2p/nameresolving
import ../tools/[unittest, crypto, multiaddress, resolver, switch_builder]

suite "System name resolution":
  teardown:
    checkTrackers()

  asyncTest "switch resolves localhost with a caller-managed system resolver":
    let resolver = newNameResolver(rng())
    let source =
      makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver).build()
    let destination = makeStandardSwitch(TcpAutoAddress)
    defer:
      await source.stop()
      await destination.stop()
      await resolver.stop()
    let addresses = await resolver.resolveMAddress(ma("/dns4/localhost/tcp/4001"))
    check ma("/ip4/127.0.0.1/tcp/4001") in addresses
    await source.stop()
    check (await resolver.resolveIp("localhost", 4001.Port)).len > 0
    await resolver.stop()
    await destination.start()
    await source.start()
    check (await resolver.resolveIp("localhost", 4001.Port)).len == 0
    resolver.start()
    let address =
      ma("/dns4/localhost") & destination.peerInfo.addrs[0][1 ..^ 1].tryGet()
    await source.connect(destination.peerInfo.peerId, @[address])
    check source.isConnected(destination.peerInfo.peerId)
    await source.stop()
    check (await resolver.resolveIp("localhost", 4001.Port)).len > 0

  asyncTest "factory preserves explicit DNS servers":
    for servers in [@[initTAddress("192.0.2.1:5353")], newSeq[TransportAddress]()]:
      let resolver = newNameResolver(rng(), servers)
      check resolver.nameServers == servers
      if servers.len == 0:
        check (await resolver.resolveIp("localhost", 4001.Port)).len == 0
        check (await resolver.resolveTxt("_dnsaddr.test.io")).len == 0

  asyncTest "requested family and port are preserved":
    let resolver = SystemResolver.new(rng())
    defer:
      await resolver.stop()
    let ipv4 = await resolver.resolveIp("localhost", 4001.Port, Domain.AF_INET)
    check:
      ipv4.len > 0
      ipv4.allIt(it.family == AddressFamily.IPv4 and it.port == 4001.Port)
    check (await resolver.resolveIp("::1", 4002.Port, Domain.AF_INET6)) ==
      @[initTAddress("[::1]:4002")]

  asyncTest "dns6 rejects IPv4 and mapped IPv4 literals":
    let resolver = SystemResolver.new(rng())
    defer:
      await resolver.stop()
    for host in ["127.0.0.1", "::ffff:127.0.0.1"]:
      check (await resolver.resolveIp(host, 0.Port, Domain.AF_INET6)).len == 0
      check (await resolver.resolveMAddress(ma("/dns6/" & host & "/tcp/4001"))).len == 0

  asyncTest "invalid host input returns no addresses":
    let resolver = SystemResolver.new(rng())
    defer:
      await resolver.stop()
    for host in ["", repeat('a', 256), "localhost\0.invalid"]:
      check (await resolver.resolveIp(host, 0.Port)).len == 0

  asyncTest "TXT queries use the supplied fallback":
    let fallback = MockResolver.new()
    fallback.txtResponses["_dnsaddr.test.io"] = @["dnsaddr=/ip4/127.0.0.1/tcp/4001"]
    let resolver = SystemResolver.new(rng(), txtResolver = fallback)
    defer:
      await resolver.stop()
    check (await resolver.resolveTxt("_dnsaddr.test.io")) ==
      @["dnsaddr=/ip4/127.0.0.1/tcp/4001"]

  asyncTest "concurrent requests preserve their ports":
    let resolver = SystemResolver.new(rng())
    defer:
      await resolver.stop()
    let futures = (0 ..< 16).mapIt(resolver.resolveIp("localhost", Port(4001 + it)))
    for i, future in futures:
      let addresses = await future
      check:
        addresses.len > 0
        addresses.allIt(it.port == Port(4001 + i))

  asyncTest "a stalled lookup does not block the event loop":
    let
      entered = ThreadSignalPtr.new().expect("create worker-entered signal")
      release = ThreadSignalPtr.new().expect("create worker-release signal")
      resolver = SystemResolver.new(rng(), workers = 1)
    resolver.setWorkerTestGate(entered, release)
    defer:
      discard release.fireSync()
      await resolver.stop()
      discard entered.close()
      discard release.close()

    let lookup = resolver.resolveIp("localhost", 4001.Port)
    await entered.wait()
    await sleepAsync(10.milliseconds)
    check not lookup.finished()
    discard release.fireSync()
    check (await lookup).len > 0

  asyncTest "shutdown yields to the event loop and discards the backlog":
    let
      entered = ThreadSignalPtr.new().expect("create worker-entered signal")
      release = ThreadSignalPtr.new().expect("create worker-release signal")
      resolver = SystemResolver.new(rng(), workers = 1)
    resolver.setWorkerTestGate(entered, release)
    defer:
      discard release.fireSync()
      await resolver.stop()
      discard entered.close()
      discard release.close()

    let inFlight = resolver.resolveIp("localhost", 4001.Port)
    await entered.wait()
    let queued = (0 ..< 8).mapIt(resolver.resolveIp("localhost", Port(4002 + it)))
    proc releaseWorker() {.async: (raises: [CancelledError]).} =
      await sleepAsync(10.milliseconds)
      discard release.fireSync()

    let releaseFuture = releaseWorker()
    let closing = resolver.stop()
    let alsoClosing = resolver.stop()
    check:
      not closing.finished()
      not alsoClosing.finished()
    await alsoClosing
    await closing
    await releaseFuture
    check resolver.workerTestGateReleased()
    for lookup in queued:
      check (await lookup).len == 0
    discard await inFlight

  asyncTest "cancelling active and queued requests leaves workers usable":
    let
      entered = ThreadSignalPtr.new().expect("create worker-entered signal")
      release = ThreadSignalPtr.new().expect("create worker-release signal")
      resolver = SystemResolver.new(rng(), workers = 1)
    resolver.setWorkerTestGate(entered, release)
    defer:
      discard release.fireSync()
      await resolver.stop()
      discard entered.close()
      discard release.close()

    let inFlight = resolver.resolveIp("localhost", 4001.Port)
    await entered.wait()
    let queued = resolver.resolveIp("localhost", 4002.Port)
    await queued.cancelAndWait()
    await inFlight.cancelAndWait()
    discard release.fireSync()
    check (await resolver.resolveIp("localhost", 4003.Port)).len > 0

  asyncTest "stop is idempotent and start reopens the worker pool":
    let resolver = SystemResolver.new(rng())
    check (await resolver.resolveIp("localhost", 4001.Port)).len > 0
    await resolver.stop()
    await resolver.stop()
    check (await resolver.resolveIp("localhost", 4001.Port)).len == 0
    resolver.start()
    check (await resolver.resolveIp("localhost", 4002.Port)).len > 0
    await resolver.stop()

  asyncTest "stop and reopen before workers are created":
    let resolver = SystemResolver.new(rng())
    await resolver.stop()
    check (await resolver.resolveTxt("_dnsaddr.test.io")).len == 0
    resolver.start()
    check (await resolver.resolveIp("localhost", 4001.Port)).len > 0
    await resolver.stop()
