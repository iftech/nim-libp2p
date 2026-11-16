# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[atomics, sequtils, strutils, tables]
import chronos, chronos/threadsync
import ../../libp2p/nameresolving/[nameresolver, system_resolver]
import ../tools/[unittest, crypto, multiaddress, resolver]
import ./suite_name_resolver

nameResolverSuite(
  "SystemResolver contract",
  resolver,
  (let resolver = SystemResolver.new(rng())),
  (await resolver.stop()),
)

type LookupGate = object
  entered, release: ThreadSignalPtr
  used, released: Atomic[bool]

proc gatedLookup(
    address: string, port: Port, domain: Domain, context: pointer
): seq[TransportAddress] {.nimcall, gcsafe, raises: [TransportAddressError].} =
  let gate = cast[ptr LookupGate](context)
  if not gate[].used.exchange(true):
    discard gate[].entered.fireSync()
    let waitResult = gate[].release.waitSync(2.seconds)
    gate[].released.store(waitResult.isOk and waitResult.get())
  resolveTAddress(address, port, domain)

proc installGate(
    resolver: SystemResolver, entered, release: ThreadSignalPtr
): ptr LookupGate =
  result = cast[ptr LookupGate](allocShared0(sizeof(LookupGate)))
  result[].entered = entered
  result[].release = release
  resolver.setLookup(gatedLookup, result)

proc fixedLookup(
    address: string, port: Port, domain: Domain, context: pointer
): seq[TransportAddress] {.nimcall, gcsafe, raises: [TransportAddressError].} =
  case address
  of "empty":
    @[]
  of "error":
    raise newException(TransportAddressError, "Lookup failed")
  else:
    newSeqWith(101, initTAddress("::ffff:127.0.0.1", port)) &
      newSeqWith(101, initTAddress("::1", port))

suite "System name resolution":
  teardown:
    checkTrackers()

  asyncTest "empty and failed lookups return no addresses":
    let resolver = SystemResolver.new(rng())
    resolver.setLookup(fixedLookup, nil)
    defer:
      await resolver.stop()
    for host in ["empty", "error"]:
      check (await resolver.resolveIp(host, 4001.Port)).len == 0

  asyncTest "result limit applies after mapped IPv4 filtering":
    let resolver = SystemResolver.new(rng())
    resolver.setLookup(fixedLookup, nil)
    defer:
      await resolver.stop()
    let addresses = await resolver.resolveIp("many", 4001.Port, Domain.AF_INET6)
    check:
      addresses.len == 100
      addresses.allIt(it == initTAddress("[::1]:4001"))

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
    let gate = resolver.installGate(entered, release)
    defer:
      discard release.fireSync()
      await resolver.stop()
      discard entered.close()
      discard release.close()
      deallocShared(gate)

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
    let gate = resolver.installGate(entered, release)
    defer:
      discard release.fireSync()
      await resolver.stop()
      discard entered.close()
      discard release.close()
      deallocShared(gate)

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
    check gate[].released.load()
    for lookup in queued:
      check (await lookup).len == 0
    discard await inFlight

  asyncTest "cancelling active and queued requests leaves workers usable":
    let
      entered = ThreadSignalPtr.new().expect("create worker-entered signal")
      release = ThreadSignalPtr.new().expect("create worker-release signal")
      resolver = SystemResolver.new(rng(), workers = 1)
    let gate = resolver.installGate(entered, release)
    defer:
      discard release.fireSync()
      await resolver.stop()
      discard entered.close()
      discard release.close()
      deallocShared(gate)

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
