# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/[switch, nameresolving/nameresolver, nameresolving/dnsresolver]
import ../tools/[unittest, crypto, multiaddress, switch_builder, resolver]

type
  LifecycleResolver = ref object of NameResolver
    stopped: bool
    starts, stops: int

  ResolverService = ref object of Service
    fail, cancelled, cancelStop, didStop: bool
    entered: AsyncEvent
    gate, stopGate: Future[void]

method start(self: LifecycleResolver) {.gcsafe.} =
  inc self.starts
  self.stopped = false

method stop(self: LifecycleResolver) {.async: (raises: []).} =
  inc self.stops
  self.stopped = true

method start(
    self: ResolverService, switch: Switch
) {.async: (raises: [CancelledError, LPError]).} =
  check not LifecycleResolver(switch.nameResolver).stopped
  if not self.gate.isNil:
    self.entered.fire()
    try:
      await self.gate.join()
    except CancelledError as exc:
      self.cancelled = true
      raise exc
  if self.fail:
    raise newException(LPError, "injected service start failure")

method stop(
    self: ResolverService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  check not LifecycleResolver(switch.nameResolver).stopped
  self.didStop = true
  if self.cancelStop:
    raise newException(CancelledError, "injected service stop cancellation")
  if not self.stopGate.isNil:
    self.entered.fire()
    await self.stopGate.join()
  check not LifecycleResolver(switch.nameResolver).stopped

proc ownedResolverSwitch(resolver: LifecycleResolver): Switch =
  result = makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver().build()
  # Substitute a lifecycle probe for the stateless default built by this PR.
  result.nameResolver = resolver

suite "Switch resolver lifecycle":
  teardown:
    checkTrackers()

  asyncTest "shared injected resolver remains caller-managed":
    let resolver = LifecycleResolver()
    let builder = makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver)
    let first = builder.build()
    let second = builder.build()
    check:
      first.nameResolver == resolver
      second.nameResolver == resolver
      not first.ownsNameResolver
      not second.ownsNameResolver
    await first.stop()
    await first.start()
    await second.start()
    await first.stop()
    await second.stop()
    check:
      resolver.starts == 0
      resolver.stops == 0

  asyncTest "stop before start and restart manage the resolver":
    let resolver = LifecycleResolver(stopped: true)
    let node = ownedResolverSwitch(resolver)
    await node.stop()
    check resolver.stopped
    await node.start()
    check not resolver.stopped
    await node.stop()
    check resolver.stopped

  asyncTest "failed startup stops the resolver after services and can retry":
    let resolver = LifecycleResolver(stopped: true)
    let node = ownedResolverSwitch(resolver)
    let service = ResolverService(fail: true)
    node.services.add(service)
    expect LPError:
      await node.start()
    check resolver.stopped
    service.fail = false
    await node.start()
    await node.stop()
    check resolver.stopped

  asyncTest "cancelled startup drains services before stopping the resolver":
    let resolver = LifecycleResolver(stopped: true)
    let node = ownedResolverSwitch(resolver)
    let service = ResolverService(
      entered: newAsyncEvent(), gate: newFuture[void]("resolver service gate")
    )
    node.services.add(service)
    let starting = node.start()
    await service.entered.wait()
    await starting.cancelAndWait()
    check service.cancelled
    check resolver.stopped
    service.gate.complete()

  asyncTest "cancelled shutdown drains services before stopping the resolver":
    let resolver = LifecycleResolver(stopped: true)
    let node = ownedResolverSwitch(resolver)
    let service = ResolverService(
      entered: newAsyncEvent(), stopGate: newFuture[void]("resolver service stop gate")
    )
    node.services.add(service)
    await node.start()
    let stopping = node.stop()
    await service.entered.wait()
    let cancelling = stopping.cancelAndWait()
    await sleepAsync(1.milliseconds)
    check not stopping.finished()
    check not resolver.stopped
    service.stopGate.complete()
    await cancelling
    check resolver.stopped

  asyncTest "internal shutdown cancellation still drains remaining components":
    let resolver = LifecycleResolver(stopped: true)
    let node = ownedResolverSwitch(resolver)
    let cancelled = ResolverService(cancelStop: true)
    let remaining = ResolverService()
    node.services.add(cancelled)
    node.services.add(remaining)
    await node.start()
    expect CancelledError:
      await node.stop()
    check:
      cancelled.didStop
      remaining.didStop
      resolver.stopped

  asyncTest "stateless resolvers inherit no-op lifecycle methods":
    let resolvers: seq[NameResolver] = @[
      NameResolver(DnsResolver.new(@[initTAddress("192.0.2.1:53")], rng())),
      NameResolver(MockResolver.new()),
      NameResolver(StallingResolver.new()),
      NameResolver(StubNameResolver.new()),
    ]
    for resolver in resolvers:
      resolver.start()
      await resolver.stop()
      resolver.start()
      await resolver.stop()
