# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../libp2p/[switch, nameresolving/nameresolver, nameresolving/dnsresolver]
import ../tools/[unittest, crypto, multiaddress, switch_builder, resolver]

type
  LifecycleResolver = ref object of NameResolver
    stopped: bool

  ResolverService = ref object of Service
    fail, cancelled: bool
    entered: AsyncEvent
    gate: Future[void]

method start(self: LifecycleResolver) {.gcsafe.} =
  self.stopped = false

method stop(self: LifecycleResolver) {.async: (raises: []).} =
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

suite "Switch resolver lifecycle":
  teardown:
    checkTrackers()

  asyncTest "successful build transfers resolver ownership only once":
    var resolver: NameResolver = LifecycleResolver()
    let builder =
      makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(move(resolver))
    let first = builder.build()
    let second = builder.build()
    check:
      resolver.isNil
      first.nameResolver of LifecycleResolver
      second.nameResolver.isNil
    await first.stop()
    await second.stop()
    check LifecycleResolver(first.nameResolver).stopped

  asyncTest "stop before start and restart manage the resolver":
    let resolver = LifecycleResolver()
    let node =
      makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver).build()
    await node.stop()
    check resolver.stopped
    await node.start()
    check not resolver.stopped
    await node.stop()
    check resolver.stopped

  asyncTest "failed startup stops the resolver after services and can retry":
    let resolver = LifecycleResolver()
    let node =
      makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver).build()
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
    let resolver = LifecycleResolver()
    let node =
      makeStandardSwitchBuilder(TcpAutoAddress).withNameResolver(resolver).build()
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
