# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, metrics, std/[deques, importutils, sequtils]
import
  ../../../libp2p/[
    builders,
    switch,
    protocols/connectivity/autonat/client,
    protocols/connectivity/autonat/service,
    nameresolving/nameresolver,
    nameresolving/mockresolver,
  ]
import ../../../libp2p/utils/future
from ../../../libp2p/protocols/connectivity/autonat/types import
  AutonatError, AutonatUnreachableError
import ../../stubs/autonatclientstub
import
  ../../tools/[unittest, futures, crypto, reachability, multiaddress, metrics_utils]

proc createSwitch(
    withAutonat = true,
    maxConnsPerPeer = 1,
    maxConns = 100,
    nameResolver: NameResolver = nil,
): Switch =
  return SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[TcpWildcardAddress])
    .withWildcardResolver(false)
    .withTcpTransport()
    .withMaxConnsPerPeer(maxConnsPerPeer)
    .withMaxConnections(maxConns)
    .withMplex()
    .withNoise()
    .withNameResolver(nameResolver)
    .withAutonat(withAutonat)
    .build()

proc startAutonatSwitch(switch: Switch, service: AutonatService) {.async.} =
  await switch.start()
  await service.start(switch)

proc stopAutonatSwitch(switch: Switch, service: AutonatService) {.async.} =
  try:
    await service.stop(switch)
  finally:
    await switch.stop()

type BlockingAutonatClient = ref object of AutonatClient
  dialStarted: AsyncEvent
  dialCancelled: AsyncEvent

method dialMe*(
    self: BlockingAutonatClient,
    switch: Switch,
    pid: PeerId,
    addrs: seq[MultiAddress] = newSeq[MultiAddress](),
): Future[MultiAddress] {.
    async: (raises: [AutonatError, AutonatUnreachableError, CancelledError])
.} =
  self.dialStarted.fire()
  try:
    await newAsyncEvent().wait()
  except CancelledError as exc:
    self.dialCancelled.fire()
    raise exc
  return TcpWildcardAddress

const AutonatReachabilityConfidenceMetric = "libp2p_autonat_reachability_confidence"

proc reachabilityConfidence(reachability: NetworkReachability): float64 =
  metricValueByName(
    libp2p_autonat_reachability_confidence,
    AutonatReachabilityConfidenceMetric,
    [$reachability],
  )

suite "Autonat Service":
  teardown:
    checkTrackers()

  asyncTest "Peer must be not reachable":
    let autonatClientStub = AutonatClientStub.new(expectedDials = 3)
    autonatClientStub.answer = NotReachable

    let autonatService = AutonatService.new(autonatClientStub, rng())

    let switch1 = createSwitch()
    let switch2 = createSwitch()
    let switch3 = createSwitch()
    let switch4 = createSwitch()

    check autonatService.networkReachability == NetworkReachability.Unknown

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService),
      switch2.start(),
      switch3.start(),
      switch4.start(),
    )

    await switch1.connect(switch2)
    await switch1.connect(switch3)
    await switch1.connect(switch4)

    await autonatClientStub.finished

    check autonatService.networkReachability == NetworkReachability.NotReachable
    check reachabilityConfidence(NetworkReachability.NotReachable) == 0.3

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService),
      switch2.stop(),
      switch3.stop(),
      switch4.stop(),
    )

  asyncTest "Dispatch reaches every subscriber, and skips an unsubscribed one":
    let autonatClientStub = AutonatClientStub.new(expectedDials = 1)
    autonatClientStub.answer = NotReachable

    # maxQueueSize 1: a single answer already clears the confidence threshold.
    let autonatService = AutonatService.new(autonatClientStub, rng(), maxQueueSize = 1)
    let observers = autonatService.reachabilityObservers

    let switch1 = createSwitch()
    let switch2 = createSwitch()

    let gate = newAsyncEvent()
    let first = newFuture[NetworkReachability]()
    let last = newFuture[NetworkReachability]()
    var goneCalls = 0

    let gone: ReachabilityHandler = proc(
        reachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      goneCalls.inc()

    check:
      observers.add(
        proc(
            reachability: NetworkReachability,
            confidence: Opt[float],
            dialBackAddr: Opt[MultiAddress],
        ) {.async: (raises: [CancelledError]).} =
          first.completeOnce(reachability)
          # Block the first handler: the last one still gets the answer.
          await gate.wait()
      )
      observers.add(gone)
      observers.add(
        proc(
            reachability: NetworkReachability,
            confidence: Opt[float],
            dialBackAddr: Opt[MultiAddress],
        ) {.async: (raises: [CancelledError]).} =
          last.completeOnce(reachability)
      )
      observers.remove(gone)
      autonatService.networkReachability == NetworkReachability.Unknown

    await startAutonatSwitch(switch1, autonatService)
    await switch2.start()
    await switch1.connect(switch2)

    check:
      (await first) == autonatClientStub.answer
      (await last) == autonatClientStub.answer
      goneCalls == 0
      autonatService.networkReachability == autonatClientStub.answer

    gate.fire()
    await allFuturesRaising(stopAutonatSwitch(switch1, autonatService), switch2.stop())

  asyncTest "Stop cancels an in-flight probe before it notifies":
    for scheduled in [false, true]:
      let autonatClientStub = AutonatClientStub.new(expectedDials = 1)
      autonatClientStub.answer = NotReachable
      autonatClientStub.release = newAsyncEvent()

      let autonatService =
        if scheduled:
          AutonatService.new(
            autonatClientStub,
            rng(),
            Opt.some(1.seconds),
            askNewConnectedPeers = false,
            maxQueueSize = 1,
          )
        else:
          AutonatService.new(autonatClientStub, rng(), maxQueueSize = 1)
      var observerCalls = 0
      check autonatService.reachabilityObservers.add(
        proc(
            reachability: NetworkReachability,
            confidence: Opt[float],
            dialBackAddr: Opt[MultiAddress],
        ) {.async: (raises: [CancelledError]).} =
          observerCalls.inc()
      )

      let switch1 = createSwitch()
      let switch2 = createSwitch()
      await switch1.start()
      await autonatService.start(switch1)
      await switch2.start()
      await switch1.connect(switch2)
      await autonatClientStub.finished

      await autonatService.stop(switch1)
      check autonatClientStub.cancelledDials == 1

      autonatClientStub.release.fire()
      await allFuturesRaising(switch1.stop(), switch2.stop())

      check:
        observerCalls == 0
        autonatService.networkReachability == NetworkReachability.Unknown

  asyncTest "Peer must be reachable":
    let autonatService =
      AutonatService.new(AutonatClient.new(), rng(), Opt.some(1.seconds))

    let switch1 = createSwitch()
    let switch2 = createSwitch()
    let switch3 = createSwitch()
    let switch4 = createSwitch()

    let awaiter = newFuture[void]()

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if settled(networkReachability, NetworkReachability.Reachable, confidence):
        awaiter.completeOnce()

    check autonatService.networkReachability == NetworkReachability.Unknown

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService),
      switch2.start(),
      switch3.start(),
      switch4.start(),
    )

    await switch1.connect(switch2)
    await switch1.connect(switch3)
    await switch1.connect(switch4)

    await awaiter

    check autonatService.networkReachability == NetworkReachability.Reachable
    check reachabilityConfidence(NetworkReachability.Reachable) >= MinTestConfidence

    check switch1.peerInfo.addrs ==
      switch1.peerInfo.addrs.mapIt(switch1.addressManager.externalAddrFor(it))

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService),
      switch2.stop(),
      switch3.stop(),
      switch4.stop(),
    )

    check switch1.peerInfo.addrs == switch1.peerInfo.addrs

  asyncTest "Peer must be not reachable and then reachable":
    let autonatClientStub = AutonatClientStub.new(expectedDials = 6)
    autonatClientStub.answer = NotReachable

    let autonatService =
      AutonatService.new(autonatClientStub, rng(), Opt.some(1.seconds))

    let switch1 = createSwitch()
    let switch2 = createSwitch()
    let switch3 = createSwitch()
    let switch4 = createSwitch()

    let notReachableAwaiter = newFuture[void]()
    let reachableAwaiter = newFuture[void]()
    var notReachableConfidence = Opt.none(float)
    var reachableConfidence = Opt.none(float)

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if settled(networkReachability, NetworkReachability.NotReachable, confidence):
        notReachableConfidence = confidence
        autonatClientStub.answer = Reachable
        notReachableAwaiter.completeOnce()
      elif settled(networkReachability, NetworkReachability.Reachable, confidence) and
          reachableConfidence.isNone():
        reachableConfidence = confidence
        reachableAwaiter.completeOnce()

    check autonatService.networkReachability == NetworkReachability.Unknown

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService),
      switch2.start(),
      switch3.start(),
      switch4.start(),
    )

    await switch1.connect(switch2)
    await switch1.connect(switch3)
    await switch1.connect(switch4)

    await notReachableAwaiter

    # The stub now answers Reachable, so the live state can already be Reachable.
    check notReachableConfidence == 0.3

    await autonatClientStub.finished
    await reachableAwaiter

    check autonatService.networkReachability == NetworkReachability.Reachable
    check reachableConfidence == 0.3

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService),
      switch2.stop(),
      switch3.stop(),
      switch4.stop(),
    )

  asyncTest "Peer must be reachable when one connected peer has autonat disabled":
    let autonatService = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(1.seconds), maxQueueSize = 2
    )

    let switch1 = createSwitch()
    let switch2 = createSwitch(withAutonat = false)
    let switch3 = createSwitch()
    let switch4 = createSwitch()

    let awaiter = newFuture[void]()

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if networkReachability == NetworkReachability.Reachable and confidence == 1.0:
        awaiter.completeOnce()

    check autonatService.networkReachability == NetworkReachability.Unknown

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService),
      switch2.start(),
      switch3.start(),
      switch4.start(),
    )

    await switch1.connect(switch2)
    await switch1.connect(switch3)
    await switch1.connect(switch4)

    await awaiter

    check autonatService.networkReachability == NetworkReachability.Reachable
    check reachabilityConfidence(NetworkReachability.Reachable) == 1

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService),
      switch2.stop(),
      switch3.stop(),
      switch4.stop(),
    )

  asyncTest "Unknown answers must be ignored":
    let autonatClientStub = AutonatClientStub.new(expectedDials = 6)
    autonatClientStub.answer = NotReachable

    let autonatService = AutonatService.new(
      autonatClientStub, rng(), Opt.some(1.seconds), maxQueueSize = 3
    )

    let switch1 = createSwitch()
    let switch2 = createSwitch()
    let switch3 = createSwitch()
    let switch4 = createSwitch()

    let awaiter = newFuture[void]()

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if settled(networkReachability, NetworkReachability.NotReachable, confidence):
        autonatClientStub.answer = Unknown
        awaiter.completeOnce()

    check autonatService.networkReachability == NetworkReachability.Unknown

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService),
      switch2.start(),
      switch3.start(),
      switch4.start(),
    )

    await switch1.connect(switch2)
    await switch1.connect(switch3)
    await switch1.connect(switch4)

    await awaiter

    check autonatService.networkReachability == NetworkReachability.NotReachable
    check reachabilityConfidence(NetworkReachability.NotReachable) == 1 / 3

    await autonatClientStub.finished

    check autonatService.networkReachability == NetworkReachability.NotReachable
    check reachabilityConfidence(NetworkReachability.NotReachable) == 1 / 3

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService),
      switch2.stop(),
      switch3.stop(),
      switch4.stop(),
    )

  asyncTest "Restart clears the answers, so the first verdict notifies again":
    const maxQueueSize = 10
    let autonatClientStub = AutonatClientStub.new(expectedDials = 3)
    autonatClientStub.answer = Reachable

    let autonatService =
      AutonatService.new(autonatClientStub, rng(), maxQueueSize = maxQueueSize)

    let switch1 = createSwitch()
    let switch2 = createSwitch()
    let switch3 = createSwitch()
    let switch4 = createSwitch()

    let awaiter = newFuture[void]()
    var reachableNotifies = 0

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if networkReachability == NetworkReachability.Reachable:
        reachableNotifies.inc()
        awaiter.completeOnce()

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService),
      switch2.start(),
      switch3.start(),
      switch4.start(),
    )

    privateAccess(AutonatService)
    for _ in 0 ..< maxQueueSize:
      autonatService.answers.addLast(Reachable)
    autonatService.networkReachability = Reachable
    autonatService.confidence = Opt.some(1.0)

    await autonatService.stop(switch1)
    check:
      autonatService.answers.len == 0
      autonatService.networkReachability == NetworkReachability.Unknown
      autonatService.confidence.isNone()
    await autonatService.start(switch1)

    await switch1.connect(switch2)
    await switch1.connect(switch3)
    await switch1.connect(switch4)

    await awaiter

    check:
      reachableNotifies == 1
      autonatService.networkReachability == NetworkReachability.Reachable

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService),
      switch2.stop(),
      switch3.stop(),
      switch4.stop(),
    )

  asyncTest "Stop cancels an in-flight dial-back":
    let client = BlockingAutonatClient(
      dialStarted: newAsyncEvent(), dialCancelled: newAsyncEvent()
    )
    let autonatService = AutonatService.new(client, rng())

    let switch1 = createSwitch()
    let switch2 = createSwitch()
    await startAutonatSwitch(switch1, autonatService)
    await switch2.start()

    await switch1.connect(switch2)
    await client.dialStarted.wait()

    await autonatService.stop(switch1)
    check:
      client.dialCancelled.isSet()
      autonatService.networkReachability == NetworkReachability.Unknown
      autonatService.reachabilityObservers.lastReachability() ==
        NetworkReachability.Unknown

    await allFuturesRaising(stopAutonatSwitch(switch1, autonatService), switch2.stop())

  asyncTest "Must bypass maxConnectionsPerPeer limit":
    let autonatService = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(1.seconds), maxQueueSize = 1
    )

    let switch1 = createSwitch(maxConnsPerPeer = 1)

    let switch2 =
      createSwitch(maxConnsPerPeer = 1, nameResolver = MockResolver.default())

    let awaiter = newFuture[void]()

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if networkReachability == NetworkReachability.Reachable and confidence == 1.0:
        awaiter.completeOnce()

    check autonatService.networkReachability == NetworkReachability.Unknown

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await startAutonatSwitch(switch1, autonatService)
    switch1.peerInfo.addrs.add(
      [ma("/dns4/localhost/") & switch1.peerInfo.addrs[0][1].tryGet()]
    )

    await switch2.start()

    await switch1.connect(switch2)

    await awaiter

    check autonatService.networkReachability == NetworkReachability.Reachable
    check reachabilityConfidence(NetworkReachability.Reachable) == 1

    await allFuturesRaising(stopAutonatSwitch(switch1, autonatService), switch2.stop())

  asyncTest "Must work when peers ask each other at the same time with max 1 conn per peer":
    let autonatService1 = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(500.millis), maxQueueSize = 3
    )
    let autonatService2 = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(500.millis), maxQueueSize = 3
    )
    let autonatService3 = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(500.millis), maxQueueSize = 3
    )

    let switch1 = createSwitch(maxConnsPerPeer = 1)
    let switch2 = createSwitch(maxConnsPerPeer = 1)
    let switch3 = createSwitch(maxConnsPerPeer = 1)

    let awaiter1 = newFuture[void]()
    let awaiter2 = newFuture[void]()

    proc reachabilityHandler1(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if networkReachability == NetworkReachability.Reachable and confidence == 1.0:
        awaiter1.completeOnce()

    proc reachabilityHandler2(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if networkReachability == NetworkReachability.Reachable and confidence == 1.0:
        awaiter2.completeOnce()

    check autonatService1.networkReachability == NetworkReachability.Unknown
    check autonatService2.networkReachability == NetworkReachability.Unknown
    check autonatService3.networkReachability == NetworkReachability.Unknown

    check autonatService1.reachabilityObservers.add(reachabilityHandler1)
    check autonatService2.reachabilityObservers.add(reachabilityHandler2)
    check autonatService3.reachabilityObservers.add(reachabilityHandler2)

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService1),
      startAutonatSwitch(switch2, autonatService2),
      startAutonatSwitch(switch3, autonatService3),
    )

    await switch1.connect(switch2)
    await switch2.connect(switch1)
    await switch2.connect(switch3)

    await awaiter1
    await awaiter2

    check autonatService1.networkReachability == NetworkReachability.Reachable
    check autonatService2.networkReachability == NetworkReachability.Reachable
    check reachabilityConfidence(NetworkReachability.Reachable) == 1

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService1),
      stopAutonatSwitch(switch2, autonatService2),
      stopAutonatSwitch(switch3, autonatService3),
    )

  asyncTest "Must work for one peer when two peers ask each other at the same time with max 1 conn per peer":
    let autonatService1 = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(500.millis), maxQueueSize = 3
    )
    let autonatService2 = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(500.millis), maxQueueSize = 3
    )

    let switch1 = createSwitch(maxConnsPerPeer = 1)
    let switch2 = createSwitch(maxConnsPerPeer = 1)

    let awaiter1 = newFuture[void]()

    proc reachabilityHandler1(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if networkReachability == NetworkReachability.Reachable and confidence == 1.0:
        awaiter1.completeOnce()

    check autonatService1.networkReachability == NetworkReachability.Unknown

    check autonatService1.reachabilityObservers.add(reachabilityHandler1)

    await startAutonatSwitch(switch1, autonatService1)
    await startAutonatSwitch(switch2, autonatService2)

    await switch1.connect(switch2)
    try:
      # We allow a temp conn for the peer to dial us. It could use this conn to just connect to us and not dial.
      # We don't care if it fails at this point or not. But this conn must be closed eventually.
      # Bellow we check that there's only one connection between the peers
      await switch2.connect(switch1, reuseConnection = false)
    except DialFailedError:
      discard

    await awaiter1

    check autonatService1.networkReachability == NetworkReachability.Reachable
    check reachabilityConfidence(NetworkReachability.Reachable) == 1

    # Make sure remote peer can't create a connection to us
    check switch1.connManager.connCount(switch2.peerInfo.peerId) == 1

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService1),
      stopAutonatSwitch(switch2, autonatService2),
    )

  asyncTest "Must work with low maxConnections":
    let autonatService = AutonatService.new(
      AutonatClient.new(), rng(), Opt.some(1.seconds), maxQueueSize = 1
    )

    let switch1 = createSwitch(maxConns = 4)
    let switch2 = createSwitch()
    let switch3 = createSwitch()
    let switch4 = createSwitch()
    let switch5 = createSwitch()

    var awaiter = newFuture[void]()

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      if networkReachability == NetworkReachability.Reachable and confidence == 1.0:
        awaiter.completeOnce()

    check autonatService.networkReachability == NetworkReachability.Unknown

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await allFuturesRaising(
      startAutonatSwitch(switch1, autonatService),
      switch2.start(),
      switch3.start(),
      switch4.start(),
      switch5.start(),
    )

    await switch1.connect(switch2)

    await awaiter

    await switch1.connect(switch3)
    await switch1.connect(switch4)
    await switch5.connect(switch1)
    # switch1 is now full, should stick to last observation
    awaiter = newFuture[void]()
    await autonatService.start(switch1)

    await sleepAsync(100.millis)

    check autonatService.networkReachability == NetworkReachability.Reachable
    check reachabilityConfidence(NetworkReachability.Reachable) == 1

    await allFuturesRaising(
      stopAutonatSwitch(switch1, autonatService),
      switch2.stop(),
      switch3.stop(),
      switch4.stop(),
      switch5.stop(),
    )

  asyncTest "Peer must not ask an incoming peer":
    let autonatService = AutonatService.new(AutonatClient.new(), rng())

    let switch1 = createSwitch()
    let switch2 = createSwitch()

    proc reachabilityHandler(
        networkReachability: NetworkReachability,
        confidence: Opt[float],
        dialBackAddr: Opt[MultiAddress],
    ) {.async: (raises: [CancelledError]).} =
      fail()

    check autonatService.networkReachability == NetworkReachability.Unknown

    check autonatService.reachabilityObservers.add(reachabilityHandler)

    await startAutonatSwitch(switch1, autonatService)
    await switch2.start()

    await switch2.connect(switch1)

    await sleepAsync(250.milliseconds)

    await allFuturesRaising(stopAutonatSwitch(switch1, autonatService), switch2.stop())
