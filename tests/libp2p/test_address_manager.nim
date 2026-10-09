# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import
  ../../libp2p/
    [address_manager, crypto/crypto, multiaddress, multicodec, peerinfo, switch]
import ../../libp2p/services/natservice
import ../tools/[unittest, crypto, switch_builder, multiaddress, lifecycle]

const VerifyInterval = 10.milliseconds

proc makeManager(
    maxSize = DefaultObservedAddrMaxSize,
    minCount = DefaultObservedAddrMinCount,
    verifyInterval = DefaultVerifyInterval,
    verifyTimeout = DefaultVerifyTimeout,
    verifier: Verifier = nil,
): AddressManager =
  let manager = AddressManager.new(
    AddressManagerConfig(
      maxSize: maxSize,
      minCount: minCount,
      verifyInterval: verifyInterval,
      verifyTimeout: verifyTimeout,
    )
  )
  manager.verifier = verifier
  manager

proc makePeerInfo(
    listenAddrs: seq[MultiAddress] = @[],
    announcedAddrs: seq[MultiAddress] = @[],
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
): PeerInfo {.raises: [LPError].} =
  PeerInfo.new(
    PrivateKey.random(PKScheme.Ed25519, rng()).get(),
    listenAddrs,
    announcedAddrs = announcedAddrs,
    addressPolicy = addressPolicy,
  )

proc constantMapper(addrs: seq[MultiAddress]): AddressMapper =
  proc(
      listenAddrs: seq[MultiAddress]
  ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    addrs

proc addingMapper(addrs: seq[MultiAddress]): AddressMapper =
  proc(
      listenAddrs: seq[MultiAddress]
  ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
    listenAddrs & addrs

type
  Verdict = object
    address: MultiAddress
    state: AddrState

  StubVerifier = ref object of Verifier
    verdicts: seq[Verdict]
    asked: seq[MultiAddress]
    ran: AsyncEvent
    delay: Duration
    slow: seq[MultiAddress] ## the addresses `delay` applies to, all when empty

func verdict(address: MultiAddress, state: AddrState): Verdict =
  Verdict(address: address, state: state)

proc makeStubVerifier(
    verdicts: seq[Verdict] = @[], delay = ZeroDuration, slow: seq[MultiAddress] = @[]
): StubVerifier =
  StubVerifier(verdicts: verdicts, ran: newAsyncEvent(), delay: delay, slow: slow)

func timesAsked(self: StubVerifier, address: MultiAddress): int =
  self.asked.countIt(it == address)

method verify(
    self: StubVerifier, address: MultiAddress
): Future[Opt[AddrState]] {.async: (raises: [CancelledError]).} =
  self.asked.add(address)
  self.ran.fire()
  if self.slow.len == 0 or address in self.slow:
    await sleepAsync(self.delay)

  for verdict in self.verdicts:
    if verdict.address == address:
      return Opt.some(verdict.state)
  Opt.none(AddrState)

proc interfaceProvider(hosts: seq[string]): NetworkInterfaceProvider =
  proc(addrFamily: AddressFamily): seq[InterfaceAddress] {.gcsafe, raises: [].} =
    var res: seq[InterfaceAddress]
    for host in hosts:
      let address =
        try:
          InterfaceAddress.init(initTAddress(host), 24)
        except TransportAddressError:
          raiseAssert "test address is valid: " & host
      if address.host.family == addrFamily:
        res.add(address)
    res

suite "AddressManager observations":
  teardown:
    checkTrackers()

  asyncTest "Calculate the most observed IP correctly":
    let manager = makeManager(minCount = 3)
    startAndDeferStop(manager)

    let mostObservedIP4AndPort = ma("/ip4/1.2.3.0/tcp/1")
    let maIP4 = ma("/ip4/0.0.0.0/tcp/80")

    check:
      manager.addObservation(randomPeerId(), mostObservedIP4AndPort)
      manager.addObservation(randomPeerId(), mostObservedIP4AndPort)

      manager.externalAddrFor(maIP4) == maIP4

      manager.addObservation(randomPeerId(), ma("/ip4/1.2.3.0/tcp/2"))
      manager.addObservation(randomPeerId(), ma("/ip4/1.2.3.1/tcp/1"))

      manager.externalAddrFor(maIP4) == ma("/ip4/1.2.3.0/tcp/80")
      manager.mostObservedProtosAndPorts().len == 0

      manager.addObservation(randomPeerId(), mostObservedIP4AndPort)

      manager.mostObservedProtosAndPorts() == @[mostObservedIP4AndPort]

    let mostObservedIP6AndPort = ma("/ip6/::2/tcp/1")
    let maIP6 = ma("/ip6/::1/tcp/80")

    check:
      manager.addObservation(randomPeerId(), mostObservedIP6AndPort)
      manager.addObservation(randomPeerId(), mostObservedIP6AndPort)

      manager.externalAddrFor(maIP6) == maIP6

      manager.addObservation(randomPeerId(), ma("/ip6/::2/tcp/2"))
      manager.addObservation(randomPeerId(), ma("/ip6/::3/tcp/1"))

      manager.externalAddrFor(maIP6) == ma("/ip6/::2/tcp/80")
      manager.mostObservedProtosAndPorts().len == 1

      manager.addObservation(randomPeerId(), mostObservedIP6AndPort)

      manager.mostObservedProtosAndPorts() ==
        @[mostObservedIP4AndPort, mostObservedIP6AndPort]

  asyncTest "replace first proto value by most observed when there is only one protocol":
    let manager = makeManager(minCount = 3)
    startAndDeferStop(manager)
    let mostObservedIP4AndPort = ma("/ip4/1.2.3.4/tcp/1")

    check:
      manager.addObservation(randomPeerId(), mostObservedIP4AndPort)
      manager.addObservation(randomPeerId(), mostObservedIP4AndPort)
      manager.addObservation(randomPeerId(), mostObservedIP4AndPort)

      manager.externalAddrFor(ma("/ip4/0.0.0.0")) == ma("/ip4/1.2.3.4")

  asyncTest "one peer counts once, however often it reports":
    let
      manager = makeManager(minCount = 3)
      observer = randomPeerId()
      observed = ma("/ip4/1.2.3.4/tcp/1")

    startAndDeferStop(manager)
    for _ in 0 ..< 5:
      check manager.addObservation(observer, observed)

    check manager.mostObservedProtosAndPorts().len == 0

    for _ in 0 ..< 2:
      check manager.addObservation(randomPeerId(), observed)

    check manager.mostObservedProtosAndPorts() == @[observed]

  asyncTest "the last report of a peer replaces its previous one":
    let
      manager = makeManager(minCount = 2)
      observer = randomPeerId()
      first = ma("/ip4/1.2.3.4/tcp/1")
      last = ma("/ip4/5.6.7.8/tcp/1")

    startAndDeferStop(manager)
    check:
      manager.addObservation(randomPeerId(), first)
      manager.addObservation(observer, first)
      manager.mostObservedProtosAndPorts() == @[first]

      manager.addObservation(observer, last)
      manager.mostObservedProtosAndPorts().len == 0

  asyncTest "a peer holds one slot of the window, whatever it reports":
    let
      manager = makeManager(maxSize = 3, minCount = 2)
      noisy = randomPeerId()
      observed = ma("/ip4/1.2.3.4/tcp/1")

    startAndDeferStop(manager)
    check manager.addObservation(randomPeerId(), observed)

    for i in 0 ..< 4:
      check manager.addObservation(noisy, ma("/ip4/9.9.9." & $i & "/tcp/1"))

    check:
      manager.addObservation(randomPeerId(), observed)
      manager.mostObservedProtosAndPorts() == @[observed]

  asyncTest "an address which is not a direct IP address with a transport is rejected":
    let
      manager = makeManager(maxSize = 2, minCount = 1)
      observed = ma("/ip4/1.2.3.4/tcp/1")

    startAndDeferStop(manager)
    check manager.addObservation(randomPeerId(), observed)

    # the window is small: junk must neither be counted nor evict the good entry
    for _ in 0 ..< 4:
      check:
        not manager.addObservation(randomPeerId(), ma("/dns4/example.com/tcp/1"))
        not manager.addObservation(randomPeerId(), ma("/ip4/1.2.3.4"))
        not manager.addObservation(randomPeerId(), ma("/ip4/1.2.3.4/tcp/1/p2p-circuit"))

    check manager.mostObservedProtosAndPorts() == @[observed]

  asyncTest "a threshold below one is raised to one":
    let
      manager = makeManager(maxSize = 0, minCount = 0)
      firstObserved = ma("/ip4/1.2.3.4/tcp/1")
      lastObserved = ma("/ip4/5.6.7.8/tcp/1")

    startAndDeferStop(manager)
    check:
      manager.addObservation(randomPeerId(), firstObserved)
      manager.addObservation(randomPeerId(), lastObserved)
      manager.mostObservedProtosAndPorts() == @[lastObserved]

  asyncTest "a stopped manager rejects observations until it starts again":
    let
      manager = makeManager(minCount = 1)
      observed = ma("/ip4/1.2.3.4/tcp/1")

    manager.start()
    check manager.addObservation(randomPeerId(), observed)

    manager.stop()
    check:
      not manager.addObservation(randomPeerId(), observed)
      manager.mostObservedProtosAndPorts().len == 0

    manager.start()
    check:
      manager.addObservation(randomPeerId(), observed)
      manager.mostObservedProtosAndPorts() == @[observed]

    manager.stop()

  asyncTest "start and stop are idempotent":
    let
      manager = makeManager(minCount = 1)
      observed = ma("/ip4/1.2.3.4/tcp/1")

    manager.stop()
    check not manager.isStarted()

    manager.start()
    manager.start()

    check:
      manager.isStarted()
      manager.addObservation(randomPeerId(), observed)
      manager.mostObservedProtosAndPorts() == @[observed]

    manager.stop()
    manager.stop()

    check:
      not manager.isStarted()
      manager.mostObservedProtosAndPorts().len == 0

  asyncTest "a manager which never started rejects observations":
    let
      manager = makeManager(minCount = 1)
      observed = ma("/ip4/1.2.3.4/tcp/1")

    check:
      not manager.isStarted()
      not manager.addObservation(randomPeerId(), observed)
      manager.mostObservedProtosAndPorts().len == 0

    manager.start()
    check manager.addObservation(randomPeerId(), observed)
    manager.stop()

suite "AddressManager wildcard expansion":
  let provider =
    interfaceProvider(@["127.0.0.1:0", "192.168.1.22:0", "[::1]:0", "[fe80::1]:0"])

  test "an IPv4 wildcard expands to the IPv4 interfaces only":
    check expandWildcardAddresses(provider, @[ma("/ip4/0.0.0.0/tcp/4001")]) ==
      @[ma("/ip4/127.0.0.1/tcp/4001"), ma("/ip4/192.168.1.22/tcp/4001")]

  test "an IPv6 wildcard expands to the IPv6 and the IPv4 interfaces":
    # TODO: vacp2p/nim-libp2p#2757
    check expandWildcardAddresses(provider, @[ma("/ip6/::/tcp/4001")]) ==
      @[
        ma("/ip6/::1/tcp/4001"),
        ma("/ip6/fe80::1/tcp/4001"),
        ma("/ip4/127.0.0.1/tcp/4001"),
        ma("/ip4/192.168.1.22/tcp/4001"),
      ]

  test "a non-wildcard and a non-IP address pass through unchanged":
    let inputs = @[
      ma("/ip4/1.2.3.4/tcp/4001"),
      ma("/dns4/example.com/tcp/4001"),
      ma("/memorytransport/addr-1"),
    ]
    check expandWildcardAddresses(provider, inputs) == inputs

suite "AddressManager candidates":
  teardown:
    checkTrackers()

  asyncTest "a candidate is stored once and keeps every source which adds it":
    let
      manager = makeManager()
      address = ma("/ip4/1.2.3.4/tcp/1")

    startAndDeferStop(manager)
    check:
      manager.add(address, AddrSource.Listen)
      not manager.add(address, AddrSource.Upnp)
      manager.candidates().len == 1
      manager.candidates()[0].sources == {AddrSource.Listen, AddrSource.Upnp}
      manager.candidates()[0].state == AddrState.Unverified

  asyncTest "a refresh keeps the state a verifier assigned":
    let
      manager = makeManager()
      address = ma("/ip4/1.2.3.4/tcp/1")

    startAndDeferStop(manager)
    manager.add(address, AddrSource.Listen)

    check:
      manager.update(address, AddrState.Confirmed)
      not manager.add(address, AddrSource.Listen)
      manager.candidates()[0].state == AddrState.Confirmed

  asyncTest "update and remove report an unknown address":
    let
      manager = makeManager()
      address = ma("/ip4/1.2.3.4/tcp/1")

    startAndDeferStop(manager)
    check:
      not manager.update(address, AddrState.Confirmed)
      not manager.remove(address)

    manager.add(address, AddrSource.Listen)

    check:
      manager.remove(address)
      manager.candidates().len == 0

suite "AddressManager verification":
  teardown:
    checkTrackers()

  asyncTest "a candidate stays unverified while no verifier runs":
    let
      manager = makeManager(verifyInterval = VerifyInterval)
      address = ma("/ip4/1.2.3.4/tcp/1")

    startAndDeferStop(manager)
    manager.add(address, AddrSource.Listen)
    # long enough for the heartbeat to run, which without a verifier changes nothing
    await sleepAsync(VerifyInterval * 2)

    check:
      manager.candidates()[0].state == AddrState.Unverified
      manager.confirmedAddrs().len == 0

  asyncTest "the heartbeat verifies every candidate and applies the verdicts":
    let
      confirmed = ma("/ip4/1.2.3.4/tcp/1")
      unreachable = ma("/ip4/5.6.7.8/tcp/1")
      verifier = makeStubVerifier(
        @[
          verdict(confirmed, AddrState.Confirmed),
          verdict(unreachable, AddrState.Unreachable),
        ]
      )
      manager = makeManager(verifyInterval = VerifyInterval, verifier = verifier)

    startAndDeferStop(manager)
    manager.add(confirmed, AddrSource.Listen)
    manager.add(unreachable, AddrSource.Upnp)

    checkUntilTimeout:
      manager.confirmedAddrs() == @[confirmed]
      manager.candidates().anyIt(
        it.address == unreachable and it.state == AddrState.Unreachable
      )
      confirmed in verifier.asked
      unreachable in verifier.asked

  asyncTest "a verifier which runs out of time applies nothing and runs again":
    let
      address = ma("/ip4/1.2.3.4/tcp/1")
      verifier =
        makeStubVerifier(@[verdict(address, AddrState.Confirmed)], delay = 1.hours)
      manager = makeManager(
        verifyInterval = VerifyInterval,
        verifyTimeout = VerifyInterval,
        verifier = verifier,
      )

    startAndDeferStop(manager)
    manager.add(address, AddrSource.Listen)

    checkUntilTimeout:
      verifier.asked.len >= 2
      manager.confirmedAddrs().len == 0

  asyncTest "a run which times out keeps the verdicts it already collected":
    let
      quick = ma("/ip4/1.2.3.4/tcp/1")
      slow = ma("/ip4/5.6.7.8/tcp/1")
      verifier = makeStubVerifier(
        @[verdict(quick, AddrState.Confirmed), verdict(slow, AddrState.Confirmed)],
        delay = 1.hours,
        slow = @[slow],
      )
      manager = makeManager(
        verifyInterval = VerifyInterval,
        verifyTimeout = VerifyInterval,
        verifier = verifier,
      )

    startAndDeferStop(manager)
    manager.add(quick, AddrSource.Listen)
    manager.add(slow, AddrSource.Listen)

    checkUntilTimeout:
      manager.confirmedAddrs() == @[quick]

  asyncTest "the schedule interval does not cap a run":
    let
      address = ma("/ip4/1.2.3.4/tcp/1")
      verifier = makeStubVerifier(
        @[verdict(address, AddrState.Confirmed)], delay = VerifyInterval * 4
      )
      manager = makeManager(verifyInterval = VerifyInterval, verifier = verifier)

    startAndDeferStop(manager)
    manager.add(address, AddrSource.Listen)

    checkUntilTimeout:
      manager.confirmedAddrs() == @[address]

  asyncTest "stopping the manager stops the heartbeat":
    let
      address = ma("/ip4/1.2.3.4/tcp/1")
      verifier = makeStubVerifier()
      manager = makeManager(verifyInterval = VerifyInterval, verifier = verifier)

    manager.start()
    manager.add(address, AddrSource.Listen)
    await verifier.ran.wait()

    manager.stop()
    let runs = verifier.asked.len
    manager.add(address, AddrSource.Listen)
    await sleepAsync(VerifyInterval * 2)

    check verifier.asked.len == runs

  asyncTest "an interval and a verifier set after start take effect without a stale wait":
    let
      address = ma("/ip4/1.2.3.4/tcp/1")
      verifier = makeStubVerifier(@[verdict(address, AddrState.Confirmed)])
      # the default interval is minutes; a stale first sleep would outlive the test
      manager = makeManager()

    startAndDeferStop(manager)
    manager.add(address, AddrSource.Listen)
    manager.verifier = verifier
    manager.verifyInterval = VerifyInterval

    checkUntilTimeout:
      manager.confirmedAddrs() == @[address]

  asyncTest "the reachability summary follows the candidate states":
    let
      manager = makeManager()
      first = ma("/ip4/1.2.3.4/tcp/1")
      second = ma("/ip4/5.6.7.8/tcp/1")

    startAndDeferStop(manager)
    check manager.reachability() == NetworkReachability.Unknown

    manager.add(first, AddrSource.Listen)
    check manager.reachability() == NetworkReachability.Unknown

    manager.update(first, AddrState.Unreachable)
    check manager.reachability() == NetworkReachability.NotReachable

    manager.add(second, AddrSource.Upnp)
    manager.update(second, AddrState.Confirmed)
    check manager.reachability() == NetworkReachability.Reachable

  asyncTest "a verify run which changes the summary fires the handler once":
    let
      address = ma("/ip4/1.2.3.4/tcp/1")
      verifier = makeStubVerifier(@[verdict(address, AddrState.Confirmed)])
      manager = makeManager(verifyInterval = VerifyInterval, verifier = verifier)

    startAndDeferStop(manager)
    var notified: seq[NetworkReachability]
    manager.onReachabilityChange = proc(
        reachability: NetworkReachability
    ) {.async: (raises: [CancelledError]).} =
      notified.add(reachability)

    manager.add(address, AddrSource.Listen)

    checkUntilTimeout:
      notified == @[NetworkReachability.Reachable]

    # further runs repeat the same verdict, and the summary change fires no more
    await sleepAsync(VerifyInterval * 3)
    check notified == @[NetworkReachability.Reachable]

  asyncTest "a cancelled reachability notification is not retried":
    let
      address = ma("/ip4/1.2.3.4/tcp/1")
      verifier = makeStubVerifier(@[verdict(address, AddrState.Confirmed)])
      manager = makeManager(verifyInterval = 1.minutes, verifier = verifier)
      firstCall = newAsyncEvent()
      handlerCancelled = newAsyncEvent()
      blockHandler = newAsyncEvent()

    var calls = 0
    manager.onReachabilityChange = proc(
        reachability: NetworkReachability
    ) {.async: (raises: [CancelledError]).} =
      calls.inc()
      if calls == 1:
        firstCall.fire()
        try:
          await blockHandler.wait()
        except CancelledError as e:
          handlerCancelled.fire()
          raise e

    manager.add(address, AddrSource.Listen)
    startAndDeferStop(manager)
    await firstCall.wait()

    # restarting the heartbeat cancels the pending first invocation
    manager.verifyInterval = VerifyInterval
    await handlerCancelled.wait()

    # `verifier.ran` fires before its verdict reaches `notifyReachability`, so
    # let several full passes finish before checking that cancellation did not
    # cause the reachability change to be delivered again.
    await sleepAsync(VerifyInterval * 3)
    check calls == 1

  asyncTest "triggerVerification runs a pass without waiting for the interval":
    let
      address = ma("/ip4/1.2.3.4/tcp/1")
      verifier = makeStubVerifier()
      manager = makeManager(verifyInterval = 10.minutes, verifier = verifier)

    startAndDeferStop(manager)
    manager.add(address, AddrSource.Listen)
    check verifier.asked.len == 0

    manager.triggerVerification()
    checkUntilTimeout:
      verifier.asked == @[address]

  asyncTest "a relayed candidate is never sent to the verifier":
    let
      relayAddr = ma("/ip4/1.2.3.4/tcp/1/p2p-circuit")
      directAddr = ma("/ip4/5.6.7.8/tcp/1")
      verifier = makeStubVerifier()
      manager = makeManager(verifyInterval = VerifyInterval, verifier = verifier)

    startAndDeferStop(manager)
    manager.add(relayAddr, AddrSource.Circuit)
    manager.add(directAddr, AddrSource.Listen)

    checkUntilTimeout:
      verifier.asked.len >= 1

    check verifier.asked.allIt(it == directAddr)

  asyncTest "the address policy keeps a banned candidate out of the dial requests":
    let
      privateAddr = ma("/ip4/192.168.0.2/tcp/1")
      publicAddr = ma("/ip4/8.8.8.8/tcp/1")
      verifier = makeStubVerifier()
      manager = makeManager(verifyInterval = VerifyInterval, verifier = verifier)
      peerInfo = makePeerInfo(addressPolicy = publicRoutableAddressPolicy)

    startAndDeferStop(manager, peerInfo)
    manager.add(privateAddr, AddrSource.Listen)
    manager.add(publicAddr, AddrSource.Listen)

    checkUntilTimeout:
      verifier.asked.len >= 1
    check verifier.asked.allIt(it == publicAddr)

  asyncTest "a refuted guess waits out its runs before it is asked again":
    let
      directAddr = ma("/ip4/5.6.7.8/tcp/1")
      observed = ma("/ip4/8.8.8.8/tcp/9")
      verifier = makeStubVerifier(@[verdict(observed, AddrState.Unreachable)])
      manager =
        makeManager(minCount = 1, verifyInterval = VerifyInterval, verifier = verifier)
      peerInfo = makePeerInfo()

    manager.deriveIdentifyCandidates = true
    startAndDeferStop(manager, peerInfo)
    manager.add(directAddr, AddrSource.Listen)
    check manager.addObservation(randomPeerId(), observed)

    checkUntilTimeout:
      verifier.timesAsked(directAddr) >= 3
    check verifier.timesAsked(observed) == 1

    checkUntilTimeout:
      verifier.timesAsked(observed) >= 2

  asyncTest "a refuted identify guess makes the node unreachable":
    let
      observed = ma("/ip4/8.8.8.8/tcp/9")
      verifier = makeStubVerifier(@[verdict(observed, AddrState.Unreachable)])
      manager =
        makeManager(minCount = 1, verifyInterval = VerifyInterval, verifier = verifier)
      peerInfo = makePeerInfo(addressPolicy = publicRoutableAddressPolicy)

    # with no listen address the guess is the only candidate a dial-back reaches
    manager.deriveIdentifyCandidates = true
    startAndDeferStop(manager, peerInfo)
    check manager.addObservation(randomPeerId(), observed)

    checkUntilTimeout:
      manager.reachability() == NetworkReachability.NotReachable

  asyncTest "newer refutations evict the oldest refuted guess, which becomes eligible":
    let
      firstIp4 = ma("/ip4/8.8.8.8/tcp/1")
      secondIp4 = ma("/ip4/9.9.9.9/tcp/1")
      ip6 = ma("/ip6/2001:db8::1/tcp/1")
      verifier = makeStubVerifier(
        @[
          verdict(firstIp4, AddrState.Unreachable),
          verdict(secondIp4, AddrState.Unreachable),
          verdict(ip6, AddrState.Unreachable),
        ]
      )
      manager = makeManager(
        maxSize = 2, minCount = 1, verifyInterval = VerifyInterval, verifier = verifier
      )
      peerInfo = makePeerInfo()

    manager.deriveIdentifyCandidates = true
    startAndDeferStop(manager, peerInfo)

    check manager.addObservation(randomPeerId(), firstIp4)
    checkUntilTimeout:
      verifier.timesAsked(firstIp4) == 1

    # two newer refutations fill the ring of two and evict the first guess
    check manager.addObservation(randomPeerId(), secondIp4)
    check manager.addObservation(randomPeerId(), ip6)
    checkUntilTimeout:
      secondIp4 in verifier.asked
      ip6 in verifier.asked

    # the evicted guess becomes a candidate again on a new observation
    check manager.addObservation(randomPeerId(), firstIp4)
    checkUntilTimeout:
      verifier.timesAsked(firstIp4) >= 2

  asyncTest "observations become candidates when derivation is enabled":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      observed = ma("/ip4/8.8.8.8/tcp/9")
      guessed = ma("/ip4/8.8.8.8/tcp/1")
      verifier = makeStubVerifier()
      manager =
        makeManager(minCount = 3, verifyInterval = VerifyInterval, verifier = verifier)
      peerInfo = makePeerInfo(@[listenAddr])

    manager.deriveIdentifyCandidates = true
    startAndDeferStop(manager, peerInfo)

    for _ in 0 ..< 3:
      check manager.addObservation(randomPeerId(), observed)

    checkUntilTimeout:
      manager.candidates().anyIt(
        it.address == guessed and it.sources == {AddrSource.Identify}
      )
      manager.candidates().anyIt(
        it.address == observed and it.sources == {AddrSource.Identify}
      )

suite "AddressManager address mapper":
  teardown:
    checkTrackers()

  asyncTest "the manager is the only mapper the PeerInfo runs":
    let
      peerInfo = makePeerInfo(@[ma("/ip4/1.2.3.4/tcp/1")])
      manager = makeManager()

    check peerInfo.addressMappers.len == 0

    manager.setPeerInfo(peerInfo)
    manager.start()
    check peerInfo.addressMappers.len == 1

    manager.stop()
    check peerInfo.addressMappers.len == 0

  asyncTest "the manager expands the wildcard addresses":
    let
      peerInfo = makePeerInfo(@[ma("/ip4/0.0.0.0/tcp/1")])
      manager = makeManager()

    manager.networkInterfaceProvider = interfaceProvider(@["127.0.0.1:0", "10.0.0.1:0"])
    startAndDeferStop(manager, peerInfo)
    await peerInfo.update()

    check peerInfo.addrs == @[ma("/ip4/127.0.0.1/tcp/1"), ma("/ip4/10.0.0.1/tcp/1")]

    manager.networkInterfaceProvider = nil
    await peerInfo.update()

    check peerInfo.addrs == @[ma("/ip4/0.0.0.0/tcp/1")]

  asyncTest "a mapper tags the addresses it adds with its own source":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      relayAddr = ma("/ip4/1.2.3.4/tcp/1/p2p-circuit")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()

    startAndDeferStop(manager, peerInfo)
    manager.addMapper(constantMapper(@[listenAddr, relayAddr]), AddrSource.Circuit)
    await peerInfo.update()

    check:
      peerInfo.addrs == @[listenAddr, relayAddr]
      manager.candidates().len == 2

    for candidate in manager.candidates():
      if candidate.address == listenAddr:
        check candidate.sources == {AddrSource.Listen}
      else:
        check candidate.sources == {AddrSource.Circuit}

  asyncTest "a mapper which stops producing an address withdraws its candidate":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      mapper = constantMapper(@[mappedAddr])

    startAndDeferStop(manager, peerInfo)
    manager.addMapper(mapper, AddrSource.Upnp)
    await peerInfo.update()

    check:
      peerInfo.addrs == @[mappedAddr]
      manager.candidates().len == 1

    manager.removeMapper(mapper)
    await peerInfo.update()

    check:
      peerInfo.addrs == @[listenAddr]
      manager.candidates().len == 1
      manager.candidates()[0].address == listenAddr

  asyncTest "removed mappers are skipped by an in-flight resolution pass":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      gate = Future[void].Raising([CancelledError]).init("address mapper gate")
    var slowCalls, otherCalls = 0

    let slow: AddressMapper = proc(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc slowCalls
      await gate
      input
    let other: AddressMapper = proc(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc otherCalls
      input

    startAndDeferStop(manager, peerInfo)
    manager.addMapper(slow, AddrSource.PortMapped)
    manager.addMapper(other, AddrSource.Autonat)

    let pass = peerInfo.expandAddrs()
    check slowCalls == 1
    manager.removeMapper(other)
    gate.complete()
    discard await pass

    check:
      slowCalls == 1
      otherCalls == 0

  asyncTest "removing an applied mapper restarts the resolution chain":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      gate = Future[void].Raising([CancelledError]).init("address mapper gate")
    var firstCalls, slowCalls = 0

    let first: AddressMapper = proc(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc firstCalls
      @[mappedAddr]
    let slow: AddressMapper = proc(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc slowCalls
      await gate
      input

    startAndDeferStop(manager, peerInfo)
    manager.addMapper(first, AddrSource.PortMapped)
    manager.addMapper(slow, AddrSource.Autonat)

    let pass = peerInfo.expandAddrs()
    check:
      firstCalls == 1
      slowCalls == 1
    manager.removeMapper(first)
    gate.complete()
    let resolved = await pass

    check:
      firstCalls == 1
      slowCalls == 2
      resolved == @[listenAddr]
      manager.candidates().allIt(it.address != mappedAddr)

  asyncTest "an in-flight removed mapper's result is discarded":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      gate = Future[void].Raising([CancelledError]).init("address mapper gate")
    var mapperCalls = 0

    let mapper: AddressMapper = proc(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc mapperCalls
      await gate
      @[mappedAddr]

    startAndDeferStop(manager, peerInfo)
    manager.addMapper(mapper, AddrSource.PortMapped)

    let pass = peerInfo.expandAddrs()
    check mapperCalls == 1
    manager.removeMapper(mapper)
    gate.complete()
    let resolved = await pass

    check:
      mapperCalls == 1
      resolved == @[listenAddr]
      manager.candidates().allIt(it.address != mappedAddr)

  asyncTest "stopping invalidates an in-flight resolution pass":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      gate = Future[void].Raising([CancelledError]).init("address mapper gate")
    var mapperCalls = 0

    let mapper: AddressMapper = proc(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc mapperCalls
      await gate
      input

    manager.setPeerInfo(peerInfo)
    manager.start()
    manager.addMapper(mapper, AddrSource.PortMapped)

    let pass = peerInfo.expandAddrs()
    check mapperCalls == 1
    manager.stop()
    gate.complete()
    discard await pass

    check:
      manager.candidates().len == 0
      manager.mapperSources().len == 0
      peerInfo.addressMappers.len == 0

  asyncTest "a withdrawal tells the observers without waiting for the heartbeat":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      mapper = constantMapper(@[mappedAddr])

    startAndDeferStop(manager, peerInfo)
    var notified: seq[NetworkReachability]
    manager.onReachabilityChange = proc(
        reachability: NetworkReachability
    ) {.async: (raises: [CancelledError]).} =
      notified.add(reachability)

    manager.addMapper(mapper, AddrSource.Upnp)
    await peerInfo.update()
    manager.update(mappedAddr, AddrState.Confirmed)
    await peerInfo.update()
    check notified == @[NetworkReachability.Reachable]

    manager.removeMapper(mapper)
    await peerInfo.update()
    check notified == @[NetworkReachability.Reachable, NetworkReachability.Unknown]

  asyncTest "a reachability handler may update PeerInfo without deadlocking":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      mapper = constantMapper(@[mappedAddr])
      handlerFinished = newAsyncEvent()

    startAndDeferStop(manager, peerInfo)
    manager.onReachabilityChange = proc(
        reachability: NetworkReachability
    ) {.async: (raises: [CancelledError]).} =
      if reachability == NetworkReachability.Reachable:
        await peerInfo.update()
        handlerFinished.fire()

    manager.addMapper(mapper, AddrSource.Upnp)
    await peerInfo.update()
    manager.update(mappedAddr, AddrState.Confirmed)
    await peerInfo.update()

    await handlerFinished.wait()
    check peerInfo.addrs == @[mappedAddr]

  asyncTest "reachability handlers are ordered and do not overlap":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      mapper = constantMapper(@[mappedAddr])
      firstStarted = newAsyncEvent()
      releaseFirst = newAsyncEvent()
      secondStarted = newAsyncEvent()

    startAndDeferStop(manager, peerInfo)
    var notified: seq[NetworkReachability]
    manager.onReachabilityChange = proc(
        reachability: NetworkReachability
    ) {.async: (raises: [CancelledError]).} =
      notified.add(reachability)
      if notified.len == 1:
        firstStarted.fire()
        await releaseFirst.wait()
      else:
        secondStarted.fire()

    manager.addMapper(mapper, AddrSource.Upnp)
    await peerInfo.update()
    manager.update(mappedAddr, AddrState.Confirmed)
    await peerInfo.update()
    await firstStarted.wait()

    manager.update(mappedAddr, AddrState.Unreachable)
    await peerInfo.update()
    check notified == @[NetworkReachability.Reachable]

    releaseFirst.fire()
    await secondStarted.wait()
    check notified == @[NetworkReachability.Reachable, NetworkReachability.NotReachable]

  asyncTest "stopping cancels a pending reachability handler":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      mapper = constantMapper(@[mappedAddr])
      handlerStarted = newAsyncEvent()
      handlerCancelled = newAsyncEvent()

    startAndDeferStop(manager, peerInfo)
    manager.onReachabilityChange = proc(
        reachability: NetworkReachability
    ) {.async: (raises: [CancelledError]).} =
      handlerStarted.fire()
      try:
        await newAsyncEvent().wait()
      except CancelledError as exc:
        handlerCancelled.fire()
        raise exc

    manager.addMapper(mapper, AddrSource.Upnp)
    await peerInfo.update()
    manager.update(mappedAddr, AddrState.Confirmed)
    await peerInfo.update()
    await handlerStarted.wait()

    manager.stop()
    await handlerCancelled.wait()

  asyncTest "a candidate a feeder also offers survives the mapper which drops it":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      mappedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()
      mapper = constantMapper(@[listenAddr, mappedAddr])

    startAndDeferStop(manager, peerInfo)
    manager.addMapper(mapper, AddrSource.Upnp)
    await peerInfo.update()

    manager.add(mappedAddr, AddrSource.Autonat)

    check manager.candidates().anyIt(
      it.address == mappedAddr and it.sources == {AddrSource.Upnp, AddrSource.Autonat}
    )

    manager.removeMapper(mapper)
    await peerInfo.update()

    check:
      peerInfo.addrs == @[listenAddr, mappedAddr]
      manager.candidates().anyIt(
        it.address == mappedAddr and it.sources == {AddrSource.Autonat}
      )

  asyncTest "a candidate a feeder adds is announced and survives the chain":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      fedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()

    startAndDeferStop(manager, peerInfo)
    manager.add(fedAddr, AddrSource.Circuit)
    await peerInfo.update()

    check peerInfo.addrs == @[listenAddr, fedAddr]

    check manager.remove(fedAddr)
    await peerInfo.update()

    check peerInfo.addrs == @[listenAddr]

  asyncTest "a verified-unreachable public candidate is not announced":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      fedAddr = ma("/ip4/1.2.3.4/tcp/1")
      peerInfo = makePeerInfo(@[listenAddr])
      manager = makeManager()

    startAndDeferStop(manager, peerInfo)
    manager.add(fedAddr, AddrSource.Circuit)
    await peerInfo.update()
    check peerInfo.addrs == @[listenAddr, fedAddr]

    manager.update(listenAddr, AddrState.Unreachable)
    manager.update(fedAddr, AddrState.Unreachable)
    await peerInfo.update()

    check:
      # the LAN address stays: no remote peer was ever going to reach it
      peerInfo.addrs == @[listenAddr]
      manager.candidates().allIt(it.state == AddrState.Unreachable)

  asyncTest "an explicit announce list wins, and the mappers still see the bound addrs":
    let
      announced = ma("/ip4/1.2.3.4/tcp/1")
      expanded = ma("/ip4/10.0.0.1/tcp/1")
      mapped = ma("/ip4/9.9.9.9/tcp/2")
      peerInfo = makePeerInfo(@[ma("/ip4/0.0.0.0/tcp/1")], @[announced])
      manager = makeManager()

    var mapperInput: seq[MultiAddress]
    let recordingMapper: AddressMapper = proc(
        listenAddrs: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      mapperInput = listenAddrs
      @[mapped]

    manager.networkInterfaceProvider = interfaceProvider(@["10.0.0.1:0"])
    startAndDeferStop(manager, peerInfo)
    manager.addMapper(recordingMapper, AddrSource.Upnp)
    await peerInfo.update()

    check:
      peerInfo.addrs == @[announced]
      mapperInput == @[expanded]
      manager.candidates().anyIt(
        it.address == announced and it.sources == {AddrSource.Announced}
      )
      manager.candidates().anyIt(
        it.address == mapped and it.sources == {AddrSource.Upnp}
      )

suite "AddressManager verify and announce":
  teardown:
    checkTrackers()

  asyncTest "multi-source candidates verify, and only confirmed or unverified announce":
    let
      listenAddr = ma("/ip4/192.168.0.2/tcp/1")
      upnpAddr = ma("/ip4/9.9.9.9/tcp/1")
      relayAddr = ma("/ip4/1.2.3.4/tcp/2/p2p-circuit")
      observed = ma("/ip4/8.8.8.8/tcp/9")
      guessed = ma("/ip4/8.8.8.8/tcp/1")
      verifier = makeStubVerifier(
        @[
          verdict(upnpAddr, AddrState.Confirmed),
          verdict(listenAddr, AddrState.Unreachable),
          verdict(guessed, AddrState.Unreachable),
        ]
      )
      manager =
        makeManager(minCount = 3, verifyInterval = VerifyInterval, verifier = verifier)
      peerInfo = makePeerInfo(@[listenAddr])

    manager.deriveIdentifyCandidates = true
    startAndDeferStop(manager, peerInfo)
    manager.addMapper(addingMapper(@[upnpAddr]), AddrSource.Upnp)
    manager.addMapper(addingMapper(@[relayAddr]), AddrSource.Circuit)

    # identify reports: three peers on the same address reach the quorum
    for _ in 0 ..< 3:
      check manager.addObservation(randomPeerId(), observed)

    await peerInfo.update()

    checkUntilTimeout:
      # the refuted LAN listen address stays; the confirmed IPv4 replaces the relay
      peerInfo.addrs == @[listenAddr, upnpAddr]
      manager.confirmedAddrs() == @[upnpAddr]
      manager.reachability() == NetworkReachability.Reachable

    check:
      # the relayed candidate is announced yet never verified
      relayAddr notin verifier.asked
      # the refuted guess is dropped; the unverified observation stays unannounced
      manager.candidates().allIt(it.address != guessed)
      manager.candidates().anyIt(it.address == observed)

suite "Switch-owned AddressManager":
  teardown:
    checkTrackers()

  asyncTest "the switch owns the manager and identify holds the same instance":
    let switch = makeStandardSwitch(ma("/memorytransport/*"))

    check:
      not switch.addressManager.isNil()
      switch.peerStore.identify.addressManager == switch.addressManager

  asyncTest "a started switch runs one mapper, the manager's own":
    let switch = makeStandardSwitchBuilder(TcpAutoAddress)
      .withNAT(autonatConfig(AutonatV1))
      .withWildcardResolver()
      .build()

    await switch.start()
    defer:
      await switch.stop()

    check:
      switch.peerInfo.addressMappers.len == 1
      switch.addressManager.mapperSources() == @[AddrSource.Autonat]

  asyncTest "identify feeds the manager which the switch owns":
    let
      dialer = makeStandardSwitchBuilder(TcpAutoAddress)
        .withAddressManager(AddressManagerConfig(minCount: 1))
        .build()
      listener = makeStandardSwitch(TcpAutoAddress)

    await allFutures(dialer.start(), listener.start())
    defer:
      await allFutures(dialer.stop(), listener.stop())

    # the dialer identifies the listener, which reports back the address it sees
    await dialer.connect(listener)

    let observed = dialer.addressManager.mostObservedProtosAndPorts()
    check:
      observed.len == 1
      observed[0].contains(multiCodec("ip4")).get(false)

  asyncTest "the builder config sets the thresholds":
    let
      switch = makeStandardSwitchBuilder(ma("/memorytransport/*"))
        .withAddressManager(AddressManagerConfig(maxSize: 2, minCount: 1))
        .build()
      firstObserved = ma("/ip4/1.2.3.4/tcp/1")
      lastObserved = ma("/ip4/5.6.7.8/tcp/1")

    await switch.start()
    defer:
      await switch.stop()

    # minCount is 1, so a single observation is enough
    check:
      switch.addressManager.addObservation(randomPeerId(), firstObserved)
      switch.addressManager.mostObservedProtosAndPorts() == @[firstObserved]

    # maxSize is 2, so the third observation drops the first one
    check:
      switch.addressManager.addObservation(randomPeerId(), lastObserved)
      switch.addressManager.addObservation(randomPeerId(), lastObserved)
      switch.addressManager.mostObservedProtosAndPorts() == @[lastObserved]

  asyncTest "the switch starts and stops the manager":
    let switch = makeStandardSwitch(ma("/memorytransport/*"))

    check not switch.addressManager.isStarted()

    await switch.start()
    check switch.addressManager.isStarted()

    await switch.stop()
    check not switch.addressManager.isStarted()

  asyncTest "stopping the switch drops the observations":
    let
      switch = makeStandardSwitch(ma("/memorytransport/*"))
      observed = ma("/ip4/1.2.3.4/tcp/1")
      listenAddr = ma("/ip4/0.0.0.0/tcp/80")

    await switch.start()

    for _ in 0 ..< 3:
      check switch.addressManager.addObservation(randomPeerId(), observed)

    check:
      switch.addressManager.mostObservedProtosAndPorts() == @[observed]
      switch.addressManager.externalAddrFor(listenAddr) == ma("/ip4/1.2.3.4/tcp/80")

    await switch.stop()

    check:
      switch.addressManager.mostObservedProtosAndPorts().len == 0
      switch.addressManager.externalAddrFor(listenAddr) == listenAddr
