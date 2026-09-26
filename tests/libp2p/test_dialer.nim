# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, sequtils, results
import
  ../../libp2p/[
    builders,
    dialcandidate,
    muxers/muxer,
    nameresolving/mockresolver,
    peerstore,
    stream/bridgestream,
    switch,
    transports/transport,
    upgrademngrs/muxedupgrade,
    upgrademngrs/upgrade,
  ]
import ../stubs/transportstub
import
  ../tools/
    [unittest, futures, switch_builder, crypto, multiaddress, resolver, stall_server]

proc replaceIdentifyHandler(sw: Switch, handler: LPProtoHandler) =
  for holder in sw.ms.handlers:
    if IdentifyCodec in holder.protos:
      holder.protocol.handler = handler

proc stallIdentify(sw: Switch) =
  ## Never answer identify, so only the identify budget can end the dial.
  proc stall(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    await stream.join()

  sw.replaceIdentifyHandler(stall)

proc stallAfterIdentify(sw: Switch) =
  ## Answer identify, then hold the stream open so no EOF ever arrives.
  let pusher = IdentifyPush.new()
  proc hold(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    try:
      await pusher.push(sw.peerInfo, stream)
    except LPStreamError:
      discard
    await stream.join()

  sw.replaceIdentifyHandler(hold)

proc relayAddr(relay: string): MultiAddress =
  ma(relay & "/p2p/" & $randomPeerId() & "/p2p-circuit")

proc rankOf(address: MultiAddress): DialRank =
  DialCandidate(address: address).dialRank()

proc makeTcpAddrs(count: int): seq[MultiAddress] =
  (0 ..< count).mapIt(ma("/ip4/1.2.3.4/tcp/" & $(4001 + it)))

proc makeRankedDialer(src: Switch, transports: seq[Transport]): Dialer =
  Dialer.new(
    src.peerInfo.peerId,
    src.connManager,
    src.peerStore,
    transports,
    src.ms,
    dialRanking = true,
  )

suite "Dialer":
  teardown:
    checkTrackers()

  asyncTest "Connect forces a new connection":
    let
      src = makeStandardSwitchBuilder().withMaxConnsPerPeer(2).build()
      dst = makeStandardSwitchBuilder().withMaxConnsPerPeer(2).build()

    await dst.start()

    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)
    check src.connManager.connCount(dst.peerInfo.peerId) == 1

    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)
    check src.connManager.connCount(dst.peerInfo.peerId) == 1

    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs, true, false)
    check src.connManager.connCount(dst.peerInfo.peerId) == 2

    await allFutures(src.stop(), dst.stop())

  asyncTest "Max connections reached":
    var switches: seq[Switch]

    let dst = makeStandardSwitchBuilder()
      .withConnectionLimits(ConnectionLimits.maxTotal(2))
      .build()
    await dst.start()
    switches.add(dst)

    for i in 1 ..< 3:
      let src = makeStandardSwitch()
      switches.add(src)
      await src.start()
      await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs, true, false)

    let src = makeStandardSwitch()
    switches.add(src)
    await src.start()

    expect DialFailedError:
      await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)
    check src.peerInfo.peerId notin dst.connManager.connectedPeers()

    await allFuturesRaising(switches.mapIt(it.stop()))

  asyncTest "Connect to self fails":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    expect DialFailedError:
      await src.connect(src.peerInfo.peerId, src.peerInfo.addrs)

  asyncTest "Connect without addresses fails":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    expect DialFailedError:
      await src.connect(randomPeerId(), @[])

  asyncTest "A stalling remote gives up at the dial timeout":
    let
      stall = startStallServer()
      src = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    defer:
      await src.stop()
      await stall.stop()

    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      dialTimeout = 1.seconds,
    )
    let peerId = randomPeerId()

    # Twice: the second dial only gets its turn if the first freed the peer's
    # dial lock, which a dial that hangs never does.
    for _ in 0 .. 1:
      expect DialFailedError:
        await dialer.connect(peerId, @[stall.address]).wait(10.seconds)

  asyncTest "A stalling address-only dial does not block another one":
    let
      stall = startStallServer()
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()

    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      dialTimeout = 30.seconds,
    )

    # Dials with no peer id shared one lock keyed on `default(PeerId)`, so the
    # stalling one held up every other address the node dialed.
    let stalling = dialer.connect(stall.address, allowUnknownPeerId = true)
    defer:
      await noCancel stalling.cancelAndWait()
      await allFutures(src.stop(), dst.stop())
      await stall.stop()

    await stall.waitAccepted().wait(5.seconds)

    let dialed = await dialer
      .connect(dst.peerInfo.addrs[0], allowUnknownPeerId = true)
      .wait(5.seconds)
    check dialed == dst.peerInfo.peerId

  asyncTest "Ranked dialing stops at the candidate limit":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      dialRanking = true,
    )

    var addrs: seq[MultiAddress]
    for i in 0 ..< MaxDialCandidates * 2:
      addrs.add(ma("/memorytransport/addr-" & $i))

    expect DialFailedError:
      await dialer.connect(randomPeerId(), addrs)

    check transport.dialedAddrs.len == MaxDialCandidates

  asyncTest "Dialing without ranking tries every address":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
    )

    var addrs: seq[MultiAddress]
    for i in 0 ..< MaxDialCandidates * 2:
      addrs.add(ma("/memorytransport/addr-" & $i))

    expect DialFailedError:
      await dialer.connect(randomPeerId(), addrs)

    check transport.dialedAddrs.len == addrs.len

  asyncTest "Ranked dialing skips the addresses no transport handles":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      dialRanking = true,
    )

    let handled = ma("/memorytransport/addr-0")
    var addrs: seq[MultiAddress]
    for i in 0 ..< MaxDialCandidates:
      addrs.add(ma("/ip4/1.2.3.4/tcp/" & $(1000 + i)))
    addrs.add(handled)

    expect DialFailedError:
      await dialer.connect(randomPeerId(), addrs)

    check transport.dialedAddrs == @[handled]

  asyncTest "Ranked dialing dials a wire address while a name still stalls":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    let resolver = StallingResolver.new()
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      resolver,
      dialRanking = true,
    )

    let stalling = ma("/dnsaddr/stalls.example")
    await dialer.connect(dst.peerInfo.peerId, @[stalling] & dst.peerInfo.addrs).wait(
      5.seconds
    )

    check src.connManager.connCount(dst.peerInfo.peerId) == 1
    check resolver.cancelled

  asyncTest "Ranked dialing does not wait for a stalled sibling resolution":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    let resolver = StallingResolver.new()
    resolver.txtResponses["_dnsaddr.mixed.example"] =
      @["dnsaddr=" & $dst.peerInfo.addrs[0], "dnsaddr=/dns4/stalls.example/tcp/1234"]

    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      resolver,
      dialTimeout = 1.seconds,
      dialRanking = true,
    )

    let mixed = MultiAddress.init("/dnsaddr/mixed.example").tryGet()
    await dialer.connect(dst.peerInfo.peerId, @[mixed]).wait(5.seconds)

    check src.connManager.connCount(dst.peerInfo.peerId) == 1
    check resolver.cancelled

  asyncTest "Ranked dialing dials a name that answers while another one stalls":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    let resolver = StallingResolver.new()
    resolver.txtResponses["_dnsaddr.good.example"] =
      @["dnsaddr=" & $dst.peerInfo.addrs[0]]

    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      resolver,
      dialRanking = true,
    )

    let
      stalling = ma("/dnsaddr/stalls.example")
      good = ma("/dnsaddr/good.example")
    await dialer.connect(dst.peerInfo.peerId, @[stalling, good]).wait(5.seconds)

    check src.connManager.connCount(dst.peerInfo.peerId) == 1
    check resolver.cancelled

  asyncTest "Ranked dialing connects to a peer that advertises names only":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    let resolver = MockResolver.new()
    resolver.txtResponses["_dnsaddr.good.example"] =
      @["dnsaddr=" & $dst.peerInfo.addrs[0]]

    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      resolver,
      dialRanking = true,
    )

    let name = ma("/dnsaddr/good.example")
    await dialer.connect(dst.peerInfo.peerId, @[name]).wait(5.seconds)

    check src.connManager.connCount(dst.peerInfo.peerId) == 1

  asyncTest "Ranked dialing reaches the resolved addresses when the wire ones fail":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    let resolver = MockResolver.new()
    resolver.txtResponses["_dnsaddr.good.example"] =
      @["dnsaddr=" & $dst.peerInfo.addrs[0]]

    let failing = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(failing)] & src.transports,
      src.ms,
      resolver,
      dialRanking = true,
    )

    let
      dead = ma("/memorytransport/addr-0")
      name = ma("/dnsaddr/good.example")
    await dialer.connect(dst.peerInfo.peerId, @[dead, name]).wait(5.seconds)

    check failing.dialedAddrs == @[dead]
    check src.connManager.connCount(dst.peerInfo.peerId) == 1

  asyncTest "Ranked dialing gives up the lookups once the candidate limit is reached":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let
      resolver = StallingResolver.new()
      transport = FailingDialTransport.new(Upgrade(), rng())
      dialer = Dialer.new(
        src.peerInfo.peerId,
        src.connManager,
        src.peerStore,
        @[Transport(transport)],
        src.ms,
        resolver,
        dialRanking = true,
      )

    var addrs: seq[MultiAddress]
    for i in 0 ..< MaxDialCandidates:
      addrs.add(ma("/memorytransport/addr-" & $i))
    addrs.add(ma("/dnsaddr/stalls.example"))

    expect DialFailedError:
      await dialer.connect(randomPeerId(), addrs).wait(1.seconds)

    check resolver.cancelled

  asyncTest "Ranked dialing dials each address one time":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let wire = ma("/ip4/1.2.3.4/tcp/443")
    let resolver = MockResolver.new()
    resolver.txtResponses["_dnsaddr.good.example"] = @["dnsaddr=" & $wire]

    let
      transport = FailingDialTransport.new(Upgrade(), rng(), handlesAny = true)
      dialer = Dialer.new(
        src.peerInfo.peerId,
        src.connManager,
        src.peerStore,
        @[Transport(transport)],
        src.ms,
        resolver,
        dialRanking = true,
      )

    let name = ma("/dnsaddr/good.example")
    expect DialFailedError:
      await dialer.connect(randomPeerId(), @[wire, wire, name]).wait(5.seconds)

    check transport.dialedAddrs == @[wire]

  asyncTest "Ranked dialing carries the hostname of a wire address":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng(), handlesAny = true)
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      dialRanking = true,
    )

    let wss = ma("/ip4/1.2.3.4/tcp/443/wss")
    expect DialFailedError:
      await dialer.connect(randomPeerId(), @[wss])

    check transport.dialedHosts == @["1.2.3.4"]

  test "Dial ranks put direct before relay, and QUIC before TCP within each":
    check rankOf(ma("/ip4/1.2.3.4/udp/4001/quic-v1")) == DialRank.DirectQuic
    check rankOf(ma("/ip4/1.2.3.4/udp/4001/quic")) == DialRank.DirectQuic
    check rankOf(ma("/ip4/1.2.3.4/tcp/4001")) == DialRank.Direct
    check rankOf(ma("/ip4/1.2.3.4/tcp/4002/ws")) == DialRank.Direct
    check rankOf(relayAddr("/ip4/5.6.7.8/udp/4001/quic-v1")) == DialRank.RelayQuic
    check rankOf(relayAddr("/ip4/5.6.7.8/tcp/4001")) == DialRank.Relay

  asyncTest "Ranked dialing opens the attempts in rank order":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let
      transport = FailingDialTransport.new(Upgrade(), rng(), handlesAny = true)
      dialer = src.makeRankedDialer(@[Transport(transport)])
      relayTcp = relayAddr("/ip4/5.6.7.8/tcp/4001")
      tcp = ma("/ip4/1.2.3.4/tcp/4001")
      ws = ma("/ip4/1.2.3.4/tcp/4002/ws")
      relayQuic = relayAddr("/ip4/5.6.7.8/udp/4001/quic-v1")
      quic = ma("/ip4/1.2.3.4/udp/4001/quic-v1")
    expect DialFailedError:
      await dialer.connect(randomPeerId(), @[relayTcp, tcp, ws, relayQuic, quic])

    check transport.dialedAddrs == @[quic, tcp, ws, relayQuic, relayTcp]

  asyncTest "Ranked dialing fills its parallel limit with the best ranked candidates":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let
      tcps = makeTcpAddrs(MaxParallelDials)
      quic = ma("/ip4/1.2.3.4/udp/4001/quic-v1")
      transport = ScriptedDialTransport.new(Upgrade(), rng(), handled = tcps & @[quic])
      dialer = src.makeRankedDialer(@[Transport(transport)])
      dialing = dialer.connect(randomPeerId(), tcps & @[quic])

    checkUntilTimeout:
      transport.dialedAddrs.len == MaxParallelDials
    await dialing.cancelAndWait()

    check transport.dialedAddrs == @[quic] & tcps[0 ..< MaxParallelDials - 1]
    check transport.cancelledAddrs.len == MaxParallelDials

  asyncTest "Ranked dialing gives a failed attempt's slot to the next candidate":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let
      tcps = makeTcpAddrs(MaxParallelDials)
      quic = ma("/ip4/1.2.3.4/udp/4001/quic-v1")
      transport = ScriptedDialTransport.new(
        Upgrade(), rng(), handled = tcps & @[quic], failing = @[quic]
      )
      dialer = src.makeRankedDialer(@[Transport(transport)])
      dialing = dialer.connect(randomPeerId(), tcps & @[quic])
    defer:
      await dialing.cancelAndWait()

    checkUntilTimeout:
      transport.dialedAddrs == @[quic] & tcps

  asyncTest "Ranked dialing cancels a stalled QUIC attempt once TCP connects":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    let
      quic = ma("/ip4/127.0.0.1/udp/1/quic-v1")
      stalling = ScriptedDialTransport.new(Upgrade(), rng(), handled = @[quic])
      dialer = src.makeRankedDialer(@[Transport(stalling)] & src.transports)

    await dialer.connect(dst.peerInfo.peerId, @[quic] & dst.peerInfo.addrs).wait(
      5.seconds
    )

    check src.connManager.connCount(dst.peerInfo.peerId) == 1
    check stalling.dialedAddrs == @[quic]
    check stalling.cancelledAddrs == @[quic]

  asyncTest "Dialing skips an address that fails to resolve":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let resolver = MockResolver.new()
    resolver.txtResponses["_dnsaddr.bad.example"] = @["dnsaddr=/not/a/multiaddress"]

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      resolver,
    )

    let
      unresolvable = ma("/dnsaddr/bad.example")
      handled = ma("/memorytransport/addr-0")

    expect DialFailedError:
      await dialer.connect(randomPeerId(), @[unresolvable, handled])

    check transport.dialedAddrs == @[handled]

  asyncTest "An address that failed is skipped while it is on backoff":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      dialBackoff = Opt.some(
        DialBackoffConfig(tolerance: 0, base: 1.minutes, factor: 2, maxDelay: 1.minutes)
      ),
    )

    let address = MultiAddress.init("/memorytransport/addr-0").tryGet()

    # no peer id, so only the address backoff can stop the second dial
    expect DialFailedError:
      discard await dialer.connect(address, allowUnknownPeerId = true)
    check transport.dialedAddrs.len == 1

    expect DialFailedError:
      discard await dialer.connect(address, allowUnknownPeerId = true)
    check transport.dialedAddrs.len == 1

  asyncTest "An address that failed for one peer is still dialed for another":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      dialBackoff = Opt.some(
        DialBackoffConfig(tolerance: 0, base: 1.minutes, factor: 2, maxDelay: 1.minutes)
      ),
    )

    let addrs = @[MultiAddress.init("/memorytransport/addr-0").tryGet()]
    expect DialFailedError:
      await dialer.connect(randomPeerId(), addrs)
    check transport.dialedAddrs.len == 1

    expect DialFailedError:
      await dialer.connect(randomPeerId(), addrs)
    check transport.dialedAddrs.len == 2

  asyncTest "A dial that every address backoff skipped does not fail the peer":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      dialBackoff = Opt.some(
        DialBackoffConfig(tolerance: 0, base: 1.minutes, factor: 2, maxDelay: 1.minutes)
      ),
    )

    let
      peerId = randomPeerId()
      addrs = @[MultiAddress.init("/memorytransport/addr-0").tryGet()]

    # tryDial backs the address off without ever failing the peer
    expect DialFailedError:
      discard await dialer.tryDial(peerId, addrs)
    check transport.dialedAddrs.len == 1

    expect DialFailedError:
      await dialer.connect(peerId, addrs)
    check transport.dialedAddrs.len == 1

    let fresh = @[MultiAddress.init("/memorytransport/addr-1").tryGet()]
    expect DialFailedError:
      await dialer.connect(peerId, fresh)
    check transport.dialedAddrs.len == 2

  asyncTest "A peer whose addresses all failed is not dialed again while it is on backoff":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
      dialBackoff = Opt.some(
        DialBackoffConfig(tolerance: 0, base: 1.minutes, factor: 2, maxDelay: 1.minutes)
      ),
    )

    let
      peerId = randomPeerId()
      addrs = @[MultiAddress.init("/memorytransport/addr-0").tryGet()]

    expect DialFailedError:
      await dialer.connect(peerId, addrs)
    check transport.dialedAddrs.len == 1

    let fresh = @[MultiAddress.init("/memorytransport/addr-1").tryGet()]
    expect DialFailedError:
      await dialer.connect(peerId, fresh)
    check transport.dialedAddrs.len == 1

    expect DialFailedError:
      await dialer.connect(peerId, fresh, forceDial = true)
    check transport.dialedAddrs.len == 2

  asyncTest "A switch that opted into backoffs still dials a reachable peer":
    let
      src = makeStandardSwitchBuilder().withDialBackoff().build()
      dst = makeStandardSwitch()
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)
    await src.disconnect(dst.peerInfo.peerId)
    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)

    check src.connManager.connCount(dst.peerInfo.peerId) == 1

  asyncTest "Cancelling a dial at any point leaves nothing open":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    let dialer = Dialer.new(
      src.peerInfo.peerId, src.connManager, src.peerStore, src.transports, src.ms
    )

    const CancelSteps = 30
      ## Longer than the transport walk: the upgrade parks on awaits of its own.

    var cancelledDials = 0
    for steps in 0 .. CancelSteps:
      let dialFut =
        dialer.dialAndUpgrade(Opt.some(dst.peerInfo.peerId), dst.peerInfo.addrs)
      for _ in 0 ..< steps:
        await sleepAsync(0.milliseconds)

      await dialFut.cancelAndWait()

      if dialFut.completed():
        let muxed = dialFut.value()
        if not muxed.isNil():
          await muxed.close()
      elif dialFut.cancelled():
        cancelledDials.inc()

    check cancelledDials > 0

  asyncTest "A remote that never answers identify gives up at the dial timeout":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    dst.stallIdentify()
    defer:
      await allFutures(src.stop(), dst.stop())

    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      dialTimeout = 1.seconds,
    )

    # Twice: the second dial only gets its turn if the first freed the peer's
    # dial lock, which identify holds for as long as the connection lives.
    for _ in 0 .. 1:
      expect DialFailedError:
        await dialer
          .connect(
            dst.peerInfo.peerId,
            dst.peerInfo.addrs,
            forceDial = true,
            reuseConnection = false,
          )
          .wait(10.seconds)

  asyncTest "A remote that never closes the identify stream frees the dial":
    let
      src = makeStandardSwitch(TcpAutoAddress)
      dst = makeStandardSwitch(TcpAutoAddress)
    await src.start()
    await dst.start()
    dst.stallAfterIdentify()
    defer:
      await allFutures(src.stop(), dst.stop())

    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      src.transports,
      src.ms,
      dialTimeout = 1.seconds,
    )

    # Twice: the second dial gets its turn only if the first freed the lock.
    for _ in 0 .. 1:
      let dial = dialer.connect(
        dst.peerInfo.peerId,
        dst.peerInfo.addrs,
        forceDial = true,
        reuseConnection = false,
      )
      # `join`, not `wait`: a cancel waits out a dial parked in `noCancel`.
      if not await dial.join().withTimeout(IdentifyCloseTimeout * 2):
        fail()
        return
      await dial

  asyncTest "Cancelled negotiation resets its stream":
    let (stream, remote) = bridgedConnections()
    let dialer = Dialer.new(default(PeerId), nil, nil, @[], MultistreamSelect.new())
    let negotiation = dialer.negotiateStream(stream, @["/test/1.0.0"])
    defer:
      await stream.close()
      await remote.close()
    discard await remote.readLp(1024)
    discard await remote.readLp(1024)
    await negotiation.cancelAndWait()
    check stream.wasResetLocally

  asyncTest "Malformed negotiation resets its stream":
    let (stream, remote) = bridgedConnections()
    let dialer = Dialer.new(default(PeerId), nil, nil, @[], MultistreamSelect.new())
    let negotiation = dialer.negotiateStream(stream, @["/test/1.0.0"])
    defer:
      await stream.close()
      await remote.close()
    discard await remote.readLp(1024)
    discard await remote.readLp(1024)
    await remote.writeLp("bad handshake")
    expect MultiStreamError:
      discard await negotiation
    check stream.wasResetLocally

  asyncTest "tryDial raises DialFailedError when every dial fails":
    let src = makeStandardSwitch()
    await src.start()
    defer:
      await src.stop()

    let transport = FailingDialTransport.new(Upgrade(), rng())
    let dialer = Dialer.new(
      src.peerInfo.peerId,
      src.connManager,
      src.peerStore,
      @[Transport(transport)],
      src.ms,
    )

    expect DialFailedError:
      discard await dialer.tryDial(randomPeerId(), @[MemoryAutoAddress()])

suite "MuxedUpgrade":
  asyncTest "upgrade raises UpgradeFailedError without secure managers":
    let (conn, remote) = bridgedConnections()
    defer:
      await conn.close()
      await remote.close()
    let upgrader = MuxedUpgrade.new(@[], [], MultistreamSelect.new())

    expect UpgradeFailedError:
      discard await upgrader.upgrade(conn, Opt.none(PeerId))

  asyncTest "tryUpgrade returns the secure negotiation failure":
    let (conn, remote) = bridgedConnections(dirA = Direction.Out)
    defer:
      await conn.close()
      await remote.close()
    let upgrader = MuxedUpgrade.new(
      @[], [Secure(codecs: @["/test/secure"])], MultistreamSelect.new()
    )
    let upgrading = upgrader.tryUpgrade(conn, Opt.none(PeerId))

    discard await remote.readLp(1024)
    discard await remote.readLp(1024)
    await remote.writeLp("bad handshake\n")
    let res = await upgrading.wait(1.seconds)
    check res.error == $MultiStreamFailure.HandshakeFailed
