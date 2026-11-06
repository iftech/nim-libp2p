# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos
import ../../libp2p/[nameresolving/nameresolver, peerid]
import ../tools/[unittest, multiaddress, resolver]

type CountingResolver = ref object of MockResolver
  txtQueries, ipQueries: seq[string]

method resolveTxt*(
    self: CountingResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]).} =
  self.txtQueries.add(address)
  await procCall MockResolver(self).resolveTxt(address)

method resolveIp*(
    self: CountingResolver,
    address: string,
    port: Port,
    domain: Domain = Domain.AF_UNSPEC,
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError])
.} =
  self.ipQueries.add(address)
  await procCall MockResolver(self).resolveIp(address, port, domain)

suite "Multiaddress resolution":
  teardown:
    checkTrackers()

  asyncTest "replace individual DNS components without requiring a port":
    let resolver = CountingResolver()
    resolver.ipResponses[("a.test", false)] = @["192.0.2.1"]
    resolver.ipResponses[("b.test", true)] = @["2001:db8::1"]
    let cases = @[
      ("/dns4/a.test", "/ip4/192.0.2.1"),
      ("/dns6/b.test", "/ip6/2001:db8::1"),
      ("/p2p-circuit/dns4/a.test/tcp/4001", "/p2p-circuit/ip4/192.0.2.1/tcp/4001"),
      ("/dns4/a.test/dns6/b.test/tcp/4001", "/ip4/192.0.2.1/ip6/2001:db8::1/tcp/4001"),
    ]
    for (input, output) in cases:
      check (await resolver.resolveMAddress(ma(input))) == @[ma(output)]

  test "find DNS and the hostname beyond an IP or relay prefix":
    let address = ma("/ip4/192.0.2.1/tcp/4001/p2p-circuit/dns4/target.test/tcp/443/ws")
    check:
      address.containsDnsComponent()
      address.getHostname() == "target.test"
      ma("/p2p-circuit/dnsaddr/peers.test").getHostname() == "peers.test"
      not ma("/ip6/::1/tcp/4001").containsDnsComponent()
      ma("/p2p-circuit").getHostname() == ""

  asyncTest "DNSADDR matches the whole suffix and skips malformed and duplicate records":
    const peer = "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
    let resolver = CountingResolver()
    let good = "/ip4/192.0.2.1/tcp/4001/p2p/" & peer
    resolver.txtResponses["_dnsaddr.peers.test"] =
      newSeqWith(MaxDnsaddrRecords, "dnsaddr=/ip4/192.0.2.2/tcp/4002/p2p/" & peer) &
      @[
        "unrelated",
        "dnsaddr=",
        "dnsaddr=invalid",
        "dnsaddr=/ip4/192.0.2.2/tcp/4002/p2p/" & peer,
        "dnsaddr=/ip4/192.0.2.3/tcp/4001",
        "dnsaddr=" & good,
        "dnsaddr=" & good,
      ]
    check (
      await resolver.resolveMAddress(
        ma("/p2p-circuit/dnsaddr/peers.test/tcp/4001/p2p/" & peer)
      )
    ) == @[ma("/p2p-circuit" & good)]

  asyncTest "DNSADDR-only expansion preserves names for subsequent hostname extraction":
    let resolver = CountingResolver()
    resolver.txtResponses["_dnsaddr.peers.test"] =
      @["dnsaddr=/dns4/target.test/tcp/443/ws"]
    resolver.ipResponses[("target.test", false)] = @["192.0.2.1"]
    let address = ma("/p2p-circuit/dnsaddr/peers.test")
    check (await resolver.resolveDnsAddr(address)) ==
      @[ma("/p2p-circuit/dns4/target.test/tcp/443/ws")]
    check resolver.ipQueries.len == 0
    check (await resolver.resolveMAddress(address)) ==
      @[ma("/p2p-circuit/ip4/192.0.2.1/tcp/443/ws")]

  asyncTest "cycles and repeated branches do not consume the budget or hide valid siblings":
    let resolver = CountingResolver()
    resolver.txtResponses["_dnsaddr.a.test"] = @[
      "dnsaddr=/dnsaddr/a.test", "dnsaddr=/dnsaddr/b.test", "dnsaddr=/dnsaddr/b.test",
      "dnsaddr=/ip4/192.0.2.2/tcp/4001",
    ]
    resolver.txtResponses["_dnsaddr.b.test"] =
      @["dnsaddr=/dnsaddr/a.test", "dnsaddr=/ip4/192.0.2.1/tcp/4001"]
    check (await resolver.resolveMAddress(ma("/dnsaddr/a.test"))) ==
      @[ma("/ip4/192.0.2.1/tcp/4001"), ma("/ip4/192.0.2.2/tcp/4001")]
    check resolver.txtQueries == @["_dnsaddr.a.test", "_dnsaddr.b.test"]

  asyncTest "a shorter path can resolve an address first reached at the depth limit":
    let resolver = CountingResolver()
    resolver.txtResponses["_dnsaddr.root.test"] =
      @["dnsaddr=/dnsaddr/a.test", "dnsaddr=/dnsaddr/shared.test"]
    resolver.txtResponses["_dnsaddr.a.test"] = @["dnsaddr=/dnsaddr/b.test"]
    resolver.txtResponses["_dnsaddr.b.test"] = @["dnsaddr=/dnsaddr/shared.test"]
    resolver.txtResponses["_dnsaddr.shared.test"] = @["dnsaddr=/dnsaddr/end.test"]
    resolver.txtResponses["_dnsaddr.end.test"] = @["dnsaddr=/ip4/192.0.2.1"]
    check (await resolver.resolveMAddress(ma("/dnsaddr/root.test"))) ==
      @[ma("/ip4/192.0.2.1")]

  asyncTest "DNSADDR recursion stops before another query":
    let resolver = CountingResolver()
    for i in 0 .. MaxDnsaddrRecursion:
      resolver.txtResponses["_dnsaddr.level" & $i & ".test"] =
        @["dnsaddr=/dnsaddr/level" & $(i + 1) & ".test"]
    check (await resolver.resolveDnsAddr(ma("/dnsaddr/level0.test"))).len == 0
    check resolver.txtQueries.len == MaxDnsaddrRecursion

  asyncTest "sibling branches share the lookup budget":
    let resolver = CountingResolver()
    for i in 0 ..< MaxDnsaddrRecords:
      let host = "branch" & $i & ".test"
      resolver.txtResponses.mgetOrPut("_dnsaddr.root.test", @[]).add(
        "dnsaddr=/dns4/" & host & "/dns4/end.test"
      )
      resolver.ipResponses[(host, false)] = @["192.0.2." & $(i + 1)]
    resolver.ipResponses[("end.test", false)] = @["198.51.100.1"]
    let addresses = await resolver.resolveMAddress(ma("/dnsaddr/root.test"))
    check addresses.len == (MaxDnsLookups - 1) div 2
    check resolver.txtQueries.len + resolver.ipQueries.len == MaxDnsLookups

  asyncTest "irrelevant TXT records do not consume the matching-record budget":
    let resolver = CountingResolver()
    resolver.txtResponses["_dnsaddr.root.test"] =
      (0 ..< MaxDnsaddrRecords).mapIt("irrelevant " & $it)
    resolver.txtResponses["_dnsaddr.root.test"].add("dnsaddr=/ip4/192.0.2.1")
    check (await resolver.resolveDnsAddr(ma("/dnsaddr/root.test"))) ==
      @[ma("/ip4/192.0.2.1")]
    resolver.txtResponses["_dnsaddr.root.test"] =
      (1 .. MaxDnsaddrRecords + 1).mapIt("dnsaddr=/ip4/192.0.2." & $it)
    check (await resolver.resolveDnsAddr(ma("/dnsaddr/root.test"))).len ==
      MaxDnsaddrRecords

  asyncTest "expected peers prune branches before budgets and allow peerless children":
    let peer = PeerId.init("QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN").tryGet()
    let other = PeerId.init("QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa").tryGet()
    let resolver = CountingResolver()
    resolver.txtResponses["_dnsaddr.root.test"] = (0 ..< MaxDnsaddrRecords + 1).mapIt(
      "dnsaddr=/dnsaddr/other" & $it & ".test/p2p/" & $other
    )
    resolver.txtResponses["_dnsaddr.root.test"].add(
      "dnsaddr=/dnsaddr/child.test/p2p/" & $peer
    )
    resolver.txtResponses["_dnsaddr.child.test"] = @["dnsaddr=/ip4/192.0.2.1/tcp/4001"]
    check (
      await resolver.resolveDnsAddr(ma("/dnsaddr/root.test"), peerId = Opt.some(peer))
    ) == @[ma("/ip4/192.0.2.1/tcp/4001")]
    check resolver.txtQueries == @["_dnsaddr.root.test", "_dnsaddr.child.test"]

  asyncTest "output limit is shared across branches and stops further lookups":
    let resolver = CountingResolver()
    resolver.txtResponses["_dnsaddr.root.test"] =
      @["dnsaddr=/dns4/a.test", "dnsaddr=/dns4/b.test", "dnsaddr=/dns4/unused.test"]
    resolver.ipResponses[("a.test", false)] = (1 .. 60).mapIt("192.0.2." & $it)
    resolver.ipResponses[("b.test", false)] = (61 .. 120).mapIt("192.0.2." & $it)
    let addresses = await resolver.resolveMAddress(ma("/dnsaddr/root.test"))
    check addresses == (1 .. MaxResolvedAddresses).mapIt(ma("/ip4/192.0.2." & $it))
    check resolver.ipQueries == @["a.test", "b.test"]

  asyncTest "IP responses are bounded and duplicate outputs are removed":
    let resolver = CountingResolver()
    resolver.ipResponses[("a.test", false)] =
      newSeqWith(MaxResolvedAddresses, "192.0.2.1")
    resolver.ipResponses[("a.test", false)].add("192.0.2.2")
    check (await resolver.resolveMAddress(ma("/dns4/a.test"))) == @[
      ma("/ip4/192.0.2.1")
    ]

  asyncTest "cancellation propagates through nested DNSADDR lookups":
    let resolver = StallingResolver.new()
    resolver.txtResponses["_dnsaddr.root.test"] = @["dnsaddr=/dnsaddr/stalls.test"]
    let lookup = resolver.resolveMAddress(ma("/dnsaddr/root.test"))
    await lookup.cancelAndWait()
    check resolver.cancelled
