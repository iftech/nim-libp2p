# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/sequtils
import ../../../libp2p/[switch, builders, address_manager]
import ../../../libp2p/protocols/kademlia
import ../../../libp2p/services/[natservice, reachabilityobservers]
import ../../tools/[unittest, crypto, multiaddress, switch_builder]
import ./utils.nim

proc buildKadSwitch(mode: KadMode): Switch {.raises: [LPError].} =
  makeStandardSwitchBuilder(TcpAutoAddress).withKademlia(mode = mode).build()

proc buildAutoKadSwitch(): Switch {.raises: [LPError].} =
  ## Auto mode plus the AutoNAT v1 probing that drives it.
  makeStandardSwitchBuilder(TcpAutoAddress)
    .withAutonat()
    .withNAT(autonatConfig(AutonatV1, Opt.some(1.seconds)))
    .withKademlia(mode = KadMode.Auto)
    .build()

proc buildAutonatPeer(): Switch {.raises: [LPError].} =
  ## Answers the dial-back probes of `buildAutoKadSwitch`.
  makeStandardSwitchBuilder(TcpAutoAddress).withAutonat().build()

proc buildV2KadSwitch(mode: KadMode): Switch {.raises: [LPError].} =
  makeStandardSwitchBuilder(TcpAutoAddress)
    .withNAT(autonatConfig(AutonatV2))
    .withKademlia(mode = mode)
    .build()

type FixedVerdictVerifier = ref object of Verifier
  state: AddrState

method verify(
    self: FixedVerdictVerifier, address: MultiAddress
): Future[Opt[AddrState]] {.async: (raises: [CancelledError]).} =
  Opt.some(self.state)

proc mountedKad(switch: Switch): Opt[KadDHT] =
  for handler in switch.ms.handlers:
    if KadCodec in handler.protos:
      return Opt.some(KadDHT(handler.protocol))
  Opt.none(KadDHT)

const reachabilitySteps = [
  (AddrState.Confirmed, NetworkReachability.Reachable),
  (AddrState.Unverified, NetworkReachability.Unknown),
  (AddrState.Unreachable, NetworkReachability.NotReachable),
  (AddrState.Confirmed, NetworkReachability.Reachable),
]

proc checkModeFollowsSteps(
    mode: KadMode, subscribers: int, serverAfterStep: array[4, bool]
) {.async.} =
  ## Walks `reachabilitySteps` and checks `isServer` after each one.
  let node = buildV2KadSwitch(mode)
  let kad = node.mountedKad().get()
  let nat = node.natService().get()
  let verifier = FixedVerdictVerifier()

  await node.start()
  defer:
    await node.stop()

  check nat.autonatV2Service().get().reachabilityObservers.len() == subscribers

  for i, (state, reachability) in reachabilitySteps:
    verifier.state = state
    # Replaces the AutoNAT v2 verifier and restarts the verification heartbeat.
    node.addressManager.verifier = verifier
    checkUntilTimeout:
      nat.networkReachability() == reachability
      kad.isServer == serverAfterStep[i]

suite "KadDHT Switch Builder":
  teardown:
    checkTrackers()

  test "Configured mode sets the initial serving flag":
    check:
      buildKadSwitch(KadMode.Server).mountedKad().get().isServer
      not buildKadSwitch(KadMode.Client).mountedKad().get().isServer
      # Auto serves nothing until autonat proves the node reachable.
      not buildKadSwitch(KadMode.Auto).mountedKad().get().isServer

  asyncTest "Auto mode starts serving once autonat reports the node reachable":
    let node = buildAutoKadSwitch()
    let peers = @[buildAutonatPeer(), buildAutonatPeer(), buildAutonatPeer()]
    let kad = node.mountedKad().get()
    check not kad.isServer

    await allFutures(@[node.start()] & peers.mapIt(it.start()))
    defer:
      await allFutures(@[node.stop()] & peers.mapIt(it.stop()))

    for peer in peers:
      await node.connect(peer)

    checkUntilTimeout:
      kad.isServer

  asyncTest "Kad mode follows reachability changes only in Auto":
    await checkModeFollowsSteps(KadMode.Client, 0, [false, false, false, false])
    await checkModeFollowsSteps(KadMode.Server, 0, [true, true, true, true])
    await checkModeFollowsSteps(KadMode.Auto, 1, [true, true, false, true])

  asyncTest "Build switch with withKademlia":
    var switch1 = makeStandardSwitchBuilder(TcpAutoAddress).withKademlia().build()

    var switch2 = makeStandardSwitchBuilder(TcpAutoAddress)
      .withKademlia(
        bootstrapNodes = @[(switch1.peerInfo.peerId, switch1.peerInfo.addrs)]
      )
      .build()

    await allFutures(switch1.start(), switch2.start())
    defer:
      await allFutures(switch1.stop(), switch2.stop())
    check:
      switch1.ms.handlers.anyIt(KadCodec in it.protos)

  asyncTest "Use Kad as a client only":
    var switch1 = makeStandardSwitchBuilder(TcpAutoAddress).withKademlia().build()
    var switch2 = makeStandardSwitch(TcpAutoAddress)

    let kad2 = KadDHT.new(
      switch2,
      bootstrapNodes = @[(switch1.peerInfo.peerId, switch1.peerInfo.addrs)],
      rng = rng(),
      isServer = false,
    )

    await allFutures(switch1.start(), switch2.start())
    defer:
      await allFutures(switch1.stop(), switch2.stop())

    check (await kad2.putValue(kad2.rtable.selfId, @[1.byte, 2, 3, 4, 5])).isOk()
