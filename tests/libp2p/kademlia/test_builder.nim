# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, std/sequtils
import ../../../libp2p/[switch, builders]
import ../../../libp2p/protocols/kademlia
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

proc mountedKad(switch: Switch): Opt[KadDHT] =
  for handler in switch.ms.handlers:
    if KadCodec in handler.protos:
      return Opt.some(KadDHT(handler.protocol))
  Opt.none(KadDHT)

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
