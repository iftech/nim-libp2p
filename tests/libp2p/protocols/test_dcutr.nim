# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import stew/byteutils
import ../../../libp2p/protocols/connectivity/dcutr/core as dcore
import ../../../libp2p/protocols/connectivity/dcutr/[client, server]
from ../../../libp2p/protocols/connectivity/autonat/types import NetworkReachability
import ../../../libp2p/connmanager
import ../../../libp2p/[builders, utils/future]
import ../../stubs/switchstub
import ../../tools/[unittest, switch_builder, multiaddress]

proc makeSwitch(address: MultiAddress = TcpAutoAddress): Switch =
  return makeStandardSwitch(address)

proc waitDirectConnIdentified(
    clientSwitch: Switch, serverPeerId: PeerId
): Future[void].Raising([CancelledError]) =
  # Completes once the direct (second) connection to `serverPeerId` has been
  # fully identified. The inbound upgrade bumps connCount before opening the
  # identify stream, so waiting on connCount alone tears the switch down while
  # that identify LPChannel is still being opened, leaking it on slow runners.
  let identified =
    Future[void].Raising([CancelledError]).init("dcutr direct connection identified")

  proc onIdentified(
      peerId: PeerId, event: PeerEvent
  ): Future[void] {.async: (raises: [CancelledError]).} =
    if peerId == serverPeerId and clientSwitch.connManager.connCount(serverPeerId) == 2:
      identified.completeOnce()

  clientSwitch.connManager.addPeerEventHandler(onIdentified, PeerEventKind.Identified)
  identified

suite "Dcutr":
  teardown:
    checkTrackers()

  asyncTest "Connect msg Encode / Decode":
    const pbHexReference = "08641208040000000006000012080400000000060000"

    let addrs = @[TcpWildcardAddress, TcpWildcardAddress]
    let connectMsg = DcutrMsg(msgType: MsgType.Connect, addrs: addrs)

    let pb = connectMsg.encode()
    let connectMsgDecoded = DcutrMsg.decode(pb).valueOr:
      raise newException(DcutrError, "Failed to decode a Connect message.")

    check connectMsg == connectMsgDecoded
    check pb == hexToSeqByte(pbHexReference)

  asyncTest "Sync msg Encode / Decode":
    const pbHexReference = "08ac021208040000000006000012080400000000060000"

    let addrs = @[TcpWildcardAddress, TcpWildcardAddress]
    let syncMsg = DcutrMsg(msgType: MsgType.Sync, addrs: addrs)

    let pb = syncMsg.encode()
    let syncMsgDecoded = DcutrMsg.decode(pb).valueOr:
      raise newException(DcutrError, "Failed to decode a Sync message.")

    check syncMsg == syncMsgDecoded
    check pb == hexToSeqByte(pbHexReference)

  asyncTest "DCUtR establishes a new connection":
    let behindNATSwitch = makeSwitch()
    let publicSwitch = makeSwitch()

    let dcutrProto = Dcutr.new(publicSwitch)
    publicSwitch.mount(dcutrProto)

    let directConnIdentified =
      waitDirectConnIdentified(behindNATSwitch, publicSwitch.peerInfo.peerId)

    await allFutures(behindNATSwitch.start(), publicSwitch.start())
    defer:
      await allFutures(behindNATSwitch.stop(), publicSwitch.stop())

    await publicSwitch.connect(
      behindNATSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
    )

    for t in behindNATSwitch.transports:
      t.networkReachability = NetworkReachability.NotReachable

    expect AsyncTimeoutError:
      # we can't hole punch when both peers are in the same machine. This means that the simultaneous dialings will result
      # in two connections attemps, instead of one. This dial is going to fail because the dcutr client is acting as the
      # tcp simultaneous incoming upgrader in the dialer which works only in the simultaneous open case.
      await DcutrClient
        .new()
        .startSync(
          behindNATSwitch, publicSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
        )
        .wait(300.millis)

    # we still expect a new connection to be open by the receiver peer acting as
    # the dcutr server; wait until it is identified so teardown doesn't race the
    # inbound identify stream
    check await directConnIdentified.withTimeout(30.seconds)

  asyncTest "DCUtR QUIC initiator uses listener role":
    let behindNATSwitch = makeSwitch(QuicAutoAddress)
    let publicSwitch = makeSwitch(QuicAutoAddress)

    let dcutrProto = Dcutr.new(publicSwitch)
    publicSwitch.mount(dcutrProto)

    await allFutures(behindNATSwitch.start(), publicSwitch.start())
    defer:
      await allFutures(behindNATSwitch.stop(), publicSwitch.stop())

    await publicSwitch.connect(
      behindNATSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
    )
    let initialConnCount =
      behindNATSwitch.connManager.connCount(publicSwitch.peerInfo.peerId)
    check initialConnCount == 1

    for t in behindNATSwitch.transports:
      t.networkReachability = NetworkReachability.NotReachable

    # A direct QUIC connection stands in for the relay, so the listener-role
    # hole punch must time out.
    let synced = await DcutrClient.new(connectTimeout = 300.millis).tryStartSync(
      behindNATSwitch, publicSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
    )
    check synced.isParentErrOf(AsyncTimeoutError)

  template ductrClientTest(
      behindNATSwitch: Switch, publicSwitch: Switch, body: untyped
  ) =
    let dcutrProto = Dcutr.new(publicSwitch)
    publicSwitch.mount(dcutrProto)

    let directConnIdentified =
      waitDirectConnIdentified(behindNATSwitch, publicSwitch.peerInfo.peerId)

    await allFutures(behindNATSwitch.start(), publicSwitch.start())
    defer:
      await allFutures(behindNATSwitch.stop(), publicSwitch.stop())

    await publicSwitch.connect(
      behindNATSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
    )

    for t in behindNATSwitch.transports:
      t.networkReachability = NetworkReachability.NotReachable

    body

    # we still expect a new connection to be open by the receiver peer acting as
    # the dcutr server; wait until it is identified so teardown doesn't race the
    # inbound identify stream
    check await directConnIdentified.withTimeout(30.seconds)

  asyncTest "Client connect timeout":
    proc connectTimeoutProc(
        self: SwitchStub,
        peerId: PeerId,
        addrs: seq[MultiAddress],
        forceDial = false,
        reuseConnection = true,
        dir = Direction.Out,
    ): Future[void] {.async: (raises: [DialFailedError, CancelledError]).} =
      await sleepAsync(50.millis)

    let behindNATSwitch = SwitchStub.new(makeSwitch(), connectTimeoutProc)
    let publicSwitch = makeSwitch()
    ductrClientTest(behindNATSwitch, publicSwitch):
      let synced = await DcutrClient.new(connectTimeout = 5.millis).tryStartSync(
        behindNATSwitch, publicSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
      )
      check synced.isParentErrOf(AsyncTimeoutError)

  asyncTest "All client connect attempts fail":
    proc connectErrorProc(
        self: SwitchStub,
        peerId: PeerId,
        addrs: seq[MultiAddress],
        forceDial = false,
        reuseConnection = true,
        dir = Direction.Out,
    ): Future[void] {.async: (raises: [DialFailedError, CancelledError]).} =
      raise newException(DialFailedError, "error")

    let behindNATSwitch = SwitchStub.new(makeSwitch(), connectErrorProc)
    let publicSwitch = makeSwitch()
    ductrClientTest(behindNATSwitch, publicSwitch):
      let synced = await DcutrClient.new(connectTimeout = 5.millis).tryStartSync(
        behindNATSwitch, publicSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
      )
      check synced.isParentErrOf(AllFuturesFailedError)

  proc ductrServerTest(connectStub: connectStubType) {.async.} =
    let behindNATSwitch = makeSwitch()
    let publicSwitch = SwitchStub.new(makeSwitch())

    let dcutrProto = Dcutr.new(publicSwitch, connectTimeout = 5.millis)
    publicSwitch.mount(dcutrProto)

    await allFutures(behindNATSwitch.start(), publicSwitch.start())
    defer:
      await allFutures(behindNATSwitch.stop(), publicSwitch.stop())

    await publicSwitch.connect(
      behindNATSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
    )

    publicSwitch.connectStub = connectStub

    for t in behindNATSwitch.transports:
      t.networkReachability = NetworkReachability.NotReachable

    expect AsyncTimeoutError:
      # we can't hole punch when both peers are in the same machine. This means that the simultaneous dialings will result
      # in two connections attemps, instead of one. This dial is going to fail because the dcutr client is acting as the
      # tcp simultaneous incoming upgrader in the dialer which works only in the simultaneous open case.
      await DcutrClient
        .new()
        .startSync(
          behindNATSwitch, publicSwitch.peerInfo.peerId, behindNATSwitch.peerInfo.addrs
        )
        .wait(300.millis)

    checkUntilTimeout:
      # we still expect a new connection to be open by the receiver peer acting as the dcutr server
      behindNATSwitch.connManager.connCount(publicSwitch.peerInfo.peerId) == 1

  asyncTest "DCUtR server timeout when establishing a new connection":
    proc connectProc(
        self: SwitchStub,
        peerId: PeerId,
        addrs: seq[MultiAddress],
        forceDial = false,
        reuseConnection = true,
        dir = Direction.Out,
    ): Future[void] {.async: (raises: [DialFailedError, CancelledError]).} =
      await sleepAsync(50.millis)

    await ductrServerTest(connectProc)

  asyncTest "DCUtR server error when establishing a new connection":
    proc connectProc(
        self: SwitchStub,
        peerId: PeerId,
        addrs: seq[MultiAddress],
        forceDial = false,
        reuseConnection = true,
        dir = Direction.Out,
    ): Future[void] {.async: (raises: [DialFailedError, CancelledError]).} =
      raise newException(DialFailedError, "error")

    await ductrServerTest(connectProc)

  test "should return valid TCP and QUIC-v1 addresses only":
    let testAddrs = @[
      ma("/ip4/192.0.2.1/tcp/1234"),
      MultiAddress
        .init(
          "/ip4/203.0.113.5/tcp/5678/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
        )
        .tryGet(),
      ma("/ip6/::1/tcp/9012"),
      MultiAddress
        .init(
          "/dns4/example.com/tcp/3456/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
        )
        .tryGet(),
      ma("/ip4/192.0.2.2/udp/3456/quic-v1"),
      MultiAddress
        .init(
          "/ip4/203.0.113.6/udp/4567/quic-v1/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
        )
        .tryGet(),
      MultiAddress
        .init(
          "/dns4/example.org/udp/5678/quic-v1/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
        )
        .tryGet(),
      ma("/ip4/198.51.100.42/udp/7890"),
      ma("/ip4/198.51.100.43/udp/7890/quic"),
    ]

    let expected = @[
      ma("/ip4/192.0.2.1/tcp/1234"),
      ma("/ip4/203.0.113.5/tcp/5678"),
      ma("/ip6/::1/tcp/9012"),
      ma("/dns4/example.com/tcp/3456"),
      ma("/ip4/192.0.2.2/udp/3456/quic-v1"),
      ma("/ip4/203.0.113.6/udp/4567/quic-v1"),
      ma("/dns4/example.org/udp/5678/quic-v1"),
    ]

    let res = getHolePunchableAddrs(testAddrs)

    check res == expected
