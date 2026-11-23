# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    address_manager,
    connmanager,
    multiaddress,
    switch,
    protocols/connectivity/autonatv2/mockclient,
    protocols/connectivity/autonatv2/types,
    protocols/connectivity/autonatv2/verifier,
  ]
import ../../tools/[unittest, futures, crypto, switch_builder, multiaddress]

type
  VerifierClientMock = ref object of AutonatV2ClientMock
    peers: seq[PeerId]
    verdicts: seq[NetworkReachability]
    onDial: proc() {.gcsafe, raises: [].}

  VerifierPair = object
    switch: Switch
    peer: Switch
    client: VerifierClientMock
    verifier: AutonatV2Verifier

method sendDialRequest(
    self: VerifierClientMock, pid: PeerId, testAddrs: seq[MultiAddress]
): Future[AutonatV2Response] {.
    async: (raises: [AutonatV2Error, CancelledError, DialFailedError, LPStreamError])
.} =
  self.peers.add(pid)
  var response =
    await procCall AutonatV2ClientMock(self).sendDialRequest(pid, testAddrs)
  if self.verdicts.len > 0:
    response.reachability = self.verdicts[0]
    self.verdicts.delete(0)
  if self.onDial != nil:
    self.onDial()
  response

proc makePair(
    reachability: NetworkReachability,
    expectedDials = 1,
    negativeQuorum: Positive = DefaultNegativeQuorum,
): VerifierPair {.raises: [LPError].} =
  let
    switch = makeStandardSwitch(ma("/memorytransport/*"))
    client = VerifierClientMock.new(
      AutonatV2Response(
        reachability: reachability,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.Ok),
          addrIdx: Opt.some(0.AddrIdx),
        ),
      ),
      expectedDials = expectedDials,
    )
  VerifierPair(
    switch: switch,
    peer:
      makeStandardSwitchBuilder(ma("/memorytransport/*")).withAutonatV2Server().build(),
    client: client,
    verifier:
      AutonatV2Verifier.new(switch, client, rng(), negativeQuorum = negativeQuorum),
  )

proc start(self: VerifierPair) {.async.} =
  await allFutures(self.switch.start(), self.peer.start())

proc stop(self: VerifierPair) {.async.} =
  await allFutures(self.switch.stop(), self.peer.stop())

proc dialPeer(self: VerifierPair) {.async.} =
  await self.switch.connect(self.peer)

suite "AutonatV2 verifier":
  teardown:
    checkTrackers()

  asyncTest "an address the peer dials back is confirmed":
    let
      pair = makePair(Reachable, expectedDials = 2)
      addresses = @[ma("/ip4/1.2.3.4/tcp/1"), ma("/ip4/5.6.7.8/tcp/1")]

    await pair.start()
    defer:
      await pair.stop()
    await pair.dialPeer()

    check:
      (await pair.verifier.verify(addresses[0])) == AddrState.Confirmed
      (await pair.verifier.verify(addresses[1])) == AddrState.Confirmed

      # one request per address, each carrying that address alone
      pair.client.allTestAddrs == @[@[addresses[0]], @[addresses[1]]]

  asyncTest "a peer which dialed us is not asked":
    let pair = makePair(Reachable)

    await pair.start()
    defer:
      await pair.stop()
    await pair.peer.connect(pair.switch)

    check:
      (await pair.verifier.verify(ma("/ip4/1.2.3.4/tcp/1"))).isNone()
      pair.client.dials == 0

  asyncTest "a peer without the AutoNAT server is not asked":
    let
      pair = makePair(Reachable)
      peerWithoutServer = makeStandardSwitch(ma("/memorytransport/*"))

    await allFutures(pair.start(), peerWithoutServer.start())
    defer:
      await allFutures(pair.stop(), peerWithoutServer.stop())
    await pair.switch.connect(peerWithoutServer)

    check:
      (await pair.verifier.verify(ma("/ip4/1.2.3.4/tcp/1"))).isNone()
      pair.client.dials == 0

  asyncTest "a negative quorum requires three distinct conclusive replies":
    let
      pair = makePair(NotReachable, expectedDials = 12)
      address = ma("/ip4/1.2.3.4/tcp/1")
    let second =
      makeStandardSwitchBuilder(ma("/memorytransport/*")).withAutonatV2Server().build()
    let third =
      makeStandardSwitchBuilder(ma("/memorytransport/*")).withAutonatV2Server().build()
    defer:
      await allFuturesRaising(pair.stop(), second.stop(), third.stop())
    await allFuturesRaising(pair.start(), second.start(), third.start())
    await pair.dialPeer()
    check (await pair.verifier.verify(address)).isNone()
    check pair.client.peers == @[pair.peer.peerInfo.peerId]

    pair.client.peers.setLen(0)
    await pair.switch.connect(second)
    check (await pair.verifier.verify(address)).isNone()
    check:
      pair.client.peers.len == 2
      pair.client.peers[0] != pair.client.peers[1]

    await pair.switch.connect(third)
    for (verdicts, expected) in [
      (@[NotReachable, NotReachable, NotReachable], Opt.some(AddrState.Unreachable)),
      (@[NotReachable, Unknown, NotReachable], Opt.none(AddrState)),
      (@[NotReachable, NotReachable, Reachable], Opt.some(AddrState.Confirmed)),
    ]:
      pair.client.peers.setLen(0)
      pair.client.verdicts = verdicts
      check (await pair.verifier.verify(address)) == expected
      check:
        pair.client.peers.len == 3
        pair.peer.peerInfo.peerId in pair.client.peers
        second.peerInfo.peerId in pair.client.peers
        third.peerInfo.peerId in pair.client.peers
    check:
      pair.client.dials == 12
      pair.client.finished.finished()

  asyncTest "incoming capacity exhausted after a reply stops verification":
    let
      pair = makePair(NotReachable)
      second = makeStandardSwitchBuilder(ma("/memorytransport/*"))
        .withAutonatV2Server()
        .build()
      third = makeStandardSwitchBuilder(ma("/memorytransport/*"))
        .withAutonatV2Server()
        .build()
    var slots: seq[ConnectionSlot]
    defer:
      for slot in slots:
        slot.release()
      await allFuturesRaising(pair.stop(), second.stop(), third.stop())
    await allFuturesRaising(pair.start(), second.start(), third.start())
    await pair.dialPeer()
    await pair.switch.connect(second)
    await pair.switch.connect(third)

    pair.client.onDial = proc() =
      while pair.switch.connManager.availableSlots(In) > 0:
        slots.add(pair.switch.connManager.tryGetIncomingSlot().get())

    check:
      (await pair.verifier.verify(ma("/ip4/1.2.3.4/tcp/1"))).isNone()
      pair.client.dials == 1

  asyncTest "the negative quorum is configurable":
    let
      pair = makePair(NotReachable, expectedDials = 3, negativeQuorum = 2)
      second = makeStandardSwitchBuilder(ma("/memorytransport/*"))
        .withAutonatV2Server()
        .build()
      address = ma("/ip4/1.2.3.4/tcp/1")
    defer:
      await allFuturesRaising(pair.stop(), second.stop())
    await allFuturesRaising(pair.start(), second.start())
    await pair.dialPeer()

    check (await pair.verifier.verify(address)).isNone()
    check pair.client.dials == 1

    pair.client.peers.setLen(0)
    await pair.switch.connect(second)
    check:
      (await pair.verifier.verify(address)) == AddrState.Unreachable
      pair.client.peers.len == 2
      pair.client.peers[0] != pair.client.peers[1]
      pair.client.dials == 3
