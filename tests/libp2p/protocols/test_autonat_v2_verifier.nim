# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    address_manager,
    multiaddress,
    switch,
    protocols/connectivity/autonatv2/mockclient,
    protocols/connectivity/autonatv2/types,
    protocols/connectivity/autonatv2/verifier,
  ]
import ../../tools/[unittest, crypto, switch_builder, multiaddress]

type VerifierPair = object
  switch: Switch
  peer: Switch
  client: AutonatV2ClientMock
  verifier: AutonatV2Verifier

proc makePair(
    reachability: NetworkReachability, expectedDials = 1
): VerifierPair {.raises: [LPError].} =
  let
    switch = makeStandardSwitch(ma("/memorytransport/*"))
    client = AutonatV2ClientMock.new(
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
    peer: makeStandardSwitch(ma("/memorytransport/*")),
    client: client,
    verifier: AutonatV2Verifier.new(switch, client, rng()),
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
      (await pair.verifier.verify(addresses[0])) == Opt.some(AddrState.Confirmed)
      (await pair.verifier.verify(addresses[1])) == Opt.some(AddrState.Confirmed)

      # one request per address, each carrying that address alone
      pair.client.allTestAddrs == @[@[addresses[0]], @[addresses[1]]]

  asyncTest "an address the peer fails to dial is unreachable":
    let
      pair = makePair(NotReachable)
      address = ma("/ip4/1.2.3.4/tcp/1")

    await pair.start()
    defer:
      await pair.stop()
    await pair.dialPeer()

    check (await pair.verifier.verify(address)) == Opt.some(AddrState.Unreachable)

  asyncTest "a peer without a verdict leaves the state alone":
    let pair = makePair(Unknown)

    await pair.start()
    defer:
      await pair.stop()
    await pair.dialPeer()

    check (await pair.verifier.verify(ma("/ip4/1.2.3.4/tcp/1"))).isNone()

  asyncTest "a peer which dialed us is not asked":
    let pair = makePair(Reachable)

    await pair.start()
    defer:
      await pair.stop()
    await pair.peer.connect(pair.switch)

    check:
      (await pair.verifier.verify(ma("/ip4/1.2.3.4/tcp/1"))).isNone()
      pair.client.dials == 0
