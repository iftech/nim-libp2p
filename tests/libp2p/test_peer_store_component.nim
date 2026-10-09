# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, tables]
import chronos
import
  ../../libp2p/
    [peerstore, peerinfo, multiaddress, switch, connmanager, protocols/kademlia]
import ../tools/[unittest, multiaddress, switch_builder, lifecycle, topology]
import ./kademlia/utils

suite "PeerStore Address TTL - Component":
  teardown:
    checkTrackers()

  asyncTest "identify stores peer addresses at Medium confidence":
    let
      listener = makeStandardSwitch()
      dialer = makeStandardSwitch()
    startAndDeferStop(@[listener, dialer])

    await dialer.connect(listener)

    # The listener only accepts the connection, so identify is its only source for the dialer's addresses.
    # The listener never dials the dialer, so nothing upgrades it to High.
    checkUntilTimeout:
      listener.peerStore[AddressBook].entries(dialer.peerInfo.peerId).len > 0
      listener.peerStore[AddressBook].entries(dialer.peerInfo.peerId).allIt(
        it.confidence == AddressConfidence.Medium
      )

  asyncTest "successful dial records address at High confidence":
    let
      listener = makeStandardSwitch()
      dialer = makeStandardSwitch()
    startAndDeferStop(@[listener, dialer])

    await dialer.connect(listener)

    # A successful dial marks the dialed address High.
    checkUntilTimeout:
      dialer.peerStore[AddressBook].entries(listener.peerInfo.peerId).anyIt(
        it.confidence == AddressConfidence.High
      )

  asyncTest "kademlia discovery stores discovered addresses at Low confidence":
    # kads[0] is a hub that knows both others.
    # kads[1] and kads[2] are not directly connected, so kads[1] can only learn
    # kads[2] through a DHT lookup.
    let kads = setupKadSwitches(3)
    startAndDeferStop(kads)
    await connectHub(kads[0], kads[1 ..^ 1])

    check kads[2].switch.peerInfo.peerId notin kads[1].switch.peerStore[AddressBook]

    # Stop kads[2] so the lookup cannot dial it.
    await kads[2].switch.stop()

    # kads[1] discovers kads[2] through kads[0]'s FIND_NODE response.
    discard await kads[1].findNode(kads[2].rtable.selfId)

    # The addresses arrive in a DHT response, so they are stored at Low confidence.
    let entries =
      kads[1].switch.peerStore[AddressBook].entries(kads[2].switch.peerInfo.peerId)
    check:
      entries.len == 1
      entries[0].confidence == AddressConfidence.Low

  asyncTest "later identify update does not downgrade a verified High address":
    let
      listener = makeStandardSwitchBuilder().withIdentifyPusher().build()
      dialer = makeStandardSwitchBuilder().withIdentifyPusher().build()
    startAndDeferStop(@[listener, dialer])

    # Wait for the listener to finish identifying the dialer,
    # so IdentifyPusher has the dialer in its pushPeers set.
    let listenerIdentified = newFuture[void]("listenerIdentified")
    proc onIdentified(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]).} =
      if not listenerIdentified.finished:
        listenerIdentified.complete()

    listener.connManager.addPeerEventHandler(onIdentified, PeerEventKind.Identified)

    await dialer.connect(listener)

    checkUntilTimeout:
      dialer.peerStore[AddressBook].entries(listener.peerInfo.peerId).anyIt(
        it.confidence == AddressConfidence.High
      )

    await listenerIdentified

    # The listener announces an extra address.
    # Its IdentifyPusher pushes the updated PeerInfo to the dialer at Medium.
    let extra = ma("/ip4/127.0.0.1/tcp/4099")
    listener.peerInfo.listenAddrs.add(extra)
    await listener.peerInfo.update()

    # The extra address is stored at Medium.
    # The already dialed address stays High.
    checkUntilTimeout:
      dialer.peerStore[AddressBook].entries(listener.peerInfo.peerId).anyIt(
        it.address == extra and it.confidence == AddressConfidence.Medium
      )
      dialer.peerStore[AddressBook].entries(listener.peerInfo.peerId).anyIt(
        it.confidence == AddressConfidence.High
      )

  asyncTest "addresses of every confidence are pruned after their TTL":
    let switch = makeStandardSwitchBuilder()
      .withAddressConfidenceTtls(
        AddressConfidenceTtls(
          low: 10.milliseconds, medium: 20.milliseconds, high: 30.milliseconds
        )
      )
      .build()
    startAndDeferStop(@[switch])

    let
      lowPeer = randomPeerId()
      mediumPeer = randomPeerId()
      highPeer = randomPeerId()
    switch.peerStore[AddressBook].extend(
      lowPeer, @[ma("/ip4/1.2.3.4/tcp/4001")], AddressConfidence.Low
    )
    switch.peerStore[AddressBook].extend(
      mediumPeer, @[ma("/ip4/5.6.7.8/tcp/4001")], AddressConfidence.Medium
    )
    switch.peerStore[AddressBook].extend(
      highPeer, @[ma("/ip4/9.10.11.12/tcp/4001")], AddressConfidence.High
    )
    check:
      lowPeer in switch.peerStore[AddressBook]
      mediumPeer in switch.peerStore[AddressBook]
      highPeer in switch.peerStore[AddressBook]

    # The background pruning loop applies each entry's own TTL.
    # Asserting on the raw entries proves the loop ran, not just lazy filtering.
    checkUntilTimeout:
      switch.peerStore[AddressBook].entries(lowPeer).len == 0
      switch.peerStore[AddressBook].entries(mediumPeer).len == 0
      switch.peerStore[AddressBook].entries(highPeer).len == 0

  asyncTest "non-expiring addresses survive the pruning loop":
    # A zero TTL disables expiry for that confidence band.
    # Infinite confidence never expires regardless of the configured TTLs.
    # The High TTL is intentionally short so the control entry expires quickly.
    let switch = makeStandardSwitchBuilder()
      .withAddressConfidenceTtls(
        AddressConfidenceTtls(
          low: 0.seconds, medium: 10.milliseconds, high: 20.milliseconds
        )
      )
      .build()
    startAndDeferStop(@[switch])

    let
      zeroTtlPeer = randomPeerId()
      infinitePeer = randomPeerId()
      controlPeer = randomPeerId()
    switch.peerStore[AddressBook].extend(
      zeroTtlPeer, @[ma("/ip4/1.2.3.4/tcp/4001")], AddressConfidence.Low
    )
    switch.peerStore[AddressBook].extend(
      infinitePeer, @[ma("/ip4/5.6.7.8/tcp/4001")], AddressConfidence.Infinite
    )
    switch.peerStore[AddressBook].extend(
      controlPeer, @[ma("/ip4/9.10.11.12/tcp/4001")], AddressConfidence.High
    )
    # Back-date the non-expiring entries well beyond any positive TTL.
    switch.peerStore[AddressBook].book[zeroTtlPeer][0].lastUpdated =
      Moment.now() - 48.hours
    switch.peerStore[AddressBook].book[infinitePeer][0].lastUpdated =
      Moment.now() - 48.hours

    checkUntilTimeout:
      # The control was pruned, proving the loop actively expires entries.
      switch.peerStore[AddressBook].entries(controlPeer).len == 0

    check:
      # The non-expiring entries were spared.
      switch.peerStore[AddressBook].entries(zeroTtlPeer).len == 1
      switch.peerStore[AddressBook].entries(infinitePeer).len == 1

  asyncTest "connected-but-idle address stays fresh while still connected":
    # Connected peers keep already-known addresses visible and periodically
    # refreshed, so an idle long-lived connection stays redialable.
    let
      listener = makeStandardSwitch()
      # low is small so the prune loop runs often.
      # medium and high are large so the address does not expire on its own during setup.
      dialer = makeStandardSwitchBuilder()
        .withAddressConfidenceTtls(
          AddressConfidenceTtls(low: 50.milliseconds, medium: 1.hours, high: 1.hours)
        )
        .build()
    startAndDeferStop(@[listener, dialer])

    let peerId = listener.peerInfo.peerId
    await dialer.connect(peerId, listener.peerInfo.addrs)

    # The dial stores the listener's address.
    checkUntilTimeout:
      dialer.peerStore[AddressBook].entries(peerId).len > 0

    # Back-date the entries beyond the TTL to emulate an idle connection.
    for i in 0 ..< dialer.peerStore[AddressBook].book[peerId].len:
      dialer.peerStore[AddressBook].book[peerId][i].lastUpdated = Moment.now() - 2.hours

    check dialer.isConnected(peerId)
    check dialer.peerStore[AddressBook][peerId].len > 0

    # The prune loop refreshes the old address while the connection is still open.
    checkUntilTimeout:
      dialer.peerStore[AddressBook].entries(peerId).len > 0
      dialer.peerStore[AddressBook].entries(peerId).allIt(
        not it.isExpired(dialer.peerStore[AddressBook].ttls)
      )
      dialer.peerStore[AddressBook][peerId].len > 0

    await dialer.disconnect(peerId)

    checkUntilTimeout:
      not dialer.isConnected(peerId)

    check:
      dialer.peerStore[AddressBook][peerId].len > 0
      peerId in dialer.peerStore[AddressBook]
