# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/sets
import chronos, chronicles
import ../../libp2p/[builders, multiaddress, peerid, results, switch]
import ../../libp2p/services/mdns
import ../../libp2p/utils/future

{.push raises: [].}

logScope:
  topics = "interop mdns"

type MdnsDiscovery* = object
  expected: int
  peers: HashSet[PeerId]
  completed: Future[void]

proc new*(T: type MdnsDiscovery, expected: int): LPResult[ref MdnsDiscovery] =
  if expected <= 0:
    return err("expected peer count must be positive")
  ok(
    (ref MdnsDiscovery)(
      expected: expected,
      completed: Future[void].Raising([CancelledError]).init("MdnsDiscovery.completed"),
    )
  )

proc observe*(discovery: ref MdnsDiscovery, local, remote: PeerId) =
  if remote == local or discovery.peers.containsOrIncl(remote):
    return
  info "mDNS peer discovered", peerId = remote, discovered = discovery.peers.len
  if discovery.peers.len == discovery.expected:
    discovery.completed.completeOnce()

proc waitForPeers*(
    discovery: ref MdnsDiscovery, timeout: Duration
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  # A timed-out or cancelled waiter must leave shared discovery state intact.
  if not discovery.completed.finished() and
      (timeout.isZero() or not await discovery.completed.join().withTimeout(timeout)):
    return err(
      "mDNS discovery timed out; discovered " & $discovery.peers.len & " of " &
        $discovery.expected & " peers"
    )
  return ok()

proc mdnsInteropTest*(
    expectedPeers: int, timeout: Duration
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  let
    discovery = ?MdnsDiscovery.new(expectedPeers)
    address = ?MultiAddress.init("/ip4/0.0.0.0/tcp/0")

  proc onPeerFound(node: Switch, peer: MdnsPeer) {.async: (raises: [CancelledError]).} =
    discovery.observe(node.peerInfo.peerId, peer.peerId)

  let node =
    try:
      SwitchBuilder
        .new()
        .withAddress(address)
        .withTcpTransport()
        .withYamux()
        .withNoise()
        .withMdns(queryInterval = 10.seconds, onPeerFound = onPeerFound)
        .build()
    except LPError as exc:
      return err(exc, "could not build Nim peer")

  try:
    await node.start()
  except LPError as exc:
    return err(exc, "could not start Nim peer")
  defer:
    await noCancel node.stop()

  return await discovery.waitForPeers(timeout)
