# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## An `AddressManager` verifier backed by AutoNATv2. It asks a connected peer to
## dial each candidate back.

{.push raises: [].}

import std/sequtils
import results
import chronos, chronicles
import
  ../../../address_manager,
  ../../../crypto/crypto,
  ../../../errors,
  ../../../multiaddress,
  ../../../peerid,
  ../../../switch,
  ./client,
  ./types,
  ./utils

logScope:
  topics = "libp2p autonat"

const AskTimeout = 2 * DefaultDialTimeout ## Twice the time a server has to dial back.

type AutonatV2Verifier* = ref object of Verifier
  switch: Switch
  client: AutonatV2Client
  rng: Rng

proc new*(
    T: typedesc[AutonatV2Verifier], switch: Switch, client: AutonatV2Client, rng: Rng
): T =
  ## The switch must mount `client`, which receives the dial back.
  client.setup(switch)
  T(switch: switch, client: client, rng: rng)

proc selectPeer(self: AutonatV2Verifier): Opt[PeerId] =
  ## A peer which dialed us proves nothing. It has a path to us already.
  self.rng.pickOne(
    self.switch.connectedPeers(Direction.Out).filterIt(
      $AutonatV2Codec.DialRequest in self.switch.peerStore[ProtoBook][it] and
        not self.switch.hasIncomingConn(it)
    )
  )

proc askPeer(
    self: AutonatV2Verifier, peerId: PeerId, address: MultiAddress
): Future[Opt[AddrState]] {.async: (raises: [CancelledError]).} =
  let reachability =
    try:
      (await self.client.sendDialRequest(peerId, @[address]).wait(AskTimeout)).reachability
    except CancelledError as e:
      raise e
    except AsyncTimeoutError:
      trace "DialRequest timed out", peerId, address
      return Opt.none(AddrState)
    except LPError as e:
      trace "DialRequest failed", peerId, err = e.msg, address
      return Opt.none(AddrState)

  case reachability
  of Reachable:
    Opt.some(AddrState.Confirmed)
  of NotReachable:
    Opt.some(AddrState.Unreachable)
  of Unknown:
    Opt.none(AddrState)

method verify*(
    self: AutonatV2Verifier, address: MultiAddress
): Future[Opt[AddrState]] {.async: (raises: [CancelledError]).} =
  ## One request carrying that one address, to a random peer.
  if not self.switch.hasEnoughIncomingSlots():
    trace "No incoming slots left, skipping verification", address
    return Opt.none(AddrState)

  let peerId = self.selectPeer().valueOr:
    trace "No peer to ask", address
    return Opt.none(AddrState)

  await self.askPeer(peerId, address)
