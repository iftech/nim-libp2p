# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos
import results
import peerid, stream/connection, transports/transport

export results

type
  Dial* = ref object of RootObj
  DialFailedError* = object of LPError

method connect*(
    self: Dial,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    forceDial = false,
    reuseConnection = true,
    dir = Direction.Out,
    bypassBackoff = false,
) {.base, async: (raises: [DialFailedError, CancelledError]).} =
  ## connect remote peer without negotiating
  ## a protocol
  ##

  doAssert(false, "[Dial.connect] abstract method not implemented!")

method connect*(
    self: Dial, address: MultiAddress, allowUnknownPeerId = false
): Future[PeerId] {.base, async: (raises: [DialFailedError, CancelledError]).} =
  ## Connects to a peer and retrieve its PeerId

  doAssert(false, "[Dial.connect] abstract method not implemented!")

method dial*(
    self: Dial, peerId: PeerId, protos: seq[string]
): Future[Stream] {.base, async: (raises: [DialFailedError, CancelledError]).} =
  ## create a protocol stream over an
  ## existing connection
  ##

  doAssert(false, "[Dial.dial] abstract method not implemented!")

method dial*(
    self: Dial,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.base, async: (raises: [DialFailedError, CancelledError]).} =
  ## create a protocol stream and establish
  ## a connection if one doesn't exist already
  ##

  doAssert(false, "[Dial.dial] abstract method not implemented!")

method addTransport*(self: Dial, transport: Transport) {.base.} =
  doAssert(false, "[Dial.addTransport] abstract method not implemented!")
