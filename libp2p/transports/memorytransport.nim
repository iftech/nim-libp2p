# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Memory transport implementation

import std/sequtils
import pkg/chronos
import pkg/chronicles
import ./transport
import ../multiaddress
import ../stream/connection
import ../crypto/crypto
import ../upgrademngrs/upgrade
import ./memorymanager

export connection
export MemoryTransportError, MemoryTransportAcceptStopped

const MemoryAutoAddress* = "/memorytransport/*"

logScope:
  topics = "libp2p memory-transport"

type MemoryTransport* = ref object of Transport
  rng*: Rng
  connections: seq[RawConn]
  listener: Opt[MemoryListener]

proc new*(T: typedesc[MemoryTransport], upgrade: Upgrade = Upgrade(), rng: Rng): T =
  let self = T(upgrader: upgrade, rng: rng)
  procCall Transport(self).initialize()
  self

proc listenAddress(self: MemoryTransport, ma: MultiAddress): MultiAddress =
  if $ma != MemoryAutoAddress:
    return ma

  # when special address is used `/memorytransport/*` use any free address.
  # here we assume that any random generated address will be free.
  var randomBuf: array[10, byte]
  self.rng.generate(randomBuf)

  return MultiAddress.init("/memorytransport/" & toHex(randomBuf)).get()

method start*(
    self: MemoryTransport, addrs: seq[MultiAddress]
) {.async: (raises: [LPError, transport.TransportError, CancelledError]).} =
  if self.running:
    warn "Memory transport already started"
    return

  info "Starting memory transport on addrs", address = addrs

  self.addrs = addrs.mapIt(self.listenAddress(it))
  self.running = true
  self.onRunning.fire()

method stop*(self: MemoryTransport) {.async: (raises: []).} =
  if not self.running:
    warn "Memory transport already stopped"
    return

  self.running = false
  self.onStop.fire()

  # closing listener will throw interruption error to caller of accept()
  let listener = self.listener
  if listener.isSome:
    listener.get().close()

  # end all connections
  await noCancel allFutures(self.connections.mapIt(it.close()))
  info "Memory transport stopped", addresses = self.addrs

method accept*(
    self: MemoryTransport
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  if not self.running:
    raise newException(MemoryTransportError, "Transport closed, no more connections!")

  var listener: MemoryListener
  try:
    listener = getInstance().accept($self.addrs[0])
    self.listener = Opt.some(listener)
    let conn = await listener.accept()
    self.connections.add(conn)
    self.listener = Opt.none(MemoryListener)
    return conn
  except CancelledError as e:
    listener.close()
    raise e
  except MemoryTransportError as e:
    raise e
  except CatchableError:
    raiseAssert "should never happen"

method dial*(
    self: MemoryTransport,
    hostname: string,
    ma: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  try:
    let listener = getInstance().dial($ma)
    let conn = await listener.dial()
    self.connections.add(conn)
    return conn
  except CancelledError as e:
    raise e
  except MemoryTransportError as e:
    raise e
  except CatchableError:
    raiseAssert "should never happen"

proc dial*(
    self: MemoryTransport, ma: MultiAddress, peerId: Opt[PeerId] = Opt.none(PeerId)
): Future[RawConn] {.gcsafe.} =
  self.dial("", ma)

method handles*(self: MemoryTransport, ma: MultiAddress): bool {.gcsafe, raises: [].} =
  if procCall Transport(self).handles(ma):
    if ma.protocols.isOk:
      return Memory.match(ma)
