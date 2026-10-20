# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

{.push raises: [].}

import chronos
import
  ../../libp2p/[
    multiaddress,
    peerid,
    transports/transport,
    transports/memorytransport,
    upgrademngrs/upgrade,
    crypto/crypto,
  ]

type
  StubAcceptBehavior* = enum
    RaiseAlways ## every accept raises: the transport can never accept
    BlockingClose ## return connections whose close waits for `closeGate`

  MemoryTransportStub* = ref object of MemoryTransport
    behavior: StubAcceptBehavior
    acceptLimit: int ## for BlockingClose: block after this many accepts
    acceptCalls*: int ## number of times accept was invoked
    closeCalls*: int ## number of blocking connection closes started
    closeGate*: AsyncEvent

  BlockingCloseConnection = ref object of Connection
    transport: MemoryTransportStub

method closeImpl(conn: BlockingCloseConnection) {.async: (raises: []).} =
  inc conn.transport.closeCalls
  try:
    await conn.transport.closeGate.wait()
  except CancelledError:
    # Model a transport that cannot finish its close bookkeeping after cancellation.
    return
  await procCall Connection(conn).closeImpl()

proc new*(
    T: typedesc[MemoryTransportStub],
    upgrade: Upgrade,
    rng: Rng,
    behavior: StubAcceptBehavior,
    acceptLimit: int = 0,
): T =
  let self = T(
    upgrader: upgrade,
    rng: rng,
    behavior: behavior,
    acceptLimit: acceptLimit,
    closeGate: newAsyncEvent(),
  )
  procCall Transport(self).initialize()
  self

type FailingDialTransport* = ref object of MemoryTransport
  ## Records what a dial reaches the transport with, and refuses each address.
  dialedAddrs*: seq[MultiAddress]
  dialedHosts*: seq[string]
  handlesAny: bool ## handle every address, not only the memory ones

proc new*(
    T: typedesc[FailingDialTransport],
    upgrade: Upgrade,
    rng: Rng,
    handlesAny: bool = false,
): T =
  let self = T(upgrader: upgrade, rng: rng, handlesAny: handlesAny)
  procCall Transport(self).initialize()
  self

method handles*(
    self: FailingDialTransport, ma: MultiAddress
): bool {.gcsafe, raises: [].} =
  self.handlesAny or procCall MemoryTransport(self).handles(ma)

method dial*(
    self: FailingDialTransport,
    hostname: string,
    ma: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  self.dialedAddrs.add(ma)
  self.dialedHosts.add(hostname)
  raise newException(MemoryTransportError, "stub dial always fails")

type ScriptedDialTransport* = ref object of MemoryTransport
  ## Handles the `handled` addresses: a dial of a `failing` one fails, any other stalls.
  handled: seq[MultiAddress]
  failing: seq[MultiAddress]
  dialedAddrs*: seq[MultiAddress]
  cancelledAddrs*: seq[MultiAddress]

proc new*(
    T: typedesc[ScriptedDialTransport],
    upgrade: Upgrade,
    rng: Rng,
    handled: seq[MultiAddress],
    failing: seq[MultiAddress] = @[],
): T =
  let self = T(upgrader: upgrade, rng: rng, handled: handled, failing: failing)
  procCall Transport(self).initialize()
  self

method handles*(
    self: ScriptedDialTransport, ma: MultiAddress
): bool {.gcsafe, raises: [].} =
  ma in self.handled

method dial*(
    self: ScriptedDialTransport,
    hostname: string,
    ma: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  self.dialedAddrs.add(ma)
  if ma in self.failing:
    raise newException(MemoryTransportError, "stub dial fails as scripted")

  try:
    await sleepAsync(1.hours)
  except CancelledError as e:
    self.cancelledAddrs.add(ma)
    raise e
  raise newException(MemoryTransportError, "stub dial stalled past its hour")

method accept*(
    self: MemoryTransportStub
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  inc self.acceptCalls

  case self.behavior
  of RaiseAlways:
    raise newException(MemoryTransportError, "stub accept always fails")
  of BlockingClose:
    if self.acceptLimit > 0 and self.acceptCalls > self.acceptLimit:
      await sleepAsync(1.hours)
    await sleepAsync(0.milliseconds)
    let conn = BlockingCloseConnection(transport: self)
    conn.initStream()
    return conn
