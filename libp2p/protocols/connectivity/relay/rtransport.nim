# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/sequtils, chronos, chronicles

import
  ./client,
  ./rconn,
  ./utils,
  ../../../switch,
  ../../../stream/connection,
  ../../../transports/transport

logScope:
  topics = "libp2p relay"

type RelayTransport* = ref object of Transport
  client*: RelayClient
  queue: AsyncQueue[RawConn]
  selfRunning: bool

method start*(
    self: RelayTransport, ma: seq[MultiAddress]
) {.async: (raises: [LPError, transport.TransportError, CancelledError]).} =
  if self.selfRunning:
    trace "Relay transport already running"
    return

  self.client.onNewConnection = proc(
      conn: RawConn, duration: uint32 = 0, data: uint64 = 0
  ) {.async: (raises: [CancelledError]).} =
    await self.queue.addLast(RelayConnection.new(conn, duration, data))
    await conn.join()
  self.selfRunning = true
  await procCall Transport(self).start(ma)
  info "Starting Relay transport"

method stop*(self: RelayTransport) {.async: (raises: []).} =
  self.running = false
  self.selfRunning = false
  self.client.onNewConnection = nil

  let pending = toSeq(self.queue)
  self.queue.clear()
  await noCancel allFutures(pending.mapIt(it.close()))

method accept*(
    self: RelayTransport
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  await self.queue.popFirst()

type RelayAddr = object
  relay: MultiAddress
  relayPeerId: PeerId
  dstPeerId: PeerId

proc peerIdOf(part: MultiAddress): LPResult[PeerId] =
  let peerId = PeerId.init(?part.protoAddress()).valueOr:
    return err(error)
  ok(peerId)

proc parseRelayAddr(ma: MultiAddress): LPResult[RelayAddr] =
  let parts = ?ma.len()
  if parts < 4:
    return err($ma, "too few parts")
  if not CircuitRelay.match(?ma[parts - 2]):
    return err($ma, "missing p2p-circuit")

  let relayPeerId = peerIdOf(?ma[parts - 3]).valueOr:
    return err(error, "Relay doesn't exist")
  let dstPeerId = peerIdOf(?ma[parts - 1]).valueOr:
    return err(error, "Destination doesn't exist")

  ok(
    RelayAddr(
      relay: ?ma[0 .. parts - 4], relayPeerId: relayPeerId, dstPeerId: dstPeerId
    )
  )

proc tryDial*(
    self: RelayTransport, ma: MultiAddress
): Future[LPResult[RawConn]] {.async: (raises: [CancelledError]).} =
  let address = parseRelayAddr(ma).valueOr:
    return err(error, "dial address not valid")

  trace "Dial", relayPeerId = address.relayPeerId, dstPeerId = address.dstPeerId

  let conn =
    try:
      await self.client.switch.dial(
        address.relayPeerId, @[address.relay], @[RelayV2HopCodec, RelayV1Codec]
      )
    except DialFailedError as e:
      return err("dial relay peer failed: " & e.msg)
  conn.dir = Direction.Out

  var dialedConn: Stream = conn
  let dialed =
    try:
      case conn.protocol
      of RelayV1Codec:
        await self.client.tryDialPeerV1(conn, address.dstPeerId, @[])
      of RelayV2HopCodec:
        let rc = RelayConnection.new(conn, 0, 0)
        dialedConn = rc
        await self.client.tryDialPeerV2(rc, address.dstPeerId, @[])
      else:
        LPResult[RawConn].err("unexpected relay protocol")
    except CancelledError as e:
      safeClose(dialedConn)
      raise e

  if dialed.isErr():
    safeClose(dialedConn)
    return err(dialed.error, "dial relay " & conn.protocol & " failed")

  dialed

proc dial*(
    self: RelayTransport, ma: MultiAddress
): Future[RawConn] {.async: (raises: [RelayDialError, CancelledError]).} =
  (await self.tryDial(ma)).valueOrRaise(RelayDialError)

method dial*(
    self: RelayTransport,
    hostname: string,
    ma: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.async: (raises: [transport.TransportError, CancelledError]).} =
  peerId.ifValue(pid):
    let address = MultiAddress.init($ma & "/p2p/" & $pid).valueOr:
      raise error.toException(transport.TransportDialError, "relay dial failed")
    let conn = (await self.tryDial(address)).valueOr:
      raise error.toException(transport.TransportDialError, "relay dial failed")
    return conn

method handles*(self: RelayTransport, ma: MultiAddress): bool {.gcsafe.} =
  if ma.protocols.isErr() or ma.len().get(0) < 2:
    return false

  let last = ma[^1].valueOr:
    return false
  CircuitRelay.match(last)

proc new*(Self: typedesc[RelayTransport], cl: RelayClient, upgrader: Upgrade): Self =
  # Self instead of T to avoid clashing with ifValue[T]'s type param under --lineDir:on
  let self = Self(client: cl, upgrader: upgrader)
  self.running = true
  self.queue = newAsyncQueue[RawConn](0)
  procCall Transport(self).initialize()
  self
