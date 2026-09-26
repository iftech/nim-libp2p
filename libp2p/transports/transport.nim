# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
##

{.push raises: [].}

import std/oserrors
import chronos, chronicles, results
import
  ../stream/connection,
  ../multiaddress,
  ../multicodec,
  ../muxers/muxer,
  ../upgrademngrs/upgrade,
  ../protocols/connectivity/autonat/types,
  ../wire

export types.NetworkReachability

logScope:
  topics = "libp2p transport"

type
  TransportError* = object of LPError
  TransportInvalidAddrError* = object of TransportError
  TransportClosedError* = object of TransportError
  TransportStartError* = object of TransportError
  TransportDialError* = object of TransportError

  Transport* = ref object of RootObj
    addrs*: seq[MultiAddress]
    running*: bool
    upgrader*: Upgrade
    networkReachability*: NetworkReachability
    onRunning*: AsyncEvent
    onStop*: AsyncEvent

  ConnAddrs* = object
    observed*: MultiAddress
    local*: MultiAddress

proc newTransportClosedError*(parent: ref Exception = nil): ref TransportError =
  newException(TransportClosedError, "Transport closed, no more connections!", parent)

proc connAddrs*(transp: StreamTransport): LPResult[ConnAddrs] =
  let remote = transp.remoteAddress2().valueOr:
    return err("cannot read remote address. " & osErrorMsg(error))
  let local = transp.localAddress2().valueOr:
    return err("cannot read local address. " & osErrorMsg(error))

  ok(ConnAddrs(observed: ?MultiAddress.init(remote), local: ?MultiAddress.init(local)))

proc initialize*(self: Transport) =
  self.onRunning = newAsyncEvent()
  self.onStop = newAsyncEvent()

method start*(
    self: Transport, addrs: seq[MultiAddress]
) {.base, async: (raises: [LPError, TransportError, CancelledError]).} =
  ## start the transport
  ##

  self.addrs = addrs
  self.running = true
  self.onRunning.fire()

method stop*(self: Transport) {.base, async: (raises: []).} =
  ## stop and cleanup the transport
  ## including all outstanding connections
  ##

  self.running = false
  self.onStop.fire()

method accept*(
    self: Transport
): Future[RawConn] {.gcsafe, base, async: (raises: [TransportError, CancelledError]).} =
  ## accept incoming connections
  ##

  doAssert(false, "[Transport.accept] abstract method not implemented!")

method dial*(
    self: Transport,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
    dir: Direction = Direction.Out,
): Future[RawConn] {.base, gcsafe, async: (raises: [TransportError, CancelledError]).} =
  ## dial a peer
  ##

  doAssert(false, "[Transport.dial] abstract method not implemented!")

proc dial*(
    self: Transport, address: MultiAddress, peerId: Opt[PeerId] = Opt.none(PeerId)
): Future[RawConn] {.gcsafe.} =
  self.dial("", address, peerId)

method upgrade*(
    self: Transport, conn: RawConn, peerId: Opt[PeerId]
): Future[Muxer] {.base, async: (raises: [CancelledError, LPError], raw: true).} =
  ## base upgrade method that the transport uses to perform
  ## transport specific upgrades
  ##
  self.upgrader.upgrade(conn, peerId)

method handles*(
    self: Transport, address: MultiAddress
): bool {.base, gcsafe, raises: [].} =
  ## check if transport supports the multiaddress
  ##
  # by default we skip circuit addresses to avoid
  # having to repeat the check in every transport
  let protocols = address.protocols.valueOr:
    return false

  multiCodec("p2p-circuit") notin protocols

template safeCloseWait*(stream: untyped) =
  if not isNil(stream):
    try:
      await noCancel stream.closeWait()
    except CatchableError as e:
      trace "Transport stream close failed", err = e.msg

template safeClose*(stream: untyped) =
  if not isNil(stream):
    try:
      await noCancel stream.close()
    except CatchableError as e:
      trace "Libp2p stream close failed", err = e.msg

proc toTransportAddress*(
    self: Transport, addrsMa: seq[MultiAddress]
): LPResult[seq[TransportAddress]] =
  var addrsTa = newSeq[TransportAddress](addrsMa.len)
  for i, maAddr in addrsMa:
    if not self.handles(maAddr):
      return err("unsupported address: " & $maAddr)

    addrsTa[i] = initTAddress(maAddr).valueOr:
      return err("cannot use non-wire address: " & $maAddr & ". " & error)

  if addrsTa.len == 0:
    return err("no addr was provided.")

  return ok(addrsTa)
