# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import results
import chronos, chronicles
import ../../../switch, ../../../multiaddress, ../../../peerid
import types

logScope:
  topics = "libp2p autonat"

type AutonatClient* = ref object of RootObj

proc sendDial(
    stream: Stream, pid: PeerId, addrs: seq[MultiAddress]
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let pb = AutonatMsg(
    msgType: Opt.some(MsgType.Dial),
    dial: Opt.some(
      AutonatDial(peerInfo: Opt.some(AutonatPeerInfo(id: Opt.some(pid), addrs: addrs)))
    ),
  ).encode()
  await stream.writeLp(pb)

func new(T: typedesc[AutonatError], msg: string): ref LPError =
  newException(T, msg)

func new(
    T: typedesc[AutonatError], msg: string, parent: ref CatchableError
): ref LPError =
  newException(T, msg & ": " & parent.msg, parent)

func dialedAddr(msg: AutonatMsg): Result[MultiAddress, ref LPError] =
  if msg.msgType.get(MsgType.Dial) != MsgType.DialResponse:
    return err(AutonatError.new("Unexpected response"))

  let response = msg.response.valueOr:
    return err(AutonatError.new("Unexpected response"))

  case response.status.get(Ok)
  of ResponseStatus.Ok:
    let dialed = response.ma.valueOr:
      return err(AutonatError.new("Unexpected response"))
    ok(dialed)
  of ResponseStatus.DialError:
    err(
      newException(
        AutonatUnreachableError, "Peer could not dial us back: " & response.text.get("")
      )
    )
  else:
    err(
      AutonatError.new("Bad status " & $response.status & " " & response.text.get(""))
    )

proc tryDialMe*(
    self: AutonatClient,
    switch: Switch,
    pid: PeerId,
    addrs: seq[MultiAddress] = newSeq[MultiAddress](),
): Future[Result[MultiAddress, ref LPError]] {.async: (raises: [CancelledError]).} =
  let stream =
    try:
      if addrs.len == 0:
        await switch.dial(pid, @[AutonatCodec])
      else:
        await switch.dial(pid, addrs, AutonatCodec)
    except DialFailedError as e:
      return err(AutonatError.new("Unexpected error when dialling", e))

  defer:
    await stream.close()

  # To bypass maxConnectionsPerPeer
  let incomingConnection = switch.connManager.expectConnection(pid, In)
  if incomingConnection.failed() and
      incomingConnection.error of AlreadyExpectingConnectionError:
    return err(AutonatError.new(incomingConnection.error.msg))
  defer:
    incomingConnection.cancelSoon()
      # Safer to always try to cancel cause we aren't sure if the peer dialled us or not
    if incomingConnection.completed():
      try:
        await (await incomingConnection).connection.close()
      except AlreadyExpectingConnectionError as e:
        # this err is already handled above and could not happen later
        trace "Unexpected error", err = e.msg

  try:
    trace "sending Dial", addresses = switch.peerInfo.addrs
    await stream.sendDial(switch.peerInfo.peerId, switch.peerInfo.addrs)
  except LPStreamError as e:
    return err(AutonatError.new("Sending dial failed", e))

  var respBytes =
    try:
      await stream.readLp(1024)
    except LPStreamError as e:
      return err(AutonatError.new("read Dial response failed", e))

  let msg = AutonatMsg.decode(move(respBytes)).valueOr:
    return err(AutonatError.new($error))
  msg.dialedAddr()

method dialMe*(
    self: AutonatClient,
    switch: Switch,
    pid: PeerId,
    addrs: seq[MultiAddress] = newSeq[MultiAddress](),
): Future[MultiAddress] {.
    base, async: (raises: [AutonatError, AutonatUnreachableError, CancelledError])
.} =
  let dialed = await self.tryDialMe(switch, pid, addrs)
  dialed.valueOr:
    if error of AutonatUnreachableError:
      raise (ref AutonatUnreachableError)(error)
    raise (ref AutonatError)(error)
