# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/sequtils

import results
import chronos, chronicles

import core
import
  ../../protocol, ../../../stream/connection, ../../../switch, ../../../utils/future

export DcutrError

type DcutrClient* = ref object
  connectTimeout: Duration
  maxDialableAddrs: int

logScope:
  topics = "libp2p hole-punching"

proc new*(
    T: typedesc[DcutrClient], connectTimeout = 15.seconds, maxDialableAddrs = 8
): T =
  return T(connectTimeout: connectTimeout, maxDialableAddrs: maxDialableAddrs)

proc connectDirectly(
    self: DcutrClient,
    switch: Switch,
    remotePeerId: PeerId,
    peerDialableAddrs: seq[MultiAddress],
    expectedIncoming: Future[void].Raising([DialFailedError, CancelledError]),
): Future[Result[void, ref DcutrError]] {.async: (raises: [CancelledError]).} =
  trace "Dcutr initiator starting direct dial attempts",
    addresses = peerDialableAddrs, connectTimeout = self.connectTimeout
  let dialFuts = peerDialableAddrs.mapIt(
    switch.connect(
      remotePeerId, @[it], forceDial = true, reuseConnection = false, dir = Direction.In
    )
  )
  var futs = dialFuts
  futs.add(expectedIncoming)
  trace "Dcutr initiator waiting for direct dial or incoming connection",
    attempts = futs.len
  defer:
    trace "Dcutr initiator cancelling remaining direct dial attempts",
      attempts = futs.len
    await futs.cancelAndWait()
    trace "Dcutr initiator finished direct dial cleanup"

  let failure =
    try:
      discard await anyCompleted(futs).wait(self.connectTimeout)
      trace "Dcutr initiator connected directly to the remote peer"
      return ok()
    except AllFuturesFailedError as e:
      (ref CatchableError)(e)
    except AsyncTimeoutError as e:
      if dialFuts.allIt(it.finished and not it.completed()):
        newException(AllFuturesFailedError, "all direct dial attempts failed")
      else:
        e

  if failure of AllFuturesFailedError:
    trace "Dcutr initiator could not connect to the remote peer, all connect attempts failed",
      addresses = peerDialableAddrs
    return err(
      newException(
        DcutrError,
        "Dcutr initiator could not connect to the remote peer, all connect attempts failed",
        failure,
      )
    )

  trace "Dcutr initiator could not connect to the remote peer, all connect attempts timed out",
    addresses = peerDialableAddrs
  err(
    newException(
      DcutrError,
      "Dcutr initiator could not connect to the remote peer, all connect attempts timed out",
      failure,
    )
  )

proc tryStartSync*(
    self: DcutrClient, switch: Switch, remotePeerId: PeerId, addrs: seq[MultiAddress]
): Future[Result[void, ref DcutrError]] {.async: (raises: [CancelledError]).} =
  logScope:
    peerId = switch.peerInfo.peerId

  var stream: Stream
  defer:
    if not stream.isNil():
      await stream.close()

  try:
    let ourDialableAddrs = getHolePunchableAddrs(addrs)
    if ourDialableAddrs.len == 0:
      trace "Aborting Dcutr because the initiator has no supported dialable addresses",
        addresses = addrs
      return ok()

    stream = await switch.dial(remotePeerId, DcutrCodec)
    await stream.send(MsgType.Connect, addrs)
    trace "Dcutr initiator sent a Connect message"
    let rttStart = Moment.now()
    let connectAnswer = DcutrMsg.decode(await stream.readLp(1024)).valueOr:
      return err(
        newException(
          DcutrError, "Dcutr initiator received an invalid Connect message: " & $error
        )
      )

    var peerDialableAddrs = switch.peerStore.addressPolicy.filterAddrs(
      getHolePunchableAddrs(connectAnswer.addrs)
    )
    if peerDialableAddrs.len == 0:
      trace "Aborting Dcutr because the receiver has no supported dialable addresses",
        addresses = connectAnswer.addrs
      return ok()

    let rttEnd = Moment.now()
    trace "Dcutr initiator received a Connect message back",
      connectAnswer = connectAnswer
    let halfRtt = (rttEnd - rttStart) div 2'i64

    # Expected DCUtR connections bypass ConnManager limits.
    trace "Dcutr initiator registering expected incoming connection",
      remotePeerId = stream.peerId
    let expectedIncoming = switch.connManager.expectDcutrConnection(stream.peerId, In)
    defer:
      expectedIncoming.cancelSoon()

    await stream.send(MsgType.Sync, @[])
    trace "Dcutr initiator sent a Sync message"
    await sleepAsync(halfRtt)

    if peerDialableAddrs.len > self.maxDialableAddrs:
      peerDialableAddrs = peerDialableAddrs[0 ..< self.maxDialableAddrs]
    let connected = await self.connectDirectly(
      switch, stream.peerId, peerDialableAddrs, waitExpectedConnection(expectedIncoming)
    )
    connected
  except LPError as e:
    trace "Unexpected error when Dcutr initiator tried to connect to the remote peer",
      err = e.msg
    err(
      newException(
        DcutrError,
        "Unexpected error when Dcutr initiator tried to connect to the remote peer: " &
          e.msg,
        e,
      )
    )

proc startSync*(
    self: DcutrClient, switch: Switch, remotePeerId: PeerId, addrs: seq[MultiAddress]
) {.async: (raises: [DcutrError, CancelledError]).} =
  let synced = await self.tryStartSync(switch, remotePeerId, addrs)
  synced.isOkOr:
    raise error
