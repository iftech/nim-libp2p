# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils]
import stew/objects
import results, chronos, chronicles

import core
import
  ../../protocol, ../../../stream/connection, ../../../switch, ../../../utils/future

export chronicles

type Dcutr* = ref object of LPProtocol

logScope:
  topics = "libp2p hole-punching"

proc new*(
    T: typedesc[Dcutr],
    switch: Switch,
    connectTimeout = 15.seconds,
    maxDialableAddrs = 8,
): T =
  proc handleStream(
      stream: Stream, proto: ProtoCodec
  ) {.async: (raises: [CancelledError]).} =
    var peerDialableAddrs: seq[MultiAddress]
    try:
      let connectMsg =
        DcutrMsg.decode(await stream.readLp(1024)).valueOrRaise(DcutrError)

      trace "Dcutr receiver received a Connect message", connectMsg = connectMsg

      var ourAddrs = switch.addressManager.mostObservedProtosAndPorts()
        # likely empty when the peer is reachable
      if ourAddrs.len == 0:
        # this list should be the same as the peer's public addrs when it is reachable;
        # prefer the explicit/expanded announce set (withAnnouncedAddresses, UPnP,
        # autonat mappers) over a per-listen-addr guess when one is available
        ourAddrs =
          if switch.peerInfo.addrs.len > 0:
            switch.peerInfo.addrs
          else:
            switch.peerInfo.listenAddrs.mapIt(switch.addressManager.externalAddrFor(it))
      var ourDialableAddrs = getHolePunchableAddrs(ourAddrs)
      if ourDialableAddrs.len == 0:
        trace "Aborting Dcutr because the receiver has no supported dialable addresses",
          addresses = ourAddrs
        return

      peerDialableAddrs = switch.peerStore.addressPolicy.filterAddrs(
        getHolePunchableAddrs(connectMsg.addrs)
      )
      if peerDialableAddrs.len == 0:
        await stream.send(MsgType.Connect, ourAddrs)
        trace "Dcutr receiver sent a Connect message back"
        let syncMsg =
          DcutrMsg.decode(await stream.readLp(1024)).valueOrRaise(DcutrError)
        trace "Dcutr receiver received a Sync message", syncMsg
        trace "Aborting Dcutr because the initiator has no supported dialable addresses",
          addresses = connectMsg.addrs
        return

      # Expected DCUtR connections bypass ConnManager limits.
      trace "Dcutr receiver registering expected incoming connection",
        remotePeerId = stream.peerId
      let expectedIncoming = switch.connManager.expectDcutrConnection(stream.peerId, In)
      defer:
        expectedIncoming.cancelSoon()

      trace "Dcutr receiver registering expected outgoing connection",
        remotePeerId = stream.peerId
      let expectedOutgoing =
        switch.connManager.expectDcutrConnection(stream.peerId, Out)
      defer:
        expectedOutgoing.cancelSoon()

      await stream.send(MsgType.Connect, ourAddrs)
      trace "Dcutr receiver sent a Connect message back"
      let syncMsg = DcutrMsg.decode(await stream.readLp(1024)).valueOrRaise(DcutrError)
      trace "Dcutr receiver received a Sync message", syncMsg

      if peerDialableAddrs.len > maxDialableAddrs:
        peerDialableAddrs = peerDialableAddrs[0 ..< maxDialableAddrs]
      trace "Dcutr receiver starting direct dial attempts",
        addresses = peerDialableAddrs, connectTimeout
      let dialFuts = peerDialableAddrs.mapIt(
        switch.connect(
          stream.peerId,
          @[it],
          forceDial = true,
          reuseConnection = false,
          dir = Direction.Out,
        )
      )
      var futs = dialFuts
      futs.add(waitExpectedConnection(expectedIncoming))
      try:
        try:
          discard await anyCompleted(futs).wait(connectTimeout)
        except AsyncTimeoutError as err:
          if dialFuts.allIt(it.finished and not it.completed()):
            raise newException(AllFuturesFailedError, "all direct dial attempts failed")
          raise err
        trace "Dcutr receiver connected directly to the remote peer"
      finally:
        trace "Dcutr receiver cancelling remaining direct dial attempts",
          attempts = futs.len
        await futs.cancelAndWait()
        trace "Dcutr receiver finished direct dial cleanup"
    except CancelledError as err:
      trace "cancelled Dcutr receiver"
      raise err
    except AllFuturesFailedError as err:
      trace "Dcutr receiver could not connect to the remote peer, " &
        "all connect attempts failed", err = err.msg, addresses = peerDialableAddrs
    except AsyncTimeoutError as err:
      trace "Dcutr receiver could not connect to the remote peer, " &
        "all connect attempts timed out", err = err.msg, addresses = peerDialableAddrs
    except CatchableError as err:
      trace "Unexpected error when Dcutr receiver tried to connect " &
        "to the remote peer", err = err.msg

  let self = T()
  self.handler = handleStream
  self.codec = DcutrCodec
  self
