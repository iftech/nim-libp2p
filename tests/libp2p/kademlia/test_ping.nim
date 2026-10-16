# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/[protocols/kademlia, switch, builders]
import ../../tools/[lifecycle, multiaddress, switch_builder, unittest]
import ./utils.nim

type Answer = proc(stream: Stream) {.async: (raises: [CancelledError, LPStreamError]).}

proc kadPeer(answer: Answer): Switch =
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    defer:
      await stream.close()
    try:
      discard await stream.readLp(MaxMsgSize)
      await answer(stream)
    except LPStreamError as e:
      raiseAssert "kad test peer stream failed: " & e.msg

  let switch = makeStandardSwitch(TcpAutoAddress)
  switch.mount(LPProtocol.new(@[KadCodec], handle))
  switch

proc kadPeerReplying(reply: seq[byte]): Switch =
  kadPeer(
    proc(stream: Stream) {.async: (raises: [CancelledError, LPStreamError]).} =
      await stream.writeLp(reply)
  )

proc kadPeerClosing(): Switch =
  kadPeer(
    proc(stream: Stream) {.async: (raises: [CancelledError, LPStreamError]).} =
      return
  )

proc kadPeerSilent(): Switch =
  kadPeer(
    proc(stream: Stream) {.async: (raises: [CancelledError, LPStreamError]).} =
      try:
        discard await stream.readLp(MaxMsgSize)
      except LPStreamEOFError:
        return
  )

suite "KadDHT Ping":
  teardown:
    checkTrackers()

  asyncTest "Simple ping":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    check:
      (await kads[0].ping(kads[1].switch.peerInfo)).isOk()
      (await kads[1].ping(kads[0].switch.peerInfo)).isOk()

  asyncTest "Ping a peer without kad returns err":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let other = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[other])

    let res = await kads[0].ping(other.peerInfo)
    check res.isOfError("ping dial failed")

  asyncTest "Ping a stopped peer returns err":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let stopped = setupKad()
    await stopped.switch.start()
    let addrs = stopped.switch.peerInfo.addrs
    await stopped.switch.stop()

    let res = await kads[0].ping(stopped.switch.peerInfo.peerId, addrs)
    check res.isOfError("ping dial failed")

  asyncTest "Ping with an undecodable reply returns decode err":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let other = kadPeerReplying(@[0xFF'u8, 0xFF, 0xFF])
    startAndDeferStop(@[other])

    let res = await kads[0].ping(other.peerInfo)
    check res.isOfError("ping reply decode failed")

  asyncTest "Ping with a reply that differs from the request returns mismatch err":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let other =
      kadPeerReplying(Message(msgType: Opt.some(MessageType.findNode)).encode())
    startAndDeferStop(@[other])

    let res = await kads[0].ping(other.peerInfo)
    check res.isOfError("ping reply does not match the request")

  asyncTest "Ping a peer that closes without replying returns stream err":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let other = kadPeerClosing()
    startAndDeferStop(@[other])

    let res = await kads[0].ping(other.peerInfo)
    check res.isOfError("ping stream failed")

  asyncTest "Ping a peer that never replies returns timeout err":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let other = kadPeerSilent()
    startAndDeferStop(@[other])

    let res = await kads[0].ping(other.peerInfo)
    check res.isOfError("ping timed out")
