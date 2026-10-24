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
      let request = Message.decode(await stream.readLp(MaxMsgSize)).valueOr:
        raiseAssert "kad test peer got an undecodable request: " & $error
      if request.msgType != MessageType.ping:
        raiseAssert "kad test peer expected a ping"
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
        let extra = await stream.readLp(MaxMsgSize)
        raiseAssert "kad test peer got a second request of " & $extra.len & " bytes"
      except LPStreamError:
        return
  )

template checkPingFails(peer: Switch, cause: string) =
  let kads = setupKadSwitches(1)
  startAndDeferStop(kads)
  let other = peer
  startAndDeferStop(@[other])
  check (await kads[0].ping(other.peerInfo)).isOfError(cause)

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

  asyncTest "Ping a peer without kad returns refused err":
    checkPingFails(makeStandardSwitch(TcpAutoAddress), $refusedStage)

  asyncTest "Ping a stopped peer returns dial err":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let stopped = makeStandardSwitch(TcpAutoAddress)
    await stopped.start()
    let addrs = stopped.peerInfo.addrs
    await stopped.stop()

    let res = await kads[0].ping(stopped.peerInfo.peerId, addrs)
    # Windows retries a refused connect past the 1 s test timeout.
    check res.isOfError($refusedStage) or res.isOfError($dialStage)

  asyncTest "Ping with an undecodable reply returns decode err":
    checkPingFails(kadPeerReplying(@[0xFF'u8, 0xFF, 0xFF]), "reply decode fail")

  asyncTest "Ping with a reply of another type returns type mismatch err":
    checkPingFails(
      kadPeerReplying(Message(msgType: Opt.some(MessageType.findNode)).encode()),
      "reply type mismatch",
    )

  for msgType in [Opt.some(MessageType.ping), Opt.none(MessageType)]:
    let msgType = msgType # the asyncTest closure cannot capture the lent loop variable
    asyncTest "Ping with a reply that differs from the request returns mismatch err: " &
      $msgType:
      let reply = Message(msgType: msgType, key: Opt.some(Key(@[1'u8])))
      checkPingFails(
        kadPeerReplying(reply.encode()), "ping reply differs from the request"
      )

  asyncTest "Ping a peer that closes without replying returns read err":
    checkPingFails(kadPeerClosing(), $readStage)

  asyncTest "Ping a peer that never replies returns read err":
    checkPingFails(kadPeerSilent(), $readStage)
