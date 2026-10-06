# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/[protocols/kademlia, stream/connection, switch]
import ../../tools/[lifecycle, unittest]
import ./utils

proc dialFindNode(
    querier, target: KadDHT
): Future[Opt[Message]] {.async: (raises: [CancelledError]).} =
  ## Dial the target's Kad codec, send a FIND_NODE and return the reply, or
  ## `Opt.none` when the target refuses to serve (stream reset, no reply).
  let stream =
    try:
      await querier.switch.dial(
        target.switch.peerInfo.peerId, target.switch.peerInfo.addrs, querier.codec
      )
    except CatchableError:
      return Opt.none(Message)
  defer:
    await stream.close()

  let msg = Message(msgType: Opt.some(MessageType.findNode), key: target.rtable.selfId)
  try:
    await stream.writeLp(msg.encode(querier.config.hideConnectionStatus))
    let replyBuf = await stream.readLp(MaxMsgSize)
    let reply = Message.decode(replyBuf).valueOr:
      return Opt.none(Message)
    # A served query yields a well-formed FIND_NODE reply; anything else is a
    # broken server masquerading as one, so do not count it as served.
    if reply.msgType != Opt.some(MessageType.findNode):
      return Opt.none(Message)
    return Opt.some(reply)
  except CatchableError:
    return Opt.none(Message)

suite "KadDHT dynamic mode":
  teardown:
    checkTrackers()

  test "initial mode follows the configured flag":
    check:
      setupKad(isServer = true).isServer
      not setupKad(isServer = false).isServer

  asyncTest "changeMode reports whether the mode changed":
    let kad = setupKad(isServer = false)

    check (await kad.changeMode(isServer = true))
    check kad.isServer

    # The same mode twice changes nothing.
    check not (await kad.changeMode(isServer = true))
    check kad.isServer

    check (await kad.changeMode(isServer = false))
    check not kad.isServer

  asyncTest "server answers queries, client resets them":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    let client = setupKad(isServer = false)
    startAndDeferStop(@[querier, server, client])

    check (await querier.dialFindNode(server)).isSome()
    check (await querier.dialFindNode(client)).isNone()

  asyncTest "downgrade to client mode stops serving and drops peers":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    check (await querier.dialFindNode(server)).isSome()

    check (await server.changeMode(isServer = false))
    check (await querier.dialFindNode(server)).isNone()

    check (await server.changeMode(isServer = true))
    check (await querier.dialFindNode(server)).isSome()

  asyncTest "downgrade resets an in-flight inbound stream":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    let stream = await querier.switch.dial(
      server.switch.peerInfo.peerId, server.switch.peerInfo.addrs, querier.codec
    )
    defer:
      await stream.close()

    # One round-trip parks the server handler on the next read, so the stream is
    # held open and tracked as a server stream.
    let msg =
      Message(msgType: Opt.some(MessageType.findNode), key: server.rtable.selfId)
    await stream.writeLp(msg.encode(querier.config.hideConnectionStatus))
    discard await stream.readLp(MaxMsgSize)

    checkUntilTimeout:
      server.serverStreams.len == 1

    check (await server.changeMode(isServer = false))
    check server.serverStreams.len == 0

    # The downgrade must reset the parked stream: the querier's next read ends in
    # EOF, not a timeout (a timeout would mean the reset never propagated).
    expect LPStreamEOFError:
      discard await stream.readLp(MaxMsgSize)

  asyncTest "server closes the stream on an undecodable request":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    let stream = await querier.switch.dial(
      server.switch.peerInfo.peerId, server.switch.peerInfo.addrs, querier.codec
    )
    defer:
      await stream.close()

    let truncated = @[0x0A'u8, 0x05, 0x01]
    check Message.decode(truncated).isErr()

    await stream.writeLp(truncated)
    expect LPStreamEOFError:
      discard await stream.readLp(MaxMsgSize)

  asyncTest "server skips REGISTER and GET_ADS and keeps the stream open":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    let stream = await querier.switch.dial(
      server.switch.peerInfo.peerId, server.switch.peerInfo.addrs, querier.codec
    )
    defer:
      await stream.close()

    let hide = querier.config.hideConnectionStatus
    for msgType in [MessageType.register, MessageType.getAds]:
      await stream.writeLp(
        Message(msgType: Opt.some(msgType), key: server.rtable.selfId).encode(hide)
      )
    await stream.writeLp(
      Message(msgType: Opt.some(MessageType.findNode), key: server.rtable.selfId).encode(
        hide
      )
    )

    let reply = Message.decode(await stream.readLp(MaxMsgSize))
    check reply.get().msgType == Opt.some(MessageType.findNode)
