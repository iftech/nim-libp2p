# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../../libp2p/peerid
import
  ../../../../libp2p/protocols/pubsub/
    [gossipsub/extension_pingpong, gossipsub/extensions_types, rpc/messages]
import ../../../tools/[unittest, crypto]

type PeerPong = object
  peerId: PeerId
  pong: seq[byte]

type CallbackRecorder = ref object
  sentPongs: seq[PeerPong]

proc config(c: CallbackRecorder, peerBudgetBytes: int = 6400): PingPongExtensionConfig =
  proc sendPong(peerId: PeerId, pong: seq[byte]) {.gcsafe, raises: [].} =
    c.sentPongs.add(PeerPong(peerId: peerId, pong: pong))

  return PingPongExtensionConfig(sendPong: sendPong, peerBudgetBytes: peerBudgetBytes)

proc handlePingPong(
    ext: PingPongExtension, peerId: PeerId, ping: seq[byte] | Opt[seq[byte]]
) =
  ext.onHandleRPC(peerId, RPCMsg.withPing(ping))

suite "GossipSub Extensions :: PingPong Extension":
  let peerId = PeerId.random()

  test "isSupported":
    let ext = PingPongExtension.new()
    check:
      ext.isSupported(PeerExtensions()) == false
      ext.isSupported(PeerExtensions(pingpongExtension: true)) == true

  test "config validation - sendPong must be set":
    expect AssertionDefect:
      discard PingPongExtension.new(PingPongExtensionConfig())

    expect AssertionDefect:
      var cfg = CallbackRecorder().config()
      cfg.sendPong = nil
      discard PingPongExtension.new(cfg)

  test "config validation - peerBudgetBytes must be positive":
    expect AssertionDefect:
      var cfg = CallbackRecorder().config()
      cfg.peerBudgetBytes = 0
      discard PingPongExtension.new(cfg)

  test "ping triggers pong with same bytes":
    var cr = CallbackRecorder()
    let ext = PingPongExtension.new(cr.config())

    let pingBytes = @[1'u8, 2, 3]
    ext.handlePingPong(peerId, pingBytes)

    check:
      cr.sentPongs.len == 1
      cr.sentPongs[0] == PeerPong(peerId: peerId, pong: pingBytes)

  test "unset ping does not trigger pong":
    var cr = CallbackRecorder()
    let ext = PingPongExtension.new(cr.config())

    ext.handlePingPong(peerId, Opt.none(seq[byte]))

    check cr.sentPongs.len == 0

  test "rpc without pingpong extension does not trigger pong":
    var cr = CallbackRecorder()
    let ext = PingPongExtension.new(cr.config())

    ext.onHandleRPC(peerId, RPCMsg())

    check cr.sentPongs.len == 0

  test "budget is tracked and exhausted within heartbeat":
    var cr = CallbackRecorder()
    let ext = PingPongExtension.new(cr.config(peerBudgetBytes = 10))

    # first ping: 6 bytes, within budget
    let ping1 = @[1'u8, 2, 3, 4, 5, 6]
    ext.handlePingPong(peerId, ping1)
    check cr.sentPongs.len == 1

    # second ping: 5 bytes, would exceed budget (6 + 5 = 11 > 10), should be rejected
    let ping2 = @[7'u8, 8, 9, 10, 11]
    ext.handlePingPong(peerId, ping2)
    check cr.sentPongs.len == 1 # no new pong sent

  test "budget is per peer":
    var cr = CallbackRecorder()
    let ext = PingPongExtension.new(cr.config(peerBudgetBytes = 5))

    let peerId2 = PeerId.random()

    # exhaust budget for peerId
    ext.handlePingPong(peerId, @[1'u8, 2, 3, 4, 5])
    check cr.sentPongs.len == 1

    # peerId budget exhausted
    ext.handlePingPong(peerId, @[1'u8])
    check cr.sentPongs.len == 1

    # peerId2 still has its own budget
    ext.handlePingPong(peerId2, @[1'u8, 2, 3, 4, 5])
    check cr.sentPongs.len == 2

  test "heartbeat resets budget for all peers":
    var cr = CallbackRecorder()
    let ext = PingPongExtension.new(cr.config(peerBudgetBytes = 5))

    let peerId2 = PeerId.random()

    # exhaust budget for both peers
    ext.handlePingPong(peerId, @[1'u8, 2, 3, 4, 5])
    ext.handlePingPong(peerId2, @[1'u8, 2, 3, 4, 5])
    check cr.sentPongs.len == 2

    # both rejected
    ext.handlePingPong(peerId, @[1'u8])
    ext.handlePingPong(peerId2, @[1'u8])
    check cr.sentPongs.len == 2

    # heartbeat resets both
    ext.onHeartbeat()

    ext.handlePingPong(peerId, @[1'u8])
    ext.handlePingPong(peerId2, @[1'u8])
    check cr.sentPongs.len == 4
