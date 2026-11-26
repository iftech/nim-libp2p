# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import results
import
  ../../../libp2p/
    [multiaddress, peerid, protocols/kademlia, protocols/kademlia/protobuf]
import ../../tools/[unittest, multiaddress]
import ./utils

suite "KadDHT Protobuffers":
  test "Message encode/decode":
    let maddrs = @[ma("/ip4/127.0.0.1/tcp/9000")]
    # encode with hideConnectionStatus=false to preserve connection type for round-trip check
    let peer =
      Peer(id: @[1'u8, 2, 3], addrs: maddrs, connection: ConnectionStatus.connected)
    check peer == Peer.decode(peer.encode(hideConnectionStatus = false)).get()

    let msg = Message(
      msgType: MessageType.putValue,
      key: Key.init([1'u8]),
      record:
        Record(key: Key.init([1'u8]), value: Value.init([2'u8]), timeReceived: "t"),
      closerPeers: @[Peer(id: @[9'u8], addrs: maddrs, connection: canConnect)],
      providerPeers: @[Peer(id: @[9'u8], addrs: maddrs, connection: canConnect)],
    )
    check msg == Message.decode(msg.encode(hideConnectionStatus = false)).get()

  test "Peer with empty addr list and no connection":
    let peer = Peer(id: @[0x42'u8], addrs: @[], connection: Opt.none(ConnectionStatus))
    let encoded = peer.encode()
    let decoded = Peer.decode(encoded).get()
    check:
      decoded == peer

  test "Peer with multiple multiaddresses":
    let maddrs = @[
      ma("/ip4/127.0.0.1/tcp/9000"),
      ma("/ip4/192.168.1.1/tcp/4001"),
      ma("/ip6/::1/tcp/9000"),
      ma("/dns4/example.com/tcp/443"),
    ]
    let peer = Peer(id: @[1'u8, 2, 3, 4, 5], addrs: maddrs, connection: canConnect)
    let encoded = peer.encode(hideConnectionStatus = false)
    let decoded = Peer.decode(encoded).get()
    check:
      decoded == peer
      decoded.addrs == maddrs

  test "Message with empty closer/provider peers":
    let msg = Message(
      msgType: MessageType.ping,
      key: Key.init([7'u8]),
      record: Opt.none(Record),
      closerPeers: @[],
      providerPeers: @[],
    )
    let encoded = msg.encode()
    let decoded = Message.decode(encoded).tryGet()
    check:
      decoded == msg

  test "Peer encode with hideConnectionStatus=true always emits notConnected":
    let maddrs = @[ma("/ip4/127.0.0.1/tcp/9000")]
    for ct in [connected, canConnect, cannotConnect, notConnected]:
      let peer = Peer(id: @[1'u8, 2, 3], addrs: maddrs, connection: ct)
      let decoded = Peer.decode(peer.encode(hideConnectionStatus = true)).get()
      check decoded.connection == Opt.none(ConnectionStatus)

  test "Peer encode with hideConnectionStatus=false preserves actual connection type":
    let maddrs = @[ma("/ip4/127.0.0.1/tcp/9000")]
    for ct in [connected, canConnect, cannotConnect, notConnected]:
      let peer = Peer(id: @[1'u8, 2, 3], addrs: maddrs, connection: ct)
      let decoded = Peer.decode(peer.encode(hideConnectionStatus = false)).get()
      check decoded.connection == ct

  test "Message encode with hideConnectionStatus=true hides connection in both peer lists":
    let maddrs = @[ma("/ip4/127.0.0.1/tcp/9000")]
    let msg = Message(
      msgType: MessageType.findNode,
      key: Key.init([1'u8]),
      closerPeers: @[Peer(id: @[2'u8], addrs: maddrs, connection: connected)],
      providerPeers: @[Peer(id: @[3'u8], addrs: maddrs, connection: canConnect)],
    )
    let decoded = Message.decode(msg.encode(hideConnectionStatus = true)).get()
    check decoded.closerPeers[0].connection == Opt.none(ConnectionStatus)
    check decoded.providerPeers[0].connection == Opt.none(ConnectionStatus)

  test "KadDHTConfig hideConnectionStatus defaults to true":
    let cfg = KadDHTConfig.new()
    check cfg.hideConnectionStatus == true

  test "Record ignores a key or value field sent as a varint":
    let noKey = Record.decode(@[0x08'u8, 1]).expect("varint key is skipped")
    let noValue =
      Record.decode(@[0x0A'u8, 1, 7, 0x10, 1]).expect("varint value is skipped")

    check:
      noKey.key.isNone()
      noValue.key == Key.fromBytes(@[7'u8])
      noValue.value.isNone()

suite "KadDHT Protobuffers - AddProviderStatus":
  test "round-trip for AddProviderStatus":
    let accepted = Message(
      msgType: MessageType.addProvider,
      providerStatus: Opt.some(AddProviderStatus.accepted),
    )
    let rejected = Message(
      msgType: MessageType.addProvider,
      providerStatus: Opt.some(AddProviderStatus.rejected),
    )
    let noStatus = Message(
      msgType: MessageType.addProvider, providerStatus: Opt.none(AddProviderStatus)
    )

    let decodedAccepted = Message.decode(accepted.encode()).valueOr:
      raiseAssert("decode of accepted failed")
    let decodedRejected = Message.decode(rejected.encode()).valueOr:
      raiseAssert("decode of rejected failed")
    let decodedNoStatus = Message.decode(noStatus.encode()).valueOr:
      raiseAssert("decode of noStatus failed")

    check:
      decodedAccepted.providerStatus == AddProviderStatus.accepted
      decodedRejected.providerStatus == AddProviderStatus.rejected
      decodedNoStatus.providerStatus.isNone()
