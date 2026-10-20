# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, strutils, stew/[byteutils, endians2], results, nimcrypto/sha2
import
  ../../../libp2p/[
    peerid,
    peerinfo,
    crypto/crypto as crypto,
    protocols/pubsub/errors,
    protocols/pubsub/rpc/message,
    protocols/pubsub/rpc/messages,
    protocols/pubsub/rpc/protobuf,
    utils/shortlog,
  ]
import ../../tools/[unittest, crypto as cryptoTools]
import converters

suite "Message":
  const topic = "foobar"

  test "log formatting uses short byte values and renders seqno":
    let
      seqno = 42'u64
      message = Message(
        data: "message-payload-secret".toBytes(),
        seqno: @(seqno.toBytesBE()),
        topic: topic,
        signature: "signature-secret".toBytes(),
        key: "key-secret".toBytes(),
      )
      logMsg = $chroniclesFormatItIMPL(message)

    check:
      strutils.contains(logMsg, "dataLen")
      strutils.contains(logMsg, "signaturePresent")
      not strutils.contains(logMsg, message.data.shortLog)
      not strutils.contains(logMsg, message.signature.shortLog)
      strutils.contains(logMsg, message.key.shortLog)
      shortLog(message).seqno == $seqno
      shortLog(Message(topic: topic)).seqno == "<unset>"

  test "signature":
    var seqno = 11'u64
    let
      peer = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get())
      msg = Message.init(Opt.some(peer), @[], topic, Opt.some(seqno), sign = true)

    check verify(msg)

  test "signature with missing key":
    let
      seqno = 11'u64
      seckey = PrivateKey.random(Ed25519, rng()).get()
      peer = PeerInfo.new(seckey)
    check peer.peerId.hasPublicKey() == true
    var msg = Message.init(Opt.some(peer), @[], topic, Opt.some(seqno), sign = true)
    msg.key = @[]
    # get the key from fromPeer field (inlined)
    check verify(msg)

  test "signature rejects padded inline PeerId":
    let
      seqno = 11'u64
      seckey = PrivateKey.random(Ed25519, rng()).get()
      peer = PeerInfo.new(seckey)
    var msg = Message.init(Opt.some(peer), @[], topic, Opt.some(seqno), sign = true)
    msg.fromPeer.data.add(0'u8)
    msg.key = @[]
    msg.signature = sign(msg, seckey).tryGet()

    check not verify(msg)

  test "signature without inlined pubkey in peerId":
    let
      seqno = 11'u64
      peer = PeerInfo.new(PrivateKey.random(RSA, rng()).get())
    var msg = Message.init(Opt.some(peer), @[], topic, Opt.some(seqno), sign = true)
    msg.key = @[]
    # shouldn't work since there's no key field
    # and the key is not inlined in peerid (too large)
    check verify(msg) == false

  test "defaultMsgIdProvider success":
    let
      seqno = 11'u64
      pkHex = """08011240B9EA7F0357B5C1247E4FCB5AD09C46818ECB07318CA84711875F4C6C
        E6B946186A4EB44E0D714B2A2D48263D75CF52D30BEF9D9AE2A9FEB7DAF1775F
        E731065A"""
      seckey = PrivateKey.init(crypto.fromHex(stripSpaces(pkHex))).expect(
          "valid private key bytes"
        )
      peer = PeerInfo.new(seckey)
      msg = Message.init(Opt.some(peer), @[], topic, Opt.some(seqno), sign = true)
      msgIdResult = msg.defaultMsgIdProvider()

    check:
      msgIdResult.isOk
      string.fromBytes(msgIdResult.get) ==
        "000000000000000b12D3KooWGyLzSt9g4U9TdHYDvVWAs5Ht4WrocgoyqPxxvnqAL8qw"

  test "defaultMsgIdProvider error - no source peer id":
    let
      seqno = 11'u64
      pkHex = """08011240B9EA7F0357B5C1247E4FCB5AD09C46818ECB07318CA84711875F4C6C
        E6B946186A4EB44E0D714B2A2D48263D75CF52D30BEF9D9AE2A9FEB7DAF1775F
        E731065A"""
      seckey = PrivateKey.init(crypto.fromHex(stripSpaces(pkHex))).expect(
          "valid private key bytes"
        )
      peer = PeerInfo.new(seckey)

    var msg = Message.init(Opt.some(peer), @[], topic, Opt.some(seqno), sign = true)
    msg.fromPeer = PeerId()
    let msgIdResult = msg.defaultMsgIdProvider()

    check:
      msgIdResult.isErr
      msgIdResult.error == ValidationResult.Reject

  test "defaultMsgIdProvider error - no source seqno":
    let
      pkHex = """08011240B9EA7F0357B5C1247E4FCB5AD09C46818ECB07318CA84711875F4C6C
        E6B946186A4EB44E0D714B2A2D48263D75CF52D30BEF9D9AE2A9FEB7DAF1775F
        E731065A"""
      seckey = PrivateKey.init(crypto.fromHex(stripSpaces(pkHex))).expect(
          "valid private key bytes"
        )
      peer = PeerInfo.new(seckey)
      msg = Message.init(Opt.some(peer), @[], topic, Opt.none(uint64), sign = true)
      msgIdResult = msg.defaultMsgIdProvider()

    check:
      msgIdResult.isErr
      msgIdResult.error == ValidationResult.Reject

  test "byteSize for RPCMsg":
    let msg = Message(
      fromPeer: PeerId(data: @['a'.byte, 'b'.byte]), # 2 bytes
      data: @[1'u8, 2, 3], # 3 bytes
      seqno: @[4'u8, 5], # 2 bytes
      signature: @['c'.byte, 'd'.byte], # 2 bytes
      key: @[6'u8, 7], # 2 bytes
      topic: "abcde", # 5 bytes
    )
    check byteSize(msg) == 16

    let peerInfo = PeerInfoMsg(
      peerId: PeerId(data: @['e'.byte]), # 1 byte
      signedPeerRecord: @['f'.byte, 'g'.byte], # 2 bytes
    )

    let controlIHave = ControlIHave(
      topicID: "ijk", # 3 bytes
      messageIDs: @[@['l'.byte], @['m'.byte, 'n'.byte]], # 1 + 2 = 3 bytes
    )

    let controlIWant = ControlIWant(
      messageIDs: @[@['o'.byte, 'p'.byte], @['q'.byte]] # 2 + 1 = 3 bytes
    )

    let controlGraft = ControlGraft(
      topicID: "rst" # 3 bytes
    )

    let controlPrune = ControlPrune(
      topicID: "uvw", # 3 bytes
      peers: @[peerInfo, peerInfo], # (1 + 2) * 2 = 6 bytes
      backoff: 12345678.uint64, # 8 bytes for uint64
    )

    let control = ControlMessage(
      ihave: @[controlIHave, controlIHave], # (3 + 3) * 2 = 12 bytes
      iwant: @[controlIWant], # 3 bytes
      graft: @[controlGraft], # 3 bytes
      prune: @[controlPrune], # 3 + 6 + 8 = 17 bytes
      idontwant: @[controlIWant], # 3 bytes
    )

    let partialMessageExtensionRPC = PartialMessageExtensionRPC(
      topicID: "a", # 1 byte
      groupID: @[1'u8], # 1 byte
      partialMessage: @[1'u8], # 1 byte
      partsMetadata: @[1'u8], # 1 byte
    )

    let pingPongExtensionRPC = PingPongExtensionRPC(
      ping: @[1'u8, 2], # 2 bytes
      pong: @[3'u8, 4], # 2 bytes
    )

    let rpcMsg = RPCMsg(
      subscriptions: @[
        SubOpts(
          subscribe: true,
          topic: "a".repeat(12),
          requestsPartial: Opt.some(true),
          supportsSendingPartial: Opt.some(true),
        ), # 1 + 12 + 1 + 1 = 15 bytes
        SubOpts(subscribe: false, topic: "b".repeat(14)), # 1 + 14 = 15 bytes
      ],
      messages: @[msg, msg], # 16 * 2 = 32 bytes
      control: Opt.some(control), # 12 + 3 + 3 + 17 + 3 = 38 bytes
      partialMessageExtension: Opt.some(partialMessageExtensionRPC), # 4 bytes
      pingpongExtension: Opt.some(pingPongExtensionRPC), # 4 bytes
    )
    check byteSize(rpcMsg) == 30 + 32 + 38 + 4 + 4 # Total: 108 bytes

    check rpcMsg.encodedSize() == rpcMsg.encode(false).len

  test "downstream-compatible public pubsub fields":
    let
      peerId = PeerId(data: @[1'u8, 2, 3])
      message = Message(data: @[4'u8, 5, 6], topic: topic, fromPeer: peerId)
      digest = sha256.digest(message.data)
      ihave = ControlIHave(topicID: topic, messageIDs: @[])
      graft = ControlGraft(topicID: topic)
      prune = ControlPrune(topicID: topic, backoff: 10.uint64)

    proc validator(message: Message): ValidationResult =
      if message.fromPeer == peerId and message.data.len > 0:
        ValidationResult.Accept
      else:
        ValidationResult.Reject

    proc observe(
        ihave: ControlIHave, graft: ControlGraft, prune: ControlPrune
    ): string =
      ihave.topicID & graft.topicID & prune.topicID & $prune.backoff

    check:
      message.topic == topic
      message.data == @[4'u8, 5, 6]
      digest.data.len == sha256.sizeDigest
      validator(message) == ValidationResult.Accept
      observe(ihave, graft, prune) == topic & topic & topic & "10"

  test "Message decode defaults absent restored wire fields":
    let encoded: seq[byte] = @[34, 6, 102, 111, 111, 98, 97, 114]
    let message = Message.decode(encoded).get()

    check:
      message.topic == topic
      message.data == @[]
      message.fromPeer == PeerId()
      message.seqno == @[]
      message.signature == @[]
      message.key == @[]

  test "RPCMsg decode defaults absent restored wire fields":
    let
      encodedMessage: seq[byte] = @[18, 8, 34, 6, 102, 111, 111, 98, 97, 114]
      messageRpc = RPCMsg.decode(encodedMessage).get()
      encodedIHave: seq[byte] = @[26, 2, 10, 0]
      ihaveRpc = RPCMsg.decode(encodedIHave).get()
      encodedGraft: seq[byte] = @[26, 2, 26, 0]
      graftRpc = RPCMsg.decode(encodedGraft).get()
      encodedPrune: seq[byte] = @[26, 2, 34, 0]
      pruneRpc = RPCMsg.decode(encodedPrune).get()

    check:
      messageRpc.messages.len == 1
      messageRpc.messages[0].topic == topic
      messageRpc.messages[0].data == @[]
      messageRpc.messages[0].fromPeer == PeerId()
      ihaveRpc.control.isSome
      ihaveRpc.control.get().ihave.len == 1
      ihaveRpc.control.get().ihave[0].topicID == ""
      ihaveRpc.control.get().ihave[0].messageIDs.len == 0
      graftRpc.control.isSome
      graftRpc.control.get().graft.len == 1
      graftRpc.control.get().graft[0].topicID == ""
      pruneRpc.control.isSome
      pruneRpc.control.get().prune.len == 1
      pruneRpc.control.get().prune[0].topicID == ""
      pruneRpc.control.get().prune[0].backoff == 0

  test "Message decode still requires topic":
    check Message.decode(@[]).isErr

  test "RPCMsg decode still requires nested Message topic":
    check RPCMsg.decode(@[18.byte, 0]).isErr

  # check correctly parsed ihave/iwant/graft/prune/idontwant messages
  # check value before & after decoding equal using protoc cmd tool for reference
  asyncTest "RPCMsg:ControlMessage - encoding and decoding":
    let id: seq[byte] = @[123]
    let message = RPCMsg(
      control: Opt.some(
        ControlMessage(
          ihave: @[ControlIHave(topicID: topic, messageIDs: @[id])],
          iwant: @[ControlIWant(messageIDs: @[id])],
          graft: @[ControlGraft(topicID: topic)],
          prune: @[ControlPrune(topicID: topic, backoff: 10.uint64)],
          idontwant: @[ControlIWant(messageIDs: @[id])],
        )
      )
    )
    #data encoded using protoc cmd tool
    let expectedEncoded: seq[byte] = @[
      26, 45, 10, 11, 10, 6, 102, 111, 111, 98, 97, 114, 18, 1, 123, 18, 3, 10, 1, 123,
      26, 8, 10, 6, 102, 111, 111, 98, 97, 114, 34, 10, 10, 6, 102, 111, 111, 98, 97,
      114, 24, 10, 42, 3, 10, 1, 123,
    ]

    let actualEncoded = message.encode(true)
    check:
      actualEncoded == expectedEncoded

    let actualDecoded = RPCMsg.decode(expectedEncoded).get()
    check:
      actualDecoded == message

  asyncTest "RPCMsg:testExtension - encoding and decoding":
    let messageWith = RPCMsg(testExtension: Opt.some(TestExtensionRPC()))
    var decoded = RPCMsg.decode(encode(messageWith, true)).get()
    check decoded.testExtension.isSome()

    let messageWithout = RPCMsg(testExtension: Opt.none(TestExtensionRPC))
    decoded = RPCMsg.decode(encode(messageWithout, true)).get()
    check decoded.testExtension.isNone()

  test "anonymize Message - anonymize=true strips identity fields":
    let peer = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get())
    let msg =
      Message.init(Opt.some(peer), @[1'u8, 2, 3], topic, Opt.some(1'u64), sign = true)
    let anon = msg.anonymize(true)
    check:
      anon.data == msg.data
      anon.topic == msg.topic
      anon.fromPeer.data.len == 0
      anon.seqno.len == 0
      anon.signature.len == 0
      anon.key.len == 0

  test "anonymize Message - anonymize=false returns message unchanged":
    let peer = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get())
    let msg =
      Message.init(Opt.some(peer), @[1'u8, 2, 3], topic, Opt.some(1'u64), sign = true)
    let anon = msg.anonymize(false)
    check:
      anon.fromPeer == msg.fromPeer
      anon.seqno == msg.seqno
      anon.signature == msg.signature
      anon.key == msg.key
      anon.data == msg.data
      anon.topic == msg.topic

  test "anonymize RPCMsg - anonymize=true strips identity fields from all messages":
    let peer = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get())
    let msg1 =
      Message.init(Opt.some(peer), @[1'u8], topic, Opt.some(1'u64), sign = true)
    let msg2 =
      Message.init(Opt.some(peer), @[2'u8], topic, Opt.some(2'u64), sign = true)
    let rpc = RPCMsg(messages: @[msg1, msg2])
    let anon = rpc.anonymize(true)
    for m in anon.messages:
      check:
        m.fromPeer.data.len == 0
        m.seqno.len == 0
        m.signature.len == 0
        m.key.len == 0
    check:
      anon.messages[0].data == msg1.data
      anon.messages[1].data == msg2.data

  test "anonymize RPCMsg - anonymize=false returns RPCMsg unchanged":
    let peer = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get())
    let msg = Message.init(Opt.some(peer), @[1'u8], topic, Opt.some(1'u64), sign = true)
    let rpc = RPCMsg(messages: @[msg])
    let anon = rpc.anonymize(false)
    check:
      anon.messages[0].fromPeer == msg.fromPeer
      anon.messages[0].seqno == msg.seqno
      anon.messages[0].signature == msg.signature
      anon.messages[0].key == msg.key

  test "anonymize RPCMsg - anonymize=true with no messages returns unchanged":
    let rpc = RPCMsg(subscriptions: @[SubOpts(subscribe: true, topic: topic)])
    let anon = rpc.anonymize(true)
    check anon.messages.len == 0
