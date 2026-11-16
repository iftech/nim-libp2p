# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results
import
  ../../libp2p/[crypto/crypto, multiaddress, multicodec, peerid, routing_record, varint]
import ../../libp2p/protocols/pubsub/rpc/[messages, protobuf]
import ../tools/[unittest, crypto]

proc varintBytes(v: uint64): seq[byte] =
  var buf: array[10, byte]
  var n = 0
  discard PB.putUVarint(buf, n, v)
  @(buf.toOpenArray(0, n - 1))

proc identityId(digestLen: int): seq[byte] =
  ## Identity multihash with a `digestLen`-byte digest
  var id = @[0x00'u8] & varintBytes(uint64(digestLen))
  for i in 0 ..< digestLen:
    id.add byte(i and 0xff) or 1
  id

proc withP2p(code: MultiCodec, id: openArray[byte]): seq[byte] =
  ## /ip4/127.0.0.1/tcp/1 followed by a /p2p/ (or /ipfs/) component holding `id`
  MultiAddress.init("/ip4/127.0.0.1/tcp/1").get().data.buffer & varintBytes(
    uint64(code)
  ) & varintBytes(uint64(id.len)) & @id

proc base58Text(prefix: string, n: int): string =
  ## `prefix` followed by base58 characters, `n` characters in total
  const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  var text = prefix
  while text.len < n:
    text.add alphabet[text.len mod alphabet.len]
  text

suite "PeerId length bound":
  test "identity multihash longer than an inline key is rejected":
    check:
      PeerId.init(identityId(maxInlineKeyLength)).get().len == maxPeerIdLength
      PeerId.init(identityId(maxInlineKeyLength + 1)).isErr()
      PeerId.init(identityId(64 * 1024)).isErr()
      # shortest forms are unchanged
      PeerId.init(@[0x00'u8, 0x00]).isOk()
      PeerId.init(@[0x00'u8]).isErr()
      PeerId.init(newSeq[byte]()).isErr()

  test "peer ids derived from keys stay valid":
    for (scheme, length) in [
      (PKScheme.RSA, 34),
      (PKScheme.Ed25519, 38),
      (PKScheme.Secp256k1, 39),
      (PKScheme.ECDSA, 34),
    ]:
      let
        pid = PeerId.init(PrivateKey.random(scheme, rng()).get()).get()
        address = MultiAddress.init("/ip4/127.0.0.1/tcp/1/p2p/" & $pid)
      checkpoint $scheme
      check:
        pid.data.len == length
        PeerId.init(pid.data).get() == pid
        PeerId.init($pid).get() == pid
        PeerId.init(pid.toCidString().get()).get() == pid
        address.isOk()
        MultiAddress.init(address.get().data.buffer).isOk()

  test "longest peer id texts are accepted":
    let longest = PeerId.init(identityId(maxInlineKeyLength)).get()
    check PeerId.init($longest).get() == longest
    for encoding in [
      "base32", "base32pad", "base32hexpadupper", "base58btc", "base64pad", "identity"
    ]:
      let text = longest.toCidString(encoding).get()
      checkpoint encoding & " " & $text.len
      check PeerId.init(text).get() == longest
    check longest.toCidString("base32pad").get().len == 81

  test "oversized peer ids are rejected when an RPC is decoded":
    let
      honest = PeerId.random(rng()).get()
      long = PeerId(data: identityId(64 * 1024))

    proc fromPeer(pid: PeerId): Message =
      Message(fromPeer: pid, topic: "t", data: @[1'u8], signature: @[1'u8])

    proc prunePx(pid: PeerId): RPCMsg =
      let
        px = PeerInfoMsg(peerId: Opt.some(pid))
        prune = ControlPrune(topicID: "t", peers: @[px])
      RPCMsg(control: Opt.some(ControlMessage(prune: @[prune])))

    let decoded = RPCMsg.decode(encode(RPCMsg(messages: @[fromPeer(honest)]), false))
    check:
      decoded.isOk()
      decoded.get().messages[0].fromPeer == honest
      RPCMsg.decode(encode(RPCMsg(messages: @[fromPeer(long)]), false)).isErr()
      Message.decode(encode(fromPeer(honest), false)).isOk()
      Message.decode(encode(fromPeer(long), false)).isErr()
      RPCMsg.decode(encode(prunePx(honest), false)).isOk()
      RPCMsg.decode(encode(prunePx(long), false)).isErr()

  test "oversized peer id in a peer record is rejected":
    let
      honest = PeerId.random(rng()).get()
      long = PeerRecord(peerId: PeerId(data: identityId(64 * 1024)), seqNo: 1)
    check:
      PeerRecord.decode(PeerRecord(peerId: honest, seqNo: 1).encode()).isOk()
      PeerRecord.decode(long.encode()).isErr()

  test "multiaddress with an oversized /p2p/ component is rejected":
    let
      honest = PeerId.random(rng()).get()
      p2p = multiCodec("p2p")
    check:
      MultiAddress.init(withP2p(p2p, honest.data)).isOk()
      MultiAddress.init(withP2p(p2p, identityId(maxInlineKeyLength))).isOk()
      MultiAddress.init(withP2p(p2p, identityId(maxInlineKeyLength + 1))).isErr()
      MultiAddress.init(withP2p(p2p, identityId(16 * 1024))).isErr()
      MultiAddress.init(withP2p(multiCodec("ipfs"), identityId(16 * 1024))).isErr()

  test "over-long peer id text is rejected":
    let
      legacy = base58Text("1", 64 * 1024)
      legacyQm = base58Text("Qm", 64 * 1024)
      cidv1 = base58Text("z", 64 * 1024)
      address = "/ip4/127.0.0.1/tcp/1/p2p/" & legacy
    check:
      PeerId.init(legacy).isErr()
      PeerId.init(legacyQm).isErr()
      PeerId.init(cidv1).isErr()
      MultiAddress.init(address).isErr()
