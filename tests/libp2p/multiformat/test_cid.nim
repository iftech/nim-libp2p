# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sets
import ../../../libp2p/[cid, multihash, multicodec]
import ../../tools/[unittest]

suite "Content identifier CID test suite":
  test "CIDv0 test vector":
    var cid0Text = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"
    var cid0 = Cid.init(cid0Text).tryGet()
    check:
      $cid0 == cid0Text
      cid0.version() == CIDv0
      cid0.contentType().tryGet() == multiCodec("dag-pb")
      cid0.mhash().tryGet().mcodec == multiCodec("sha2-256")
      Cid.init("QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zIII").isErr()

  test "CIDv1 test vector":
    var cid1Text = "zb2rhhFAEMepUBbGyP1k8tGfz7BSciKXP6GHuUeUsJBaK6cqG"
    var chex =
      "015512209D8453505BDC6F269678E16B3E56" & "C2A2948A41F2C792617CC9611ED363C95B63"
    var cid1 = Cid.init(cid1Text).tryGet()
    check:
      $cid1 == cid1Text
      cid1.version() == CIDv1
      cid1.contentType().tryGet() == multiCodec("raw")
      cid1.mhash().tryGet().mcodec == multiCodec("sha2-256")
      hex(cid1) == chex

  test "Comparison test":
    var msg = "Hello World!"
    var mmsg = "Hello World!Hello World!"
    var bmsg = cast[seq[byte]](msg)
    var bmmsg = cast[seq[byte]](mmsg)
    var cid0 = Cid
      .init(CIDv0, multiCodec("dag-pb"), MultiHash.digest("sha2-256", bmsg).get())
      .tryGet()
    var cid1 = Cid
      .init(CIDv1, multiCodec("dag-pb"), MultiHash.digest("sha2-256", bmsg).get())
      .tryGet()
    var cid2 = cid1
    var cid3 = cid0
    var cid4 = Cid
      .init(CIDv1, multiCodec("dag-cbor"), MultiHash.digest("sha2-256", bmsg).get())
      .tryGet()
    var cid5 = Cid
      .init(CIDv1, multiCodec("dag-pb"), MultiHash.digest("sha2-256", bmmsg).get())
      .tryGet()
    var cid6 = Cid
      .init(CIDv1, multiCodec("dag-pb"), MultiHash.digest("keccak-256", bmsg).get())
      .tryGet()
    check:
      cid0 == cid1
      hash(cid0) == hash(cid1)
      cid1 in [cid0].toHashSet()
      cid1 == cid2
      cid2 == cid3
      cid3 == cid0
      cid0 != cid4
      cid1 != cid5
      cid2 != cid4
      cid3 != cid6

  test "Binary validation agrees with decoding":
    let digest = MultiHash.digest("sha2-256", [byte 1, 2, 3]).get()
    for version in [CIDv0, CIDv1]:
      let encoded = Cid.init(version, multiCodec("dag-pb"), digest).get().data.buffer
      check Cid.validate(encoded)
      check not Cid.validate(encoded[0 ..< encoded.high])
      check not Cid.validate(encoded & @[0.byte])
    check not Cid.validate([])
    check not Cid.validate([1.byte])
    check not Cid.validate([1.byte, 0xff])
    check not Cid.validate([1.byte, 0x70])

  test "decode rejects malformed input":
    let digest = MultiHash.digest("sha2-256", [byte 1, 2, 3]).get()
    check:
      Cid.init(newSeq[byte]()).error() == CidError.Incorrect
      Cid.init([byte 0x80]).error() == CidError.Incorrect
      Cid.init(@[byte 0x02, 0x55] & digest.data.buffer).error() == CidError.Incorrect
      Cid.init(@[byte 0x01, 0x12] & digest.data.buffer).error() == CidError.Incorrect
      Cid.init([byte 0x01, 0x55, 0x12, 0x01]).error() == CidError.Incorrect
      Cid.init("").error() == CidError.Incorrect
      Cid.init("!abc").error() == CidError.Incorrect

  test "init rejects unsupported version, content type and hash":
    let data = [byte 1, 2, 3]
    let sha = MultiHash.digest("sha2-256", data).get()
    let keccak = MultiHash.digest("keccak-256", data).get()
    check:
      Cid.init(CIDv0, multiCodec("raw"), sha).error() == CidError.Unsupported
      Cid.init(CIDv0, multiCodec("dag-pb"), keccak).error() == CidError.Unsupported
      Cid.init(CIDv1, multiCodec("sha2-256"), sha).error() == CidError.Incorrect
      Cid.init(CIDvReserved, multiCodec("dag-pb"), sha).error() == CidError.Unsupported

  test "empty Cid":
    let empty = Cid()
    check:
      empty.mhash().error() == CidError.Incorrect
      empty.contentType().error() == CidError.Incorrect
      $empty == ""
