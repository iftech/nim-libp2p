# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../libp2p/[cid, multicodec, multihash]
import ../../tools/unittest

suite "ContentId extensions":
  test "extended contentids correctly hash data":
    var bmsg = cast[seq[byte]]("hello")
    var cid0 = Cid
      .init(CIDv1, multiCodec("codec_mc1"), MultiHash.digest("codec_mc2", bmsg).get())
      .tryGet()
    var cid1 = Cid
      .init(CIDv1, multiCodec("codec_mc2"), MultiHash.digest("codec_mc1", bmsg).get())
      .tryGet()
    check:
      cid0.hex == "0181FE0382FE030668656C6C6F00"
      cid1.hex == "0182FE0381FE030568656C6C6F"
      $cid0 == "zZ9hvSmq764xLht1dRH"
      $cid1 == "z8JZsv4DR12xsE7Fn6"

  test "can initialise extended Cids":
    let expected1 = "zZ9hvSmq764xLht1dRH"
    let expected2 = "z8JZsv4DR12xsE7Fn6"
    let cid1 = Cid.init(expected1).get
    let cid2 = Cid.init(expected2).get

    check:
      $cid1 == expected1
      cid1.version == CIDv1
      cid1.contentType.get == multiCodec("codec_mc1")
      cid1.mhash.get.mcodec == multiCodec("codec_mc2")
      $cid2 == expected2
      cid2.version == CIDv1
      cid2.contentType.get == multiCodec("codec_mc2")
      cid2.mhash.get.mcodec == multiCodec("codec_mc1")
