# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../libp2p/[multihash, multicodec]
import ../../tools/unittest

suite "MutliHash extensions":
  test "extended hashes correctly hash data":
    var data = cast[seq[byte]]("hello")
    let mh1 = MultiHash.digest("codec_mc1", data).get
    let mh2 = MultiHash.digest("codec_mc2", data).get
    let expected1 = "81FE030568656C6C6F"
    let expected2 = "82FE030668656C6C6F00"

    check:
      mh1.hex == expected1
      mh2.hex == expected2

  test "can initialise extended MultiHashes":
    var data = cast[seq[byte]]("hello")
    let mh1 = MultiHash.digest("codec_mc1", data).get
    let mh2 = MultiHash.digest("codec_mc2", data).get
    let expected1 = "81FE030568656C6C6F"
    let expected2 = "82FE030668656C6C6F00"
    let mhInit1 = MultiHash.init(expected1).get
    let mhInit2 = MultiHash.init(expected2).get

    check:
      mhInit1 == mh1
      mhInit2 == mh2
      mhInit1.mcodec == multiCodec("codec_mc1")
      mhInit2.mcodec == multiCodec("codec_mc2")
      mhInit1.size == 5
      mhInit2.size == 6
      mhInit1.data.len == 9
      mhInit2.data.len == 10
      mhInit1.dpos == 4
      mhInit2.dpos == 4

  test "can override hash function of default hash":
    # The first "sha2-256" registration is extended in the multihash module,
    # which uses sha2-256 coder for hashing. In multihash_exts.nim, we have
    # extended a new "sha2-256" which uses `sha2_256_override` for hashing.
    var data = cast[seq[byte]]("hello")
    let mh = MultiHash.digest("sha2-256", data).get
    let expected_orig =
      "12202CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824"
    let expected_override = "120668656C6C6F00"

    check:
      mh.hex == expected_override
      mh.hex != expected_orig
