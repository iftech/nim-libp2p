# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/tables
import ../../../libp2p/multicodec
import ../../tools/unittest

suite "Multicodec extensions":
  test "can assign extended codecs by name":
    check:
      compiles:
        const codec_mc1 = multiCodec("codec_mc1")
        const codec_mc2 = multiCodec("codec_mc2")
        const codec_mc3 = multiCodec("codec_mc3")

  test "can assign extended codecs by code":
    check:
      compiles:
        const codec1x = multiCodec(0xFF01)
        const codec2x = multiCodec(0xFF02)
        const codec3x = multiCodec(0xFF03)

  test "extended codecs have correct codes at compile time":
    check:
      multiCodec("codec_mc1") == 0xFF01
      multiCodec("codec_mc2") == 0xFF02
      multiCodec("codec_mc3") == 0xFF03

  test "extended codecs have correct names at compile time":
    check:
      multiCodec(0xFF01) == multiCodec("codec_mc1")
      multiCodec(0xFF02) == multiCodec("codec_mc2")
      multiCodec(0xFF03) == multiCodec("codec_mc3")

  test "extended codecs have correct codes at runtime":
    check:
      MultiCodec.codec("codec_mc1") == 0xFF01
      MultiCodec.codec("codec_mc2") == 0xFF02
      MultiCodec.codec("codec_mc3") == 0xFF03

  test "extended codecs have correct names at runtime":
    check:
      MultiCodec.codec(0xFF01) == MultiCodec.codec("codec_mc1")
      MultiCodec.codec(0xFF02) == MultiCodec.codec("codec_mc2")
      MultiCodec.codec(0xFF03) == MultiCodec.codec("codec_mc3")

  test "prints name at compile time":
    check:
      multiCodec(0xFF01) == "codec_mc1"
      multiCodec(0xFF02) == "codec_mc2"
      multiCodec(0xFF03) == "codec_mc3"

  test "prints name at runtime":
    check:
      MultiCodec.codec(0xFF01) == "codec_mc1"
      MultiCodec.codec(0xFF02) == "codec_mc2"
      MultiCodec.codec(0xFF03) == "codec_mc3"

  test "can compare MultiCodec to string name and int code":
    check:
      MultiCodec.codec(0xFF01) == "codec_mc1"
      MultiCodec.codec(0xFF02) == "codec_mc2"
      MultiCodec.codec(0xFF03) == "codec_mc3"
      MultiCodec.codec("codec_mc1") == 0xFF01
      MultiCodec.codec("codec_mc2") == 0xFF02
      MultiCodec.codec("codec_mc3") == 0xFF03

  test "extended codecs are the same at compile time and runtime":
    check:
      MultiCodec.codec(0xFF01) == multiCodec(0xFF01)
      MultiCodec.codec(0xFF02) == multiCodec(0xFF02)
      MultiCodec.codec(0xFF03) == multiCodec(0xFF03)
      MultiCodec.codec("codec_mc1") == multiCodec("codec_mc1")
      MultiCodec.codec("codec_mc2") == multiCodec("codec_mc2")
      MultiCodec.codec("codec_mc3") == multiCodec("codec_mc3")
      MultiCodec.codec(0xFF01) == multiCodec("codec_mc1")
      MultiCodec.codec(0xFF02) == multiCodec("codec_mc2")
      MultiCodec.codec(0xFF03) == multiCodec("codec_mc3")
      MultiCodec.codec("codec_mc1") == multiCodec(0xFF01)
      MultiCodec.codec("codec_mc2") == multiCodec(0xFF02)
      MultiCodec.codec("codec_mc3") == multiCodec(0xFF03)

  test "referencing unextended codecs by name does not compile":
    check:
      not compiles(multiCodec("codecX"))

  test "referencing unextended codecs by code does not compile":
    check:
      not compiles(multiCodec(0x9999))

  test "referencing unextended codecs by name at runtime returns InvalidMultiCodec":
    check:
      MultiCodec.codec("codecX") == InvalidMultiCodec

  test "referencing unextended codecs by code at runtime returns InvalidMultiCodec":
    check:
      MultiCodec.codec(0x9999) == InvalidMultiCodec
