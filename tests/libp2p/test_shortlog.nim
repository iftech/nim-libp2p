# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../libp2p/[multiaddress, protocodec]
import ../../libp2p/utils/[opt, shortlog]
import ../tools/unittest

{.push raises: [].}

type ShortItem = object
  value: string

func shortLog(item: ShortItem): string =
  "short-" & item.value

func openArrayShortLog(item: openArray[byte]): string =
  shortLog(item)

suite "Short log":
  test "byte overloads share the same short and truncated rendering":
    let
      shortBytes = @[byte 0xAB, 0xCD]
      longBytes = @[byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

    check:
      shortLog(shortBytes) == "abcd"
      openArrayShortLog(shortBytes) == "abcd"
      shortLog(longBytes) == "000102030405...0708090a0b0c"
      openArrayShortLog(longBytes) == "000102030405...0708090a0b0c"

  test "strings preserve values through the limit and shorten longer values":
    check:
      shortLog("012345678901") == "012345678901"
      shortLog("0123456789012") == "012345...789012"

  test "optional values use inner formatters, fallbacks, and unset markers":
    check:
      shortLog(Opt.some(ShortItem(value: "one"))) == "short-one"
      shortLog(Opt.some(42)) == "42"
      shortLog(Opt.none(ShortItem)) == "<unset>"

  test "generic collections are bounded and use element short logs":
    check shortLog(@[ShortItem(value: "one"), ShortItem(value: "two")], 1) ==
      "[short-one]...(+1 more)"

  test "generic collections render empty, fallback, and truncated values":
    check:
      shortLog(newSeq[int]()) == "[]"
      shortLog(@[1, 2]) == "[1, 2]"
      shortLog(@[1, 2], averageItemLength = 32) == "[1, 2]"
      shortLog(@[1, 2, 3, 4, 5, 6]) == "[1, 2, 3, 4, 5]...(+1 more)"

  test "multiaddress collections use the shared representation":
    var addrs: seq[MultiAddress]
    for port in 1 .. 6:
      addrs.add(MultiAddress.init("/ip4/127.0.0.1/tcp/" & $port).tryGet())

    check shortLog(addrs) ==
      "[/ip4/127.0.0.1/tcp/1, /ip4/127.0.0.1/tcp/2, /ip4/127.0.0.1/tcp/3, " &
      "/ip4/127.0.0.1/tcp/4, /ip4/127.0.0.1/tcp/5]...(+1 more)"

  test "codec collections keep full codecs and bound the item count":
    var codecs: seq[ProtoCodec]
    for i in 1 .. 6:
      codecs.add(ProtoCodec("/meshsub/1.0." & $i))

    check shortLog(codecs[0]) == "/meshsub/1.0.1"
    check shortLog(codecs) ==
      "[/meshsub/1.0.1, /meshsub/1.0.2, /meshsub/1.0.3, /meshsub/1.0.4, " &
      "/meshsub/1.0.5]...(+1 more)"
