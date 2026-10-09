# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results
import ../../../libp2p/multibase
import ../../tools/[unittest]

const GoTestVectors = [
  ["identity", "\x00Decentralize everything!!!", "Decentralize everything!!!"],
  # [
  #   "base16",
  #   "f446563656e7472616c697a652065766572797468696e67212121",
  #   "Decentralize everything!!!"
  # ],
  # [
  #   "base16upper",
  #   "F446563656E7472616C697A652065766572797468696E67212121",
  #   "Decentralize everything!!!"
  # ],
  [
    "base32", "birswgzloorzgc3djpjssazlwmvzhs5dinfxgoijbee",
    "Decentralize everything!!!",
  ],
  [
    "base32upper", "BIRSWGZLOORZGC3DJPJSSAZLWMVZHS5DINFXGOIJBEE",
    "Decentralize everything!!!",
  ],
  [
    "base32pad", "cirswgzloorzgc3djpjssazlwmvzhs5dinfxgoijbee======",
    "Decentralize everything!!!",
  ],
  [
    "base32padupper", "CIRSWGZLOORZGC3DJPJSSAZLWMVZHS5DINFXGOIJBEE======",
    "Decentralize everything!!!",
  ],
  [
    "base32hex", "v8him6pbeehp62r39f9ii0pbmclp7it38d5n6e89144",
    "Decentralize everything!!!",
  ],
  [
    "base32hexupper", "V8HIM6PBEEHP62R39F9II0PBMCLP7IT38D5N6E89144",
    "Decentralize everything!!!",
  ],
  [
    "base32hexpad", "t8him6pbeehp62r39f9ii0pbmclp7it38d5n6e89144======",
    "Decentralize everything!!!",
  ],
  [
    "base32hexpadupper", "T8HIM6PBEEHP62R39F9II0PBMCLP7IT38D5N6E89144======",
    "Decentralize everything!!!",
  ],
  ["base58btc", "z36UQrhJq9fNDS7DiAHM9YXqDHMPfr4EMArvt", "Decentralize everything!!!"],
  ["base64", "mRGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE", "Decentralize everything!!!"],
  ["base64url", "uRGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE", "Decentralize everything!!!"],
  ["base64pad", "MRGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE=", "Decentralize everything!!!"],
  [
    "base64urlpad", "URGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE=",
    "Decentralize everything!!!",
  ],
]

suite "MultiBase test suite":
  test "Zero-length data encoding/decoding test":
    var enc = newString(1)
    var dec = newSeq[byte]()
    var plain = newSeq[byte]()
    var olens: array[21, int]
    check:
      MultiBase.encodedLength("identity", 0) == 1
      MultiBase.decodedLength('\x00', 0) == -1
      MultiBase.decodedLength('\x00', 1) == 0
    check:
      MultiBase.encode("identity", plain).get() == "\x00"
      # MultiBase.encode("base1", plain) == "1"
      # MultiBase.encode("base2", plain) == "0"
      # MultiBase.encode("base8", plain) == "7"
      # MultiBase.encode("base10", plain) == "9"
      # MultiBase.encode("base16", plain) == "f"
      # MultiBase.encode("base16upper", plain) == "F"
      MultiBase.encode("base32hex", plain).get() == "v"
      MultiBase.encode("base32hexupper", plain).get() == "V"
      MultiBase.encode("base32hexpad", plain).get() == "t"
      MultiBase.encode("base32hexpadupper", plain).get() == "T"
      MultiBase.encode("base32", plain).get() == "b"
      MultiBase.encode("base32upper", plain).get() == "B"
      MultiBase.encode("base32pad", plain).get() == "c"
      MultiBase.encode("base32padupper", plain).get() == "C"
      MultiBase.encode("base58btc", plain).get() == "z"
      MultiBase.encode("base58flickr", plain).get() == "Z"
      MultiBase.encode("base64", plain).get() == "m"
      MultiBase.encode("base64pad", plain).get() == "M"
      MultiBase.encode("base64url", plain).get() == "u"
      MultiBase.encode("base64urlpad", plain).get() == "U"
    check:
      len(MultiBase.decode("\x00").get()) == 0
      # len(MultiBase.decode("1")) == 0
      # len(MultiBase.decode("0")) == 0
      # len(MultiBase.decode("7")) == 0
      # len(MultiBase.decode("9")) == 0
      # len(MultiBase.decode("f")) == 0
      # len(MultiBase.decode("F")) == 0
      len(MultiBase.decode("v").get()) == 0
      len(MultiBase.decode("V").get()) == 0
      len(MultiBase.decode("t").get()) == 0
      len(MultiBase.decode("T").get()) == 0
      len(MultiBase.decode("b").get()) == 0
      len(MultiBase.decode("B").get()) == 0
      len(MultiBase.decode("c").get()) == 0
      len(MultiBase.decode("C").get()) == 0
      len(MultiBase.decode("z").get()) == 0
      len(MultiBase.decode("Z").get()) == 0
      len(MultiBase.decode("m").get()) == 0
      len(MultiBase.decode("M").get()) == 0
      len(MultiBase.decode("u").get()) == 0
      len(MultiBase.decode("U").get()) == 0
    check:
      MultiBase.encode("identity", plain, enc, olens[0]) == MultiBaseStatus.Success
      enc == "\x00"
      olens[0] == 1
      # MultiBase.encode("base1", plain, enc,
      #                  olens[1]) == MultiBaseStatus.Success
      # enc == "1"
      # olens[1] == 1
      # MultiBase.encode("base2", plain, enc,
      #                  olens[2]) == MultiBaseStatus.Success
      # enc == "0"
      # olens[2] == 1
      # MultiBase.encode("base8", plain, enc,
      #                  olens[3]) == MultiBaseStatus.Success
      # enc == "7"
      # olens[3] == 1
      # MultiBase.encode("base10", plain, enc,
      #                  olens[4]) == MultiBaseStatus.Success
      # enc == "9"
      # olens[4] == 1
      # MultiBase.encode("base16", plain, enc,
      #                  olens[5]) == MultiBaseStatus.Success
      # enc == "f"
      # olens[5] == 1
      # MultiBase.encode("base16upper", plain, enc,
      #                  olens[6]) == MultiBaseStatus.Success
      # enc == "F"
      # olens[6] == 1
      MultiBase.encode("base32hex", plain, enc, olens[7]) == MultiBaseStatus.Success
      enc == "v"
      olens[7] == 1
      MultiBase.encode("base32hexupper", plain, enc, olens[8]) == MultiBaseStatus.Success
      enc == "V"
      olens[8] == 1
      MultiBase.encode("base32hexpad", plain, enc, olens[9]) == MultiBaseStatus.Success
      enc == "t"
      olens[9] == 1
      MultiBase.encode("base32hexpadupper", plain, enc, olens[10]) ==
        MultiBaseStatus.Success
      enc == "T"
      olens[10] == 1
      MultiBase.encode("base32", plain, enc, olens[11]) == MultiBaseStatus.Success
      enc == "b"
      olens[11] == 1
      MultiBase.encode("base32upper", plain, enc, olens[12]) == MultiBaseStatus.Success
      enc == "B"
      olens[12] == 1
      MultiBase.encode("base32pad", plain, enc, olens[13]) == MultiBaseStatus.Success
      enc == "c"
      olens[13] == 1
      MultiBase.encode("base32padupper", plain, enc, olens[14]) ==
        MultiBaseStatus.Success
      enc == "C"
      olens[14] == 1
      MultiBase.encode("base58btc", plain, enc, olens[15]) == MultiBaseStatus.Success
      enc == "z"
      olens[15] == 1
      MultiBase.encode("base58flickr", plain, enc, olens[16]) == MultiBaseStatus.Success
      enc == "Z"
      olens[16] == 1
    check:
      MultiBase.decode("", dec, olens[0]) == MultiBaseStatus.Incorrect
      MultiBase.decode("\x00", dec, olens[0]) == MultiBaseStatus.Success
      olens[0] == 0
      # MultiBase.decode("1", dec, olens[1]) == MultiBaseStatus.Success
      # olens[1] == 0
      # MultiBase.decode("0", dec, olens[2]) == MultiBaseStatus.Success
      # olens[2] == 0
      # MultiBase.decode("7", dec, olens[3]) == MultiBaseStatus.Success
      # olens[3] == 0
      # MultiBase.decode("9", dec, olens[4]) == MultiBaseStatus.Success
      # olens[4] == 0
      # MultiBase.decode("f", dec, olens[5]) == MultiBaseStatus.Success
      # olens[5] == 0
      # MultiBase.decode("F", dec, olens[6]) == MultiBaseStatus.Success
      # olens[6] == 0
      MultiBase.decode("v", dec, olens[7]) == MultiBaseStatus.Success
      olens[7] == 0
      MultiBase.decode("V", dec, olens[8]) == MultiBaseStatus.Success
      olens[8] == 0
      MultiBase.decode("t", dec, olens[9]) == MultiBaseStatus.Success
      olens[9] == 0
      MultiBase.decode("T", dec, olens[10]) == MultiBaseStatus.Success
      olens[10] == 0
      MultiBase.decode("b", dec, olens[11]) == MultiBaseStatus.Success
      olens[11] == 0
      MultiBase.decode("B", dec, olens[12]) == MultiBaseStatus.Success
      olens[12] == 0
      MultiBase.decode("c", dec, olens[13]) == MultiBaseStatus.Success
      olens[13] == 0
      MultiBase.decode("C", dec, olens[14]) == MultiBaseStatus.Success
      olens[14] == 0
      MultiBase.decode("z", dec, olens[15]) == MultiBaseStatus.Success
      olens[15] == 0
      MultiBase.decode("Z", dec, olens[16]) == MultiBaseStatus.Success
      olens[16] == 0
      MultiBase.decode("m", dec, olens[16]) == MultiBaseStatus.Success
      olens[16] == 0
      MultiBase.decode("M", dec, olens[16]) == MultiBaseStatus.Success
      olens[16] == 0
      MultiBase.decode("u", dec, olens[16]) == MultiBaseStatus.Success
      olens[16] == 0
      MultiBase.decode("U", dec, olens[16]) == MultiBaseStatus.Success
      olens[16] == 0
  test "go-multibase test vectors":
    for item in GoTestVectors:
      let encoding = item[0]
      let encoded = item[1]
      var expect = item[2]
      var bexpect = cast[seq[byte]](expect)
      var outlen = 0
      check:
        MultiBase.encode(encoding, bexpect).get() == encoded
        MultiBase.decode(encoded).get() == bexpect

      let elength = MultiBase.encodedLength(encoding, len(expect))
      var ebuffer = newString(elength)
      outlen = 0
      check:
        MultiBase.encode(encoding, bexpect, ebuffer, outlen) == MultiBaseStatus.Success
      ebuffer.setLen(outlen)
      check:
        encoded == ebuffer

      let dlength = MultiBase.decodedLength(encoded[0], len(encoded))
      var dbuffer = newSeq[byte](dlength)
      outlen = 0
      check:
        MultiBase.decode(encoded, dbuffer, outlen) == MultiBaseStatus.Success
      dbuffer.setLen(outlen)
      check:
        bexpect == dbuffer
  test "Unknown codec test":
    var data = @[0x00'u8, 0x01'u8]
    var ebuffer = newString(100)
    var dbuffer = newSeq[byte](100)
    var outlen = 0
    check:
      MultiBase.encode("unknown", data, ebuffer, outlen) == MultiBaseStatus.BadCodec
      MultiBase.decode("\x01\x00", dbuffer, outlen) == MultiBaseStatus.BadCodec
      MultiBase.encode("unknwon", data).isErr()
      MultiBase.decode("\x01\x00").isErr()

  test "identity encode into a short buffer overruns":
    var ebuffer = newString(2)
    var outlen = 0
    check:
      MultiBase.encode("identity", [byte 1, 2, 3], ebuffer, outlen) ==
        MultiBaseStatus.Overrun
      outlen == 4

  test "base58flickr round-trip":
    let data = @[byte 0, 1, 2, 0xFE, 0xFF]
    let encoded = MultiBase.encode("base58flickr", data).get()
    check:
      encoded[0] == 'Z'
      MultiBase.decode(encoded).get() == data

  test "decode and encode errors":
    var dbuffer = newSeq[byte](100)
    var ebuffer = newString(10)
    var outlen = 0
    check:
      MultiBase.decode("zI0").error() == "multibase: Decoding error (Incorrect)"
      MultiBase.decode("zI0", dbuffer, outlen) == MultiBaseStatus.Incorrect
      MultiBase.decode("m!!!").error() == "multibase: Decoding error (Incorrect)"
      MultiBase.decode("m!!!", dbuffer, outlen) == MultiBaseStatus.Incorrect
      MultiBase.decode("").error() == "multibase: Could not decode zero-length string"
      MultiBase.decode("", dbuffer, outlen) == MultiBaseStatus.Incorrect
      MultiBase.decode("0101").error() == "multibase: MultiBase scheme is not supported!"
      MultiBase.decode("0101", dbuffer, outlen) == MultiBaseStatus.NotSupported
      MultiBase.encode("base2", [byte 1]).error() ==
        "multibase: Encoding scheme is not supported!"
      MultiBase.encode("base2", [byte 1], ebuffer, outlen) ==
        MultiBaseStatus.NotSupported
