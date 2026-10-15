# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, net], stew/byteutils, chronos
import protobuf_serialization, protobuf_serialization/pkg/results
import ../../../libp2p/[multicodec, multiaddress, peerid, protobuf/minprotobuf]
import ../../tools/[unittest, multiaddress]

{.push raises: [].}

type
  PatternVector = object
    pattern: MaPattern
    good: seq[string]
    bad: seq[string]

  Serializable {.proto2.} = object
    ma {.fieldNumber: 1, required, ext.}: MultiAddress
    addrs {.fieldNumber: 2, ext.}: seq[MultiAddress]
    observedAddr {.fieldNumber: 4, ext.}: Opt[MultiAddress]

const
  SuccessVectors = [
    "/ip4/1.2.3.4", "/ip4/0.0.0.0", "/ip6/::1",
    "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21",
    "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21/udp/1234/quic",
    "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21/udp/1234/quic-v1",
    "/ip6zone/x/ip6/fe80::1", "/ip6zone/x%y/ip6/fe80::1", "/ip6zone/x%y/ip6/::",
    "/ip6zone/x/ip6/fe80::1/udp/1234/quic", "/ip6zone/x/ip6/fe80::1/udp/1234/quic-v1",
    "/onion/timaq4ygg2iegci7:1234", "/onion/timaq4ygg2iegci7:80/http",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:80/http",
    "/udp/0", "/tcp/0", "/sctp/0", "/udp/1234", "/tcp/1234", "/sctp/1234", "/udp/65535",
    "/tcp/65535", "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", "/udp/1234/sctp/1234",
    "/udp/1234/udt", "/udp/1234/utp", "/tcp/1234/http", "/tcp/1234/https",
    "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
    "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
    "/ip4/127.0.0.1/udp/1234", "/ip4/127.0.0.1/udp/0", "/ip4/127.0.0.1/tcp/1234",
    "/ip4/127.0.0.1/tcp/1234/", "/ip4/127.0.0.1/udp/1234/quic",
    "/ip4/192.168.80.3/udp/33422/quic-v1",
    "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
    "/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
    "/ip4/127.0.0.1/tcp/8000/wss/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/ip4/127.0.0.1/tcp/8000/tls/ws/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/unix/a/b/c/d/e", "/unix/stdio", "/ip4/1.2.3.4/tcp/80/unix/a/b/c/d/e/f",
    "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234/unix/stdio",
    "/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234/unix/stdio",
    "/dns/example.io/udp/65535", "/dns4/example.io/udp/65535",
    "/dns6/example.io/udp/65535", "/dnsaddr/example.io/udp/65535", "/sni/example.com",
    "/ip4/127.0.0.1/tcp/443/tls/sni/example.com/ws",
  ]

  FailureVectors = [
    "", "/", "/ip4", "/ip4/::1", "/ip4/fdpsofodsajfdoisa", "/ip6", "/ip6/zzzz",
    "/ip6/1.2.3.4", "/ip6zone", "/ip6zone/", "/ip6zone//ip6/fe80::1", "/udp", "/tcp",
    "/sctp", "/udp/65536", "/tcp/65536", "/quic/65536", "/quic-v1/65536",
    "/onion/9imaq4ygg2iegci7:80", "/onion/aaimaq4ygg2iegci7:80",
    "/onion/timaq4ygg2iegci7:0", "/onion/timaq4ygg2iegci7:-1",
    "/onion/timaq4ygg2iegci7", "/onion/timaq4ygg2iegci@:666",
    "/onion3/9ww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:80",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd7:80",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:0",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:-1",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyy@:666",
    "/udp/1234/sctp", "/udp/1234/udt/1234", "/udp/1234/utp/1234",
    "/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa", "/ip4/127.0.0.1/udp",
    "/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa", "/ip4/127.0.0.1/tcp",
    "/ip4/127.0.0.1/quic/1234", "/ip4/127.0.0.1/quic-v1/1234", "/ip4/127.0.0.1/ipfs",
    "/ip4/127.0.0.1/ipfs/tcp", "/ip4/127.0.0.1/p2p", "/ip4/127.0.0.1/p2p/tcp", "/unix",
    "/sni", "/sni/",
  ]

  RustSuccessVectors = [
    "/ip4/1.2.3.4", "/ip4/0.0.0.0", "/ip6/::1",
    "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21", "/udp/0", "/tcp/0", "/sctp/0",
    "/udp/1234", "/tcp/1234", "/sctp/1234", "/udp/65535", "/tcp/65535",
    "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC", "/udp/1234/sctp/1234",
    "/udp/1234/udt", "/udp/1234/utp", "/tcp/1234/http", "/tcp/1234/https",
    "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
    "/ip4/127.0.0.1/udp/1234", "/ip4/127.0.0.1/udp/0", "/ip4/127.0.0.1/tcp/1234",
    "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
    "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/p2p-webrtc-star/ip4/127.0.0.1/tcp/9090/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
    "/ip4/127.0.0.1/tcp/9090/p2p-circuit/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
  ]

  RustSuccessExpects = [
    "0401020304", "0400000000", "2900000000000000000000000000000001",
    "29260100094F819700803ECA6566E80C21", "91020000", "060000", "84010000", "910204D2",
    "0604D2", "840104D2", "9102FFFF", "06FFFF",
    "E301221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
    "910204D2840104D2", "910204D2AD02", "910204D2AE02", "0604D2E003", "0604D2BB03",
    "E301221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B0604D2",
    "047F000001910204D2", "047F00000191020000", "047F0000010604D2",
    "047F000001E301221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
    "047F000001E301221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B0604D2",
    "29200108A07AC542013AC986FFFE317095061F40DD03E301221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
    "9302047F000001062382DD03E301221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
    "047F000001062382A202E301221220D52EBB89D85B02A284948203A62FF28389C57C9F42BEEC4EC20DB76A68911C0B",
  ]

  RustFailureVectors = [
    "/ip4", "/ip4/::1", "/ip4/fdpsofodsajfdoisa", "/ip6", "/udp", "/tcp", "/sctp",
    "/udp/65536", "/tcp/65536", "/onion/9imaq4ygg2iegci7:80",
    "/onion/aaimaq4ygg2iegci7:80", "/onion/timaq4ygg2iegci7:0",
    "/onion/timaq4ygg2iegci7:-1", "/onion/timaq4ygg2iegci7",
    "/onion/timaq4ygg2iegci@:666",
    "/onion3/9ww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:80",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd7:80",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:0",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:-1",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd",
    "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyy@:666",
    "/udp/1234/sctp", "/udp/1234/udt/1234", "/udp/1234/utp/1234",
    "/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa", "/ip4/127.0.0.1/udp",
    "/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa", "/ip4/127.0.0.1/tcp",
    "/ip4/127.0.0.1/ipfs", "/ip4/127.0.0.1/ipfs/tcp", "/p2p-circuit/50",
  ]

  PathVectors = ["/unix/a/b/c/d/e/f/g/h/i.sock"]

  PathExpects = ["9003172F612F622F632F642F652F662F672F682F692E736F636B"]

  PatternVectors = [
    PatternVector(
      pattern: IP,
      good: @["/ip4/0.0.0.0", "/ip6/fc00::"],
      bad: @["/ip4/0.0.0.0/tcp/555", "/udp/789/ip6/fc00::"],
    ),
    PatternVector(
      pattern: TCP,
      good: @["/ip4/0.0.7.6/tcp/1234", "/ip6/::/tcp/0"],
      bad: @["/tcp/12345", "/ip6/fc00::/udp/5523/tcp/9543"],
    ),
    PatternVector(
      pattern: UDP,
      good: @["/ip4/0.0.7.6/udp/1234", "/ip6/::/udp/0"],
      bad: @["/udp/12345", "/ip6/fc00::/tcp/5523/udp/9543"],
    ),
    PatternVector(
      pattern: UTP,
      good: @["/ip4/1.2.3.4/udp/3456/utp", "/ip6/::/udp/0/utp"],
      bad:
        @["/ip4/0.0.0.0/tcp/12345/utp", "/ip6/fc00::/ip4/0.0.0.0/udp/1234/utp", "/utp"],
    ),
    PatternVector(
      pattern: QUIC,
      good: @["/ip4/1.2.3.4/udp/1234/quic", "/ip6/::/udp/1234/quic"],
      bad: @[
        "/ip4/0.0.0.0/tcp/12345/quic", "/ip6/fc00::/ip4/0.0.0.0/udp/1234/quic", "/quic"
      ],
    ),
    PatternVector(
      pattern: QUIC_V1,
      good: @["/ip4/1.2.3.4/udp/1234/quic-v1", "/ip6/::/udp/1234/quic-v1"],
      bad: @[
        "/ip4/0.0.0.0/tcp/12345/quic-v1", "/ip6/fc00::/ip4/0.0.0.0/udp/1234/quic-v1",
        "/quic-v1",
      ],
    ),
    PatternVector(
      pattern: IPFS,
      good: @[
        "/ip4/1.2.3.4/tcp/1234/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ip6/::/tcp/1234/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ip6/::/udp/1234/utp/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ip4/0.0.0.0/udp/1234/utp/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
      ],
      bad: @[
        "/ip4/1.2.3.4/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ip6/::/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/tcp/123/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ip6/::/udp/1234/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ip6/::/utp/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
      ],
    ),
    PatternVector(
      pattern: DNS,
      good: @[
        "/dns/example.io", "/dnsaddr/example.io", "/dns4/example.io", "/dns6/example.io"
      ],
      bad: @["/ip4/127.0.0.1"],
    ),
    PatternVector(
      pattern: WebRTCDirect,
      good: @[
        "/ip4/1.2.3.4/tcp/3456/http/p2p-webrtc-direct",
        "/ip6/::/tcp/0/http/p2p-webrtc-direct",
      ],
      bad:
        @["/ip4/0.0.0.0", "/ip6/fc00::", "/udp/12345", "/ip6/fc00::/tcp/5523/udp/9543"],
    ),
    PatternVector(
      pattern: HTTP,
      good: @[
        "/ip4/1.2.3.4/http", "/dns4/example.io/http", "/dns6/::/tcp/7011/http",
        "/dnsaddr/example.io/http", "/ip6/fc00::/http",
      ],
      bad:
        @["/ip4/1.2.3.4/https", "/ip4/0.0.0.0/tcp/12345/quic", "/ip6/fc00::/tcp/5523"],
    ),
    PatternVector(
      pattern: HTTPS,
      good: @[
        "/ip4/1.2.3.4/https", "/dns4/example.io/https", "/dns6/::/tcp/7011/https",
        "/ip6/fc00::/https",
      ],
      bad: @["/ip4/1.2.3.4/http", "/ip4/0.0.0.0/tcp/12345/quic", "/ip6/fc00::/tcp/5523"],
    ),
  ]

  ZeroPathFailureVectors = [
    "900300", # /unix//
    "2A00", # /ip6zone//
    "3800", # /dnsaddr//
    "3600", # /dns4//
    "3700", # /dns6//
  ]

  CrashesVectors = [
    "0401020304060050900366",
    "2926013880ffffff2a040402030406005090030404020304060150900350900302030406005090030c2f383838383838383838383838383838382a",
    "04010103042a040101030406005090030c",
    "bd03afadec040bc547f9658668b1ff00000073001f101a37f54cc07fb4bc03bc039a18fbee063690033838383838383838383838383838383838383838383838383838383838",
    "2a040402030406005090030406ffff",
    "29260100094f81800e0000003880ffffff2a0404020304060050900304040203040404020304060050900304040203040601509003509003020406",
    "38060606383838380606060600802a2438380606060600802a047f0000012a163c803c3c3c0606060680ffff002a0404020304380600509003040402030406015090035e2a2a2a2a2a2a2a2a",
    "38060606060606060606060600802a2a2a047f0000012a063c803c3c3c383838012a063c80385fffffff2a260402030406005090030404020304060150900350",
    "a503220000000000000000000000000000000002003880ffffff2a040402030406005090030404020304060150900350900302030406005090030c",
    "047f0000012a2a2a2a2a2a2a2a2a2a2a2a2a2a2a062a2a042a8000142a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a50900350900302030406005090030c2f622f00000203040600030406005090030c2f612f2a712f63030406005090030c2f612f2a622f632a2a002a2a2a2a2a2a372a",
    "047f000001062a2a042a8000142a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2ad52a2a2a2a2a2a2a2a2a2a50900350900302030406005090030c2f622f00000203040600030406005090030c2f612f2a622f63030406005090030c2f612f2a622f632a2a002a2a2a2a2a2a37d52a2a2a2a2a2a2a2a2a2a5090032a",
    "90030c2a04",
  ]

suite "Protobuf serialization of types containing MultiAddress":
  test "valid multiaddress":
    let
      serializable = Serializable(
        ma: MultiAddress.init("/ip4/1.2.3.4/tcp/80").get(),
        addrs: @[MultiAddress.init("/ip4/1.2.3.4/tcp/80").get()],
      )
      encoded = Protobuf.encode(serializable)
      decoded = Protobuf.decode(encoded, Serializable)

    check decoded == serializable

  test "invalid multiaddress":
    let
      serializable = Serializable(ma: MultiAddress(), addrs: @[])
      encoded = Protobuf.encode(serializable)

    expect ProtobufReadError:
      discard Protobuf.decode(encoded, Serializable)

  test "decode should skip invalid multiaddresses":
    let
      serializable = Serializable(
        ma: MultiAddress.init("/ip4/1.2.3.4/tcp/80").get(),
        addrs: @[MultiAddress(), MultiAddress.init("/ip4/1.2.3.4/tcp/80").get()],
      )
      encoded = Protobuf.encode(serializable)
      decoded = Protobuf.decode(encoded, Serializable)

    check decoded.ma == serializable.ma
    check decoded.addrs[0] == serializable.addrs[1]

  test "decode should treat an empty optional multiaddress as none":
    let
      # An empty multiaddress encodes as a present but zero-length field 4.
      base = Serializable(
        ma: MultiAddress.init("/ip4/1.2.3.4/tcp/80").get(),
        observedAddr: Opt.some(MultiAddress()),
      )
      encoded = Protobuf.encode(base)
      decoded = Protobuf.decode(encoded, Serializable)

    check decoded.observedAddr.isNone
    check decoded.ma == base.ma

suite "MultiAddress test suite":
  test "go-multiaddr success test vectors":
    for item in SuccessVectors:
      var a = MultiAddress.init(item).get()
      check a.isEmpty() == false
      check a.validate() == true

  test "go-multiaddr failure test vectors":
    for item in FailureVectors:
      check MultiAddress.init(item).isErr()
      check MultiAddress.init(item.toBytes()).isErr()

  test "rust-multiaddr success test vectors":
    ## Rust test vectors are with changed UDP encoding and without WSS
    for i in 0 ..< len(RustSuccessVectors):
      var a = MultiAddress.init(RustSuccessVectors[i]).get()
      check:
        hex(a) == RustSuccessExpects[i]

  test "rust-multiaddr failure test vectors":
    for item in RustFailureVectors:
      check MultiAddress.init(item).isErr()

  test "SNI representation":
    let
      fromString = MultiAddress.init("/sni/example.com").tryGet()
      fromValue = MultiAddress.init(multiCodec("sni"), "example.com".toBytes()).tryGet()
      part = fromString.getPart(multiCodec("sni")).tryGet()

    check:
      $fromString == "/sni/example.com"
      fromValue == fromString
      hex(fromString) == "C1030B6578616D706C652E636F6D"
      part.protoArgument().tryGet() == "example.com".toBytes()

  test "SNI rejects malformed values":
    check:
      MultiAddress.init(multiCodec("sni"), newSeq[byte]()).isErr()
      MultiAddress.init(multiCodec("sni"), @[0xFF'u8]).isErr()
      MultiAddress.init(multiCodec("sni"), "a/b".toBytes()).isErr()
      MultiAddress.init(@[0xC1'u8, 0x03'u8, 0x01'u8, 0xFF'u8]).isErr()

  test "Concatenation test":
    var ma1 = MultiAddress.init()
    var ma2 = MultiAddress.init()
    var ma3 = MultiAddress.init("/ip4/127.0.0.1").get()
    var ma4 = MultiAddress.init("/udp/30000").get()
    var ma5 = MultiAddress.init("/p2p-circuit").get()
    var cma = ma1 & ma3 & ma4 & ma5
    ma2 &= ma3
    ma2 &= ma4
    ma2 &= ma5
    check:
      $cma == "/ip4/127.0.0.1/udp/30000/p2p-circuit"
      $ma2 == "/ip4/127.0.0.1/udp/30000/p2p-circuit"

  test "Path addresses serialization/deserialization":
    for i in 0 ..< len(PathVectors):
      var a = MultiAddress.init(PathVectors[i]).get()
      check:
        hex(a) == PathExpects[i]
        $a == PathVectors[i]

  test "p2p and ipfs accept CIDv1 peer id text":
    const legacyPeerId = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
    let
      pid = PeerId.init(legacyPeerId).tryGet()
      cidBase32 = pid.toCidString().tryGet()

    for item in [("p2p", multiCodec("p2p")), ("ipfs", multiCodec("ipfs"))]:
      let
        proto = item[0]
        ma = MultiAddress.init("/" & proto & "/" & cidBase32).tryGet()
        part = ma.getPart(item[1]).tryGet()
      check:
        part.protoAddress().tryGet() == pid.getBytes()
        $ma == "/" & proto & "/" & legacyPeerId

  test "MultiAddress pattern matching test vectors":
    for item in PatternVectors:
      for gitem in item.good:
        var a = MultiAddress.init(gitem).get()
        check item.pattern.match(a) == true
      for bitem in item.bad:
        var a = MultiAddress.init(bitem).get()
        check item.pattern.match(a) == false

  test "MultiAddress init(\"tcp/udp/dccp/sctp\", int) test":
    check:
      $MultiAddress.init(multiCodec("tcp"), 0).get() == "/tcp/0"
      $MultiAddress.init(multiCodec("tcp"), 65535).get() == "/tcp/65535"
      $MultiAddress.init(multiCodec("tcp"), 34000).get() == "/tcp/34000"
      $MultiAddress.init(multiCodec("udp"), 0).get() == "/udp/0"
      $MultiAddress.init(multiCodec("udp"), 65535).get() == "/udp/65535"
      $MultiAddress.init(multiCodec("udp"), 34000).get() == "/udp/34000"
      $MultiAddress.init(multiCodec("dccp"), 0).get() == "/dccp/0"
      $MultiAddress.init(multiCodec("dccp"), 65535).get() == "/dccp/65535"
      $MultiAddress.init(multiCodec("dccp"), 34000).get() == "/dccp/34000"
      $MultiAddress.init(multiCodec("sctp"), 0).get() == "/sctp/0"
      $MultiAddress.init(multiCodec("sctp"), 65535).get() == "/sctp/65535"
      $MultiAddress.init(multiCodec("sctp"), 34000).get() == "/sctp/34000"

    check:
      MultiAddress.init(multiCodec("ip4"), 0).isErr()
      MultiAddress.init(multiCodec("ip6"), 0).isErr()
      MultiAddress.init(multiCodec("p2p"), 0).isErr()
      MultiAddress.init(multiCodec("tcp"), 65536).isErr()
      MultiAddress.init(multiCodec("udp"), 65536).isErr()
      MultiAddress.init(multiCodec("dccp"), 65536).isErr()
      MultiAddress.init(multiCodec("sctp"), 65536).isErr()
      MultiAddress.init(multiCodec("tcp"), -1).isErr()
      MultiAddress.init(multiCodec("udp"), -1).isErr()
      MultiAddress.init(multiCodec("dccp"), -1).isErr()
      MultiAddress.init(multiCodec("sctp"), -1).isErr()

  test "MultiAddress protoAddress(fixed) test":
    var
      address_v4: array[4, byte]
      address_v6: array[16, byte]
    let
      onionMa = MultiAddress.init("/onion/timaq4ygg2iegci7:1234/http").get()
      onionPart = onionMa.getPart(multiCodec("onion")).get()
      onionArg = onionPart.protoAddress().get()
    check:
      MultiAddress.init("/ip4/0.0.0.0").get().protoAddress().get() == address_v4
      MultiAddress.init("/ip6/::0").get().protoAddress().get() == address_v6
      $onionMa == "/onion/timaq4ygg2iegci7:1234/http"
      onionMa.protocols().get() == @[multiCodec("onion"), multiCodec("http")]
      len(onionMa).get() == 2
      onionArg.len == 12
      onionArg[10] == 0x04'u8
      onionArg[11] == 0xD2'u8

  test "MultiAddress init fixed byte length validation":
    check:
      MultiAddress.init(multiCodec("ip4"), @[1'u8, 2, 3]).isErr()
      MultiAddress.init(multiCodec("ip4"), @[1'u8, 2, 3, 4, 5]).isErr()
      MultiAddress.init(multiCodec("ip4"), @[1'u8, 2, 3, 4]).isOk()
      MultiAddress.init(multiCodec("tcp"), @[0'u8]).isErr()
      MultiAddress.init(multiCodec("tcp"), @[0'u8, 80]).isOk()

  test "MultiAddress getPart":
    let ma = MultiAddress
      .init(
        "/ip4/0.0.0.0/tcp/0/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSuNEXT/unix/stdio/"
      )
      .get()
    check:
      $ma.getPart(multiCodec("ip4")).get() == "/ip4/0.0.0.0"
      $ma.getPart(multiCodec("tcp")).get() == "/tcp/0"
      # returns first codec match
      $ma.getPart(multiCodec("p2p")).get() ==
        "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
      ma.getPart(multiCodec("udp")).isErr()

  test "MultiAddress getParts":
    let ma = MultiAddress
      .init(
        "/ip4/0.0.0.0/tcp/0/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSuNEXT/unix/stdio/"
      )
      .get()
    check:
      $ma[0 .. 0].get() == "/ip4/0.0.0.0"
      $ma[^1].get() == "/unix/stdio"
      ma[-100].isErr()
      ma[100].isErr()
      ma[^100].isErr()
      ma[^0].isErr()
      $ma[0 .. 1].get() == "/ip4/0.0.0.0/tcp/0"
      $ma[1 .. 2].get() == "/tcp/0/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
      $ma[^3 ..^ 1].get() ==
        "/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSuNEXT/unix/stdio"
      ma[5 .. 7].isErr()

  test "[](MultiCodec) test":
    let onionMAStr =
      "/onion3/torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd:80"
    let ma = MultiAddress.init(onionMAStr).get()
    check $(ma[multiCodec("onion3")].tryGet()) == onionMAStr

    let onionMAWithTcpStr =
      "/onion3/torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd:80/tcp/80"
    let maWithTcp = MultiAddress.init(onionMAWithTcpStr).get()
    check $(maWithTcp[multiCodec("onion3")].tryGet()) == onionMAStr

  test "matchPartial":
    const tcp = mapEq("tcp")
    let ma = MultiAddress.init("/ip4/0.0.0.0/tcp/0").get()

    check not tcp.matchPartial(ma)
    check IP4.matchPartial(ma)

  test "getField returns ok(true) for valid multiaddress":
    var pb = initProtoBuffer()
    let ma = MultiAddress.init("/ip4/1.2.3.4/tcp/80").get()
    pb.write(1, ma)
    pb.finish()

    var decoded: MultiAddress
    check:
      pb.getField(1, decoded).get() == true
      decoded == ma

  test "getField returns ok(false) for missing field":
    var pb = initProtoBuffer()
    pb.write(2, "placeholder")
    pb.finish()

    var decoded: MultiAddress
    check:
      pb.getField(1, decoded).get() == false
      decoded == MultiAddress()

  test "getField returns err for empty multiaddress":
    var pb = initProtoBuffer()
    pb.write(1, newSeq[byte]())
    pb.finish()

    var decoded: MultiAddress
    let error = pb.getField(1, decoded).error()
    check:
      error == ProtoError.IncorrectBlob
      decoded == MultiAddress()

  test "getField returns err for invalid multiaddress":
    var pb = initProtoBuffer()
    pb.write(1, "invalid")
    pb.finish()

    var decoded: MultiAddress
    let error = pb.getField(1, decoded).error()
    check:
      error == ProtoError.IncorrectBlob
      decoded == MultiAddress()

  test "getRepeatedField does not fail when all addresses are valid":
    var pb = initProtoBuffer()
    let mas = SuccessVectors.mapIt(MultiAddress.init(it).get())
    for ma in mas:
      pb.write(1, ma)
    pb.finish()

    var decoded = newSeq[MultiAddress]()
    check pb.getRepeatedField(1, decoded)
    check decoded == mas

  test "getRepeatedField does not fail when some addresses are invalid":
    var pb = initProtoBuffer()
    var mas = @[MultiAddress.init("/ip4/1.2.3.4").get(), MultiAddress()]
    for ma in mas:
      pb.write(1, ma)
    pb.finish()

    var decoded = newSeq[MultiAddress]()
    check pb.getRepeatedField(1, decoded)
    check decoded == @[MultiAddress.init("/ip4/1.2.3.4").get()]

  test "getRepeatedField fails when all addresses are invalid":
    var pb = initProtoBuffer()
    var mas = @[MultiAddress(), MultiAddress()]
    for ma in mas:
      pb.write(1, ma)
    pb.finish()

    var decoded = newSeq[MultiAddress]()
    let error = pb.getRepeatedField(1, decoded).error()
    check error == ProtoError.IncorrectBlob
    check decoded.len == 0

  test "MultiAddress with empty path test":
    for item in ZeroPathFailureVectors:
      let res = MultiAddress.init(hexToSeqByte(item))
      check res.isErr()

  test "MultiAddress crash test":
    for item in CrashesVectors:
      let res = MultiAddress.init(hexToSeqByte(item))
      check res.isErr()

  test "areAddrsConsistent":
    # same address should be consistent
    check areAddrsConsistent(
      MultiAddress.init("/ip4/127.0.0.1/tcp/4040").get(),
      MultiAddress.init("/ip4/127.0.0.1/tcp/4040").get(),
    )

    # different addresses with same stack should be consistent
    check areAddrsConsistent(
      MultiAddress.init("/ip4/127.0.0.2/tcp/4041").get(),
      MultiAddress.init("/ip4/127.0.0.1/tcp/4040").get(),
    )

    # addresses with different stacks should not be consistent
    check not areAddrsConsistent(
      MultiAddress.init("/ip4/127.0.0.1/tcp/4040").get(),
      MultiAddress.init("/ip4/127.0.0.1/udp/4040").get(),
    )

    # DNS/IP pairs should be symmetric for the first component
    check:
      areAddrsConsistent(
        MultiAddress.init("/ip4/127.0.0.1/tcp/4040").get(),
        MultiAddress.init("/dns4/example.com/tcp/4040").get(),
      )
      areAddrsConsistent(
        MultiAddress.init("/dns4/example.com/tcp/4040").get(),
        MultiAddress.init("/ip4/127.0.0.1/tcp/4040").get(),
      )
      areAddrsConsistent(
        MultiAddress.init("/dns/example.com/tcp/4040").get(),
        MultiAddress.init("/ip6/::1/tcp/4040").get(),
      )
      areAddrsConsistent(
        MultiAddress.init("/ip6/::1/tcp/4040").get(),
        MultiAddress.init("/dnsaddr/example.com/tcp/4040").get(),
      )
      not areAddrsConsistent(
        MultiAddress.init("/dns4/example.com/tcp/4040").get(),
        MultiAddress.init("/ip6/::1/tcp/4040").get(),
      )

  test "MultiAddress init with a value for a marker":
    check MultiAddress.init(multiCodec("p2p-circuit"), @[1'u8]).error() ==
      "multiaddress: Value must be empty for markers"
    check $MultiAddress.init(multiCodec("p2p-circuit")).get() == "/p2p-circuit"

  test "MultiAddress init from TransportAddress":
    let ta = initTAddress("1.2.3.4:5")
    check:
      $MultiAddress.init(ta).get() == "/ip4/1.2.3.4/tcp/5"
      $MultiAddress.init(ta, Protocol.IPPROTO_UDP).get() == "/ip4/1.2.3.4/udp/5"
      MultiAddress.init(ta, Protocol.IPPROTO_ICMP).error() ==
        "multiaddress: protocol should be either TCP or UDP"
      $MultiAddress.init(initTAddress("[::1]:5")).get() == "/ip6/::1/tcp/5"

    let unix = MultiAddress.init(initTAddress("/tmp/sock")).get()
    check:
      unix.protoCode().get() == multiCodec("unix")
      unix.protoArgument().get() == "/tmp/sock".toBytes()
      unix == MultiAddress.init("/unix/tmp/sock").get()
      MultiAddress.init(TransportAddress(family: AddressFamily.Unix)).error() ==
        "multiaddress: Unix path must not be empty"

suite "parseIpAddress":
  test "valid IPv4 addresses parse to IPv4 family":
    check parseIpAddress("1.2.3.4").family == IpAddressFamily.IPv4
    check parseIpAddress("0.0.0.0").family == IpAddressFamily.IPv4
    check parseIpAddress("255.255.255.255").family == IpAddressFamily.IPv4
    check parseIpAddress("127.0.0.1").family == IpAddressFamily.IPv4

  test "valid IPv4 address bytes are correct":
    check parseIpAddress("1.2.3.4").address_v4 == [1'u8, 2, 3, 4]
    check parseIpAddress("0.0.0.0").address_v4 == [0'u8, 0, 0, 0]
    check parseIpAddress("255.255.255.255").address_v4 == [255'u8, 255, 255, 255]
    check parseIpAddress("192.168.1.100").address_v4 == [192'u8, 168, 1, 100]

  test "valid IPv6 addresses parse to IPv6 family":
    check parseIpAddress("::1").family == IpAddressFamily.IPv6
    check parseIpAddress("::").family == IpAddressFamily.IPv6
    check parseIpAddress("2001:db8::1").family == IpAddressFamily.IPv6
    check parseIpAddress("fe80::1").family == IpAddressFamily.IPv6
    check parseIpAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").family ==
      IpAddressFamily.IPv6

  test "valid IPv6 address bytes are correct":
    # ::1 → all zeros except last byte = 1
    let loopback = parseIpAddress("::1").address_v6
    check loopback[0 .. 14] == [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    check loopback[15] == 1

    # :: → all zeros
    check parseIpAddress("::").address_v6 ==
      [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

  test "IPv4 string is not parsed as IPv6":
    check parseIpAddress("1.2.3.4").family != IpAddressFamily.IPv6

  test "IPv6 string is not parsed as IPv4":
    check parseIpAddress("::1").family != IpAddressFamily.IPv4

  test "invalid addresses raise ValueError":
    expect ValueError:
      discard parseIpAddress("")
    expect ValueError:
      discard parseIpAddress("not-an-ip")
    expect ValueError:
      discard parseIpAddress("256.0.0.1")
    expect ValueError:
      discard parseIpAddress("1.2.3")
    expect ValueError:
      discard parseIpAddress("1.2.3.4.5")
    expect ValueError:
      discard parseIpAddress(":::1")

suite "MultiAddress IP utilities":
  test "getIp":
    check:
      MultiAddress.init("/ip4/1.2.3.4/tcp/1234").get().getIp() ==
        Opt.some(IpAddress(family: IpAddressFamily.IPv4, address_v4: [1'u8, 2, 3, 4]))
      MultiAddress.init("/ip6/::1/tcp/1234").get().getIp() ==
        Opt.some(
          IpAddress(
            family: IpAddressFamily.IPv6,
            address_v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
          )
        )
      MultiAddress.init("/tcp/1234").get().getIp() == Opt.none(IpAddress)
      MultiAddress.init("/ip4/5.6.7.8/tcp/80/ws").get().getIp() ==
        Opt.some(IpAddress(family: IpAddressFamily.IPv4, address_v4: [5'u8, 6, 7, 8]))

  test "getIPs":
    let addrs = @[
      MultiAddress.init("/ip4/1.2.3.4/tcp/1234").get(),
      MultiAddress.init("/tcp/1234").get(),
      MultiAddress.init("/ip6/::1/tcp/80").get(),
      MultiAddress.init("/ip4/5.6.7.8/tcp/80/ws").get(),
    ]
    check addrs.getIPs() ==
      @[
        IpAddress(family: IpAddressFamily.IPv4, address_v4: [1'u8, 2, 3, 4]),
        IpAddress(
          family: IpAddressFamily.IPv6,
          address_v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        IpAddress(family: IpAddressFamily.IPv4, address_v4: [5'u8, 6, 7, 8]),
      ]
    check newSeq[MultiAddress]().getIPs().len == 0

  test "replaceIp":
    let
      ip4 = parseIpAddress("203.0.113.7")
      ip6 = parseIpAddress("2001:db8::1")
    check:
      ma("/ip4/1.2.3.4/tcp/1234").replaceIp(ip4).get == ma("/ip4/203.0.113.7/tcp/1234")
      ma("/ip4/1.2.3.4/tcp/80/ws").replaceIp(ip4).get == ma(
        "/ip4/203.0.113.7/tcp/80/ws"
      )
      ma("/ip4/1.2.3.4/tcp/80/wss").replaceIp(ip4).get ==
        ma("/ip4/203.0.113.7/tcp/80/wss")
      ma("/ip4/1.2.3.4/tcp/80/tls/ws").replaceIp(ip4).get ==
        ma("/ip4/203.0.113.7/tcp/80/tls/ws")
      ma("/ip4/1.2.3.4/udp/9000/quic-v1").replaceIp(ip4).get ==
        ma("/ip4/203.0.113.7/udp/9000/quic-v1")
      ma("/ip6/::1/tcp/1234").replaceIp(ip6).get == ma("/ip6/2001:db8::1/tcp/1234")
      # cross-family swap (IPv6 -> IPv4 and vice versa)
      ma("/ip6/::/tcp/80/ws").replaceIp(ip4).get == ma("/ip4/203.0.113.7/tcp/80/ws")
      ma("/ip4/0.0.0.0/tcp/80").replaceIp(ip6).get == ma("/ip6/2001:db8::1/tcp/80")
      # no IP component
      ma("/unix/tmp/sock").replaceIp(ip4).isErr
