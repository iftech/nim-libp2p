# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils]
import chronos
import ../../libp2p/nameresolving/dnsmessage
import ../tools/[unittest]

# Real status.im responses captured for the resolver tests; they use the
# `\xc0\x0c` compression pointer for answer names, so they double as compression
# coverage for the codec.
const statusImA =
  "\xae\xbf\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x06\x73\x74\x61" &
  "\x74\x75\x73\x02\x69\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00" &
  "\x01\x00\x00\x00\x4f\x00\x04\x68\x16\x18\xb5\xc0\x0c\x00\x01\x00" &
  "\x01\x00\x00\x00\x4f\x00\x04\xac\x43\x0a\xa1\xc0\x0c\x00\x01\x00" &
  "\x01\x00\x00\x00\x4f\x00\x04\x68\x16\x19\xb5"

const statusImAAAA =
  "\xe8\xc5\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x06\x73\x74\x61" &
  "\x74\x75\x73\x02\x69\x6d\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00" &
  "\x01\x00\x00\x00\x4f\x00\x10\x26\x06\x47\x00\x00\x10\x00\x00\x00" &
  "\x00\x00\x00\x68\x16\x19\xb5\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00" &
  "\x4f\x00\x10\x26\x06\x47\x00\x00\x10\x00\x00\x00\x00\x00\x00\x68" &
  "\x16\x18\xb5\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x4f\x00\x10\x26" &
  "\x06\x47\x00\x00\x10\x00\x00\x00\x00\x00\x00\xac\x43\x0a\xa1"

proc toBytes(s: string): seq[byte] =
  cast[seq[byte]](s)

suite "DNS message codec":
  test "encodeQuery builds a recursive A query":
    let q = encodeQuery(0x1234'u16, "status.im", A)
    check:
      q[0 .. 1] == @[0x12'u8, 0x34] # id
      q[2 .. 3] == @[0x01'u8, 0x00] # flags: rd=1
      q[4 .. 5] == @[0x00'u8, 0x01] # qdcount=1
      q[6 .. 11] == @[0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x01] # an/ns = 0, ar = 1
      # question: labels "status"."im", root, qtype=A, qclass=IN
      q[12 .. ^12] == "\x06status\x02im\x00\x00\x01\x00\x01".toBytes()

  test "queries advertise an EDNS UDP payload size":
    for kind in [A, AAAA, TXT]:
      let q = encodeQuery(1, "example.test", kind)
      check q[^11 .. ^1] == @[0'u8, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]
      check parseMessage(q).questions[0].kind == kind

  test "truncation is reported before parsing incomplete records":
    var response = statusImA.toBytes()
    response[2] = response[2] or 0x02'u8
    response.setLen(12)
    expect DnsTruncatedError:
      discard parseAnswers(response, 0xaebf'u16)
    expectMsg ValueError, "DNS response id does not match the query":
      discard parseAnswers(response, 0)
    response[2] = response[2] and 0x7f'u8
    expectMsg ValueError, "DNS message is not a response":
      discard parseAnswers(response, 0xaebf'u16)

  test "parseAnswers rejects responses larger than the TCP length limit":
    expect ValueError:
      discard parseAnswers(newSeq[byte](65536), 0)

  test "encodeQuery rejects illegal names":
    expect ValueError:
      discard encodeQuery(0, "", A)
    expect ValueError:
      discard encodeQuery(0, "host..domain", A)
    expect ValueError:
      discard encodeQuery(0, strutils.repeat("a", 64) & ".com", A)
    # 128 single-char labels: each label is legal, but the encoded name (257
    # bytes) exceeds the RFC 1035 255-byte limit.
    expect ValueError:
      discard encodeQuery(0, strutils.repeat("a.", 127) & "a", A)

  test "parseAnswers decodes A records (with compression)":
    let answers = parseAnswers(statusImA.toBytes(), 0xaebf'u16)
    check answers.allIt(it.kind == A)
    check answers.mapIt(initTAddress(it.value, Port(0))) ==
      @["104.22.24.181", "172.67.10.161", "104.22.25.181"].mapIt(
        initTAddress(it, Port(0))
      )

  test "parseAnswers decodes AAAA records (with compression)":
    let answers = parseAnswers(statusImAAAA.toBytes(), 0xe8c5'u16)
    check answers.allIt(it.kind == AAAA)
    check answers.mapIt(initTAddress(it.value, Port(0))) ==
      @["2606:4700:10::6816:19b5", "2606:4700:10::6816:18b5", "2606:4700:10::ac43:aa1"].mapIt(
        initTAddress(it, Port(0))
      )

  test "parseAnswers decodes and concatenates TXT records":
    let txt = (
      "\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" & # id, flags, qd=1, an=1
      "\x01x\x00\x00\x10\x00\x01" & # question: "x", TXT, IN
      "\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x00\x00\x0c" & # answer: TXT, rdlen=12
      "\x05hello\x05world"
    ).toBytes()
    let answers = parseAnswers(txt, 0x0001'u16)
    check answers.len == 1
    check answers[0].kind == TXT
    check answers[0].value == "helloworld"

  test "parseAnswers rejects malformed input without defects":
    expect ValueError:
      discard parseAnswers(@[0x00'u8, 0x01, 0x02], 0) # shorter than header
    # qdcount=1/ancount=1, but the message is truncated right after the header
    let truncated =
      @[0x00'u8, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
    expect ValueError:
      discard parseAnswers(truncated, 0x0001'u16)

  test "parseAnswers rejects a response whose id does not match the query":
    expect ValueError:
      discard parseAnswers(statusImA.toBytes(), 0x0000'u16)

  test "parseAnswers rejects a message that is not a response":
    # QR bit clear in the flags (0x0100 = query, rd=1)
    let query =
      @[0x00'u8, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    expect ValueError:
      discard parseAnswers(query, 0x0001'u16)

  test "parseAnswers rejects a response without a question":
    let noQuestion =
      @[0x00'u8, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    expect ValueError:
      discard parseAnswers(noQuestion, 0x0001'u16)

  test "parseAnswers rejects an A record with the wrong length":
    let badA = (
      "\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" & # id, flags, qd=1, an=1
      "\x01x\x00\x00\x01\x00\x01" & # question: "x", A, IN
      "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x03\x01\x02\x03" # A, rdlen=3
    ).toBytes()
    expect ValueError:
      discard parseAnswers(badA, 0x0001'u16)

  test "parseAnswers rejects a reserved DNS label type":
    # question label starts with 0x40 (reserved label type, top two bits 01)
    let reserved = "\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\x40\x00".toBytes()
    expect ValueError:
      discard parseAnswers(reserved, 0x0001'u16)

suite "DNS message codec: whole messages":
  test "encodeMessage and parseMessage round-trip a query":
    let query = DnsMessage(
      questions: @[
        DnsQuestion(name: @["_p2p", "_udp", "local"], kind: PTR),
        DnsQuestion(name: @["a", "local"], kind: A, unicastResponse: true),
      ]
    )
    let decoded = parseMessage(encodeMessage(query))
    check:
      not decoded.response
      decoded.questions == query.questions
      decoded.answers.len == 0

  test "encodeMessage and parseMessage round-trip a DNS-SD response":
    let
      service = @["_p2p", "_udp", "local"]
      instance = @["abc"] & service
      host = @["abc", "local"]
    let response = DnsMessage(
      response: true,
      answers: @[DnsRecord(name: service, kind: PTR, ttl: 120, target: instance)],
      additionals: @[
        DnsRecord(
          name: instance,
          kind: TXT,
          ttl: 120,
          strings: @["dnsaddr=/ip4/1.2.3.4/tcp/1", "dnsaddr=/ip6/::1/tcp/2"],
        ),
        DnsRecord(
          name: instance,
          kind: SRV,
          ttl: 120,
          priority: 3,
          weight: 7,
          port: 4001,
          target: host,
        ),
        DnsRecord(name: host, kind: A, ttl: 120, cacheFlush: true, address: "1.2.3.4"),
        DnsRecord(name: host, kind: AAAA, ttl: 120, address: "::1"),
      ],
    )
    let decoded = parseMessage(encodeMessage(response))
    check:
      decoded.response
      decoded.answers == response.answers
      decoded.additionals == response.additionals

  test "a label may contain a dot":
    let name = @["my.computer", "local"]
    let query = DnsMessage(questions: @[DnsQuestion(name: name, kind: A)])
    let encoded = encodeMessage(query)
    check:
      encoded[12] == 11'u8 # the length octet of "my.computer", right after the header
      parseMessage(encoded).questions[0].name == name

  test "parseMessage skips a record whose class is not IN":
    let message = (
      "\x00\x00\x84\x00\x00\x00\x00\x02\x00\x00\x00\x00" & # response, an=2
      "\x01a\x00\x00\x01\x00\x03\x00\x00\x00\x01\x00\x04\x01\x02\x03\x04" & # A, CH
      "\x01a\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x05\x06\x07\x08" # A, IN
    ).toBytes()
    let decoded = parseMessage(message)
    check:
      decoded.answers.len == 1
      decoded.answers[0].address == "5.6.7.8"

  test "parseMessage keeps the cursor after a compressed name":
    let message = (
      "\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x01" & # response, qd=1, an=1, ar=1
      "\x01a\x00\x00\x0c\x00\x01" & # question: "a", PTR, IN
      "\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x0a\x00\x04\x01x\xc0\x0c" & # PTR -> "x.a"
      "\x01x\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x0a\x00\x03\x02hi" # TXT "hi"
    ).toBytes()
    let decoded = parseMessage(message)
    check:
      decoded.answers.len == 1
      decoded.answers[0].name == @["a"]
      decoded.answers[0].kind == PTR
      decoded.answers[0].ttl == 10
      decoded.answers[0].target == @["x", "a"]
      decoded.additionals.len == 1
      decoded.additionals[0].name == @["x", "a"]
      decoded.additionals[0].strings == @["hi"]

  test "parseMessage skips an unknown record type":
    let withCname = (
      "\x00\x00\x84\x00\x00\x00\x00\x02\x00\x00\x00\x00" & # response, an=2
      "\x01a\x00\x00\x05\x00\x01\x00\x00\x00\x01\x00\x03\x01b\x00" & # CNAME "a" -> "b"
      "\x01a\x00\x00\x0c\x00\x01\x00\x00\x00\x01\x00\x03\x01b\x00" # PTR "a" -> "b"
    ).toBytes()
    let decoded = parseMessage(withCname)
    check:
      decoded.answers.len == 1
      decoded.answers[0].kind == PTR
      decoded.answers[0].name == @["a"]
      decoded.answers[0].target == @["b"]

  test "parseMessage rejects a compression loop":
    # the answer name is a pointer to itself
    let loop = "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\xc0\x0c".toBytes()
    expect ValueError:
      discard parseMessage(loop)

  test "encodeMessage rejects a TXT string above 255 bytes":
    let big = DnsMessage(
      response: true,
      answers: @[
        DnsRecord(
          name: @["a", "local"],
          kind: TXT,
          ttl: 1,
          strings: @[strutils.repeat("x", 256)],
        )
      ],
    )
    expect ValueError:
      discard encodeMessage(big)

  test "parseMessage enforces the 255-byte name limit":
    let header =
      @[0x00'u8, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    let tail = @[0x00'u8, 0x01, 0x00, 0x01] # qtype = A, qclass = IN

    var legal: seq[byte] # 127 one-char labels plus the terminator = 255 bytes
    for _ in 0 ..< 127:
      legal.add([0x01'u8, byte('a')])
    legal.add(0x00'u8)

    var illegal: seq[byte] # one label carries a second char, making it 256
    for _ in 0 ..< 126:
      illegal.add([0x01'u8, byte('a')])
    illegal.add([0x02'u8, byte('a'), byte('a'), 0x00'u8])

    check parseMessage(header & legal & tail).questions.len == 1
    expect ValueError:
      discard parseMessage(header & illegal & tail)
