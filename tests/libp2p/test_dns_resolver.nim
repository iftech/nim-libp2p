# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils]
import chronos
import stew/endians2
import ../../libp2p/nameresolving/[dnsresolver, dnsmessage]
import ../tools/[unittest, crypto]
import ./suite_name_resolver

proc answerLoopback(
    transport: DatagramTransport, address: TransportAddress
) {.async: (raises: []).} =
  try:
    let query = parseMessage(transport.getMessage())
    var response = DnsMessage(id: query.id, response: true, questions: query.questions)
    for question in query.questions:
      let ip = if question.kind == A: "127.0.0.1" else: "::1"
      response.answers.add(
        DnsRecord(name: question.name, kind: question.kind, address: ip)
      )
    await transport.sendTo(address, encodeMessage(response))
  except CancelledError, TransportError, ValueError:
    raiseAssert "Unexpected DNS fixture error: " & getCurrentExceptionMsg()

nameResolverSuite(
  "DnsResolver contract",
  resolver,
  (
    let server = newDatagramTransport(answerLoopback)
    let resolver = DnsResolver.new(@[server.localAddress], rng())
  ),
  (await server.closeWait()),
)

suite "DNS resolver configuration":
  teardown:
    checkTrackers()

  asyncTest "explicit DNS servers are preserved, including an empty list":
    for servers in [@[initTAddress("192.0.2.1:5353")], newSeq[TransportAddress]()]:
      let resolver = DnsResolver.new(servers, rng())
      check resolver.nameServers == servers
      if servers.len == 0:
        check (await resolver.resolveIp("localhost", 4001.Port)).len == 0
        check (await resolver.resolveTxt("_dnsaddr.test.io")).len == 0

proc txtResponse(query: seq[byte], count: int): seq[byte] =
  let decoded = parseMessage(query)
  let question = decoded.questions[0]
  var response =
    DnsMessage(id: decoded.id, response: true, questions: decoded.questions)
  for _ in 0 ..< count:
    response.answers.add(
      DnsRecord(name: question.name, kind: TXT, strings: @[repeat("a", 200)])
    )
  encodeMessage(response)

type TcpReply = enum
  Complete
  ShortLength
  EarlyEof
  WrongId
  StillTruncated
  Timeout
  Cancel

proc checkTcpFallback(reply: TcpReply) {.async.} =
  let tcp = createStreamServer(initTAddress("127.0.0.1:0"))
  var udpQuery: seq[byte]
  proc answerTruncated(
      transport: DatagramTransport, address: TransportAddress
  ) {.async: (raises: []).} =
    try:
      udpQuery = transport.getMessage()
      var response = txtResponse(udpQuery, 1)
      response[2] = response[2] or 0x02'u8
      # The TC bit must be handled even if the answer ends mid-record.
      response.setLen(response.len - 10)
      await transport.sendTo(address, response)
    except CancelledError, TransportError, ValueError:
      raiseAssert "Unexpected DNS fixture error: " & getCurrentExceptionMsg()

  let udp = newDatagramTransport(answerTruncated, local = tcp.local)
  let resolver = DnsResolver.new(@[udp.localAddress], rng())
  let resolution = resolver.resolveTxt("_dnsaddr.example.test")
  var client: StreamTransport
  try:
    client = await tcp.accept()
    var length: array[2, byte]
    await client.readExactly(addr length[0], length.len)
    var query = newSeq[byte](fromBytesBE(uint16, length).int)
    await client.readExactly(addr query[0], query.len)
    check query == udpQuery

    var response = txtResponse(query, 10)
    check response.len > DnsUdpPayloadSize
    case reply
    of Complete:
      # Split both the prefix and payload to exercise stream framing.
      let frame = @(toBytesBE(response.len.uint16)) & response
      discard await client.write(frame[0 .. 0])
      await sleepAsync(1.milliseconds)
      discard await client.write(frame[1 .. 100])
      await sleepAsync(1.milliseconds)
      discard await client.write(frame[101 .. ^1])
      check (await resolution) == newSeqWith(10, repeat("a", 200))
    of ShortLength:
      discard await client.write(@[0'u8, 0])
    of EarlyEof:
      discard await client.write(@(toBytesBE(response.len.uint16)))
      discard await client.write(response[0 .. 20])
      await client.closeWait()
    of WrongId, StillTruncated:
      if reply == WrongId:
        response[0] = response[0] xor 1'u8
      else:
        response[2] = response[2] or 0x02'u8
      discard await client.write(@(toBytesBE(response.len.uint16)) & response)
    of Timeout:
      discard
    of Cancel:
      await resolution.cancelAndWait()
      check resolution.cancelled()

    if reply notin {Complete, Cancel}:
      check (await resolution).len == 0

    if reply in {Timeout, Cancel}:
      # The resolver must close its TCP socket on cancellation and timeout.
      var data: array[1, byte]
      expect TransportIncompleteError:
        await client.readExactly(addr data[0], 1)
  finally:
    await resolution.cancelAndWait()
    if not client.isNil:
      await client.closeWait()
    await udp.closeWait()
    await tcp.closeWait()

suite "DNS large responses":
  teardown:
    checkTrackers()

  asyncTest "TXT responses above 512 bytes resolve over UDP":
    proc answerLarge(
        transport: DatagramTransport, address: TransportAddress
    ) {.async: (raises: []).} =
      try:
        let response = txtResponse(transport.getMessage(), 3)
        doAssert response.len > 512 and response.len <= DnsUdpPayloadSize
        await transport.sendTo(address, response)
      except CancelledError, TransportError, ValueError:
        raiseAssert "Unexpected DNS fixture error: " & getCurrentExceptionMsg()

    let server = newDatagramTransport(answerLarge)
    try:
      let resolver = DnsResolver.new(@[server.localAddress], rng())
      check (await resolver.resolveTxt("_dnsaddr.example.test")) ==
        newSeqWith(3, repeat("a", 200))
    finally:
      await server.closeWait()

  asyncTest "truncated UDP answers retry over TCP with length framing":
    await checkTcpFallback(Complete)

  asyncTest "invalid TCP responses fail without leaking transports":
    for reply in [ShortLength, EarlyEof, WrongId, StillTruncated]:
      await checkTcpFallback(reply)

  asyncTest "TCP response timeout closes the connection":
    await checkTcpFallback(Timeout)

  asyncTest "cancelling TCP fallback closes the connection":
    await checkTcpFallback(Cancel)
