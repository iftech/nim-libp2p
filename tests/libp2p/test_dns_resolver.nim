# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
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
