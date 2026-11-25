# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils], chronos, chronicles, ./dnsmessage

import stew/endians2
import nameresolver, nameservers

export nameservers
import ../crypto/rng, ../utils/future

logScope:
  topics = "libp2p name-resolution"

type DnsResolver* = ref object of NameResolver
  nameServers*: seq[TransportAddress]
  rng: Rng

proc getTcpDnsResponse(
    dnsServer: TransportAddress, query: seq[byte], queryId: uint16
): Future[seq[DnsAnswer]] {.
    async: (raises: [CancelledError, TransportError, ValueError])
.} =
  let sock = await connect(dnsServer)
  try:
    let frame = @(toBytesBE(query.len.uint16)) & query
    if (await sock.write(frame)) != frame.len:
      raise newException(TransportError, "Incomplete DNS query write")

    var length: array[2, byte]
    await sock.readExactly(addr length[0], length.len)
    let size = fromBytesBE(uint16, length).int
    if size < 12:
      raise newException(ValueError, "DNS response shorter than header")
    var response = newSeq[byte](size)
    await sock.readExactly(addr response[0], response.len)
    return parseAnswers(response, queryId)
  finally:
    await sock.closeWait()

proc getDnsResponse(
    rng: Rng, dnsServer: TransportAddress, address: string, kind: DnsRecordKind
): Future[seq[DnsAnswer]] {.
    async: (raises: [CancelledError, IOError, TransportError, ValueError])
.} =
  let queryId = rng.generate(uint16)
  var sendBuf = encodeQuery(queryId, address, kind)

  let receivedDataFuture = Future[void].Raising([CancelledError]).init()

  proc datagramDataReceived(
      transp: DatagramTransport, raddr: TransportAddress
  ): Future[void] {.async: (raises: []).} =
    receivedDataFuture.completeOnce()

  var response: seq[byte]
  let sock =
    if dnsServer.family == AddressFamily.IPv6:
      newDatagramTransport6(datagramDataReceived, bufSize = DnsUdpPayloadSize)
    else:
      newDatagramTransport(datagramDataReceived, bufSize = DnsUdpPayloadSize)

  try:
    await sock.sendTo(dnsServer, addr sendBuf[0], sendBuf.len)

    try:
      await receivedDataFuture.wait(5.seconds) #unix default
    except AsyncTimeoutError as e:
      raise newException(IOError, "DNS server timeout: " & e.msg, e)

    response = sock.getMessage()
  finally:
    await sock.closeWait()

  try:
    return parseAnswers(response, queryId)
  except DnsTruncatedError:
    try:
      return await getTcpDnsResponse(dnsServer, sendBuf, queryId).wait(5.seconds)
    except AsyncTimeoutError as e:
      raise newException(IOError, "DNS TCP server timeout: " & e.msg, e)

method resolveIp*(
    self: DnsResolver, address: string, port: Port, domain: Domain = Domain.AF_UNSPEC
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError])
.} =
  trace "Resolving IP using DNS", address, servers = self.nameServers.mapIt($it), domain
  for _ in 0 ..< self.nameServers.len:
    let server = self.nameServers[0]
    var responseFutures: seq[
      Future[seq[DnsAnswer]].Raising(
        [CancelledError, IOError, TransportError, ValueError]
      )
    ]
    if domain == Domain.AF_INET or domain == Domain.AF_UNSPEC:
      responseFutures.add(getDnsResponse(self.rng, server, address, A))

    if domain == Domain.AF_INET6 or domain == Domain.AF_UNSPEC:
      let fut = getDnsResponse(self.rng, server, address, AAAA)
      if server.family == AddressFamily.IPv6:
        trace "IPv6 DNS results prioritized", server = $server
        responseFutures.insert(fut)
      else:
        responseFutures.add(fut)

    defer:
      await noCancel responseFutures.cancelAndWait()

    var
      resolvedAddresses: OrderedSet[string]
      resolveFailed = false
    template handleFail(e): untyped =
      trace "DNS address query failed", err = e.msg, address
      resolveFailed = true
      break

    for fut in responseFutures:
      try:
        let resp = await fut
        for answer in resp:
          resolvedAddresses.incl(answer.value)
      except CancelledError as e:
        raise e
      except ValueError as e:
        trace "DNS address response rejected", err = e.msg, address
        return @[]
      except IOError as e:
        handleFail(e)
      except TransportError as e:
        handleFail(e)

    if resolveFailed:
      self.nameServers.add(self.nameServers[0])
      self.nameServers.delete(0)
      continue

    trace "DNS address query completed", resolvedAddresses, server = $server
    return resolvedAddresses.toSeq().mapIt(initTAddress(it, port))

  trace "DNS address resolution returned no results"
  return @[]

method resolveTxt*(
    self: DnsResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]).} =
  trace "Resolving TXT using DNS", address, servers = self.nameServers.mapIt($it)
  for _ in 0 ..< self.nameServers.len:
    let server = self.nameServers[0]
    template handleFail(e): untyped =
      trace "DNS TXT query failed", err = e.msg, address
      self.nameServers.add(self.nameServers[0])
      self.nameServers.delete(0)
      continue

    try:
      let response = await getDnsResponse(self.rng, server, address, TXT)
      trace "DNS TXT query completed", server = $server, answerCount = response.len
      return response.mapIt(it.value)
    except CancelledError as e:
      raise e
    except IOError as e:
      handleFail(e)
    except TransportError as e:
      handleFail(e)
    except ValueError as e:
      handleFail(e)

  trace "DNS TXT resolution returned no results"
  return @[]

proc new*(
    T: typedesc[DnsResolver], nameServers: seq[TransportAddress], rng: Rng = newRng()
): T =
  T(nameServers: nameServers, rng: rng)
