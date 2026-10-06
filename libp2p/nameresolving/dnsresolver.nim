# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils], chronos, chronicles, ./dnsmessage

import nameresolver
import ../crypto/rng, ../utils/future

logScope:
  topics = "libp2p name-resolution"

const DefaultDnsServers* = @[
  initTAddress("1.1.1.1:53"),
  initTAddress("1.0.0.1:53"),
  initTAddress("[2606:4700:4700::1111]:53"),
]

type DnsResolver* = ref object of NameResolver
  nameServers*: seq[TransportAddress]
  rng: Rng

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

  let sock =
    if dnsServer.family == AddressFamily.IPv6:
      newDatagramTransport6(datagramDataReceived)
    else:
      newDatagramTransport(datagramDataReceived)

  try:
    await sock.sendTo(dnsServer, addr sendBuf[0], sendBuf.len)

    try:
      await receivedDataFuture.wait(5.seconds) #unix default
    except AsyncTimeoutError as e:
      raise newException(IOError, "DNS server timeout: " & e.msg, e)

    parseAnswers(sock.getMessage(), queryId)
  finally:
    await sock.closeWait()

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
