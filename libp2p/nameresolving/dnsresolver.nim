# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils, strutils], chronos, chronicles, ./dnsmessage

import nameresolver
import ../crypto/rng, ../utils/future

logScope:
  topics = "libp2p name-resolution"

const DefaultDnsServers* = @[
  initTAddress("1.1.1.1:53"),
  initTAddress("1.0.0.1:53"),
  initTAddress("[2606:4700:4700::1111]:53"),
]

when defined(windows):
  const
    WindowsDnsHeaders = """#include <winsock2.h>
#include <iphlpapi.h>"""
    ErrorSuccess = 0'u32
    ErrorBufferOverflow = 111'u32
    AfUnspec = 0'u32
    AfInet = 2'u16
    AfInet6 = 23'u16

  type
    RawSockaddr = object
      family: uint16

    RawSockaddrIn = object
      family, port: uint16
      address: array[4, uint8]
      padding: array[8, uint8]

    RawSockaddrIn6 = object
      family, port: uint16
      flowInfo: uint32
      address: array[16, uint8]
      scopeId: uint32

    SocketAddress {.importc: "SOCKET_ADDRESS", header: WindowsDnsHeaders, bycopy.} = object
      sockAddr {.importc: "lpSockaddr".}: pointer
      length {.importc: "iSockaddrLength".}: int32

    IpAdapterDnsServerAddress {.
      importc: "IP_ADAPTER_DNS_SERVER_ADDRESS", header: WindowsDnsHeaders, bycopy
    .} = object
      next {.importc: "Next".}: ptr IpAdapterDnsServerAddress
      address {.importc: "Address".}: SocketAddress

    IpAdapterAddresses {.
      importc: "IP_ADAPTER_ADDRESSES", header: WindowsDnsHeaders, bycopy
    .} = object
      next {.importc: "Next".}: ptr IpAdapterAddresses
      firstDnsServerAddress {.importc: "FirstDnsServerAddress".}:
        ptr IpAdapterDnsServerAddress

  static:
    doAssert sizeof(RawSockaddrIn) == 16
    doAssert sizeof(RawSockaddrIn6) == 28

  proc getAdaptersAddresses(
    family, flags: uint32,
    reserved: pointer,
    addresses: ptr IpAdapterAddresses,
    size: ptr uint32,
  ): uint32 {.stdcall, importc: "GetAdaptersAddresses", dynlib: "iphlpapi.dll".}

proc parseNameServers*(conf: string): seq[TransportAddress] =
  ## Extracts nameserver addresses from resolv.conf-formatted content.
  ## resolv.conf(5): at most 3 nameservers are used.
  var servers: seq[TransportAddress]
  for line in conf.splitLines():
    let parts = line.splitWhitespace()
    if parts.len >= 2 and parts[0] == "nameserver":
      # TransportAddress cannot represent an IPv6 interface scope.
      let host = parts[1]
      if '%' in host:
        continue
      try:
        servers.add(initTAddress((if ':' in host: "[" & host & "]" else: host) & ":53"))
      except TransportAddressError:
        discard
    if servers.len >= 3:
      break
  return servers

when defined(windows):
  proc addWindowsNameServer(
      servers: var seq[TransportAddress], address: SocketAddress
  ) =
    if address.sockAddr.isNil:
      return

    let family = cast[ptr RawSockaddr](address.sockAddr)[].family
    var server: TransportAddress
    case family
    of AfInet:
      if address.length < int32(sizeof(RawSockaddrIn)):
        return
      let raw = cast[ptr RawSockaddrIn](address.sockAddr)
      server = TransportAddress(
        family: AddressFamily.IPv4, address_v4: raw[].address, port: Port(53)
      )
    of AfInet6:
      if address.length < int32(sizeof(RawSockaddrIn6)):
        return
      let raw = cast[ptr RawSockaddrIn6](address.sockAddr)
      # TransportAddress cannot carry an IPv6 interface scope. Prefer another
      # configured server over turning a scoped link-local address into an
      # unusable unscoped destination.
      if raw[].scopeId != 0:
        return
      server = TransportAddress(
        family: AddressFamily.IPv6, address_v6: raw[].address, port: Port(53)
      )
    else:
      return

    if server notin servers:
      servers.add(server)

  proc getWindowsNameServers(): seq[TransportAddress] =
    var servers: seq[TransportAddress]
    var size = 0'u32
    if getAdaptersAddresses(AfUnspec, 0, nil, nil, addr size) != ErrorBufferOverflow or
        size == 0:
      return @[]

    let addresses = cast[ptr IpAdapterAddresses](alloc0(int(size)))
    if addresses.isNil:
      return @[]
    defer:
      dealloc(addresses)

    if getAdaptersAddresses(AfUnspec, 0, nil, addresses, addr size) != ErrorSuccess:
      return @[]

    var adapter = addresses
    while not adapter.isNil:
      var server = adapter[].firstDnsServerAddress
      while not server.isNil:
        servers.addWindowsNameServer(server[].address)
        server = server[].next
      adapter = adapter[].next
    return servers

proc getSystemNameServers*(): seq[TransportAddress] =
  ## Best-effort system nameserver discovery, falling back to
  ## `DefaultDnsServers` when the platform configuration has no usable entries.
  var servers: seq[TransportAddress]
  when defined(windows):
    servers = getWindowsNameServers()
  else:
    var conf: string
    try:
      conf = readFile("/etc/resolv.conf")
    except IOError, OSError:
      discard
    servers = parseNameServers(conf)
  if servers.len == 0:
    return DefaultDnsServers
  return servers

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
