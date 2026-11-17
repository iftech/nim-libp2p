# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos

const
  WindowsDnsHeaders = """#include <winsock2.h>
#include <iphlpapi.h>"""
  ErrorSuccess = 0'u32
  ErrorBufferOverflow = 111'u32
  MaxAdapterQueryAttempts = 3
  IfOperStatusUp = 1'u32
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
    operStatus {.importc: "OperStatus".}: uint32
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

proc addWindowsNameServer(servers: var seq[TransportAddress], address: SocketAddress) =
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

  if server.family == AddressFamily.IPv6 and server.isLinkLocal():
    return
  if server notin servers:
    servers.add(server)

proc getNameServers*(): seq[TransportAddress] =
  var servers: seq[TransportAddress]
  var size = 0'u32
  if getAdaptersAddresses(AfUnspec, 0, nil, nil, addr size) != ErrorBufferOverflow or
      size == 0:
    return @[]

  for attempt in 0 ..< MaxAdapterQueryAttempts:
    let addresses = cast[ptr IpAdapterAddresses](alloc0(int(size)))
    if addresses.isNil:
      return @[]
    defer:
      dealloc(addresses)

    let status = getAdaptersAddresses(AfUnspec, 0, nil, addresses, addr size)
    if status == ErrorBufferOverflow:
      continue
    if status != ErrorSuccess:
      return @[]

    var adapter = addresses
    while not adapter.isNil:
      if adapter[].operStatus == IfOperStatusUp:
        var server = adapter[].firstDnsServerAddress
        while not server.isNil:
          servers.addWindowsNameServer(server[].address)
          server = server[].next
      adapter = adapter[].next
    return servers
  return @[]
