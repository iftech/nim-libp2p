# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sets, sequtils, strutils]
import chronos, chronicles, stew/endians2
import ../[multiaddress, multicodec]

logScope:
  topics = "libp2p name-resolution"

type NameResolver* = ref object of RootObj

method resolveTxt*(
    self: NameResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]), base.} =
  ## Get TXT record
  raiseAssert "[NameResolver.resolveTxt] abstract method not implemented!"

method resolveIp*(
    self: NameResolver, address: string, port: Port, domain: Domain = Domain.AF_UNSPEC
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError]), base
.} =
  ## Resolve the specified address
  raiseAssert "[NameResolver.resolveIp] abstract method not implemented!"

proc getHostname*(ma: MultiAddress): string =
  let
    firstPart = ma[0].valueOr:
      return ""
    fpSplitted = ($firstPart).split('/', 2)
  if fpSplitted.len > 2:
    fpSplitted[2]
  else:
    ""

proc resolveOneAddress(
    self: NameResolver, ma: MultiAddress, domain: Domain = Domain.AF_UNSPEC, prefix = ""
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  # Resolve a single address
  let portPart = ma[1].valueOr:
    raise maErr error
  var pbuf: array[2, byte]
  let plen = portPart.protoArgument(pbuf).valueOr:
    raise maErr error
  if plen == 0:
    raise maErr "Incorrect port number"
  let
    port = Port(fromBytesBE(uint16, pbuf))
    dnsval = getHostname(ma)
    resolvedAddresses = await self.resolveIp(prefix & dnsval, port, domain)

  var resultAddrs: seq[MultiAddress]
  for resolvedAddr in resolvedAddresses:
    let address = MultiAddress.init(resolvedAddr).valueOr:
      raise maErr error
    var createdAddress = address[0].valueOr:
      raise maErr error
    for part in ma:
      let part = part.valueOr:
        raise maErr error
      if DNS.match(part):
        continue
      createdAddress &= part
    resultAddrs.add(createdAddress)
  resultAddrs

proc resolveDnsAddr*(
    self: NameResolver, ma: MultiAddress, depth: int = 0
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  if not DNSADDR.matchPartial(ma):
    return @[ma]

  trace "DNSADDR resolution started", address = ma
  if depth > 6:
    trace "DNSADDR resolution stopped at recursion limit", address = ma
    return @[]

  let
    dnsval = getHostname(ma)
    txt = await self.resolveTxt("_dnsaddr." & dnsval)

  trace "DNSADDR TXT records received", address = ma, recordCount = txt.len

  const codec = multiCodec("p2p")
  let maCodec = block:
    let hasCodec = ma.contains(codec).valueOr:
      raise maErr error
    if hasCodec:
      ma[codec]
    else:
      (static(default(MaResult[MultiAddress])))

  var res: seq[MultiAddress]
  for entry in txt:
    if not entry.startsWith("dnsaddr="):
      continue
    let
      entryValue = MultiAddress.init(entry[8 ..^ 1]).valueOr:
        raise maErr error
      entryHasCodec = entryValue.contains(multiCodec("p2p")).valueOr:
        raise maErr error
    if entryHasCodec and maCodec.isOk and entryValue[codec] != maCodec:
      continue

    let resolved = await self.resolveDnsAddr(entryValue, depth + 1)
    for r in resolved:
      res.add(r)

  if res.len == 0:
    trace "DNSADDR resolution failed", address = ma
  res

proc resolveMAddress*(
    self: NameResolver, address: MultiAddress
): Future[seq[MultiAddress]] {.
    async: (raises: [CancelledError, MaError, TransportAddressError])
.} =
  var res = initOrderedSet[MultiAddress]()
  if not DNS.matchPartial(address):
    res.incl(address)
  else:
    let
      firstPart = address[0].valueOr:
        raise maErr error
      code = firstPart.protoCode().valueOr:
        raise maErr error
      ads =
        case code
        of multiCodec("dns"):
          await self.resolveOneAddress(address)
        of multiCodec("dns4"):
          await self.resolveOneAddress(address, Domain.AF_INET)
        of multiCodec("dns6"):
          await self.resolveOneAddress(address, Domain.AF_INET6)
        of multiCodec("dnsaddr"):
          await self.resolveDnsAddr(address)
        else:
          raise maErr("Unsupported codec " & $code)
    for ad in ads:
      res.incl(ad)
  res.toSeq
