# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.push raises: [].}

import chronos, chronicles, results, strutils
import stew/[base36, base64]
import
  ../errors,
  ../peerid,
  ../multihash,
  ../cid,
  ../multicodec,
  ../nameresolving/nameresolver,
  ./acme/client

logScope:
  topics = "libp2p auto-tls"

type AutoTLSError* = object of LPError

const
  DefaultDnsRetries = 3
  DefaultDnsRetryTime = 1.seconds

proc encodePeerId*(peerId: PeerId): Result[string, string] =
  var mh: MultiHash
  let decoded = MultiHash.decode(peerId.data, mh)
  if decoded.isErr() or decoded.get() == -1:
    return err("Failed to decode PeerId: invalid multihash format")

  let cid = Cid.init(CIDv1, multiCodec("libp2p-key"), mh).valueOr:
    return err("Failed to initialize CID from multihash")

  ok(Base36.encode(cid.data.buffer))

const PemLineWidth = 64

func pemEncode*(data: openArray[byte], banner: string): string =
  ## RFC 7468: padded base64 in 64-column lines, between BEGIN and END banners.
  var pem = "-----BEGIN " & banner & "-----\n"

  let body = Base64Pad.encode(data)
  var i = 0
  while i < body.len:
    let stop = min(i + PemLineWidth, body.len)
    pem.add(body[i ..< stop])
    pem.add('\n')
    i = stop

  pem & "-----END " & banner & "-----\n"

func dnsLabel(ipAddress: IpAddress): string =
  ## p2p-forge label: 100.10.10.3 gives 100-10-10-3, ::1 gives 0--1 (RFC 1123).
  if ipAddress.family == IpAddressFamily.IPv4:
    return ($ipAddress).replace('.', '-')

  var label = ($ipAddress).replace(':', '-')
  if label.startsWith('-'):
    label = "0" & label
  if label.endsWith('-'):
    label = label & "0"
  label

proc checkDNSRecords*(
    nameResolver: NameResolver,
    ipAddress: IpAddress,
    baseDomain: api.Domain,
    keyAuth: KeyAuthorization,
    retries: int = DefaultDnsRetries,
    retryTime: Duration = DefaultDnsRetryTime,
): Future[bool] {.async: (raises: [AutoTLSError, CancelledError]).} =
  let acmeChalDomain = api.Domain("_acme-challenge." & baseDomain)
  let ipDomain = api.Domain(ipAddress.dnsLabel() & "." & baseDomain)
  trace "Waiting for DNS record to be set", ip = ipDomain, acmeDomain = acmeChalDomain

  for attempt in 0 .. retries:
    if attempt > 0:
      await sleepAsync(retryTime)

    let txt = await nameResolver.resolveTxt(acmeChalDomain)
    var resolvedIps: seq[TransportAddress]
    try:
      resolvedIps = await nameResolver.resolveIp(ipDomain, 0.Port)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      trace "Failed to resolve IP", err = exc.msg # retry

    if txt.len > 0 and txt[0] == keyAuth and resolvedIps.len > 0:
      return true

  return false
