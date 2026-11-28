# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Routing-table admission policy: bound how many peers of one IP group a table
## and a single bucket accept, so one network cannot own the peers a key maps to.

import std/[sequtils, net, sets]
import results
import ../../[peerid, peerstore, multiaddress, wire]
import ./[types, routing_table]

{.push raises: [].}

type
  PeerIps = object
    ipv4s: seq[IpAddress]
    ipv6s: seq[IpAddress]

  DiversityPeer = object
    ips: PeerIps
    sameBucket: bool ## shares the bucket the candidate would be admitted to

  GroupCount = object
    table: int
    bucket: int

func subnetOf(ip: IpAddress): IpAddress =
  var subnet = ip
  case ip.family
  of IpAddressFamily.IPv4:
    subnet.address_v4[3] = 0
  of IpAddressFamily.IPv6:
    for i in 8 ..< 16:
      subnet.address_v6[i] = 0
  return subnet

func ipsOf(peer: DiversityPeer, ip: IpAddress): seq[IpAddress] =
  case ip.family
  of IpAddressFamily.IPv4:
    return peer.ips.ipv4s
  of IpAddressFamily.IPv6:
    return peer.ips.ipv6s

func countPeer(c: var GroupCount, sameBucket: bool) =
  c.table.inc
  if sameBucket:
    c.bucket.inc

func within(c: GroupCount, cap: DiversityCap): bool =
  return c.table < cap.table and c.bucket < cap.bucket

func uniquePublicIps(addrs: openArray[MultiAddress]): PeerIps =
  # Only a literal public IP has a prefix to count; a relay or DNS address has none.
  var peerIps: PeerIps
  var ipv4s: HashSet[array[4, byte]]
  var ipv6s: HashSet[array[16, byte]]
  for ma in addrs:
    if not ma.isPublicMA():
      continue
    let ip = ma.getIp().valueOr:
      continue
    case ip.family
    of IpAddressFamily.IPv4:
      if not ipv4s.containsOrIncl(ip.address_v4):
        peerIps.ipv4s.add(ip)
    of IpAddressFamily.IPv6:
      if not ipv6s.containsOrIncl(ip.address_v6):
        peerIps.ipv6s.add(ip)
  return peerIps

proc diversityPeer(
    addressBook: AddressBook, peerId: PeerId, sameBucket: bool
): DiversityPeer =
  DiversityPeer(ips: addressBook[peerId].uniquePublicIps(), sameBucket: sameBucket)

proc diversityPeers(
    addressBook: AddressBook,
    rtable: RoutingTable,
    candidate: PeerId,
    pending: openArray[PeerId],
): seq[DiversityPeer] =
  ## In-flight probes count too, so one reply cannot fan out dials.
  let candidateBucket = rtable.bucketIndex(candidate.toKey())
  var peers: seq[DiversityPeer]

  # A bucket's index is its peers' bucket index; rehashing each key costs a sha256.
  for idx, bucket in rtable.buckets:
    for key in bucket.peers:
      let pid = key.toPeerId().valueOr:
        continue
      if pid == candidate:
        continue
      peers.add(addressBook.diversityPeer(pid, idx == candidateBucket))

  for pid in pending:
    if pid == candidate:
      continue
    let key = pid.toKey()
    # A probe that already landed in the table holds one slot, not two.
    if key in rtable:
      continue
    peers.add(
      addressBook.diversityPeer(pid, rtable.bucketIndex(key) == candidateBucket)
    )

  peers

func admitsIp(
    candidateIp: IpAddress,
    others: openArray[DiversityPeer],
    ipCap, subnetCap: DiversityCap,
): bool =
  ## Counts peers, not addresses: many addresses of one group fill one slot.
  let candidateSubnet = candidateIp.subnetOf()
  var exact, subnet: GroupCount

  for other in others:
    let ips = other.ipsOf(candidateIp)
    if ips.anyIt(it == candidateIp):
      exact.countPeer(other.sameBucket)
    if ips.anyIt(it.subnetOf() == candidateSubnet):
      subnet.countPeer(other.sameBucket)

  return exact.within(ipCap) and subnet.within(subnetCap)

proc hasIpDiversity*(
    addressBook: AddressBook,
    rtable: RoutingTable,
    peerId: PeerId,
    addrs: openArray[MultiAddress],
    caps: DiversityCaps,
    pending: openArray[PeerId] = [],
): bool =
  # The caps gate new admissions, not address refreshes of current members.
  if peerId.toKey() in rtable:
    return true

  let candidateIps = addrs.uniquePublicIps()
  # No public literal IP means no prefix to count; the address policy decides.
  if candidateIps.ipv4s.len == 0 and candidateIps.ipv6s.len == 0:
    return true

  let others = addressBook.diversityPeers(rtable, peerId, pending)
  # One public address below every cap admits the peer.
  for candidateIp in candidateIps.ipv4s:
    if candidateIp.admitsIp(others, caps.perIp, caps.perIpv4Subnet):
      return true

  for candidateIp in candidateIps.ipv6s:
    if candidateIp.admitsIp(others, caps.perIp, caps.perIpv6Subnet):
      return true

  false
