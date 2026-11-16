# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[net, tables]
import chronos, results
import ../../peerid
import ../../utils/[iptree, opt]
import ./types

export types

proc len*(c: AdvertisementCache): int =
  c.count

proc serviceLen*(c: AdvertisementCache): int =
  c.byService.len

proc serviceCacheAdsLen*(c: AdvertisementCache, serviceId: ServiceId): int =
  c.byService.withValue(serviceId, peers):
    return peers[].len
  0

proc contains*(c: AdvertisementCache, serviceId: ServiceId): bool =
  serviceId in c.byService

proc contains*(c: AdvertisementCache, serviceId: ServiceId, advertiser: PeerId): bool =
  c.byService.withValue(serviceId, peers):
    return advertiser in peers[]
  false

proc getServiceCachedAds*(
    c: AdvertisementCache, serviceId: ServiceId, limit: int
): seq[CachedAd] =
  if limit <= 0:
    return @[]
  var ads: seq[CachedAd]
  c.byService.withValue(serviceId, peers):
    ads = newSeqOfCap[CachedAd](min(limit, peers[].len))
    for _, cachedAd in peers[]:
      if ads.len >= limit:
        break
      ads.add(cachedAd)
  ads

proc getCachedAd*(
    c: AdvertisementCache, serviceId: ServiceId, advertiser: PeerId
): Opt[CachedAd] =
  c.byService.withValue(serviceId, peers):
    return peers[].getOpt(advertiser)
  Opt.none(CachedAd)

proc ipSimilarity*(
    c: AdvertisementCache,
    ips: seq[IpAddress],
    advertiser: Opt[PeerId],
    serviceId: ServiceId,
    discountedServices: int,
): float64 =
  ## The own IPs of `advertiser` count once it has `discountedServices` or more other ads.
  if discountedServices <= 0:
    return c.ipTree.ipsMaxScore(ips)
  let peer = advertiser.valueOr:
    return c.ipTree.ipsMaxScore(ips)

  var otherServices = 0
  var peerIps: seq[IpAddress]
  for sid, peers in c.byService.mpairs:
    peers.withValue(peer, cachedAd):
      if sid != serviceId:
        inc otherServices
        if otherServices >= discountedServices:
          return c.ipTree.ipsMaxScore(ips)
      peerIps.add(cachedAd[].ips)

  c.ipTree.ipsMaxScore(ips, peerIps)

proc remove*(c: AdvertisementCache, serviceId: ServiceId, advertiser: PeerId) =
  c.byService.withValue(serviceId, peers):
    peers[].withValue(advertiser, cachedAd):
      c.ipTree.removeIps(cachedAd[].ips)
      peers[].del(advertiser)
      dec c.count
    if peers[].len > 0:
      return

    c.byService.del(serviceId)
    if not c.onServiceRemoved.isNil():
      c.onServiceRemoved(serviceId)

proc findOldest(c: AdvertisementCache): Opt[(ServiceId, PeerId)] =
  var oldest = Opt.none((ServiceId, PeerId))
  var oldestTime = Moment.high

  for serviceId, peers in c.byService:
    for advertiser, cachedAd in peers:
      if cachedAd.timestamp <= oldestTime:
        oldestTime = cachedAd.timestamp
        oldest = Opt.some((serviceId, advertiser))

  oldest

proc evictOldest(c: AdvertisementCache) =
  c.findOldest().ifValue(entry):
    c.remove(entry[0], entry[1])

proc hasNewer*(c: AdvertisementCache, serviceId: ServiceId, ad: Advertisement): bool =
  ## True when the service holds an ad signed by the same peer with a higher seqNo.
  c.byService.withValue(serviceId, peers):
    for _, cachedAd in peers[]:
      if cachedAd.ad.data.peerId == ad.data.peerId and
          cachedAd.ad.data.seqNo > ad.data.seqNo:
        return true
  false

proc removeSuperseded(c: AdvertisementCache, serviceId: ServiceId, ad: Advertisement) =
  var superseded: seq[PeerId]
  c.byService.withValue(serviceId, peers):
    for advertiser, cachedAd in peers[]:
      if cachedAd.ad.data.peerId == ad.data.peerId and
          cachedAd.ad.data.seqNo < ad.data.seqNo:
        superseded.add(advertiser)

  for advertiser in superseded:
    c.remove(serviceId, advertiser)

proc put*(
    c: AdvertisementCache,
    serviceId: ServiceId,
    advertiser: PeerId,
    ad: Advertisement,
    ips: seq[IpAddress],
    now: Moment,
) =
  ## Insert or replace the ad for `(serviceId, advertiser)`; skip it when its signer has a newer cached ad.
  if c.hasNewer(serviceId, ad):
    return

  c.removeSuperseded(serviceId, ad)

  c.byService.withValue(serviceId, peers):
    if advertiser in peers[]:
      peers[].withValue(advertiser, cachedAd):
        c.ipTree.removeIps(cachedAd[].ips)
        cachedAd[] = CachedAd(ad: ad, advertiser: advertiser, ips: ips, timestamp: now)
        c.ipTree.insertIps(ips)
      return

  if c.count.uint64 >= c.capacity:
    c.evictOldest()

  if serviceId notin c.byService:
    c.byService[serviceId] = initTable[PeerId, CachedAd]()
  c.byService.withValue(serviceId, peers):
    peers[][advertiser] =
      CachedAd(ad: ad, advertiser: advertiser, ips: ips, timestamp: now)
  c.ipTree.insertIps(ips)
  inc c.count

proc pruneExpired*(c: AdvertisementCache, now: Moment, expiry: Duration): int =
  ## Remove cachedAds whose timestamp is older than `expiry`. Returns how many
  ## cachedAds were removed.
  let cutoff = now - expiry
  var
    removed = 0
    toRemove: seq[(ServiceId, PeerId)]

  for serviceId, peers in c.byService:
    for advertiser, cachedAd in peers:
      if cachedAd.timestamp < cutoff:
        toRemove.add((serviceId, advertiser))

  for (serviceId, advertiser) in toRemove:
    c.remove(serviceId, advertiser)
    inc removed

  removed

proc clear*(c: AdvertisementCache) =
  var removed = newSeqOfCap[ServiceId](c.byService.len)
  for serviceId in c.byService.keys:
    removed.add(serviceId)

  c.byService.clear()
  c.ipTree = IpTree.new()
  c.count = 0

  if c.onServiceRemoved.isNil():
    return
  for serviceId in removed:
    c.onServiceRemoved(serviceId)
