# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[algorithm, sequtils]
import pkg/[chronos, chronicles]
import ./results
import
  peerid,
  multiaddress,
  multicodec,
  crypto/crypto,
  routing_record,
  peeraddrpolicy,
  errors,
  utils/lock,
  utils/shortlog

export peerid, multiaddress, crypto, routing_record, peeraddrpolicy, errors, results

logScope:
  topics = "libp2p peer-info"

const p2pMultiCodec = multiCodec("p2p")

type
  PeerInfoError* = object of LPError

  AddressMapper* = proc(listenAddrs: seq[MultiAddress]): Future[seq[MultiAddress]] {.
    gcsafe, async: (raises: [CancelledError])
  .} ## A proc that resolves listen addresses into dialable addresses.

  PeerInfoObserver* = proc(p: PeerInfo) {.gcsafe, raises: [].}
    ## A callback type for observing changes in a `PeerInfo`'s resolved addresses.
    ## `PeerInfo` object passed to the observer contains the updated state at the time of the callback.
    ##
    ## This observer is invoked in two scenarios:
    ## 1. Automatically after a call to `PeerInfo.update`, which may change the
    ##    resolved `addrs` list.
    ## 2. Manually when `PeerInfo.notifyObservers` is called explicitly.

  PeerInfo* = ref object ## PeerInfo represents our local peer info
    peerId*: PeerId
    listenAddrs*: seq[MultiAddress]
    ## contains addresses the node listens on, which may include wildcard and private addresses (not directly reachable).
    announcedAddrs*: seq[MultiAddress]
    ## explicit addresses to announce to peers, distinct from listenAddrs.
    ## When non-empty, these replace the output of the mapper chain, e.g. to
    ## advertise a public NAT-mapped address while binding locally. The mappers
    ## still run, and addressPolicy still filters.
    addrs*: seq[MultiAddress]
    ## contains resolved addresses that other peers can use to connect, including public-facing NAT and port-forwarded addresses.
    addressMappers*: seq[AddressMapper]
    ## contains a list of procs that can be used to resolve the listen addresses into dialable addresses.
    addressPolicy*: PeerAddressPolicy
    ## applied after address mappers
    protocols*: seq[string]
    protoVersion*: string
    agentVersion*: string
    privateKey*: PrivateKey
    publicKey*: PublicKey
    signedPeerRecord*: SignedPeerRecord
    observers: seq[PeerInfoObserver]
    expandAddrsLock: AsyncLock
    ## serializes address-mapper passes, which can mutate mapper state

func shortLog*(p: PeerInfo): auto =
  (
    peerId: $p.peerId,
    listenAddrs: p.listenAddrs.mapIt($it),
    addrs: p.addrs.mapIt($it),
    protocols: p.protocols.mapIt($it),
    protoVersion: p.protoVersion,
    agentVersion: p.agentVersion,
  )

chronicles.formatIt(PeerInfo):
  shortLog(it)

proc addObserver*(p: PeerInfo, observer: PeerInfoObserver) =
  if observer.isNil:
    return
  p.observers.add(observer)

proc removeObserver*(p: PeerInfo, observer: PeerInfoObserver) =
  p.observers.keepItIf(it != observer)

proc notifyObservers*(p: PeerInfo) =
  for observer in p.observers:
    observer(p)

proc ensureExpandAddrsLock(p: PeerInfo): AsyncLock =
  ## `PeerInfo` is public and can be constructed directly, bypassing `tryNew`.
  if p.expandAddrsLock.isNil:
    p.expandAddrsLock = newAsyncLock()
  p.expandAddrsLock

proc expandAddrs*(
    p: PeerInfo, listenAddrs: seq[MultiAddress]
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  ## Resolve the complete supplied set of bound listen addresses into dialable
  ## addresses.
  ## This lets startup-time users work with transport addresses before the switch
  ## has published them in ``p.listenAddrs``.
  ##
  ## Mappers may maintain state based on the supplied set, so callers must not
  ## pass only a subset of addresses that remain bound.
  withLock p.ensureExpandAddrsLock():
    var addrs = listenAddrs
    for mapper in p.addressMappers:
      addrs = await mapper(addrs)

    # a port mapper maps the bound ports even when the operator picks
    # what is announced, so the chain runs first
    if p.announcedAddrs.len > 0:
      addrs = p.announcedAddrs

    return p.addressPolicy.filterAddrs(addrs)

proc expandAddrs*(
    p: PeerInfo
): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
  await p.expandAddrs(p.listenAddrs)

proc update*(p: PeerInfo) {.async: (raises: [CancelledError]).} =
  var hasChanged: bool
  defer:
    if hasChanged:
      p.notifyObservers()

  let newAddrs = await p.expandAddrs()

  hasChanged = p.addrs.sorted() != newAddrs.sorted()
  p.addrs = newAddrs

  p.signedPeerRecord = SignedPeerRecord.init(
    p.privateKey, PeerRecord.init(p.peerId, p.addrs)
  ).valueOr:
    debug "Signed peer record update failed"
    return

proc addrs*(p: PeerInfo): seq[MultiAddress] =
  p.addrs

proc fullAddrs*(p: PeerInfo): MaResult[seq[MultiAddress]] =
  let peerIdPart = ?MultiAddress.init(p2pMultiCodec, p.peerId.data)
  var res = newSeqOfCap[MultiAddress](p.addrs.len)
  for address in p.addrs:
    res.add(?concat(address, peerIdPart))
  ok(res)

proc stripPeerId*(ma: MultiAddress): MultiAddress =
  ## Strip a terminal /p2p/<peer-id> suffix from a dial address.
  ## Keeps relay route components like /p2p/<relay>/p2p-circuit intact.
  let maLen = ma.len().valueOr:
    return ma

  if maLen < 2:
    return ma

  let lastPart = ma[^1].valueOr:
    return ma

  let protoCode = lastPart.protoCode().valueOr:
    return ma
  if protoCode != p2pMultiCodec:
    return ma

  let protoArg = lastPart.protoArgument().valueOr:
    return ma

  discard PeerId.init(protoArg).valueOr:
    return ma

  ma[0 .. ^2].valueOr:
    return ma

proc parseFullAddress*(ma: MultiAddress): MaResult[(PeerId, MultiAddress)] =
  let p2pPart = ?ma[^1]
  if ?p2pPart.protoCode != p2pMultiCodec:
    return err("missing p2p part from multiaddress")

  let peerId = ?PeerId.init(?p2pPart.protoArgument()).orErr("invalid peerid")

  ok((peerId, ?ma[0 .. ^2]))

proc parseFullAddress*(ma: string | seq[byte]): MaResult[(PeerId, MultiAddress)] =
  parseFullAddress(?MultiAddress.init(ma))

proc toFullAddress*(peerId: PeerId, ma: MultiAddress): MaResult[MultiAddress] =
  let peerIdPart = ?MultiAddress.init(p2pMultiCodec, peerId.data)
  concat(ma, peerIdPart)

proc tryNew*(
    p: typedesc[PeerInfo],
    key: PrivateKey,
    listenAddrs: openArray[MultiAddress] = [],
    protocols: openArray[string] = [],
    protoVersion: string = "",
    agentVersion: string = "",
    addressMappers = newSeq[AddressMapper](),
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
    announcedAddrs: openArray[MultiAddress] = [],
): LPResult[PeerInfo] =
  let pubkey = key.getPublicKey().valueOr:
    return err(error, "PeerInfo.tryNew called with invalid private key")
  let peerId = PeerId.init(pubkey).valueOr:
    return err(error, "PeerInfo.tryNew failed to derive peer id from public key")

  ok PeerInfo(
    peerId: peerId,
    publicKey: pubkey,
    privateKey: key,
    protoVersion: protoVersion,
    agentVersion: agentVersion,
    listenAddrs: @listenAddrs,
    announcedAddrs: @announcedAddrs,
    protocols: @protocols,
    addressMappers: addressMappers,
    addressPolicy: addressPolicy,
    expandAddrsLock: newAsyncLock(),
  )

proc new*(
    p: typedesc[PeerInfo],
    key: PrivateKey,
    listenAddrs: openArray[MultiAddress] = [],
    protocols: openArray[string] = [],
    protoVersion: string = "",
    agentVersion: string = "",
    addressMappers = newSeq[AddressMapper](),
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
    announcedAddrs: openArray[MultiAddress] = [],
): PeerInfo {.raises: [LPError].} =
  PeerInfo
    .tryNew(
      key, listenAddrs, protocols, protoVersion, agentVersion, addressMappers,
      addressPolicy, announcedAddrs,
    )
    .valueOrRaise(PeerInfoError)
