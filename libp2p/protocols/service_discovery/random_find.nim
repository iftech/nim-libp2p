# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[sequtils, sets]
import chronos, chronicles, results
import ../../[peerid, peerinfo, switch, multihash, routing_record, extended_peer_record]
import ../protocol
import ../kademlia/[types, find, get, protobuf]
import ./[types]

logScope:
  topics = "libp2p service-discovery"

type PendingGetVal = object
  key: Key
  fut: Future[LPResult[Message]].Raising([CancelledError])

proc replyXpr*(key: Key, reply: Message): Opt[SignedExtendedPeerRecord] =
  let record = reply.record.valueOr:
    return Opt.none(SignedExtendedPeerRecord)

  if record.key != Opt.some(key):
    trace "Get-value reply names another key", key
    return Opt.none(SignedExtendedPeerRecord)

  let value = record.value.valueOr:
    return Opt.none(SignedExtendedPeerRecord)

  boundXpr(key, value)

proc randomRecords(
    disco: ServiceDiscovery
): Future[seq[ExtendedPeerRecord]] {.async: (raises: [CancelledError]).} =
  ## Return all peer records on the path towards a random target ID.

  let randomPeerId = PeerId.random(disco.rng).valueOr:
    debug "Cannot generate random peer id", error
    return @[]

  let randomKey = randomPeerId.toKey()

  var queried: HashSet[PeerId]
  var pending: seq[PendingGetVal]

  # getValue runs in parallel with the rest of the lookup.
  let onReply = proc(
      peerId: PeerId, msg: Opt[Message], state: LookupState
  ): Future[void] {.async: (raises: []), gcsafe.} =
    if peerId notin queried:
      queried.incl(peerId)
      let key = peerId.toKey()
      pending.add(PendingGetVal(key: key, fut: disco.dispatchGetVal(peerId, key)))

  try:
    discard await disco.iterativeLookup(randomKey, findNodeDispatch, onReply)
  except CancelledError as e:
    await noCancel allFutures(pending.mapIt(it.fut.cancelAndWait()))
    raise e

  var records: HashSet[ExtendedPeerRecord]
  for p in pending:
    let res =
      try:
        await p.fut
      except CancelledError as e:
        await noCancel allFutures(pending.mapIt(it.fut.cancelAndWait()))
        raise e

    let reply = res.valueOr:
      trace "Kademlia get-value failed", err = error
      continue

    let sxpr = replyXpr(p.key, reply).valueOr:
      continue

    records.incl(sxpr.data)

  records.toSeq()

proc lookupRandom*(
    disco: ServiceDiscovery
): Future[seq[ExtendedPeerRecord]] {.async: (raises: [CancelledError]).} =
  await disco.randomRecords()
