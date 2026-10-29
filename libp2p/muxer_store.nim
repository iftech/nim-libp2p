# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/[tables, sequtils]
import results
from peerinfo import PeerId
from muxers/muxer import Muxer
from stream/connection import Direction

type MuxerStore* = ref object
  muxed: Table[PeerId, seq[Muxer]]

proc getAll*(s: MuxerStore): Table[PeerId, seq[Muxer]] =
  return s.muxed

proc get*(s: MuxerStore, peerId: PeerId): Result[seq[Muxer], string] =
  s.muxed.withValue(peerId, muxers):
    return ok(muxers[])
  err("No connections for peer")

proc countPeers*(s: MuxerStore): int =
  return s.muxed.len

proc count*(s: MuxerStore, peerId: PeerId): int =
  s.muxed.withValue(peerId, muxers):
    return muxers[].len
  return 0

proc contains*(s: MuxerStore, peerId: PeerId): bool =
  peerId in s.muxed

proc contains*(s: MuxerStore, muxer: Muxer): bool =
  let peerId = muxer.connection.peerId
  s.muxed.withValue(peerId, muxers):
    return muxer in muxers[]
  return false

proc remove*(s: MuxerStore, peerId: PeerId): seq[Muxer] =
  let muxers = s.muxed.getOrDefault(peerId)
  s.muxed.del(peerId)
  return muxers

proc remove*(s: MuxerStore, muxer: Muxer): bool =
  let peerId = muxer.connection.peerId
  s.muxed.withValue(peerId, muxers):
    let idx = muxers[].find(muxer)
    if idx >= 0:
      muxers[].del(idx)
      if muxers[].len == 0:
        s.muxed.del(peerId)
      return true
  return false

proc add*(s: MuxerStore, muxer: Muxer): bool =
  let peerId = muxer.connection.peerId
  s.muxed.withValue(peerId, muxers):
    if muxer notin muxers[]:
      muxers[].add(muxer)
      return true
    return false
  do:
    s.muxed[peerId] = @[muxer]
    return true

proc getPeers*(s: MuxerStore): seq[PeerId] =
  return s.muxed.keys().toSeq()

proc getPeers*(s: MuxerStore, dir: Direction): seq[PeerId] =
  var peers = newSeqOfCap[PeerId](s.muxed.len)
  for peerId, mux in s.muxed:
    if mux.anyIt(it.connection.dir == dir):
      peers.add(peerId)
  return peers

proc selectMuxer*(s: MuxerStore, peerId: PeerId, dir: Direction): Muxer =
  s.muxed.withValue(peerId, muxers):
    for _, m in muxers[]:
      if m.connection.dir == dir:
        return m
  return nil

proc clear*(s: MuxerStore) =
  s.muxed.clear()

proc new*(T: type MuxerStore): T =
  T()
