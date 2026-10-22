# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/tables
import chronos
import ../../libp2p/[muxer_store, muxers/muxer, stream/connection, peerinfo]
import ../tools/unittest
import ../tools/crypto

template makeMuxer(name: untyped, pid: PeerId, dir: Direction = Direction.In) =
  let name = Muxer(connection: Connection.new(pid, dir))
  defer:
    await name.close()

suite "MuxerStore":
  teardown:
    checkTrackers()

  let pidA = PeerId.random()
  let pidB = PeerId.random()
  let pid = pidA

  test "new creates an empty store":
    let store = MuxerStore.new()
    check:
      store.countPeers() == 0
      store.getAll().len == 0

  asyncTest "add single muxer":
    let store = MuxerStore.new()
    makeMuxer(mux, pid)

    check store.add(mux) == true
    check store.countPeers() == 1
    check store.contains(pid) == true
    check store.contains(mux) == true
    check store.count(pid) == 1

  asyncTest "add returns false for duplicate muxer":
    let store = MuxerStore.new()
    makeMuxer(mux, pid)

    check store.add(mux) == true
    check store.add(mux) == false
    check store.count(pid) == 1

  asyncTest "add multiple muxers for same peer":
    let store = MuxerStore.new()
    makeMuxer(muxA, pid, Direction.In)
    makeMuxer(muxB, pid, Direction.Out)

    check store.add(muxA) == true
    check store.add(muxB) == true
    check store.countPeers() == 1
    check store.count(pid) == 2

  asyncTest "add muxers for different peers":
    let store = MuxerStore.new()
    makeMuxer(muxA, pidA)
    makeMuxer(muxB, pidB)

    check store.add(muxA) == true
    check store.add(muxB) == true
    check store.countPeers() == 2
    check store.count(pidA) == 1
    check store.count(pidB) == 1

  test "contains peer returns false for unknown peer":
    let store = MuxerStore.new()
    check store.contains(pid) == false

  asyncTest "contains muxer returns false for unknown muxer":
    let store = MuxerStore.new()
    makeMuxer(mux, pid)

    check store.contains(mux) == false

  test "count returns 0 for unknown peer":
    let store = MuxerStore.new()
    check store.count(pid) == 0

  asyncTest "remove by peer returns muxers and cleans up":
    let store = MuxerStore.new()
    makeMuxer(muxA, pid, Direction.In)
    makeMuxer(muxB, pid, Direction.Out)

    discard store.add(muxA)
    discard store.add(muxB)
    check store.countPeers() == 1

    let removed = store.remove(pid)
    check removed.len == 2
    check muxA in removed
    check muxB in removed
    check store.countPeers() == 0
    check store.contains(pid) == false

  test "remove by peer returns empty seq for unknown peer":
    let store = MuxerStore.new()
    let removed = store.remove(pid)
    check removed.len == 0

  asyncTest "remove muxer returns true and removes entry":
    let store = MuxerStore.new()
    makeMuxer(mux, pid)

    discard store.add(mux)
    check store.remove(mux) == true
    check store.contains(mux) == false
    check store.contains(pid) == false
    check store.countPeers() == 0

  asyncTest "remove muxer cleans up peer when last muxer removed":
    let store = MuxerStore.new()
    makeMuxer(muxA, pid, Direction.In)
    makeMuxer(muxB, pid, Direction.Out)

    discard store.add(muxA)
    discard store.add(muxB)

    check store.remove(muxA) == true
    check store.contains(pid) == true
    check store.count(pid) == 1

    check store.remove(muxB) == true
    check store.contains(pid) == false
    check store.countPeers() == 0

  asyncTest "remove muxer returns false for unknown muxer":
    let store = MuxerStore.new()
    makeMuxer(mux, pid)

    check store.remove(mux) == false

  asyncTest "remove muxer returns false when muxer not in store for peer":
    let store = MuxerStore.new()
    makeMuxer(muxA, pidA)
    makeMuxer(muxB, pidB)

    discard store.add(muxA)
    check store.remove(muxB) == false

  asyncTest "getPeers filters by inbound direction":
    let store = MuxerStore.new()
    makeMuxer(muxA, pidA, Direction.In)
    makeMuxer(muxB, pidB, Direction.Out)

    discard store.add(muxA)
    discard store.add(muxB)

    let inPeers = store.getPeers(Direction.In)
    check inPeers.len == 1
    check pidA in inPeers
    check pidB notin inPeers

  asyncTest "getPeers filters by outbound direction":
    let store = MuxerStore.new()
    makeMuxer(muxA, pidA, Direction.In)
    makeMuxer(muxB, pidB, Direction.Out)

    discard store.add(muxA)
    discard store.add(muxB)

    let outPeers = store.getPeers(Direction.Out)
    check outPeers.len == 1
    check pidB in outPeers
    check pidA notin outPeers

  asyncTest "getPeers includes peer with both directions":
    let store = MuxerStore.new()
    makeMuxer(muxA, pid, Direction.In)
    makeMuxer(muxB, pid, Direction.Out)

    discard store.add(muxA)
    discard store.add(muxB)

    check pid in store.getPeers(Direction.In)
    check pid in store.getPeers(Direction.Out)

  test "getPeers returns empty seq when store is empty":
    let store = MuxerStore.new()
    check store.getPeers(Direction.In).len == 0
    check store.getPeers(Direction.Out).len == 0

  asyncTest "getPeers without direction returns peers of both directions":
    let store = MuxerStore.new()
    makeMuxer(muxA, pidA, Direction.In)
    makeMuxer(muxB, pidB, Direction.Out)

    discard store.add(muxA)
    discard store.add(muxB)

    let peers = store.getPeers()
    check peers.len == 2
    check pidA in peers
    check pidB in peers

  asyncTest "getPeers without direction lists a both-directions peer once":
    let store = MuxerStore.new()
    makeMuxer(muxIn, pid, Direction.In)
    makeMuxer(muxOut, pid, Direction.Out)

    discard store.add(muxIn)
    discard store.add(muxOut)

    check store.getPeers() == @[pid]

  test "getPeers without direction returns empty seq when store is empty":
    let store = MuxerStore.new()
    check store.getPeers().len == 0

  asyncTest "selectMuxer returns correct muxer by direction":
    let store = MuxerStore.new()
    makeMuxer(muxIn, pid, Direction.In)
    makeMuxer(muxOut, pid, Direction.Out)

    discard store.add(muxIn)
    discard store.add(muxOut)

    check store.selectMuxer(pid, Direction.In) == muxIn
    check store.selectMuxer(pid, Direction.Out) == muxOut

  test "selectMuxer returns nil for unknown peer":
    let store = MuxerStore.new()
    check store.selectMuxer(pid, Direction.In) == nil

  asyncTest "selectMuxer returns nil when direction not present":
    let store = MuxerStore.new()
    makeMuxer(muxIn, pid, Direction.In)

    discard store.add(muxIn)
    check store.selectMuxer(pid, Direction.Out) == nil

  asyncTest "getAll returns all muxers grouped by peer":
    let store = MuxerStore.new()
    makeMuxer(mux1, pidA, Direction.In)
    makeMuxer(mux2, pidA, Direction.Out)
    makeMuxer(mux3, pidB, Direction.In)

    discard store.add(mux1)
    discard store.add(mux2)
    discard store.add(mux3)

    let all = store.getAll()
    check all.len == 2
    check all[pidA].len == 2
    check all[pidB].len == 1
    check mux1 in all[pidA]
    check mux2 in all[pidA]
    check mux3 in all[pidB]

  asyncTest "clear removes all entries":
    let store = MuxerStore.new()
    makeMuxer(muxA, pidA)
    makeMuxer(muxB, pidB)

    discard store.add(muxA)
    discard store.add(muxB)
    check store.countPeers() == 2

    store.clear()
    check store.countPeers() == 0
    check store.getAll().len == 0
    check store.contains(pidA) == false
    check store.contains(pidB) == false

  test "clear on empty store is a no-op":
    let store = MuxerStore.new()
    store.clear()
    check store.countPeers() == 0
