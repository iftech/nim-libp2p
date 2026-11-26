# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Time of one `findClosest` call on a 300-key routing table with the default
## SHA-256 hasher. `make bench_kad_find_closest` runs it, and no CI job does.
## `-d:findClosestBenchRounds=N` overrides the default.

import std/[monotimes, sequtils, strformat, times]
import ../../libp2p/[protocols/kademlia, crypto/crypto]

const
  findClosestBenchRounds {.intdefine.} = 1000
  TableKeys = 300
  MaxInsertAttempts = 4_000_000

static:
  doAssert findClosestBenchRounds > 0, "findClosestBenchRounds must be positive"

proc randomKey(rng: Rng): Key =
  var buf = newSeqUninit[byte](IdLength)
  rng.generate(buf)
  Key.fromBytes(buf)

proc keyCount(rt: RoutingTable): int =
  var total = 0
  for bucket in rt.buckets:
    total += bucket.peers.len
  total

proc filledTable(rng: Rng): RoutingTable =
  let rt = RoutingTable.new(randomKey(rng))
  for _ in 0 ..< MaxInsertAttempts:
    if rt.keyCount() >= TableKeys:
      return rt
    discard rt.insert(randomKey(rng))
  raiseAssert &"table holds {rt.keyCount()} keys after {MaxInsertAttempts} inserts"

proc main() =
  let rng = newRng()
  let rt = filledTable(rng)
  let targets = newSeqWith(findClosestBenchRounds, randomKey(rng))

  var found = 0
  let started = getMonoTime()
  for target in targets:
    found += rt.findClosest(target, DefaultReplication).len
  let elapsed = getMonoTime() - started

  doAssert found == findClosestBenchRounds * DefaultReplication,
    &"found {found} keys, expected {findClosestBenchRounds * DefaultReplication}"
  let perCall = elapsed.inNanoseconds().float / findClosestBenchRounds.float / 1000.0
  echo &"findClosest: {rt.keyCount()} keys, {findClosestBenchRounds} rounds, " &
    &"{perCall:.1f} us per call"

main()
