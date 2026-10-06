# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[random, tables]

import pkg/[chronos, chronicles, metrics]

import multiaddress, multicodec, peerid, utils/opt

logScope:
  topics = "libp2p dial-backoff"

declareCounter libp2p_dial_backoffs,
  "failures that started or raised a backoff", ["scope"]
declareCounter libp2p_dial_backoff_skips, "dials skipped while on backoff", ["scope"]
declarePublicGauge libp2p_dial_backoff_entries,
  "entries in the dial backoff table, capped at MaxBackoffEntries", ["scope"]

const MaxBackoffEntries* = 1024
  ## Cap per table, so a peer that names a fresh address per dial stays bounded.

const p2pCodec = multiCodec("p2p")

type
  DialBackoffConfig* = object
    tolerance*: int ## consecutive failures dialed before the first backoff
    base*: Duration ## wait after the first failure over the tolerance
    factor*: int ## multiplier that each further failure applies
    maxDelay*: Duration
      ## ceiling on the wait, and the idle time an entry keeps its count
    jitter*: float ## fraction of the wait that is drawn off at random, in `0.0 .. 1.0`

  BackoffEntry = object
    failures: int
    until: Moment

  DialBackoff* = ref object
    config: DialBackoffConfig
    rng: Rand
    peers: Table[PeerId, BackoffEntry]
    addrs: Table[MultiAddress, BackoffEntry]

const DefaultDialBackoff* = DialBackoffConfig(
  tolerance: 0, base: 5.seconds, factor: 2, maxDelay: 5.minutes, jitter: 0.2
)

proc backoffKey*(address: MultiAddress, peerId: Opt[PeerId]): MultiAddress =
  ## Any peer can advertise any address, so the key holds the peer that named it.

  let pid = peerId.valueOr:
    return address

  let p2pPart = MultiAddress.init(p2pCodec, pid.data).valueOr:
    return address

  concat(address, p2pPart).valueOr:
    return address

func delay(config: DialBackoffConfig, failures: int): Duration =
  ## The wait after `failures` consecutive failures, zero under the tolerance.

  if failures <= config.tolerance:
    return ZeroDuration

  if config.base <= ZeroDuration or config.maxDelay <= ZeroDuration:
    return ZeroDuration

  if config.factor <= 1:
    return min(config.base, config.maxDelay)

  var delay = config.base
  for _ in 1 ..< failures - config.tolerance:
    if delay > config.maxDelay div config.factor:
      return config.maxDelay
    delay = delay * config.factor

  if delay > config.maxDelay: config.maxDelay else: delay

func decayed(config: DialBackoffConfig, entry: BackoffEntry, now: Moment): bool =
  ## True once the entry spent a full `maxDelay` blocking nothing.
  entry.until + config.maxDelay <= now

proc prune[K](
    entries: var Table[K, BackoffEntry], config: DialBackoffConfig, now: Moment
) =
  var stale: seq[K]
  for key, entry in entries:
    if config.decayed(entry, now):
      stale.add(key)

  for key in stale:
    entries.del(key)

proc evictSoonest[K](entries: var Table[K, BackoffEntry]) =
  ## Drop the entry whose wait ends first, so a full table keeps taking failures.

  var
    soonest: K
    ends: Moment
    empty = true

  for key, entry in entries:
    if empty or entry.until < ends:
      soonest = key
      ends = entry.until
      empty = false

  if not empty:
    entries.del(soonest)

proc blockedIn[K](
    entries: Table[K, BackoffEntry], key: K, scope: string, now: Moment
): bool =
  let entry = entries.getOrDefault(key, BackoffEntry(until: now))
  if entry.until <= now:
    return false

  libp2p_dial_backoff_skips.inc(labelValues = [scope])
  trace "Skipping the dial, it is on backoff",
    scope, key, backoffMs = (entry.until - now).milliseconds
  true

proc jittered(self: DialBackoff, delay: Duration): Duration =
  ## Spread the retries of the peers that failed together.

  if delay <= ZeroDuration or self.config.jitter <= 0.0:
    return delay

  let span = int(float(delay.nanoseconds) * min(self.config.jitter, 1.0))
  delay - nanoseconds(self.rng.rand(span))

proc countFailure[K](
    self: DialBackoff,
    entries: var Table[K, BackoffEntry],
    key: K,
    scope: string,
    now: Moment,
) =
  if entries.len >= MaxBackoffEntries and key notin entries:
    entries.prune(self.config, now)
    if entries.len >= MaxBackoffEntries:
      entries.evictSoonest()

  var entry = entries.getOrDefault(key, BackoffEntry(until: now))
  if self.config.decayed(entry, now):
    entry = BackoffEntry(until: now)

  entry.failures.inc()
  entry.until = now + self.jittered(self.config.delay(entry.failures))
  entries[key] = entry
  libp2p_dial_backoff_entries.set(entries.len, labelValues = [scope])

  if entry.until <= now:
    return

  libp2p_dial_backoffs.inc(labelValues = [scope])
  trace "Backing the dial off",
    scope, key, failures = entry.failures, backoffMs = (entry.until - now).milliseconds

proc blocked*(self: DialBackoff, peerId: PeerId, now = Moment.now()): bool =
  self.peers.blockedIn(peerId, "peer", now)

proc blocked*(self: DialBackoff, address: MultiAddress, now = Moment.now()): bool =
  self.addrs.blockedIn(address, "address", now)

proc blocked*(self: DialBackoff, peerId: Opt[PeerId], now = Moment.now()): bool =
  peerId.ifValue(pid):
    return self.blocked(pid, now)
  false

proc recordFailure*(self: DialBackoff, peerId: PeerId, now = Moment.now()) =
  self.countFailure(self.peers, peerId, "peer", now)

proc recordFailure*(self: DialBackoff, address: MultiAddress, now = Moment.now()) =
  self.countFailure(self.addrs, address, "address", now)

proc recordFailure*(self: DialBackoff, peerId: Opt[PeerId], now = Moment.now()) =
  peerId.ifValue(pid):
    self.recordFailure(pid, now)

proc recordSuccess*(self: DialBackoff, peerId: PeerId) =
  self.peers.del(peerId)
  libp2p_dial_backoff_entries.set(self.peers.len, labelValues = ["peer"])

proc recordSuccess*(self: DialBackoff, address: MultiAddress) =
  self.addrs.del(address)
  libp2p_dial_backoff_entries.set(self.addrs.len, labelValues = ["address"])

proc recordSuccess*(self: DialBackoff, peerId: Opt[PeerId]) =
  peerId.ifValue(pid):
    self.recordSuccess(pid)

proc new*(T: type DialBackoff, config: DialBackoffConfig): T =
  T(config: config, rng: initRand())
