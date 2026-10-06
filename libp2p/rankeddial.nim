# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[algorithm, sequtils, sets]

import pkg/[chronos, chronicles, metrics]

import dialcandidate, muxers/muxer, utils/collections, utils/future

logScope:
  topics = "libp2p dialer"

declarePublicHistogram libp2p_dial_candidates,
  "candidates a ranked dial queued after dedup",
  buckets = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0]
declarePublicCounter libp2p_dial_winner_rank, "ranked dials won, by rank", ["rank"]
declarePublicCounter libp2p_dial_cancelled_attempts,
  "losing attempts that a ranked dial cancelled or closed"

const MaxDialCandidates* = 32
  ## A peer names as many addresses as it likes, and each dnsaddr fans out further.

const MaxParallelDials* = 8 ## Attempts one ranked peer dial holds open at once.

const MaxExpandedAddresses = MaxDialCandidates * 8
  ## Ceiling on what one peer's dnsaddr chain holds in flight before the filter.

type
  DialAttempt* = Future[Muxer].Raising([CancelledError])
  CandidateLookup* = Future[seq[DialCandidate]].Raising([CancelledError])

  DialBudget = ref object
    ## One cap and one seen set shared by every holder of the same dial.
    left: int
    seen: HashSet[string]
    exhausted: AsyncEvent

  PendingAttempt = object
    rank: DialRank
    attempt: DialAttempt

  RankedDial* = ref object
    deadline: Moment
    attempt: proc(candidate: DialCandidate): DialAttempt {.gcsafe, raises: [].}
    expand: proc(candidate: DialCandidate): CandidateLookup {.gcsafe, raises: [].}
    resolve: proc(candidate: DialCandidate): CandidateLookup {.gcsafe, raises: [].}
    dialable: DialBudget
    unresolved: DialBudget
    queued: seq[DialCandidate] ## best rank first, in arrival order within a rank
    pending: seq[PendingAttempt]
    lookups: int ## advertised names whose lookups can still queue candidates
    changed: Future[void] ## completes when a candidate is queued or a name lookup ends

proc newBudget(limit: int): DialBudget =
  let budget = DialBudget(left: max(limit, 0), exhausted: newAsyncEvent())
  if budget.left == 0:
    budget.exhausted.fire()
  budget

proc take(budget: DialBudget, candidates: seq[DialCandidate]): seq[DialCandidate] =
  var fresh: seq[DialCandidate]
  for candidate in candidates:
    if not budget.seen.containsOrIncl(candidate.key()):
      fresh.add(candidate)

  if fresh.len > budget.left:
    debug "Dial candidates truncated", limit = budget.left

  let taken = fresh.take(budget.left)
  budget.left -= taken.len
  if budget.left == 0:
    budget.exhausted.fire()
  taken

proc awaitLookup(
    budget: DialBudget, lookup: CandidateLookup
): Future[seq[DialCandidate]] {.async: (raises: [CancelledError]).} =
  ## Empty once the budget leaves no room for the answer, so a stalling name ends here.

  let exhausted = budget.exhausted.wait()
  defer:
    await noCancel allFutures(exhausted.cancelAndWait(), lookup.cancelAndWait())

  discard await race(lookup, exhausted)
  if lookup.completed():
    return lookup.value()

  debug "Address lookup stopped at candidate limit"
  @[]

proc dropLosers(pending: seq[PendingAttempt], won: bool) {.async: (raises: []).} =
  ## Give up every attempt that did not win, and close a muxer that landed anyway.
  ## Only a dial that `won` counts its losers, an aborted dial wastes nothing.

  let attempts = pending.mapIt(it.attempt)
  await noCancel attempts.cancelAndWait()
  var lost = 0
  for attempt in attempts:
    if attempt.cancelled():
      lost.inc()
    elif attempt.completed():
      let mux = attempt.value()
      if not isNil(mux):
        lost.inc()
        await mux.close()

  if won:
    libp2p_dial_cancelled_attempts.inc(lost.int64)

proc new*(
    T: typedesc[RankedDial],
    deadline: Moment,
    attempt: proc(candidate: DialCandidate): DialAttempt {.gcsafe, raises: [].},
    expand: proc(candidate: DialCandidate): CandidateLookup {.gcsafe, raises: [].},
    resolve: proc(candidate: DialCandidate): CandidateLookup {.gcsafe, raises: [].},
): T =
  T(
    deadline: deadline,
    attempt: attempt,
    expand: expand,
    resolve: resolve,
    dialable: newBudget(MaxDialCandidates),
    unresolved: newBudget(MaxExpandedAddresses),
    changed: newFuture[void]("libp2p.rankeddial.changed"),
  )

proc wake(dial: RankedDial) =
  if not dial.changed.finished():
    dial.changed.complete()

func byRank(a, b: DialCandidate): int =
  cmp(a.dialRank(), b.dialRank())

proc queue(dial: RankedDial, candidates: seq[DialCandidate]) =
  for candidate in dial.dialable.take(candidates.sorted(byRank)):
    dial.queued.insert(candidate, dial.queued.upperBound(candidate, byRank))
  dial.wake()

proc queueResolved(
    dial: RankedDial, lookup: CandidateLookup
) {.async: (raises: [CancelledError]).} =
  dial.queue(await dial.dialable.awaitLookup(lookup))

proc queueName(
    dial: RankedDial, candidate: DialCandidate
) {.async: (raises: [CancelledError]).} =
  defer:
    dial.lookups.dec()
    dial.wake()

  let expanded =
    dial.unresolved.take(await dial.dialable.awaitLookup(dial.expand(candidate)))
  let lookups = expanded.mapIt(dial.resolve(it))
  await allOrCancel(lookups.mapIt(dial.queueResolved(it)))

proc openSlots(dial: RankedDial) =
  if dial.deadline.timeLeft().isZero():
    return

  while dial.queued.len > 0 and dial.pending.len < MaxParallelDials:
    let candidate = dial.queued[0]
    dial.queued.delete(0)
    trace "Ranked dial attempt opened", candidate
    dial.pending.add(
      PendingAttempt(rank: candidate.dialRank(), attempt: dial.attempt(candidate))
    )

proc takeWinner(dial: RankedDial): Muxer =
  ## Drop the attempts that ended, and hand over one that connected.

  var i = 0
  while i < dial.pending.len:
    let slot = dial.pending[i]
    if not slot.attempt.finished():
      i.inc()
      continue

    dial.pending.del(i)
    if slot.attempt.completed() and not isNil(slot.attempt.value()):
      libp2p_dial_winner_rank.inc(labelValues = [$slot.rank])
      return slot.attempt.value()

  nil

proc firstConnected(
    dial: RankedDial
): Future[Muxer] {.async: (raises: [CancelledError]).} =
  ## The first attempt that connects. Nil once nothing waits, runs, or can still arrive.

  var won = false
  defer:
    await dropLosers(dial.pending, won)

  while true:
    if dial.changed.finished():
      dial.changed = newFuture[void]("libp2p.rankeddial.changed")

    let mux = dial.takeWinner()
    if not isNil(mux):
      won = true
      return mux

    dial.openSlots()
    if dial.pending.len == 0 and dial.lookups == 0:
      return nil

    # `changed` keeps the race non-empty. Every attempt and lookup ends by the deadline.
    try:
      discard await race(
        dial.pending.mapIt(FutureBase(it.attempt)) & FutureBase(dial.changed)
      )
    except ValueError as e:
      raiseAssert "race() over a seq that holds `changed`: " & e.msg

proc run*(
    dial: RankedDial, direct, names: seq[DialCandidate]
): Future[Muxer] {.async: (raises: [CancelledError]).} =
  ## Dial `direct` at once and each of `names` as it resolves, best rank first.

  dial.queue(direct)

  let named = newBudget(MaxDialCandidates).take(names)
  dial.lookups = named.len
  let lookups = named.mapIt(dial.queueName(it))
  defer:
    await noCancel lookups.cancelAndWait()
    libp2p_dial_candidates.observe(float(MaxDialCandidates - dial.dialable.left))

  # The deferred await replaces the child future that a trailing `await` reads its value from.
  let mux = await dial.firstConnected()
  mux
