# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/sequtils
import chronos, chronicles

logScope:
  topics = "libp2p futures"

type
  AllFuturesFailedError* = object of CatchableError

  FutureOutcomeCounts* = object ## Futures grouped by their current outcome.
    succeeded*, failed*, cancelled*, pending*: int

proc countFutureOutcomes*[Fut](
    futs: openArray[Fut]
): FutureOutcomeCounts {.raises: [].} =
  ## Counts futures by current state, including those still pending.
  for fut in futs:
    if fut.cancelled():
      result.cancelled.inc()
    elif fut.failed():
      result.failed.inc()
    elif fut.completed():
      result.succeeded.inc()
    else:
      result.pending.inc()

proc anyCompleted*[T](
    futs: seq[T]
): Future[T] {.async: (raises: [AllFuturesFailedError, CancelledError]).} =
  ## Returns a future that will complete with the first future that completes.
  ## If all futures fail or futs is empty, the returned future will fail with AllFuturesFailedError.

  var requests = futs

  while true:
    try:
      var raceFut = await one(requests)
      if raceFut.completed:
        return raceFut
      requests.del(requests.find(raceFut))
    except ValueError as e:
      raise newException(
        AllFuturesFailedError, "None of the futures completed successfully: " & e.msg, e
      )
    except CancelledError as exc:
      raise exc
    except CatchableError:
      continue

template timeLeft*(deadline: Moment): Duration =
  ## Zero once the deadline passed: chronos clamps a negative `Duration`.
  deadline - Moment.now()

template awaitWithDeadline*(fut: untyped, deadline: Moment): untyped =
  ## Await `fut` with what is left of `deadline`. A future that already finished
  ## still gives its result, whatever the clock says. Otherwise, with no time
  ## left, cancel it and raise `AsyncTimeoutError`: `wait(ZeroDuration)` raises
  ## that error too, but it leaves `fut` running with nobody to reap it.
  let
    f = fut
    remaining = deadline.timeLeft()
  if remaining.isZero() and not f.finished():
    await f.cancelAndWait()
    raise newException(AsyncTimeoutError, "deadline exceeded")
  await f.wait(remaining)

template newFutureCompleted*[T](): auto =
  let fut = newFuture[T]()
  fut.complete()
  fut

proc warnNilCancelAndWait(firstNonNilProc = "", firstNonNilLoc = "") =
  if firstNonNilProc.len > 0:
    warn "cancelAndWait called on nil future", firstNonNilProc, firstNonNilLoc
  else:
    warn "cancelAndWait called on nil future"

template cancelAndWait*[T](futs: seq[T]): auto =
  var cancelFuts = newSeqOfCap[Future[void].Raising([])](futs.len)
  for fut in futs:
    if fut.isNil:
      let nonNil = futs.filterIt(not it.isNil)
      if nonNil.len > 0:
        let loc = nonNil[0].location[LocationKind.Create]
        warnNilCancelAndWait($loc.procedure, $loc.file & ":" & $loc.line)
      else:
        warnNilCancelAndWait()
      continue
    cancelFuts.add(fut.cancelAndWait())
  allFutures(cancelFuts)

proc allOrCancel*[T](futs: seq[T]) {.async: (raises: [CancelledError]).} =
  ## Await every future, also one that fails. On cancel, cancel them all first,
  ## because `allFutures` leaves its children running.
  try:
    await allFutures(futs)
  except CancelledError as e:
    await noCancel futs.cancelAndWait()
    raise e

template cancelSoon*[T](futs: seq[T]) =
  for fut in futs:
    fut.cancelSoon()

proc trackFut*[T](futs: var seq[T], fut: T) =
  ## Prune finished futures, then take ownership of `fut` for later teardown.
  futs.keepItIf(not it.finished())
  futs.add(fut)

proc allFuturesWaitOrTimeout*[Fut](
    futs: seq[Fut], timeout: Duration
) {.async: (raises: [CancelledError]).} =
  try:
    await futs.allFutures().wait(timeout)
  except AsyncTimeoutError:
    discard

template completeOnce*(fut: auto) =
  ## Complete a future only if it is not already finished.
  if not fut.finished:
    fut.complete()

template completeOnce*(fut: auto, val: auto) =
  ## Complete a future only if it is not already finished.
  if not fut.finished:
    fut.complete(val)

template completeOnceRaising*(fut: auto, val: auto) =
  ## Complete a future, or raise a defect when it is already finished.
  if fut.finished:
    raiseAssert "future completed more than once"
  fut.complete(val)

proc collectCompleted*[T, E](
    futs: seq[InternalRaisesFuture[T, E]], timeout = InfiniteDuration
): Future[seq[T]] {.async: (raises: [CancelledError]).} =
  ## Collect the values of the futures that completed, cancelling the rest.
  try:
    await allOrCancel(futs).wait(timeout)
  except AsyncTimeoutError:
    discard

  return futs.filterIt(it.completed()).mapIt(it.value())

proc waitForTCPServer*(
    taddr: TransportAddress,
    retries: int = 20,
    delay: chronos.Duration = 500.milliseconds,
): Future[bool] {.async.} =
  for i in 0 ..< retries:
    try:
      let conn = await connect(taddr)
      await conn.closeWait()
      return true
    except OSError:
      discard
    except TransportOsError:
      discard
    await sleepAsync(delay)
  return false

proc reportBackgroundFailure*(
    fut: FutureBase, operation: string
) {.gcsafe, raises: [].} =
  ## Cancellation is normal shutdown and deliberately produces no event.
  fut.addCallback proc(udata: pointer) {.gcsafe, raises: [].} =
    if fut.failed():
      let exc = fut.error()
      error "Background operation stopped", err = exc.msg, errType = exc.name, operation
