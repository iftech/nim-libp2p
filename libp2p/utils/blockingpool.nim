# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Run blocking calls on worker threads and complete chronos futures on the
## event-loop thread.
##
## - `T` is fixed-size plain data. Variable-size data crosses as a
##   `ptr UncheckedArray[byte]` plus a length inside `T`: the submitter
##   allocates it with `allocShared` and owns it. Free it after the future
##   completes with a result, or after `stop` returns when the future was
##   cancelled.
## - `work` returns true for Done and false for Discarded. Done completes the
##   future with the payload, Discarded completes it with `PoolErrorKind.Discarded`.
## - A cancel of the future flips the job to Discarded and completes the future
##   at once. A worker that already took the job runs it to the end and the pool
##   drops the result.
## - `stop` waits for the in-flight jobs and discards the queued ones, then
##   joins the threads and frees the shared heap. Concurrent `stop` callers
##   await the same cleanup, and the event loop stays responsive.
## - Workers spawn on the first `submit`. `start` reopens a stopped pool, or
##   reopens it when an in-flight `stop` finishes.

{.push raises: [].}

import std/[atomics, locks, tables, typetraits]
import chronos, chronos/threadsync
import ../results

type
  WorkProc*[T] = proc(payload: var T): bool {.nimcall, gcsafe, raises: [].}

  PoolErrorKind* {.pure.} = enum
    Discarded ## work returned false, the pool stopped, or the job was queued at stop
    StartFailed ## the pool could not create its signals or threads

  PoolError* = object
    kind*: PoolErrorKind
    detail*: string

  JobState {.pure.} = enum
    Pending
    Done
    Discarded

  # Workers touch only this shared-heap plain data, never GC'd Nim types.
  Job[T] = object
    next: ptr Job[T]
    state: Atomic[int] # JobState
    payload: T

  SharedState[T] = object
    lock: Lock
    queueHead, queueTail: ptr Job[T]
    completedHead: ptr Job[T] # singly-linked via `next`
    running: Atomic[bool]
    workersRunning: Atomic[int]
    requestSignal, responseSignal: ThreadSignalPtr
    work: WorkProc[T]

  JobFuture[T] = Future[Result[T, PoolError]].Raising([CancelledError])

  BlockingPoolObj[T] = object
    work: WorkProc[T]
    shared: ptr SharedState[T]
    workers: seq[Thread[ptr SharedState[T]]]
    workerCount: int
    pending: Table[ptr Job[T], JobFuture[T]]
    dispatcherFut: Future[void].Raising([])
    stopFut: Future[void].Raising([])
    stopped: bool
    reopen: bool

  BlockingPool*[T] = ref BlockingPoolObj[T]

proc settle[T](job: ptr Job[T], state: JobState) =
  var expected = ord(JobState.Pending)
  discard job.state.compareExchange(expected, ord(state))

proc destroy[T](shared: ptr SharedState[T]) =
  if not shared[].requestSignal.isNil:
    discard shared[].requestSignal.close()
  if not shared[].responseSignal.isNil:
    discard shared[].responseSignal.close()
  deinitLock(shared[].lock)
  deallocShared(shared)

proc workerLoop[T](shared: ptr SharedState[T]) {.thread.} =
  {.cast(gcsafe).}:
    while shared[].running.load():
      discard shared[].requestSignal.waitSync()
      while true:
        var job: ptr Job[T]
        withLock shared[].lock:
          if shared[].running.load():
            job = shared[].queueHead
            if not job.isNil:
              shared[].queueHead = job.next
              if shared[].queueHead.isNil:
                shared[].queueTail = nil
        if job.isNil:
          break

        if JobState(job.state.load()) == JobState.Pending:
          let done = shared[].work(job.payload)
          job.settle(if done: JobState.Done else: JobState.Discarded)

        withLock shared[].lock:
          job.next = shared[].completedHead
          shared[].completedHead = job
        discard shared[].responseSignal.fireSync()

    # Wake the next idle worker, then tell the loop this worker is gone.
    discard shared[].requestSignal.fireSync()
    discard shared[].workersRunning.fetchSub(1)
    discard shared[].responseSignal.fireSync()

proc finishRequest[T](p: BlockingPool[T], job: ptr Job[T]) =
  ## Complete the future of `job` unless cancelled, then free `job`. Loop thread only.
  var fut: JobFuture[T]
  if p.pending.pop(job, fut):
    if not fut.finished():
      let res =
        if JobState(job.state.load()) == JobState.Done:
          Result[T, PoolError].ok(job.payload)
        else:
          Result[T, PoolError].err(PoolError(kind: PoolErrorKind.Discarded))
      fut.complete(res)
  deallocShared(job)

proc finishRequests[T](p: BlockingPool[T], head: ptr Job[T]) =
  var cur = head
  while not cur.isNil:
    let job = cur
    cur = job.next
    p.finishRequest(job)

proc drainCompleted[T](p: BlockingPool[T]) =
  let shared = p.shared
  var head: ptr Job[T]
  withLock shared[].lock:
    head = shared[].completedHead
    shared[].completedHead = nil
  p.finishRequests(head)

proc dispatchLoop[T](p: BlockingPool[T]) {.async: (raises: []).} =
  while not p.stopped:
    try:
      await p.shared[].responseSignal.wait()
    except AsyncError, CancelledError:
      continue
    p.drainCompleted()

func startFailed(detail: string): PoolError =
  PoolError(kind: PoolErrorKind.StartFailed, detail: detail)

proc startWorkers[T](p: BlockingPool[T]): Result[void, PoolError] =
  # Allocate workers lazily so unused pools consume no threads.
  if not p.shared.isNil:
    return ok()
  if p.workerCount < 1:
    return err(startFailed("Invalid worker count: " & $p.workerCount & " < 1"))
  if p.work.isNil:
    return err(startFailed("Work proc is nil"))

  let shared = cast[ptr SharedState[T]](allocShared0(sizeof(SharedState[T])))
  initLock(shared[].lock)
  shared[].running.store(true)
  shared[].workersRunning.store(0)
  shared[].work = p.work
  shared[].requestSignal = ThreadSignalPtr.new().valueOr:
    shared.destroy()
    return err(startFailed("Failed to create request signal: " & error))
  shared[].responseSignal = ThreadSignalPtr.new().valueOr:
    shared.destroy()
    return err(startFailed("Failed to create response signal: " & error))

  # createThread hands pthread the Thread address, so spawn into the final
  # storage and never resize it while threads run.
  p.workers = newSeq[Thread[ptr SharedState[T]]](p.workerCount)
  var started = 0
  try:
    for i in 0 ..< p.workers.len:
      createThread(p.workers[i], workerLoop[T], shared)
      discard shared[].workersRunning.fetchAdd(1)
      inc started
  except ResourceExhaustedError as e:
    shared[].running.store(false)
    discard shared[].requestSignal.fireSync()
    joinThreads(p.workers.toOpenArray(0, started - 1))
    p.workers = @[]
    shared.destroy()
    return err(startFailed("Failed to spawn pool worker: " & e.msg))

  p.shared = shared
  p.dispatcherFut = p.dispatchLoop()
  ok()

proc new*[T](_: type BlockingPool[T], work: WorkProc[T], workers = 2): BlockingPool[T] =
  ## Create a pool which starts `workers` threads running `work` on first use.
  static:
    doAssert supportsCopyMem(T), "BlockingPool payload must be plain data"
  BlockingPool[T](work: work, workerCount: workers)

func isStopped*[T](p: BlockingPool[T]): bool =
  p.stopped

proc submit*[T](
    p: BlockingPool[T], payload: T
): Future[Result[T, PoolError]] {.async: (raises: [CancelledError]).} =
  ## Run `work` on a copy of `payload`; a stopped pool returns Discarded.
  if p.stopped:
    return err(PoolError(kind: PoolErrorKind.Discarded))

  ?p.startWorkers()

  let
    shared = p.shared
    job = cast[ptr Job[T]](allocShared0(sizeof(Job[T])))
    fut = JobFuture[T].init("blockingpool.submit")
  job.payload = payload
  job.state.store(ord(JobState.Pending))

  proc cancellation(udata: pointer) {.gcsafe, raises: [].} =
    job.settle(JobState.Discarded)

  fut.cancelCallback = cancellation
  p.pending[job] = fut

  withLock shared[].lock:
    if shared[].queueTail.isNil:
      shared[].queueHead = job
    else:
      shared[].queueTail.next = job
    shared[].queueTail = job
  discard shared[].requestSignal.fireSync()

  return await fut

proc start*[T](p: BlockingPool[T]) =
  ## Reopen a stopped pool. Workers spawn on the next `submit`.
  if not p.stopFut.isNil and not p.stopFut.finished():
    p.reopen = true
  elif p.shared.isNil:
    p.stopped = false
    p.stopFut = nil

proc stopWorkers[T](p: BlockingPool[T]) {.async: (raises: []).} =
  p.stopped = true

  if p.shared.isNil:
    return

  let shared = p.shared
  withLock shared[].lock:
    shared[].running.store(false)
  discard shared[].requestSignal.fireSync()

  # Stop the dispatcher before using its signal to await worker exits.
  if not p.dispatcherFut.isNil:
    discard shared[].responseSignal.fireSync()
    await noCancel p.dispatcherFut
    p.dispatcherFut = nil

  # Each worker fires responseSignal after the decrement, so the wait yields.
  while shared[].workersRunning.load() > 0:
    try:
      await shared[].responseSignal.wait()
    except AsyncError, CancelledError:
      continue
    p.drainCompleted()

  # All workers have exited, so joining only releases their thread handles.
  joinThreads(p.workers)

  # No worker remains: finish completed jobs and discard the queue.
  p.drainCompleted()
  p.finishRequests(shared[].queueHead)
  shared.destroy()
  p.shared = nil
  p.workers = @[]

  if p.reopen:
    p.reopen = false
    p.stopped = false
    p.stopFut = nil

proc stop*[T](p: BlockingPool[T]) {.async: (raises: []).} =
  ## Wait for in-flight jobs, discard queued jobs, and release workers.
  p.reopen = false
  if p.stopFut.isNil:
    p.stopFut = p.stopWorkers()
  await noCancel p.stopFut
