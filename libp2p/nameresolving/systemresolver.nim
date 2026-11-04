# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Resolve IPs through the OS, including hosts files and search domains.
## Blocking getaddrinfo calls run on worker threads; TXT queries use a fallback
## NameResolver. Call stop() to release workers, and start() to reuse a resolver.

{.push raises: [].}

import std/[atomics, locks]
import chronos, chronos/threadsync, chronicles
import nameresolver, dnsresolver
import ../crypto/rng

logScope:
  topics = "libp2p systemresolver"

const MaxSystemAddresses = 100

type
  RequestState {.pure.} = enum
    Pending
    Done
    Discarded

  # Everything the worker threads touch lives in the shared heap and is
  # plain data - no GC'd Nim types may cross the thread boundary.
  SharedRequest = object
    next: ptr SharedRequest
    host: array[256, char] # null-terminated, copied at submission
    port: uint16
    domain: Domain
    state: Atomic[int] # RequestState
    results: array[MaxSystemAddresses, TransportAddress]
    resultsLen: int

  SharedState = object
    lock: Lock
    queueHead, queueTail: ptr SharedRequest
    completedHead: ptr SharedRequest # singly-linked via `next`
    running: Atomic[bool]
    workersRunning: Atomic[int]
    requestSignal, responseSignal: ThreadSignalPtr
    when defined(libp2p_testing):
      workerEntered, workerRelease: ThreadSignalPtr
      workerGateReleased: Atomic[bool]

  PendingRequest = object
    req: ptr SharedRequest
    fut: Future[seq[TransportAddress]].Raising([CancelledError])

  SystemResolver* = ref object of NameResolver
    ## Resolves names through the OS resolver (getaddrinfo), offloaded to
    ## lazily-created worker threads.
    txtResolver: NameResolver
    shared: ptr SharedState
    workers: seq[Thread[ptr SharedState]]
    workerCount: int
    pending: seq[PendingRequest]
    dispatcherFut: Future[void].Raising([])
    stopFut: Future[void].Raising([])
    stopped: bool
    when defined(libp2p_testing):
      workerEntered, workerRelease: ThreadSignalPtr
      workerGateReleased: bool

proc isV4Mapped(address: TransportAddress): bool =
  if address.family != AddressFamily.IPv6:
    return false
  for i in 0 ..< 10:
    if address.address_v6[i] != 0:
      return false
  address.address_v6[10] == 0xff and address.address_v6[11] == 0xff

proc workerLoop(shared: ptr SharedState) {.thread.} =
  {.cast(gcsafe).}:
    while shared[].running.load():
      discard shared[].requestSignal.waitSync()
      while true:
        var req: ptr SharedRequest
        shared[].lock.acquire()
        if shared[].running.load():
          req = shared[].queueHead
          if not req.isNil:
            shared[].queueHead = req.next
            if shared[].queueHead.isNil:
              shared[].queueTail = nil
        shared[].lock.release()
        if req.isNil:
          break

        if RequestState(req.state.load()) == RequestState.Pending:
          let host = $cast[cstring](addr req.host[0])
          when defined(libp2p_testing):
            let workerRelease = shared[].workerRelease
            if not workerRelease.isNil:
              shared[].workerRelease = nil
              discard shared[].workerEntered.fireSync()
              let waitResult = workerRelease.waitSync(2.seconds)
              shared[].workerGateReleased.store(waitResult.isOk and waitResult.get())
          try:
            let resolved = resolveTAddress(host, Port(req.port), req.domain)
            for address in resolved:
              # getaddrinfo can return mapped literals even without AI_V4MAPPED.
              if req.domain == Domain.AF_INET6 and address.isV4Mapped():
                continue
              if req.resultsLen == MaxSystemAddresses:
                break
              req.results[req.resultsLen] = address
              inc req.resultsLen
            var expected = ord(RequestState.Pending)
            discard req.state.compareExchange(expected, ord(RequestState.Done))
          except TransportAddressError:
            var expected = ord(RequestState.Pending)
            discard req.state.compareExchange(expected, ord(RequestState.Discarded))

        shared[].lock.acquire()
        req.next = shared[].completedHead
        shared[].completedHead = req
        shared[].lock.release()
        discard shared[].responseSignal.fireSync()

    # Wake another idle worker during shutdown, then notify the event-loop
    # thread that this worker no longer touches shared state.
    discard shared[].requestSignal.fireSync()
    discard shared[].workersRunning.fetchSub(1)
    discard shared[].responseSignal.fireSync()

proc finishRequest(self: SystemResolver, req: ptr SharedRequest) =
  ## Complete (or skip, when cancelled) the future waiting on `req` and
  ## free the shared request. Event-loop thread only.
  var idx = -1
  for i, p in self.pending:
    if p.req == req:
      idx = i
      break
  if idx >= 0:
    let fut = self.pending[idx].fut
    self.pending.del(idx)
    if not fut.finished():
      let deliver = RequestState(req.state.load()) == RequestState.Done
      var res = newSeqOfCap[TransportAddress](if deliver: req.resultsLen else: 0)
      if deliver:
        for i in 0 ..< req.resultsLen:
          res.add(req.results[i])
      fut.complete(res)
  deallocShared(req)

proc drainCompleted(self: SystemResolver) =
  let shared = self.shared
  shared[].lock.acquire()
  var cur = shared[].completedHead
  shared[].completedHead = nil
  shared[].lock.release()
  while not cur.isNil:
    let req = cur
    cur = req.next
    self.finishRequest(req)

proc dispatchLoop(self: SystemResolver) {.async: (raises: []).} =
  while not self.stopped:
    try:
      await self.shared[].responseSignal.wait()
    except AsyncError, CancelledError:
      continue
    self.drainCompleted()

proc startWorkers(self: SystemResolver) {.raises: [TransportAddressError].} =
  # Allocate workers lazily so unused resolvers consume no threads.
  if not self.shared.isNil:
    return

  let shared = cast[ptr SharedState](allocShared0(sizeof(SharedState)))
  initLock(shared[].lock)
  shared[].running.store(true)
  shared[].workersRunning.store(0)
  when defined(libp2p_testing):
    shared[].workerEntered = self.workerEntered
    shared[].workerRelease = self.workerRelease
    shared[].workerGateReleased.store(false)
  shared[].requestSignal = ThreadSignalPtr.new().valueOr:
    deinitLock(shared[].lock)
    deallocShared(shared)
    raise
      newException(TransportAddressError, "Failed to create request signal: " & error)
  shared[].responseSignal = ThreadSignalPtr.new().valueOr:
    discard shared[].requestSignal.close()
    deinitLock(shared[].lock)
    deallocShared(shared)
    raise
      newException(TransportAddressError, "Failed to create response signal: " & error)

  # createThread passes the address of the Thread object itself to pthread, so
  # every object must already occupy its final, stable sequence slot.
  var workers = newSeq[Thread[ptr SharedState]](self.workerCount)
  var started = 0
  try:
    for i in 0 ..< workers.len:
      createThread(workers[i], workerLoop, shared)
      discard shared[].workersRunning.fetchAdd(1)
      inc started
  except ResourceExhaustedError as exc:
    workers.setLen(started)
    shared[].running.store(false)
    discard shared[].requestSignal.fireSync()
    joinThreads(workers)
    discard shared[].requestSignal.close()
    discard shared[].responseSignal.close()
    deinitLock(shared[].lock)
    deallocShared(shared)
    raise newException(
      TransportAddressError, "Failed to spawn resolver worker: " & exc.msg, exc
    )

  self.shared = shared
  self.workers = workers
  self.dispatcherFut = self.dispatchLoop()

proc new*(
    T: type SystemResolver, rng: Rng, txtResolver: NameResolver = nil, workers: int = 2
): T =
  ## Create a SystemResolver which starts `workers` worker threads on first use.
  ## `txtResolver` handles TXT queries (getaddrinfo cannot); when nil, a
  ## `DnsResolver` over the system nameservers is used.
  doAssert workers >= 1

  T(
    txtResolver:
      if txtResolver.isNil:
        NameResolver(DnsResolver.new(getSystemNameServers(), rng))
      else:
        txtResolver,
    workerCount: workers,
  )

when defined(libp2p_testing):
  proc setWorkerTestGate*(self: SystemResolver, entered, release: ThreadSignalPtr) =
    ## Delay the first worker lookup so shutdown behavior can be tested.
    doAssert self.shared.isNil
    doAssert not entered.isNil and not release.isNil
    self.workerEntered = entered
    self.workerRelease = release
    self.workerGateReleased = false

  proc workerTestGateReleased*(self: SystemResolver): bool =
    self.workerGateReleased

method resolveIp*(
    self: SystemResolver, address: string, port: Port, domain: Domain = Domain.AF_UNSPEC
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError])
.} =
  if self.stopped or address.len == 0 or address.len > 255 or '\0' in address:
    return @[]

  if self.shared.isNil:
    self.startWorkers()

  let
    shared = self.shared
    req = cast[ptr SharedRequest](allocShared0(sizeof(SharedRequest)))
    fut = Future[seq[TransportAddress]].Raising([CancelledError]).init(
        "systemresolver.resolveIp"
      )
  copyMem(addr req.host[0], address.cstring, address.len)
  req.port = uint16(port)
  req.domain = domain
  req.state.store(ord(RequestState.Pending))

  proc cancellation(udata: pointer) {.gcsafe, raises: [].} =
    var expected = ord(RequestState.Pending)
    discard req.state.compareExchange(expected, ord(RequestState.Discarded))

  fut.cancelCallback = cancellation
  self.pending.add(PendingRequest(req: req, fut: fut))

  shared[].lock.acquire()
  if shared[].queueTail.isNil:
    shared[].queueHead = req
  else:
    shared[].queueTail.next = req
  shared[].queueTail = req
  shared[].lock.release()
  discard shared[].requestSignal.fireSync()

  trace "Resolving via getaddrinfo", address, port = uint16(port), domain
  return await fut

method resolveTxt*(
    self: SystemResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]).} =
  if self.stopped:
    return @[]
  return await self.txtResolver.resolveTxt(address)

method start*(self: SystemResolver) {.gcsafe.} =
  ## Worker resources are created lazily by the next IP resolution.
  if self.shared.isNil:
    self.stopped = false
    self.stopFut = nil

proc stopWorkers(self: SystemResolver) {.async: (raises: []).} =
  self.stopped = true

  if self.shared.isNil:
    return

  let shared = self.shared
  shared[].lock.acquire()
  shared[].running.store(false)
  shared[].lock.release()
  discard shared[].requestSignal.fireSync()

  # Stop the dispatcher before using its signal to await worker exits.
  if not self.dispatcherFut.isNil:
    discard shared[].responseSignal.fireSync()
    await noCancel self.dispatcherFut
    self.dispatcherFut = nil

  # A worker may still be inside getaddrinfo, but waiting for it must not
  # block the event loop. Every worker signals after decrementing this count.
  while shared[].workersRunning.load() > 0:
    try:
      await shared[].responseSignal.wait()
    except AsyncError, CancelledError:
      continue
    self.drainCompleted()

  # All workers have exited, so joining only releases their thread handles.
  joinThreads(self.workers)
  when defined(libp2p_testing):
    self.workerGateReleased = shared[].workerGateReleased.load()

  # No worker can touch the shared state anymore: complete whatever is
  # left, with results where the worker managed to produce them.
  self.drainCompleted()
  var cur = shared[].queueHead
  while not cur.isNil:
    let req = cur
    cur = req.next
    self.finishRequest(req)

  discard shared[].requestSignal.close()
  discard shared[].responseSignal.close()
  deinitLock(shared[].lock)
  deallocShared(shared)
  self.shared = nil
  self.workers = @[]

method stop*(self: SystemResolver) {.async: (raises: []).} =
  ## Wait for active OS lookups, discard queued lookups, and release workers.
  ## Concurrent callers await the same cleanup; the event loop stays responsive.
  if self.stopFut.isNil:
    self.stopFut = self.stopWorkers()
  await noCancel self.stopFut
