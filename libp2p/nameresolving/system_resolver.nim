# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Resolve IPs through the OS, including hosts files and search domains.
## Blocking getaddrinfo calls run on worker threads; TXT queries use a fallback
## NameResolver. Call stop() to release workers, and start() to reuse a resolver.

{.push raises: [].}

import std/[atomics, locks]
import chronos, chronos/[threadsync, transports/ipnet], chronicles
import nameresolver, dnsresolver
import ../crypto/rng
import ../results

logScope:
  topics = "libp2p systemresolver"

const MaxSystemAddresses = 100

type
  Lookup = proc(
    address: string, port: Port, domain: Domain, context: pointer
  ): seq[TransportAddress] {.nimcall, gcsafe, raises: [TransportAddressError].}

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
    lookup: Lookup
    lookupContext: pointer

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
    lookup: Lookup
    lookupContext: pointer

proc settle(req: ptr SharedRequest, state: RequestState) =
  var expected = ord(RequestState.Pending)
  discard req.state.compareExchange(expected, ord(state))

proc destroy(shared: ptr SharedState) =
  if not shared[].requestSignal.isNil:
    discard shared[].requestSignal.close()
  if not shared[].responseSignal.isNil:
    discard shared[].responseSignal.close()
  deinitLock(shared[].lock)
  deallocShared(shared)

proc systemLookup(
    address: string, port: Port, domain: Domain, context: pointer
): seq[TransportAddress] {.gcsafe, raises: [TransportAddressError].} =
  resolveTAddress(address, port, domain)

proc resolve(req: ptr SharedRequest, lookup: Lookup, context: pointer) =
  let host = $cast[cstring](addr req.host[0])
  try:
    let resolved = lookup(host, Port(req.port), req.domain, context)
    for address in resolved:
      # getaddrinfo can return mapped literals even without AI_V4MAPPED.
      if req.domain == Domain.AF_INET6 and address.isV4Mapped():
        continue
      if req.resultsLen >= MaxSystemAddresses:
        break
      req.results[req.resultsLen] = address
      inc req.resultsLen
    req.settle(RequestState.Done)
  except TransportAddressError:
    req.settle(RequestState.Discarded)

proc workerLoop(shared: ptr SharedState) {.thread.} =
  {.cast(gcsafe).}:
    while shared[].running.load():
      discard shared[].requestSignal.waitSync()
      while true:
        var req: ptr SharedRequest
        withLock shared[].lock:
          if shared[].running.load():
            req = shared[].queueHead
            if not req.isNil:
              shared[].queueHead = req.next
              if shared[].queueHead.isNil:
                shared[].queueTail = nil
        if req.isNil:
          break

        if RequestState(req.state.load()) == RequestState.Pending:
          req.resolve(shared[].lookup, shared[].lookupContext)

        withLock shared[].lock:
          req.next = shared[].completedHead
          shared[].completedHead = req
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
      let res =
        if RequestState(req.state.load()) == RequestState.Done:
          @(req.results.toOpenArray(0, req.resultsLen - 1))
        else:
          @[]
      fut.complete(res)
  deallocShared(req)

proc finishRequests(self: SystemResolver, head: ptr SharedRequest) =
  var cur = head
  while not cur.isNil:
    let req = cur
    cur = req.next
    self.finishRequest(req)

proc drainCompleted(self: SystemResolver) =
  let shared = self.shared
  var head: ptr SharedRequest
  withLock shared[].lock:
    head = shared[].completedHead
    shared[].completedHead = nil
  self.finishRequests(head)

proc dispatchLoop(self: SystemResolver) {.async: (raises: []).} =
  while not self.stopped:
    try:
      await self.shared[].responseSignal.wait()
    except AsyncError, CancelledError:
      continue
    self.drainCompleted()

proc startWorkers(self: SystemResolver): LPResult[void] =
  # Allocate workers lazily so unused resolvers consume no threads.
  if not self.shared.isNil:
    return ok()

  let shared = cast[ptr SharedState](allocShared0(sizeof(SharedState)))
  initLock(shared[].lock)
  shared[].running.store(true)
  shared[].workersRunning.store(0)
  shared[].lookup = self.lookup
  shared[].lookupContext = self.lookupContext
  shared[].requestSignal = ThreadSignalPtr.new().valueOr:
    shared.destroy()
    return err(error, "Failed to create request signal")
  shared[].responseSignal = ThreadSignalPtr.new().valueOr:
    shared.destroy()
    return err(error, "Failed to create response signal")

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
    shared.destroy()
    return err(exc, "Failed to spawn resolver worker")

  self.shared = shared
  self.workers = workers
  self.dispatcherFut = self.dispatchLoop()
  ok()

proc new*(
    T: type SystemResolver, rng: Rng, txtResolver: NameResolver = nil, workers: int = 2
): T =
  ## Create a SystemResolver which starts `workers` worker threads on first use.
  ## `txtResolver` handles TXT queries (getaddrinfo cannot); when nil, a
  ## `DnsResolver` over the system nameservers is used. Discovery is synchronous
  ## during construction and can block the calling thread while reading system config.
  doAssert workers >= 1

  T(
    txtResolver:
      if txtResolver.isNil:
        NameResolver(DnsResolver.new(getSystemNameServers(), rng))
      else:
        txtResolver,
    workerCount: workers,
    lookup: systemLookup,
  )

proc setLookup(self: SystemResolver, lookup: Lookup, context: pointer) =
  # The callback context must outlive all workers, including asynchronous shutdown.
  doAssert self.shared.isNil
  doAssert not lookup.isNil
  self.lookup = lookup
  self.lookupContext = context

when defined(libp2p_testing):
  export setLookup

method resolveIp*(
    self: SystemResolver, address: string, port: Port, domain: Domain = Domain.AF_UNSPEC
): Future[seq[TransportAddress]] {.
    async: (raises: [CancelledError, TransportAddressError])
.} =
  if self.stopped or address.len == 0 or address.len > 255 or '\0' in address:
    return @[]

  if self.shared.isNil:
    self.startWorkers().onErrorRaise(TransportAddressError)

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
    req.settle(RequestState.Discarded)

  fut.cancelCallback = cancellation
  self.pending.add(PendingRequest(req: req, fut: fut))

  withLock shared[].lock:
    if shared[].queueTail.isNil:
      shared[].queueHead = req
    else:
      shared[].queueTail.next = req
    shared[].queueTail = req
  discard shared[].requestSignal.fireSync()

  trace "Resolving via getaddrinfo", address, port = uint16(port), domain
  return await fut

method resolveTxt*(
    self: SystemResolver, address: string
): Future[seq[string]] {.async: (raises: [CancelledError]).} =
  if self.stopped:
    return @[]
  return await self.txtResolver.resolveTxt(address)

proc start*(self: SystemResolver) {.gcsafe.} =
  ## Worker resources are created lazily by the next IP resolution.
  if self.shared.isNil:
    self.stopped = false
    self.stopFut = nil

proc stopWorkers(self: SystemResolver) {.async: (raises: []).} =
  self.stopped = true

  if self.shared.isNil:
    return

  let shared = self.shared
  withLock shared[].lock:
    shared[].running.store(false)
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

  # No worker can touch the shared state anymore: complete whatever is
  # left, with results where the worker managed to produce them.
  self.drainCompleted()
  self.finishRequests(shared[].queueHead)
  shared.destroy()
  self.shared = nil
  self.workers = @[]

proc stop*(self: SystemResolver) {.async: (raises: []).} =
  ## Wait for active OS lookups, discard queued lookups, and release workers.
  ## Concurrent callers await the same cleanup; the event loop stays responsive.
  if self.stopFut.isNil:
    self.stopFut = self.stopWorkers()
  await noCancel self.stopFut
