# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## NAT port mapper backed by libplum (PCP / NAT-PMP / UPnP-IGD).
##
## `plum_init`/`plum_cleanup` is a process-global singleton, so this module
## ref-counts init across every live `PlumMapper` and keeps the first mapper's
## settings (protocol filter + timeouts). Those globals are unsynchronized:
## create and close every `PlumMapper` from the same chronos event-loop thread.

{.push raises: [].}

import std/[net, tables]
import chronos, chronicles
import libplum/plum
import ./portmapper, ../../errors

export ProtocolFilter

logScope:
  topics = "libp2p nat-traversal"

const
  # Private defaults for new(); the public NAT knobs live in natservice.
  DefaultDiscoverTimeout = 10.seconds
  DefaultMappingTimeout = 10.seconds

type
  # Keyed by the internal (listen) port so a repeated map() for an unchanged
  # listen address reuses the existing libplum mapping instead of leaking it.
  MappingKey = tuple[internalPort: uint16, proto: MapProto]

  MappingEntry = tuple[id: cint, mapped: MappedPort] ## libplum id + its result

  PlumMapper* = ref object of PortMapper
    filter: ProtocolFilter
    mappingTimeout: Duration
    closed: bool
    lock: AsyncLock ## serializes map/unmap/close over `mappings`
    mappings: Table[MappingKey, MappingEntry]

var
  plumRefCount = 0
  plumActiveFilter = ProtocolFilter.Any
  plumActiveDiscoverTimeout = DefaultDiscoverTimeout
  plumActiveMappingTimeout = DefaultMappingTimeout

func toPlumProto(p: MapProto): PlumProtocol =
  case p
  of mpTcp: PlumProtocol.TCP
  of mpUdp: PlumProtocol.UDP

func toMs(d: Duration): int32 =
  int32(d.milliseconds.clamp(0'i64, int64(high(int32))))

proc safeRelease(lock: AsyncLock) =
  ## Release from a defer block; releasing without holding is a developer error.
  try:
    lock.release()
  except AsyncLockError as e:
    raiseAssert "PlumMapper lock release failed: " & e.msg

proc acquirePlum(
    filter: ProtocolFilter, discoverTimeout, mappingTimeout: Duration
): LPResult[void] =
  if plumRefCount == 0:
    plum.init(
      logLevel = PlumLogLevel.None,
      discoverTimeout = toMs(discoverTimeout),
      mappingTimeout = toMs(mappingTimeout),
      protocol = filter,
    ).isOkOr:
      return err(error)
    plumActiveFilter = filter
    plumActiveDiscoverTimeout = discoverTimeout
    plumActiveMappingTimeout = mappingTimeout
  elif filter != plumActiveFilter or discoverTimeout != plumActiveDiscoverTimeout or
      mappingTimeout != plumActiveMappingTimeout:
    # plum_init is process-global; the first mapper's settings win and every
    # later mapper silently reuses them.
    warn "libplum already initialized with different settings; reusing existing",
      requestedFilter = filter,
      activeFilter = plumActiveFilter,
      requestedDiscoverTimeout = discoverTimeout,
      activeDiscoverTimeout = plumActiveDiscoverTimeout,
      requestedMappingTimeout = mappingTimeout,
      activeMappingTimeout = plumActiveMappingTimeout
  inc plumRefCount
  ok()

proc releasePlum() =
  if plumRefCount == 0:
    return
  dec plumRefCount
  if plumRefCount == 0:
    plum.cleanup().isOkOr:
      warn "plum_cleanup failed", err = error

proc new*(
    T: typedesc[PlumMapper],
    filter = ProtocolFilter.Any,
    discoverTimeout = DefaultDiscoverTimeout,
    mappingTimeout = DefaultMappingTimeout,
): LPResult[T] =
  ?acquirePlum(filter, discoverTimeout, mappingTimeout)
  ok(PlumMapper(filter: filter, mappingTimeout: mappingTimeout, lock: newAsyncLock()))

method map*(
    self: PlumMapper, internalPort: Port, externalPort: Port, proto: MapProto
): Future[LPResult[MappedPort]] {.async: (raises: [CancelledError]), gcsafe.} =
  if self.closed:
    return err("PlumMapper closed")

  await self.lock.acquire()
  defer:
    self.lock.safeRelease()

  # close() may have run (and torn libplum down) while we waited for the lock.
  if self.closed:
    return err("PlumMapper closed")

  # Reuse a still-live mapping for this listen port rather than asking libplum
  # for a fresh one (which would orphan the previous id).
  let key: MappingKey = (internalPort.uint16, proto)
  self.mappings.withValue(key, existing):
    if hasMapping(existing.id):
      return ok(existing.mapped)
    destroyMapping(existing.id)
    self.mappings.del(key)

  let res = ?await createMapping(
    protocol = toPlumProto(proto),
    internalPort = internalPort.uint16,
    externalPort = externalPort.uint16,
    timeout = self.mappingTimeout,
  )

  # close() may have torn libplum down during the await; drop the new mapping.
  if self.closed:
    destroyMapping(res.id)
    return err("PlumMapper closed")

  let externalIp =
    try:
      parseIpAddress(res.mapping.externalHost)
    except ValueError as e:
      destroyMapping(res.id)
      return err(
        "plum: cannot parse external host '" & res.mapping.externalHost & "': " & e.msg
      )

  let mapped =
    MappedPort(externalIp: externalIp, externalPort: Port(res.mapping.externalPort))
  self.mappings[key] = (id: res.id, mapped: mapped)
  ok(mapped)

method unmap*(
    self: PlumMapper, externalPort: Port, proto: MapProto
): Future[LPResult[void]] {.async: (raises: [CancelledError]), gcsafe.} =
  if self.closed:
    return err("PlumMapper closed")

  await self.lock.acquire()
  defer:
    self.lock.safeRelease()

  if self.closed:
    return err("PlumMapper closed")

  # The PortMapper contract keys unmap on the external port; find the entry
  # whose assigned external port matches.
  for key, entry in self.mappings:
    if key.proto == proto and entry.mapped.externalPort == externalPort:
      destroyMapping(entry.id)
      self.mappings.del(key)
      return ok()

  err("plum unmap: no known mapping for external port " & $externalPort.uint16)

method close*(self: PlumMapper) {.async: (raises: []), gcsafe.} =
  if self.closed:
    return
  self.closed = true

  # Wait uncancellably for any in-flight map/unmap so we don't tear libplum
  # down (or clear `mappings`) while another op is mid-await.
  await noCancel(self.lock.acquire())
  defer:
    self.lock.safeRelease()

  for entry in self.mappings.values():
    destroyMapping(entry.id)
  self.mappings.clear()
  releasePlum()
