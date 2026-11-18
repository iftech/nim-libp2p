# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Stores generic informations about peers.
runnableExamples:
  # Will keep info of all connected peers +
  # last 50 disconnected peers.
  # Passing `nil` for `identify` is only safe for simple peer-book usage like
  # this example. APIs that rely on identify metadata require a real
  # `Identify` instance when constructing the `PeerStore`.
  import libp2p/[peerid, crypto/crypto]

  let ps = PeerStore.new(nil, capacity = 50)

  # Create a custom book type
  type MoodBook = ref object of PeerBook[string]

  let exampleRng = newRng()
  var somePeerId = PeerId.random(exampleRng).expect("get random key")

  ps[MoodBook][somePeerId] = "Happy"
  doAssert ps[MoodBook][somePeerId] == "Happy"

{.push raises: [].}

import
  std/[tables, sets, macros, sequtils],
  chronos,
  ./utils/heartbeat,
  ./crypto/crypto,
  ./protocols/identify,
  ./protocols/protocol,
  ./peerid,
  ./peeraddrpolicy,
  ./peerinfo,
  ./routing_record,
  ./multiaddress,
  ./stream/connection,
  ./multistream,
  ./muxers/muxer,
  utils/opt

when defined(libp2p_agents_metrics):
  import utils/agents

const IdentifyCloseTimeout* = 5.seconds
  ## Grace for the remote's EOF once identify is done.

type
  #################
  # Handler types #
  #################
  PeerBookChangeHandler* = proc(peerId: PeerId) {.gcsafe, raises: [].}

  #########
  # Books #
  #########

  # Each book contains a book (map) and event handler(s)
  BasePeerBook = ref object of RootObj
    changeHandlers: seq[PeerBookChangeHandler]
    deletor: PeerBookChangeHandler

  PeerBook*[T] = ref object of BasePeerBook
    book*: Table[PeerId, T]

  SeqPeerBook*[T] = ref object of PeerBook[seq[T]]

  AddressConfidence* = enum
    ## Received from a discovery mechanism (DHT, rendezvous, mDNS, etc.).
    ## Not yet verified by a direct connection. Short TTL: quickly discarded
    ## if the address is never used.
    Low
    ## Self-reported by the peer via identify/identify-push, or manually
    ## provided by the user. Not yet verified by a direct connection.
    ## Medium TTL: reasonably trusted but not confirmed reachable.
    Medium
    ## Verified: we successfully dialled this address at least once.
    ## Long TTL: high confidence that the address is reachable.
    High
    ## Never expires regardless of how long since the last update.
    Infinite

  AddressEntry* = object
    address*: MultiAddress
    confidence*: AddressConfidence
    lastUpdated*: Moment

  TimestampPolicy = enum
    ReplaceTimestamp
    KeepLatestTimestamp

  AddressConfidenceTtls* = object
    low*: Duration = 15.minutes
    medium*: Duration = 1.hours
    high*: Duration = 24.hours

  AddressBook* = ref object of PeerBook[seq[AddressEntry]]
    ttls*: AddressConfidenceTtls
    connectedPeers: HashSet[PeerId]

  KeyBook* = ref object of PeerBook[PublicKey]

  ProtoBook* = ref object of SeqPeerBook[string]
  AgentBook* = ref object of PeerBook[string]
  LastSeenBook* = ref object of PeerBook[Opt[MultiAddress]]
  LastSeenOutboundBook* = ref object of PeerBook[Opt[MultiAddress]]
  ProtoVersionBook* = ref object of PeerBook[string]
  SPRBook* = ref object of PeerBook[Envelope]

  ####################
  # Peer store types #
  ####################
  PeerStore* = ref object
    books: Table[string, BasePeerBook]
    identify*: Identify
    capacity*: int
    toClean*: seq[PeerId]
    addressPolicy*: PeerAddressPolicy
      ## Gate on an inbound peer address: storage, redistribution, hole punch, lookup.
    allowUndialableAddrs*: bool ## Local test setups store a wildcard host too.
    addressTtls*: AddressConfidenceTtls ## Per-confidence TTLs for address expiry.
    identifyCloseTimeout*: Duration ## Grace for the remote's EOF after identify.
    pruneHandle*: Future[void]

func new*(
    Self: type PeerStore,
    identify: Identify,
    capacity = 1000,
    addressTtls = AddressConfidenceTtls(),
    identifyCloseTimeout = IdentifyCloseTimeout,
): PeerStore =
  # Self instead of T to avoid clashing with ifValue[T]'s type param under --lineDir:on
  Self(
    identify: identify,
    capacity: capacity,
    addressPolicy: defaultAddressPolicy,
    addressTtls: addressTtls,
    identifyCloseTimeout: identifyCloseTimeout,
  )

#########################
# Generic Peer Book API #
#########################

proc notifyChangeHandlers(peerBook: BasePeerBook, peerId: PeerId) =
  for handler in peerBook.changeHandlers:
    handler(peerId)

func `[]`*[T](peerBook: PeerBook[T], peerId: PeerId): T =
  ## Get all known metadata of a provided peer, or default(T) if missing
  peerBook.book.getOrDefault(peerId)

proc `[]=`*[T](peerBook: PeerBook[T], peerId: PeerId, entry: T) =
  ## Set metadata for a given peerId.

  peerBook.book[peerId] = entry

  peerBook.notifyChangeHandlers(peerId)

proc del*[T](peerBook: PeerBook[T], peerId: PeerId): bool =
  ## Delete the provided peer from the book. Returns whether the peer was in the book
  if peerId notin peerBook.book:
    return false

  peerBook.book.del(peerId)
  peerBook.notifyChangeHandlers(peerId)
  return true

func contains*[T](peerBook: PeerBook[T], peerId: PeerId): bool =
  peerId in peerBook.book

proc addHandler*[T](peerBook: PeerBook[T], handler: PeerBookChangeHandler) =
  ## Adds a callback that will be called everytime the book changes
  peerBook.changeHandlers.add(handler)

func len*[T](peerBook: PeerBook[T]): int =
  peerBook.book.len

################################
# AddressBook per-address TTLs #
################################

proc isExpired*(entry: AddressEntry, ttls: AddressConfidenceTtls): bool =
  ## Returns true only when the TTL is positive and the elapsed time exceeds it.
  let ttl =
    case entry.confidence
    of AddressConfidence.Low:
      ttls.low
    of AddressConfidence.Medium:
      ttls.medium
    of AddressConfidence.High:
      ttls.high
    of AddressConfidence.Infinite:
      return false

  if ttl <= ZeroDuration:
    return false

  Moment.now() - entry.lastUpdated > ttl

func higherConfidence(
    prevConf: Table[MultiAddress, AddressConfidence],
    ma: MultiAddress,
    incoming: AddressConfidence,
): AddressConfidence =
  ## Returns the higher of the stored and incoming confidence for `ma`.
  ## A previously verified (High/Infinite) address is never downgraded.
  max(prevConf.getOrDefault(ma, incoming), incoming)

func findWithAddress(entries: openArray[AddressEntry], ma: MultiAddress): int =
  for i, e in entries:
    if e.address == ma:
      return i
  -1

func upsertAddress(
    entries: var seq[AddressEntry],
    incoming: AddressEntry,
    timestampPolicy: TimestampPolicy,
) =
  let idx = entries.findWithAddress(incoming.address)
  if idx >= 0:
    entries[idx].confidence = max(entries[idx].confidence, incoming.confidence)
    case timestampPolicy
    of ReplaceTimestamp:
      entries[idx].lastUpdated = incoming.lastUpdated
    of KeepLatestTimestamp:
      entries[idx].lastUpdated = max(entries[idx].lastUpdated, incoming.lastUpdated)
  else:
    entries.add(incoming)

proc isLive(addressBook: AddressBook, peerId: PeerId, entry: AddressEntry): bool =
  peerId in addressBook.connectedPeers or not entry.isExpired(addressBook.ttls)

proc addressesChanged(
    addressBook: AddressBook, peerId: PeerId, previous, current: openArray[AddressEntry]
): bool =
  ## Compare addresses, confidence and visibility, ignoring order and timestamps.
  ## Current entries must have unique addresses, as produced by set.
  if current.len != previous.len:
    return true

  var prevSet = initHashSet[(MultiAddress, AddressConfidence, bool)]()
  for entry in previous:
    prevSet.incl((entry.address, entry.confidence, addressBook.isLive(peerId, entry)))
  for entry in current:
    if (entry.address, entry.confidence, addressBook.isLive(peerId, entry)) notin prevSet:
      return true
  false

proc refreshExpired(addressBook: AddressBook, peerId: PeerId, now = Moment.now()) =
  var entries = addressBook.book.getOrDefault(peerId)
  if entries.len == 0:
    return

  var refreshed = false
  for entry in entries.mitems:
    if entry.isExpired(addressBook.ttls):
      entry.lastUpdated = now
      refreshed = true

  if refreshed:
    addressBook.book[peerId] = entries

func replacementEntries(
    previous: openArray[AddressEntry],
    addrs: openArray[MultiAddress],
    confidence: AddressConfidence,
    now: Moment,
): seq[AddressEntry] =
  ## Normalize and deduplicate incoming addresses, preserving verified entries.
  var prevConf: Table[MultiAddress, AddressConfidence]
  for entry in previous:
    let normalized = entry.address.stripPeerId()
    prevConf[normalized] =
      max(prevConf.getOrDefault(normalized, entry.confidence), entry.confidence)

  var newEntries = newSeqOfCap[AddressEntry](addrs.len)
  for ma in addrs:
    let normalized = stripPeerId(ma)
    newEntries.upsertAddress(
      AddressEntry(
        address: normalized,
        confidence: higherConfidence(prevConf, normalized, confidence),
        lastUpdated: now,
      ),
      ReplaceTimestamp,
    )

  for entry in previous:
    let normalized = entry.address.stripPeerId()
    if entry.confidence >= AddressConfidence.High:
      newEntries.upsertAddress(
        AddressEntry(
          address: normalized,
          confidence: entry.confidence,
          lastUpdated: entry.lastUpdated,
        ),
        KeepLatestTimestamp,
      )
  return newEntries

proc set*(
    addressBook: AddressBook,
    peerId: PeerId,
    addrs: openArray[MultiAddress],
    confidence = AddressConfidence.Medium,
) =
  ## Replace the address list for `peerId`. For addresses that already exist
  ## the confidence is upgraded to `max(existing, confidence)` so that a
  ## high-confidence entry is never downgraded by a lower-confidence update.
  ## High/Infinite entries absent from the incoming list are preserved so that
  ## a verified dial address is never evicted by a later Identify update.
  ## Every incoming address refreshes its timestamp, including duplicates.
  ## Subscribers are notified when addresses, confidence or visibility change.
  if addrs.len == 0:
    discard addressBook.del(peerId)
    return

  let now = Moment.now()
  let previous = addressBook.book.getOrDefault(peerId)
  let newEntries = replacementEntries(previous, addrs, confidence, now)
  let changed = addressBook.addressesChanged(peerId, previous, newEntries)
  addressBook.book[peerId] = newEntries
  if changed:
    addressBook.notifyChangeHandlers(peerId)

proc `[]=`*(addressBook: AddressBook, peerId: PeerId, addrs: openArray[MultiAddress]) =
  addressBook.set(peerId, addrs)

proc `[]`*(addressBook: AddressBook, peerId: PeerId): seq[MultiAddress] =
  ## Return non-expired addresses for `peerId`.
  ## Connected peers keep their known addresses visible until disconnect.
  addressBook.book.getOrDefault(peerId).filterIt(addressBook.isLive(peerId, it)).mapIt(
    it.address
  )

func entries*(addressBook: AddressBook, peerId: PeerId): seq[AddressEntry] =
  ## Return the raw entry list for `peerId`, including expired entries.
  addressBook.book.getOrDefault(peerId)

proc contains*(addressBook: AddressBook, peerId: PeerId): bool =
  for entry in addressBook.book.getOrDefault(peerId):
    if addressBook.isLive(peerId, entry):
      return true
  return false

proc markConnected*(addressBook: AddressBook, peerId: PeerId, ma: MultiAddress) =
  ## Called after a successful outbound connection to `ma`.
  ## Upgrades the address to High confidence and refreshes its lastUpdated.
  ## If the address is not yet in the book it is added.
  defer:
    addressBook.notifyChangeHandlers(peerId)

  let now = Moment.now()
  var entries = addressBook.book.getOrDefault(peerId)
  entries.upsertAddress(
    AddressEntry(
      address: ma.stripPeerId(), confidence: AddressConfidence.High, lastUpdated: now
    ),
    ReplaceTimestamp,
  )
  addressBook.book[peerId] = entries

proc extend*(
    addressBook: AddressBook,
    key: PeerId,
    addrs: openArray[MultiAddress],
    confidence = AddressConfidence.Medium,
) =
  ## Add addresses for `key` without removing existing ones.
  ## For addresses already present the confidence is upgraded to
  ## `max(existing, confidence)` and lastUpdated is always refreshed.
  ## New addresses are added with `confidence`.
  ## Timestamp-only changes notify subscribers only when an address becomes visible.
  let now = Moment.now()
  var entries = addressBook.book.getOrDefault(key)
  var changed = false
  for ma in addrs:
    let normalized = ma.stripPeerId()
    let idx = entries.findWithAddress(normalized)
    if idx < 0 or entries[idx].confidence < confidence or
        not addressBook.isLive(key, entries[idx]):
      changed = true
    entries.upsertAddress(
      AddressEntry(address: normalized, confidence: confidence, lastUpdated: now),
      ReplaceTimestamp,
    )
  if entries.len > 0:
    addressBook.book[key] = entries
  if changed:
    addressBook.notifyChangeHandlers(key)

proc pruneExpired*(addressBook: AddressBook) =
  ## Remove all per-address entries whose TTL has elapsed.
  ## Connected peers keep their entries fresh while they remain connected.
  ## Peers whose last address expires are removed from the AddressBook only;
  ## other peer metadata (keys, protocols, agent version, etc.) is left intact.
  var pending: seq[(PeerId, seq[AddressEntry])]
  var refresh: seq[PeerId]
  for peerId, entries in addressBook.book:
    if peerId in addressBook.connectedPeers:
      if entries.anyIt(it.isExpired(addressBook.ttls)):
        refresh.add(peerId)
      continue

    let alive = entries.filterIt(not it.isExpired(addressBook.ttls))
    if alive.len < entries.len:
      pending.add((peerId, alive))

  let now = Moment.now()
  for peerId in refresh:
    addressBook.refreshExpired(peerId, now)

  for (peerId, alive) in pending:
    if alive.len > 0:
      addressBook.book[peerId] = alive
      addressBook.notifyChangeHandlers(peerId)
    else:
      discard addressBook.del(peerId)

proc shouldStoreSignedPeerRecord(
    sprBook: SPRBook, peerId: PeerId, incoming: Envelope
): bool =
  let incomingRecord = SignedPeerRecord.decode(incoming).valueOr:
    return false

  if incomingRecord.data.peerId != peerId:
    return false

  if peerId notin sprBook:
    return true

  let existingRecord = SignedPeerRecord.decode(sprBook[peerId]).valueOr:
    return true

  incomingRecord.data.seqNo > existingRecord.data.seqNo

##################
# Peer Store API #
##################
macro getTypeName(t: type): untyped =
  # Symbol signatures include module identity, including for generic arguments.
  func qualify(n: NimNode): NimNode =
    if n.kind == nnkSym:
      return ident(n.signatureHash())
    let res = copyNimNode(n)
    for child in n:
      res.add qualify(child)
    res

  newLit(repr(qualify(getTypeImpl(t)[1])))

proc getOrCreateBook[T](p: PeerStore, typ: type[T]): T =
  let name = getTypeName(T)
  p.books.withValue(name, bookPtr):
    return T(bookPtr[])

  let book = T.new()
  when T is AddressBook and AddressBook is T:
    book.ttls = p.addressTtls
  book.deletor = proc(pid: PeerId) =
    # Manual method because generic method don't work
    discard T(p.books.getOrDefault(name)).del(pid)
  p.books[name] = book
  book

proc `[]`*(p: PeerStore, _: type[AddressBook]): AddressBook =
  ## Get the AddressBook, initialising it with the store's configured TTLs.
  p.getOrCreateBook(AddressBook)

proc `[]`*[T](p: PeerStore, typ: type[T]): T =
  ## Get a book from the PeerStore (ex: peerStore[AddressBook])
  p.getOrCreateBook(typ)

func firstSupportedProtocol*(
    p: PeerStore, peerId: PeerId, protocols: openArray[string]
): Opt[string] =
  ## Return the first requested protocol advertised by the peer without
  ## creating a protocol book or copying its entry.
  let name = getTypeName(ProtoBook)
  p.books.withValue(name, bookPtr):
    ProtoBook(bookPtr[]).book.withValue(peerId, supportedPtr):
      for protocol in protocols:
        if protocol in supportedPtr[]:
          return Opt.some(protocol)
  Opt.none(string)

proc removeFromCleanupQueue(peerStore: PeerStore, peerId: PeerId) =
  let cleanupPos = peerStore.toClean.find(peerId)
  if cleanupPos >= 0:
    peerStore.toClean.delete(cleanupPos)

proc del*(peerStore: PeerStore, peerId: PeerId) =
  ## Delete the provided peer from every book.
  peerStore.removeFromCleanupQueue(peerId)

  peerStore.books.withValue(getTypeName(AddressBook), bookPtr):
    AddressBook(bookPtr[]).connectedPeers.excl(peerId)

  for _, book in peerStore.books:
    book.deletor(peerId)

proc markPeerConnected*(peerStore: PeerStore, peerId: PeerId) =
  ## Mark `peerId` as actively connected so known addresses do not TTL-expire.
  peerStore[AddressBook].connectedPeers.incl(peerId)
  peerStore.removeFromCleanupQueue(peerId)

proc markPeerDisconnected*(peerStore: PeerStore, peerId: PeerId) =
  ## Drop active connection state after refreshing known addresses for redial.
  let addressBook = peerStore[AddressBook]
  addressBook.refreshExpired(peerId)
  addressBook.connectedPeers.excl(peerId)

proc addressPruneLoop(
    peerStore: PeerStore, interval: Duration
) {.async: (raises: [CancelledError]).} =
  heartbeat "AddressBook TTL pruning", interval, sleepFirst = true:
    peerStore[AddressBook].pruneExpired()

proc startAddressPruning*(peerStore: PeerStore) =
  ## Start the periodic per-address TTL pruning loop. No-op if already running.
  ## Uses the smallest positive TTL across all confidence levels as the interval.
  ## If all TTLs are zero (non-expiring), the loop is not started.
  if not peerStore.pruneHandle.isNil:
    return

  let ttls = peerStore.addressTtls
  let ttlsSeq = [ttls.low, ttls.medium, ttls.high].filterIt(it > ZeroDuration)
  if ttlsSeq.len == 0:
    return

  let interval = ttlsSeq.foldl(min(a, b))

  peerStore.pruneHandle = addressPruneLoop(peerStore, interval)

proc close*(peerStore: PeerStore) =
  ## Cancel the background TTL-pruning loop, if running.
  if not peerStore.pruneHandle.isNil:
    peerStore.pruneHandle.cancelSoon()
    peerStore.pruneHandle = nil

proc updateIdentifyAddresses(
    peerStore: PeerStore, peerId: PeerId, advertisedAddrs: openArray[MultiAddress]
) =
  if advertisedAddrs.len > 0:
    var addrs = peerStore.addressPolicy.dialableAddrs(
      advertisedAddrs, peerStore.allowUndialableAddrs
    )
    addrs.setLen(min(addrs.len, MaxIdentifyAddrs))
    if addrs.len > 0:
      peerStore[AddressBook].set(peerId, addrs, AddressConfidence.Medium)
    else:
      discard peerStore[AddressBook].del(peerId)

proc recordObservedAddress(
    peerStore: PeerStore,
    peerId: PeerId,
    observedAddr: Opt[MultiAddress],
    direction: Opt[Direction],
) =
  peerStore[LastSeenBook][peerId] = observedAddr

  # Update LastSeenOutboundBook only for outbound connections
  direction.ifValue(dir):
    if dir == Direction.Out:
      peerStore[LastSeenOutboundBook][peerId] = observedAddr

proc updatePeerInfo*(
    peerStore: PeerStore,
    info: IdentifyInfo,
    observedAddr: Opt[MultiAddress] = Opt.none(MultiAddress),
    direction: Opt[Direction] = Opt.none(Direction),
) =
  peerStore.updateIdentifyAddresses(info.peerId, info.addrs)
  peerStore.recordObservedAddress(info.peerId, observedAddr, direction)

  info.pubkey.ifValue(pubkey):
    peerStore[KeyBook][info.peerId] = pubkey

  info.agentVersion.ifValue(agentVersion):
    peerStore[AgentBook][info.peerId] = agentVersion

  info.protoVersion.ifValue(protoVersion):
    peerStore[ProtoVersionBook][info.peerId] = protoVersion

  if info.protos.len > 0:
    peerStore[ProtoBook][info.peerId] = info.protos

  info.signedPeerRecord.ifValue(signedPeerRecord):
    let sprBook = peerStore[SPRBook]
    if sprBook.shouldStoreSignedPeerRecord(info.peerId, signedPeerRecord):
      sprBook[info.peerId] = signedPeerRecord

  peerStore.removeFromCleanupQueue(info.peerId)

proc cleanup*(peerStore: PeerStore, peerId: PeerId) =
  if peerStore.capacity == 0:
    peerStore.del(peerId)
    return
  elif peerStore.capacity < 0:
    #infinite capacity
    return
  peerStore.removeFromCleanupQueue(peerId)

  peerStore.toClean.add(peerId)
  while peerStore.toClean.len > peerStore.capacity:
    # `del` shifts `toClean` down, so own the id before it frees the slot.
    let oldest = move(peerStore.toClean[0])
    peerStore.toClean.delete(0)
    peerStore.del(oldest)

proc retireStream(
    stream: Stream, identified: bool, closeTimeout: Duration
) {.async: (raises: []).} =
  ## `noCancel` swallows the caller's deadline, so the close carries its own.
  if identified:
    if await noCancel stream.closeWithEOF().withTimeout(closeTimeout):
      return
  await noCancel stream.reset()

when defined(libp2p_agents_metrics):
  func classifyAgent(agentVersion: Opt[string]): string =
    let shortAgent = agentVersion.get("").split("/")[0].safeToLowerAscii().get("")
    if KnownLibP2PAgentsSeq.contains(shortAgent): shortAgent else: "unknown"

proc identify*(
    peerStore: PeerStore, muxer: Muxer, dir: Direction
) {.
    async: (
      raises: [
        CancelledError, IdentityNoMatchError, IdentityInvalidMsgError, MultiStreamError,
        LPStreamError, MuxerError,
      ]
    )
.} =
  # new stream for identify
  var stream = await muxer.newStream()
  if stream == nil:
    return

  var identifyCompleted = false
  try:
    if (await MultistreamSelect.select(stream, peerStore.identify.codec())):
      let info = await peerStore.identify.identify(stream, stream.peerId)

      when defined(libp2p_agents_metrics):
        muxer.setShortAgent(classifyAgent(info.agentVersion))

      peerStore.updatePeerInfo(info, stream.observedAddr, Opt.some(dir))
      identifyCompleted = true
  except CancelledError as exc:
    raise exc
  finally:
    await retireStream(stream, identifyCompleted, peerStore.identifyCloseTimeout)

func getMostObservedProtosAndPorts*(
    self: PeerStore
): seq[MultiAddress] {.deprecated: "use switch.addressManager".} =
  return self.identify.addressManager.mostObservedProtosAndPorts()

func guessDialableAddr*(
    self: PeerStore, ma: MultiAddress
): MultiAddress {.deprecated: "use switch.addressManager.externalAddrFor".} =
  return self.identify.addressManager.externalAddrFor(ma)

proc extend*[T](self: SeqPeerBook[T], key: PeerId, new: openArray[T]) =
  var extended: HashSet[T]

  for old in self[key]:
    extended.incl(old)

  for elem in new:
    extended.incl(elem)

  self[key] = extended.toSeq()
