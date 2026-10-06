# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import tables, sequtils, sugar, sets
import metrics except collect
import chronos, chronicles, stew/[byteutils, objects]
import
  ./protobuf,
  ../protocol,
  ../../switch,
  ../../dial,
  ../../routing_record,
  ../../crypto/rng,
  ../../utils/heartbeat,
  ../../utils/future,
  ../../stream/connection,
  ../../utils/offsettedseq

export chronicles, offsettedseq

logScope:
  topics = "libp2p rendezvous"

declareCounter(libp2p_rendezvous_register, "number of advertise requests")
declareCounter(libp2p_rendezvous_discover, "number of discovery requests")
declareGauge(libp2p_rendezvous_registered, "number of registered peers")
declareGauge(libp2p_rendezvous_namespaces, "number of registered namespaces")

const
  RendezVousCodec* = "/rendezvous/1.0.0"
  # Default minimum TTL per libp2p spec
  MinimumDuration* = 2.hours
  # Lower validation limit to accommodate Waku requirements
  MinimumAcceptedDuration* = 1.minutes
  MaximumDuration* = 72.hours
  MaximumMessageLen = 1 shl 22 # 4MB
  MinimumNamespaceLen = 1
  MaximumNamespaceLen = 255
  RegistrationLimitPerPeer* = 1000
  MaximumNamespaces* = 1000
  DiscoverLimit = 1000'u64
  SemaphoreDefaultSize* = 5

type PeerRecordValidator*[E] =
  proc(_: E, spr: seq[byte], peerId: PeerId): LPResult[void] {.gcsafe.}

type RendezVousConfig* = object
  minDuration*: Duration
  maxDuration*: Duration
  minTTL*: uint64
  maxTTL*: uint64
  maxNamespaces*: int

proc new*(
    T: typedesc[RendezVousConfig],
    minDuration: Duration = MinimumDuration,
    maxDuration: Duration = MaximumDuration,
    maxNamespaces: int = MaximumNamespaces,
): T =
  var minD = minDuration
  var maxD = maxDuration
  var maxNs = maxNamespaces
  if minD < MinimumAcceptedDuration:
    warn "TTL too short: 1 minute minimum"
    minD = MinimumAcceptedDuration
  if maxD > MaximumDuration:
    warn "TTL too long: 72 hours maximum"
    maxD = MaximumDuration
  if minD >= maxD:
    warn "Minimum TTL longer than maximum"
    minD = MinimumAcceptedDuration
    maxD = MaximumDuration
  if maxNs <= 0:
    warn "Namespace limit must be positive"
    maxNs = MaximumNamespaces
  T(
    minDuration: minD,
    maxDuration: maxD,
    minTTL: minD.seconds.uint64,
    maxTTL: maxD.seconds.uint64,
    maxNamespaces: maxNs,
  )

# A config built with an object literal leaves maxNamespaces at 0.
func namespaceLimit*(config: RendezVousConfig): int =
  if config.maxNamespaces <= 0: MaximumNamespaces else: config.maxNamespaces

type
  RendezVousError* = object of LPError
  AdvertiseError* = object of RendezVousError
  RegisteredData* = object
    expiration*: Moment
    peerId*: PeerId
    data*: Register

  # For any custom peer record type E, constructor has to be implemented
  GenericRendezVous*[E] = ref object of LPProtocol
    # Registered needs to be an offsetted sequence
    # because we need stable index for the cookies.
    registered*: OffsettedSeq[RegisteredData]
    # Namespaces is a table whose key is a salted namespace and
    # the value is the index sequence corresponding to this
    # namespace in the offsettedqueue.
    namespaces*: Table[string, seq[int]]
    # Number of entries of `registered` per peer.
    registeredCount*: Table[PeerId, int]
    rng*: Rng
    config*: RendezVousConfig
    salt*: string
    expiredDT*: Moment
    registerDeletionLoop*: Future[void]
    #registerEvent: AsyncEvent # TODO: to raise during the heartbeat
    # + make the heartbeat sleep duration "smarter"
    sema*: AsyncSemaphore
    peers*: seq[PeerId]
    cookiesSaved*: Table[PeerId, Table[string, seq[byte]]]
    switch*: Switch
    peerRecordValidator*: PeerRecordValidator[E]

  RendezVous* = GenericRendezVous[PeerRecord]

func checkNamespace(ns: string): LPResult[void] =
  if ns.len < MinimumNamespaceLen:
    return err(
      "namespace length " & $ns.len & " is shorter than minimum " & $MinimumNamespaceLen
    )
  if ns.len > MaximumNamespaceLen:
    return err(
      "namespace length " & $ns.len & " is longer than maximum " & $MaximumNamespaceLen
    )
  ok()

func checkTtl(config: RendezVousConfig, ttl: Duration): LPResult[void] =
  if ttl < config.minDuration or ttl > config.maxDuration:
    return err(
      "time to live " & $ttl & " is not in valid range [" & $config.minDuration & "-" &
        $config.maxDuration & "]"
    )
  ok()

func checkRequest(ns: Opt[string], limit: int): LPResult[void] =
  if limit <= 0 or limit > DiscoverLimit.int:
    return err("Invalid limit")
  if ns.isSome():
    ?ns.get().checkNamespace()
  ok()

proc checkPeerRecord*(_: PeerRecord, spr: seq[byte], peerId: PeerId): LPResult[void] =
  if spr.len == 0:
    return err("Empty peer record")
  let signedEnv = SignedPeerRecord.decode(spr).valueOr:
    return err($error)
  if signedEnv.data.peerId != peerId:
    return err("Bad Peer ID")
  return ok()

proc sendRegisterResponse*(
    stream: Stream, ttl: uint64
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let msg = encode(
    Message(
      msgType: MessageType.RegisterResponse,
      registerResponse: Opt.some(RegisterResponse(status: Ok, ttl: Opt.some(ttl))),
    )
  )
  await stream.writeLp(msg)

proc sendRegisterResponseError*(
    stream: Stream, status: ResponseStatus, text: string = ""
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let msg = encode(
    Message(
      msgType: MessageType.RegisterResponse,
      registerResponse: Opt.some(RegisterResponse(status: status, text: Opt.some(text))),
    )
  )
  await stream.writeLp(msg)

proc sendDiscoverResponse*(
    stream: Stream, s: seq[Register], cookie: Cookie
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let msg = encode(
    Message(
      msgType: MessageType.DiscoverResponse,
      discoverResponse: Opt.some(
        DiscoverResponse(status: Ok, registrations: s, cookie: Opt.some(encode(cookie)))
      ),
    )
  )
  await stream.writeLp(msg)

proc sendDiscoverResponseError*(
    stream: Stream, status: ResponseStatus, text: string = ""
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let msg = encode(
    Message(
      msgType: MessageType.DiscoverResponse,
      discoverResponse: Opt.some(DiscoverResponse(status: status, text: Opt.some(text))),
    )
  )
  await stream.writeLp(msg)

func countRegister*[E](rdv: GenericRendezVous[E], peerId: PeerId): int =
  rdv.registeredCount.getOrDefault(peerId)

proc recountRegistered[E](rdv: GenericRendezVous[E]) =
  rdv.registeredCount.clear()
  for reg in rdv.registered.s:
    rdv.registeredCount.mgetOrPut(reg.peerId, 0).inc()

proc save*[E](
    rdv: GenericRendezVous[E],
    ns: string,
    peerId: PeerId,
    r: Register,
    update: bool = true,
): LPResult[void] =
  let nsSalted = ns & rdv.salt
  if not rdv.namespaces.hasKey(nsSalted) and
      rdv.namespaces.len >= rdv.config.namespaceLimit():
    return err("Namespace limit reached")

  for index in rdv.namespaces.getOrDefault(nsSalted):
    if rdv.registered[index].peerId == peerId:
      if update == false:
        return ok()
      rdv.registered[index].expiration = rdv.expiredDT
  rdv.registered.add(
    RegisteredData(
      peerId: peerId,
      expiration: Moment.now() + r.ttl.get(rdv.config.minTTL).int64.seconds,
      data: r,
    )
  )
  rdv.registeredCount.mgetOrPut(peerId, 0).inc()
  rdv.namespaces.mgetOrPut(nsSalted, @[]).add(rdv.registered.high)
  ok()

proc register*[E](
    rdv: GenericRendezVous[E], stream: Stream, r: Register, peerRecord: E
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  trace "Register received", peerId = stream.peerId, namespace = r.ns
  libp2p_rendezvous_register.inc()
  if r.ns.len < MinimumNamespaceLen or r.ns.len > MaximumNamespaceLen:
    return stream.sendRegisterResponseError(InvalidNamespace)
  let ttl = r.ttl.get(rdv.config.minTTL)
  if ttl < rdv.config.minTTL or ttl > rdv.config.maxTTL:
    return stream.sendRegisterResponseError(InvalidTTL)
  rdv.peerRecordValidator(peerRecord, r.signedPeerRecord, stream.peerId).isOkOr:
    return stream.sendRegisterResponseError(InvalidSignedPeerRecord, error)
  if rdv.countRegister(stream.peerId) >= RegistrationLimitPerPeer:
    return stream.sendRegisterResponseError(NotAuthorized, "Registration limit reached")

  rdv.save(r.ns, stream.peerId, r).isOkOr:
    return stream.sendRegisterResponseError(NotAuthorized, error)
  libp2p_rendezvous_registered.inc()
  libp2p_rendezvous_namespaces.set(int64(rdv.namespaces.len))
  stream.sendRegisterResponse(ttl)

proc unregister*[E](rdv: GenericRendezVous[E], stream: Stream, u: Unregister) =
  trace "Unregister received", peerId = stream.peerId, namespace = u.ns
  let nsSalted = u.ns & rdv.salt
  for index in rdv.namespaces.getOrDefault(nsSalted):
    if rdv.registered[index].peerId == stream.peerId:
      rdv.registered[index].expiration = rdv.expiredDT
      libp2p_rendezvous_registered.dec()

iterator discoverIndexes(nsIndexes: Opt[seq[int]], first, last: int): int =
  if nsIndexes.isSome():
    for index in nsIndexes.get():
      yield index
  else:
    for index in first .. last:
      yield index

proc discover*[E](
    rdv: GenericRendezVous[E], stream: Stream, d: Discover
) {.async: (raises: [CancelledError, LPStreamError]).} =
  trace "Discover received", peerId = stream.peerId, namespace = d.ns
  libp2p_rendezvous_discover.inc()
  if d.ns.isSome() and d.ns.get().len > MaximumNamespaceLen:
    await stream.sendDiscoverResponseError(InvalidNamespace)
    return
  var limit = min(DiscoverLimit, d.limit.get(DiscoverLimit))
  var cookie =
    if d.cookie.isSome():
      Cookie.decode(d.cookie.get()).valueOr:
        await stream.sendDiscoverResponseError(InvalidCookie)
        return
    else:
      # Start from the current lowest index (inclusive)
      Cookie(offset: rdv.registered.low().uint64)
  if d.ns.isSome() and cookie.ns.isSome() and cookie.ns.get() != d.ns.get():
    # Namespace changed: start from the beginning of that namespace
    cookie = Cookie(offset: rdv.registered.low().uint64)
  elif cookie.offset < rdv.registered.low().uint64:
    # Cookie behind available range: reset to current low
    cookie.offset = rdv.registered.low().uint64
  elif cookie.offset > (rdv.registered.high() + 1).uint64:
    # Cookie ahead of available range: reset to one past current high (empty page)
    cookie.offset = (rdv.registered.high() + 1).uint64
  let nsIndexes =
    if d.ns.isSome():
      let nsSalted = d.ns.get() & rdv.salt
      if nsSalted notin rdv.namespaces:
        await stream.sendDiscoverResponse(@[], Cookie())
        return
      Opt.some(rdv.namespaces.getOrDefault(nsSalted))
    else:
      Opt.none(seq[int])
  let
    first = max(cookie.offset.int, rdv.registered.offset)
    last = rdv.registered.high()
    n = Moment.now()
  var
    nextOffset = cookie.offset
    s: seq[Register] = @[]
    hasCandidates = false
  for index in discoverIndexes(nsIndexes, first, last):
    hasCandidates = true
    if limit == 0:
      break
    let expiration = rdv.registered[index].expiration
    if expiration < n or index.uint64 < cookie.offset:
      continue
    limit.dec()
    nextOffset = index.uint64 + 1
    var data = rdv.registered[index].data
    data.ttl = Opt.some((expiration - n).seconds.uint64)
    s.add(data)

  if not hasCandidates:
    await stream.sendDiscoverResponse(@[], Cookie())
    return

  rdv.rng.shuffle(s)
  await stream.sendDiscoverResponse(s, Cookie(offset: nextOffset, ns: d.ns))

proc sendRegister[E](
    rdv: GenericRendezVous[E], peer: PeerId, msg: seq[byte]
): Future[LPResult[RegisterResponse]] {.async: (raises: [CancelledError]).} =
  let stream =
    try:
      await rdv.switch.dial(peer, rdv.codec)
    except DialFailedError as e:
      return err("Failed to dial: " & e.msg)
  defer:
    await stream.close()

  let buf =
    try:
      await stream.writeLp(msg)
      await stream.readLp(4096)
    except LPStreamError as e:
      return err("Failed to communicate: " & e.msg)

  let msgRecv = Message.decode(buf).valueOr:
    return err("Failed to decode Message: " & $error)
  if msgRecv.msgType != MessageType.RegisterResponse:
    return err("Unexpected register response: " & $msgRecv.msgType)
  let response = msgRecv.registerResponse.valueOr:
    return err("Register response is empty")
  ok(response)

proc advertisePeer[E](
    rdv: GenericRendezVous[E], peer: PeerId, msg: seq[byte]
): Future[bool] {.async: (raises: [CancelledError]).} =
  await rdv.sema.acquire()
  defer:
    try:
      rdv.sema.release()
    except AsyncSemaphoreError:
      raiseAssert "semaphore released without acquire"

  let response = (await rdv.sendRegister(peer, msg)).valueOr:
    return false
  response.status == ResponseStatus.Ok

proc advertise*[E](
    rdv: GenericRendezVous[E],
    ns: string,
    customPeerRecord: E,
    ttl: Duration,
    peers: seq[PeerId],
) {.async: (raises: [CancelledError, AdvertiseError]).} =
  let signedPeerRecord = SignedPayload[E].init(
    rdv.switch.peerInfo.privateKey, customPeerRecord
  ).valueOr:
    info "Can't create the signed peer record", err = error
    return

  let pBuff = signedPeerRecord.encode()
  await rdv.advertise(ns, ttl, peers, pBuff)

proc advertise*[E](
    rdv: GenericRendezVous[E],
    ns: string,
    ttl: Duration,
    peers: seq[PeerId],
    sprBuff: seq[byte],
) {.async: (raises: [CancelledError, AdvertiseError]).} =
  ns.checkNamespace().isOkOr:
    raise newException(AdvertiseError, error)
  rdv.config.checkTtl(ttl).isOkOr:
    raise newException(AdvertiseError, error)

  let
    r = Register(ns: ns, signedPeerRecord: sprBuff, ttl: Opt.some(ttl.seconds.uint64))
    msg = encode(Message(msgType: MessageType.Register, register: Opt.some(r)))

  rdv.save(ns, rdv.switch.peerInfo.peerId, r).isOkOr:
    raise newException(AdvertiseError, error)

  let futs = peers.mapIt(rdv.advertisePeer(it, msg))
  await allFutures(futs.mapIt(it.withTimeout(5.seconds)))

  let registeredCount = futs.countIt(it.completed() and it.value())
  debug "Advertise completed", namespace = ns, peersCount = peers.len, registeredCount

method advertise*(
    rdv: RendezVous, ns: string, ttl: Opt[Duration] = Opt.none(Duration)
) {.base, async: (raises: [CancelledError, AdvertiseError]).} =
  let lttl = ttl.get(rdv.config.minDuration)
  if rdv.switch.isNil:
    # I don't like this, but adding this as i don't understand why we have a constructor without switch as arg
    raise newException(AdvertiseError, "Rendezvous not setup with a switch")
  let sprBuff = rdv.switch.peerInfo.signedPeerRecord.encode()
  await rdv.advertise(ns, lttl, rdv.peers, sprBuff)

proc requestLocally*[E](rdv: GenericRendezVous[E], ns: string): seq[E] =
  let
    nsSalted = ns & rdv.salt
    n = Moment.now()
  collect(newSeq()):
    for index in rdv.namespaces.getOrDefault(nsSalted):
      if rdv.registered[index].expiration > n:
        let res = SignedPayload[E].decode(rdv.registered[index].data.signedPeerRecord).valueOr:
          continue
        res.data

proc requestPeer[E](
    rdv: GenericRendezVous[E], limit: uint64, ns: Opt[string], peer: PeerId
): Future[LPResult[seq[Register]]] {.async: (raises: [CancelledError]).} =
  let stream =
    try:
      await rdv.switch.dial(peer, rdv.codec)
    except DialFailedError as e:
      return err("Failed to dial: " & e.msg)
  defer:
    await stream.close()

  var d = Discover(ns: ns, limit: Opt.some(limit))
  if ns.isSome():
    rdv.cookiesSaved.withValue(peer, cookies):
      cookies[].withValue(ns.get(), cookie):
        d.cookie = Opt.some(cookie[])
  let buf =
    try:
      await stream.writeLp(
        encode(Message(msgType: MessageType.Discover, discover: Opt.some(d)))
      )
      await stream.readLp(MaximumMessageLen)
    except LPStreamError as e:
      return err("Failed to communicate: " & e.msg)

  let msgRcv = Message.decode(buf).valueOr:
    return err("Message undecodable: " & $error)
  if msgRcv.msgType != MessageType.DiscoverResponse:
    return err("Unexpected discover response: " & $msgRcv.msgType)
  let resp = msgRcv.discoverResponse.valueOr:
    return err("Discover response is empty")
  if resp.status != ResponseStatus.Ok:
    return err("Cannot discover: " & $resp.status & " " & resp.text.get(""))
  resp.cookie.ifValue(cookie):
    if ns.isSome() and cookie.len() < 1000:
      rdv.cookiesSaved.mgetOrPut(peer, initTable[string, seq[byte]]())[ns.get()] =
        cookie
  return ok(resp.registrations)

proc request*[E](
    rdv: GenericRendezVous[E], ns: Opt[string], lt: Opt[int], peersOpt: Opt[seq[PeerId]]
): Future[seq[E]] {.async: (raises: [LPError, CancelledError]).} =
  var
    s: Table[PeerId, (E, Register)]
    limit: uint64
  let l = lt.get(DiscoverLimit.int)
  let peers = peersOpt.get(rdv.peers)
  checkRequest(ns, l).isOkOr:
    raise newException(AdvertiseError, error)

  limit = l.uint64

  for peer in peers:
    if limit == 0:
      break
    if rdv.codec notin rdv.switch.peerStore[ProtoBook][peer]:
      continue
    let registrations = (await rdv.requestPeer(limit, ns, peer)).valueOr:
      trace "Failed to request peer", peer, namespace = ns, err = error
      continue
    for r in registrations:
      if limit == 0:
        break
      let ttl = r.ttl.get(rdv.config.maxTTL + 1)
      if ttl > rdv.config.maxTTL:
        continue
      let
        spr = SignedPayload[E].decode(r.signedPeerRecord).valueOr:
          continue
        pr = spr.data
      s.withValue(pr.peerId, saved):
        let (prSaved, rSaved) = saved[]
        if (prSaved.seqNo == pr.seqNo and rSaved.ttl.get(rdv.config.maxTTL) < ttl) or
            prSaved.seqNo < pr.seqNo:
          saved[] = (pr, r)
      do:
        s[pr.peerId] = (pr, r)
      limit.dec()
    if ns.isSome():
      for (_, r) in s.values():
        rdv.save(ns.get(), peer, r, false).isOkOr:
          trace "Cannot save registration", namespace = ns, description = error
  return toSeq(s.values()).mapIt(it[0])

proc unsubscribeLocally*[E](rdv: GenericRendezVous[E], ns: string) =
  let nsSalted = ns & rdv.salt
  for index in rdv.namespaces.getOrDefault(nsSalted):
    if rdv.registered[index].peerId == rdv.switch.peerInfo.peerId:
      rdv.registered[index].expiration = rdv.expiredDT

proc unsubscribe*[E](
    rdv: GenericRendezVous[E], ns: string, peerIds: seq[PeerId]
) {.async: (raises: [RendezVousError, CancelledError]).} =
  ns.checkNamespace().isOkOr:
    raise newException(RendezVousError, error)

  let msg = encode(
    Message(msgType: MessageType.Unregister, unregister: Opt.some(Unregister(ns: ns)))
  )

  proc sendUnregister(
      peerId: PeerId
  ): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
    let stream =
      try:
        await rdv.switch.dial(peerId, RendezVousCodec)
      except DialFailedError as e:
        return err("Failed to dial: " & e.msg)
    defer:
      await stream.close()

    try:
      await stream.writeLp(msg)
    except LPStreamError as e:
      return err("Failed to write: " & e.msg)
    ok()

  proc unsubscribePeer(peerId: PeerId) {.async: (raises: [CancelledError]).} =
    (await sendUnregister(peerId)).isOkOr:
      trace "Failed to send unsubscribe message to peer", peerId, err = error

  let futs = collect(newSeq()):
    for peer in peerIds:
      unsubscribePeer(peer)

  await allFutures(futs)

proc unsubscribe*[E](
    rdv: GenericRendezVous[E], ns: string
) {.async: (raises: [RendezVousError, CancelledError]).} =
  rdv.unsubscribeLocally(ns)

  await rdv.unsubscribe(ns, rdv.peers)

proc setup*[E](rdv: GenericRendezVous[E], switch: Switch) =
  rdv.switch = switch
  proc handlePeer(
      peerId: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    if event.kind == PeerEventKind.Joined:
      rdv.peers.add(peerId)
    elif event.kind == PeerEventKind.Left:
      rdv.peers.keepItIf(it != peerId)

  rdv.switch.addPeerEventHandler(handlePeer, Joined)
  rdv.switch.addPeerEventHandler(handlePeer, Left)

proc new*(
    T: typedesc[RendezVous], rng: Rng, config: RendezVousConfig = RendezVousConfig.new()
): T =
  let rdv = GenericRendezVous[PeerRecord](
    rng: rng,
    config: config,
    salt: string.fromBytes(generateBytes(rng, 8)),
    registered: initOffsettedSeq[RegisteredData](),
    expiredDT: Moment.now() - 1.days,
    #registerEvent: newAsyncEvent(),
    sema: newAsyncSemaphore(SemaphoreDefaultSize),
    peerRecordValidator: checkPeerRecord,
  )
  logScope:
    topics = "libp2p rendezvous"
  proc handleStream(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    defer:
      await stream.close()

    try:
      let
        buf = await stream.readLp(4096)
        msg = Message.decode(buf).valueOr:
          trace "Failed to decode Message", err = error
          return
      case msg.msgType
      of MessageType.Register:
        let register = msg.register.valueOr:
          trace "Register message is empty", peerId = stream.peerId
          return
        await rdv.register(stream, register, rdv.switch.peerInfo.signedPeerRecord.data)
      of MessageType.RegisterResponse:
        trace "Got an unexpected Register Response", response = msg.registerResponse
      of MessageType.Unregister:
        let unregister = msg.unregister.valueOr:
          trace "Unregister message is empty", peerId = stream.peerId
          return
        rdv.unregister(stream, unregister)
      of MessageType.Discover:
        let discover = msg.discover.valueOr:
          trace "Discover message is empty", peerId = stream.peerId
          return
        await rdv.discover(stream, discover)
      of MessageType.DiscoverResponse:
        trace "Got an unexpected Discover Response",
          response = msg.discoverResponse.get(DiscoverResponse())
    except LPStreamError as e:
      trace "Stream error in rendezvous handler", peerId = stream.peerId, err = e.msg

  rdv.handler = handleStream
  rdv.codec = RendezVousCodec
  return rdv

proc new*(
    T: typedesc[RendezVous],
    switch: Switch,
    rng: Rng,
    config: RendezVousConfig = RendezVousConfig.new(),
): T =
  let rdv = T.new(rng, config)
  rdv.setup(switch)
  return rdv

func isLive(reg: RegisteredData, n: Moment): bool =
  reg.expiration >= n

proc clearExpiredRegistrations[E](rdv: GenericRendezVous[E], n: Moment) =
  rdv.registered.flushIfIt(it.expiration < n)

  # An entry behind a live one keeps its index so the cookies stay valid.
  for reg in rdv.registered.mitems():
    if not reg.isLive(n):
      reg = RegisteredData(expiration: rdv.expiredDT)

proc dropExpiredNamespaces[E](rdv: GenericRendezVous[E], n: Moment) =
  var emptied: seq[string] = @[]

  for ns, indexes in rdv.namespaces.mpairs():
    indexes =
      indexes.filterIt(it >= rdv.registered.offset and rdv.registered[it].isLive(n))
    if indexes.len == 0:
      emptied.add(ns)

  for ns in emptied:
    rdv.namespaces.del(ns)

func liveRegistrations[E](rdv: GenericRendezVous[E]): int =
  var total = 0
  for indexes in rdv.namespaces.values():
    total += indexes.len
  total

proc deletesRegister*[E](
    rdv: GenericRendezVous[E], interval = 1.minutes
) {.async: (raises: [CancelledError]).} =
  heartbeat "Register timeout", interval:
    let n = Moment.now()
    rdv.clearExpiredRegistrations(n)
    rdv.dropExpiredNamespaces(n)
    rdv.recountRegistered()
    libp2p_rendezvous_registered.set(int64(rdv.liveRegistrations()))
    libp2p_rendezvous_namespaces.set(int64(rdv.namespaces.len))

method start*[E](
    rdv: GenericRendezVous[E]
): Future[void] {.async: (raises: [CancelledError], raw: true).} =
  let fut = newFutureCompleted[void]()
  if not rdv.registerDeletionLoop.isNil:
    warn "Starting rendezvous twice"
    return fut
  rdv.registerDeletionLoop = rdv.deletesRegister()
  rdv.started = true
  info "Rendezvous service started"
  fut

method stop*[E](
    rdv: GenericRendezVous[E]
): Future[void] {.async: (raises: [], raw: true).} =
  if rdv.registerDeletionLoop.isNil:
    warn "Stopping rendezvous without starting it"
    return newFutureCompleted[void]()

  rdv.started = false
  rdv.registerDeletionLoop.cancelSoon()
  rdv.registerDeletionLoop = nil
  newFutureCompleted[void]()
