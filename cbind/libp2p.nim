# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## C FFI bindings for nim-libp2p, on top of `nim-ffi` (the FFI runtime + C/CDDL
## generator). Declares the request/response shapes and libp2p bodies that
## `genBindings()` emits at the bottom; config parsing lives in the `include`d `config`.

import ffi

import std/[tables, sequtils, sets, json, jsonutils, strformat, strutils, locks, net]
from std/times import getTime, toUnix, Time, nanosecond
import chronos
import chronicles
import metrics

import ../libp2p
import ../libp2p/logging
import ../libp2p/services/natservice
import ../libp2p/[multiaddress, peerid]
import ../libp2p/crypto/crypto
import ../libp2p/nameresolving/dnsresolver
import ../libp2p/protocols/pubsub/gossipsub
import ../libp2p/protocols/protocol
import ../libp2p/protocols/ping
import ../libp2p/protocols/kademlia
import ../libp2p/protocols/service_discovery
import ../libp2p/protocols/service_discovery/[random_find, types]
import ../libp2p/protocols/connectivity/relay/client
import ../libp2p/protocols/connectivity/autonatv2/service
import ../libp2p/extended_peer_record

type StreamRegistry = ref object
  ## Owns the live streams handed across the FFI boundary and the release-waiter
  ## futures keeping custom-protocol handlers alive until the host is done. A `ref`
  ## so a handler captures it alone, avoiding a `lib` cycle that leaks under `--mm:refc`.
  streams: Table[uint64, Stream]
  nextStreamId: uint64
  releaseWaiters: Table[uint64, Future[void].Raising([CancelledError])]

type LibP2P* = ref object
  ## Main library state. The FFI context owns one instance; its tables mutate
  ## through the `lib` receiver of every `{.ffi.}` proc.
  switch: Switch
  rng: Rng
  gossipSub: Opt[GossipSub]
  kad: Opt[KadDHT]
  relayClient: Opt[RelayClient]
  topicHandlers: Table[string, TopicHandler]
  customProtocols: Table[string, LPProtocol]
  streams: StreamRegistry
  running: bool

declareLibrary("libp2p", LibP2P)

include "libp2p/config"

type PeerDirection {.ffi.} = enum
  Inbound = "in"
  Outbound = "out"

type PeerInfoResponse {.ffi.} = object
  peerId: string
  addrs: seq[string]

type PeersResponse {.ffi.} = object
  peerIds: seq[string]

type ConnectRequest {.ffi.} = object
  peerId: string
  multiaddrs: seq[string]
  timeoutMs: int64

type DialRequest {.ffi.} = object
  peerId: string
  proto: string
  multiaddrs: seq[string] ## empty dials a peer the switch is already connected to
  forceDial: bool ## bypasses dial-limit backoff; needs multiaddrs
  timeoutMs: int64

type DialResponse {.ffi.} = object
  streamId: uint64

type DialCircuitRelayRequest {.ffi.} = object
  peerId: string
  multiaddr: string
  proto: string
  timeoutMs: int64

type StreamWriteRequest {.ffi.} = object
  streamId: uint64
  data: seq[byte]

type StreamReadExactlyRequest {.ffi.} = object
  streamId: uint64
  numBytes: int64

type StreamReadLpRequest {.ffi.} = object
  streamId: uint64
  maxSize: int64

type PublishRequest {.ffi.} = object
  topic: string
  data: seq[byte]

type PublishResponse {.ffi.} = object
  peerCount: int64 ## number of peers the message was forwarded to

type ReadResponse {.ffi.} = object
  data: seq[byte]

type CreateCidRequest {.ffi.} = object
  version: int
  multicodec: string
  hash: string
  data: seq[byte]

type NewPrivateKeyRequest {.ffi.} = object
  scheme: int

# Named wire values for the two `int` fields above, so a host doesn't hardcode
# them. A `{.ffi.}` enum can't do this job here: Nim reads `CidV0` and `CIDv0` as
# one identifier, so a mirror enum collides with the very type it mirrors.
const
  # Not libp2p's `CidVersion` ordinals (`CIDvIncorrect` takes 0 there) — the
  # wire numbering is cbind's own, mapped in `libp2pCreateCid`.
  CidVersionV0 {.ffiConst.} = 0
  CidVersionV1 {.ffiConst.} = 1
  # These are cast straight to `PKScheme`, so derive them and they can't drift.
  KeySchemeRsa {.ffiConst.} = ord(PKScheme.RSA)
  KeySchemeEd25519 {.ffiConst.} = ord(PKScheme.Ed25519)
  KeySchemeSecp256k1 {.ffiConst.} = ord(PKScheme.Secp256k1)
  KeySchemeEcdsa {.ffiConst.} = ord(PKScheme.ECDSA)
  # consts for chronicles runtime log level
  LogLevelNone {.ffiConst.} = ord(chronicles.LogLevel.NONE)
  LogLevelTrace {.ffiConst.} = ord(chronicles.LogLevel.TRACE)
  LogLevelDebug {.ffiConst.} = ord(chronicles.LogLevel.DEBUG)
  LogLevelInfo {.ffiConst.} = ord(chronicles.LogLevel.INFO)
  LogLevelNotice {.ffiConst.} = ord(chronicles.LogLevel.NOTICE)
  LogLevelWarn {.ffiConst.} = ord(chronicles.LogLevel.WARN)
  LogLevelError {.ffiConst.} = ord(chronicles.LogLevel.ERROR)
  LogLevelFatal {.ffiConst.} = ord(chronicles.LogLevel.FATAL)

type KadPutValueRequest {.ffi.} = object
  key: seq[byte] ## Raw Kademlia key bytes; converted to `Key` at the FFI boundary.
  value: seq[byte] ## Raw record bytes; converted to `Value` at the FFI boundary.

type KadGetValueRequest {.ffi.} = object
  key: seq[byte] ## Raw Kademlia key bytes; converted to `Key` at the FFI boundary.
  quorum: int

type ProviderInfo {.ffi.} = object
  peerId: string
  addrs: seq[string]

type ProvidersResponse {.ffi.} = object
  providers: seq[ProviderInfo]

type ServiceInfoEntry {.ffi.} = object
  id: string
  data: seq[byte]

type ExtendedPeerRecordEntry {.ffi.} = object
  peerId: string
  seqNo: uint64
  addrs: seq[string]
  services: seq[ServiceInfoEntry]

type ExtendedRecordsResponse {.ffi.} = object
  records: seq[ExtendedPeerRecordEntry]

type StartAdvertisingRequest {.ffi.} = object
  serviceId: string
  serviceData: seq[byte]
  advertisement: seq[byte]

type CreateXprRequest {.ffi.} = object
  addrs: seq[string]
  services: seq[ServiceInfoEntry]
  seqNo: uint64

type DecodeXprRequest {.ffi.} = object
  encoded: seq[byte]

type LookupRequest {.ffi.} = object
  serviceId: string
  serviceData: seq[byte]

type ReservationResponse {.ffi.} = object
  addrs: seq[string]
  expireTime: uint64

type CircuitRelayReserveRequest {.ffi.} = object
  relayPeerId: string
  relayAddrs: seq[string]

type AddPeerRequest {.ffi.} = object
  peerId: string
  addrs: seq[string]
  protocols: seq[string]

type SetAddressesRequest {.ffi.} = object
  peerId: string
  addrs: seq[string]

type SetProtocolsRequest {.ffi.} = object
  peerId: string
  protocols: seq[string]

type PeerStoreEntryResponse {.ffi.} = object
  peerId: string
  addrs: seq[string]
  protocols: seq[string]
  publicKey: seq[byte]
  agentVersion: string
  protoVersion: string

type IncomingStreamEvent {.ffi.} = object
  proto: string
  streamId: uint64
  peerId: string

type PubsubMessageEvent {.ffi.} = object
  topic: string
  data: seq[byte]

proc onIncomingStream*(event: IncomingStreamEvent) {.ffiEvent.} =
  ## Fired by a mounted custom protocol when a peer opens a stream on it.

proc onPubsubMessage*(event: PubsubMessageEvent) {.ffiEvent.} =
  ## Fired for every message received on a subscribed gossipsub topic.

proc register(reg: StreamRegistry, stream: Stream): uint64 =
  reg.nextStreamId.inc()
  let id = reg.nextStreamId
  reg.streams[id] = stream
  id

func get(reg: StreamRegistry, id: uint64): Result[Stream, string] =
  let stream = reg.streams.getOrDefault(id, nil)
  if stream.isNil():
    return err("unknown stream handle")
  ok(stream)

proc release(reg: StreamRegistry, id: uint64) =
  # Completes the waiting protocol handler so multistream doesn't close the stream early.
  let releaseWaiter = reg.releaseWaiters.getOrDefault(id, nil)
  if not releaseWaiter.isNil():
    reg.releaseWaiters.del(id)
    if not releaseWaiter.finished():
      releaseWaiter.complete()
  reg.streams.del(id)

const MaxReadBytes {.ffiConst.} = 64 * 1024 * 1024
  ## Caps the buffer an untrusted peer can make us pre-allocate before any byte
  ## arrives; well above libp2p's largest framed messages.

proc mountGossipsub(lib: LibP2P, cfg: ParsedGossipsub): Result[void, string] =
  # `init` marks the set explicit, so every parameter left out keeps its default.
  # It also runs `validateParameters`, which rejects an inconsistent rate limit.
  let gs =
    try:
      GossipSub.init(
        switch = lib.switch,
        triggerSelf = cfg.triggerSelf,
        maxMessageSize = cfg.maxMessageSize,
        rng = lib.rng,
        parameters = GossipSubParams.init(
          overheadRateLimit = cfg.overheadRateLimit,
          disconnectPeerAboveRateLimit = cfg.disconnectPeerAboveRateLimit,
        ),
      )
    except InitializationError as e:
      return err(e)
  try:
    lib.switch.mount(gs)
  except LPError as e:
    return err(e)
  lib.gossipSub = Opt.some(gs)
  ok()

proc defaultKadConfig(): KadDHTConfig =
  # Validator/selector are host callbacks that can't cross the FFI boundary; use the defaults.
  KadDHTConfig.new(
    validator = DefaultEntryValidator(), selector = DefaultEntrySelector()
  )

proc mountKad(
    lib: LibP2P, bootstrapNodes: seq[(PeerId, seq[MultiAddress])]
): Result[void, string] =
  try:
    let k = KadDHT.new(
      lib.switch,
      bootstrapNodes = bootstrapNodes,
      config = defaultKadConfig(),
      rng = lib.rng,
    )
    lib.switch.mount(k)
    lib.kad = Opt.some(k)
  except LPError as e:
    return err(e)
  ok()

proc mountServiceDiscovery(lib: LibP2P, cfg: ParsedConfig): Result[void, string] =
  try:
    let sd = ServiceDiscovery.new(
      lib.switch,
      bootstrapNodes = cfg.bootstrapNodes,
      config = defaultKadConfig(),
      rng = lib.rng,
      client = cfg.serviceDiscoveryMode == ServiceDiscoveryMode.Client,
      codec = ExtendedServiceDiscoveryCodec,
      xprPublishing = not cfg.serviceDiscoveryDisableXprPublishing,
    )
    lib.switch.mount(sd)
    lib.kad = Opt.some(KadDHT(sd))
  except LPError as e:
    return err(e)
  ok()

proc mountProtocols(lib: LibP2P, cfg: ParsedConfig): Result[void, string] =
  if cfg.gossipsub.mount:
    ?mountGossipsub(lib, cfg.gossipsub)

  if cfg.mountServiceDiscovery:
    ?mountServiceDiscovery(lib, cfg)
  elif cfg.mountKad:
    ?mountKad(lib, cfg.bootstrapNodes)

  try:
    lib.switch.mount(Ping.new(rng = lib.rng))
  except LPError as e:
    return err(e)
  ok()

proc withConfiguredTransport(
    builder: SwitchBuilder, transport: ParsedTransport
): SwitchBuilder =
  case transport.kind
  of TransportType.Quic:
    builder.withQuicTransport()
  of TransportType.Tcp:
    let tcp = builder.withTcpTransport()
    case transport.muxer
    of MuxerType.Mplex:
      tcp.withMplex()
    of MuxerType.Yamux:
      tcp.withYamux()

proc createLibp2pNode(config: Libp2pConfig): Result[LibP2P, string] =
  let cfg = ?config.parse()
  let rng = newRng()

  var switchBuilder = SwitchBuilder
    .new()
    .withRng(rng)
    .withMaxConnsPerPeer(cfg.maxConnsPerPeer)
    .withNameResolver(DnsResolver.new(cfg.dnsServers))
    .withNoise()
    .withPrivateKey(cfg.privKey)
    .withAddresses(cfg.addrs)
    .withConfiguredTransport(cfg.transport)

  if cfg.maxIn > 0 and cfg.maxOut > 0:
    switchBuilder = switchBuilder.withConnectionLimits(
      ConnectionLimits.maxInOut(cfg.maxIn, cfg.maxOut)
    )
  elif cfg.maxConnections > 0:
    switchBuilder =
      switchBuilder.withConnectionLimits(ConnectionLimits.maxTotal(cfg.maxConnections))

  var relayClientOpt = Opt.none(RelayClient)
  if cfg.circuitRelayClient:
    let cl = RelayClient.new()
    switchBuilder = switchBuilder.withCircuitRelay(cl)
    relayClientOpt = Opt.some(cl)
  elif cfg.circuitRelay:
    switchBuilder = switchBuilder.withCircuitRelay()

  if cfg.autonat:
    switchBuilder = switchBuilder.withAutonat()

  cfg.nat.ifValue(natCfg):
    switchBuilder = switchBuilder.withNAT(natCfg)

  if cfg.autonatV2Server:
    switchBuilder = switchBuilder.withAutonatV2Server()

  let switch =
    try:
      switchBuilder.build()
    except LPError as e:
      return err(e, "could not create libp2p node")

  let lib = LibP2P(
    switch: switch, rng: rng, relayClient: relayClientOpt, streams: StreamRegistry()
  )

  ?mountProtocols(lib, cfg)

  ok(lib)

proc applyLogLevel(level: int): Result[void, string] =
  if level < ord(low(chronicles.LogLevel)) or level > ord(high(chronicles.LogLevel)):
    return err($level, "invalid log level")

  when chronicles.runtimeFilteringEnabled:
    logging.setLogLevel(chronicles.LogLevel(level))
    ok()
  else:
    err("nim-libp2p runtime logs filtering is disabled")

proc libp2pNew*(config: Libp2pConfig): Future[Result[LibP2P, string]] {.ffiCtor.} =
  ## Builds the switch from `config` and mounts the requested protocols. The
  ## node is not listening yet; call `libp2p_ctx_start` for that.
  if config.logLevel != ord(chronicles.LogLevel.NONE):
    ?applyLogLevel(config.logLevel)

  try:
    createLibp2pNode(config)
  except LPError as e:
    err(e, "could not create libp2p node")

proc shutdownSwitch(lib: LibP2P) {.async.} =
  ## Single source of truth for graceful shutdown. Idempotent: safe to call from
  ## both an explicit `libp2pStop` and `libp2pDestroy`'s teardown.
  if not lib.running:
    return
  await lib.switch.stop()
  lib.running = false

proc libp2pStart*(lib: LibP2P): Future[Result[bool, string]] {.ffi.} =
  ## Starts the switch so it listens and accepts connections. Idempotent.
  ## Returns before the DHT bootstrap ends; `libp2p_ctx_kad_wait_bootstrap`
  ## waits for it.
  if lib.running:
    return ok(true)
  try:
    await lib.switch.start()
  except LPError as e:
    return err(e)
  lib.running = true
  ok(true)

proc libp2pStop*(lib: LibP2P): Future[Result[bool, string]] {.ffi.} =
  ## Stops the switch and closes every connection. Optional:
  ## `libp2p_ctx_destroy` does the same at teardown.
  await shutdownSwitch(lib)
  ok(true)

proc libp2pDestroy*(lib: LibP2P): Future[void] {.ffiDtor.} =
  ## Runs on the worker loop, so the switch stops gracefully before the threads
  ## join. Sufficient on its own; `libp2p_ctx_stop` beforehand is optional.
  await shutdownSwitch(lib)

# Hand-maintained plain-C mirror of `Libp2pConfig`, for hosts that build the
# config without the generated header. Not layout-compatible with the generated
# `Libp2pConfig` (strings and enums differ); `muxer`/`transport` carry the
# `MuxerType`/`TransportType` ordinals. Keep the field list in sync.
type CRateLimitConfig {.exportc: "libp2p_rate_limit_config", bycopy.} = object
  bytes: cint
  intervalMs: int64

type CGossipsubConfig {.exportc: "libp2p_gossipsub_config", bycopy.} = object
  mount: cint
  triggerSelf: cint
  maxMessageSize: cint
  overheadRateLimit: CRateLimitConfig
  disconnectPeerAboveRateLimit: cint

type CLibp2pConfig {.exportc: "libp2p_config", bycopy.} = object
  logLevel: cint
  gossipsub: CGossipsubConfig
  mountKad: cint
  mountServiceDiscovery: cint
  serviceDiscoveryMode: cint
  serviceDiscoveryDisableXprPublishing: cint
  dnsResolver: cstring
  addrs: ptr cstring
  addrsLen: csize_t
  muxer: cint
  transport: cint
  bootstrapNodes: pointer
  bootstrapNodesLen: csize_t
  privKey: ptr byte
  privKeyLen: csize_t
  maxConnections: cint
  maxIn: cint
  maxOut: cint
  maxConnsPerPeer: cint
  circuitRelay: cint
  circuitRelayClient: cint
  autonat: cint
  autonatV2: cint
  autonatV2Server: cint
  natPortMappingAuto: cint
  natPortMappingUpnp: cint
  natPortMappingNatPmp: cint
  natExplicitIp: cstring
  natDiscoveryTimeoutMs: int64
  natMappingTimeoutMs: int64
  natReachabilityV1: cint
  natReachabilityV2: cint
  natReachabilityScheduleIntervalMs: int64
  natHolePunching: cint
  natHolePunchingMaxNumRelays: cint
  natHolePunchingScheduleIntervalMs: int64

proc libp2pNewDefaultConfig(): CLibp2pConfig {.
    exportc: "libp2p_new_default_config", cdecl, dynlib
.} =
  CLibp2pConfig()

proc libp2pPublicKey*(lib: LibP2P): Future[Result[seq[byte], string]] {.ffi.} =
  ## The node's public key, serialized in its own key scheme's format.
  let peerInfo = lib.switch.peerInfo
  if peerInfo.isNil():
    return err("switch peerInfo is nil")

  # Scheme-native serialization: whatever key the switch was built with round-trips, not just secp256k1 (the default builder uses Ed25519).
  let rawBytes = peerInfo.publicKey.getRawBytes().valueOr:
    return err(error, "could not serialize public key")
  ok(rawBytes)

func callTimeout(timeoutMs: int64): Duration =
  ## The caller's limit on one call; `<= 0` leaves only libp2p's own timeouts.
  ## nim-ffi never cancels a handler, so nothing else limits the call.
  if timeoutMs <= 0:
    InfiniteDuration
  else:
    chronos.milliseconds(timeoutMs)

proc libp2pConnect*(
    lib: LibP2P, req: ConnectRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Dials `peerId` at `multiaddrs` and keeps the connection in the switch.
  ## `timeoutMs <= 0` defers to libp2p's own dial timeout.
  let multiaddresses = parseMultiaddrs(req.multiaddrs).valueOr:
    return err(error)

  let peerId = PeerId.init(req.peerId).valueOr:
    return err(error)

  try:
    await lib.switch.connect(peerId, multiaddresses).wait(callTimeout(req.timeoutMs))
  except AsyncTimeoutError:
    return err("dial timeout")
  except DialFailedError as e:
    return err(e)

  ok(true)

proc libp2pDisconnect*(
    lib: LibP2P, peerId: string
): Future[Result[bool, string]] {.ffi.} =
  ## Closes every connection to `peerId`.
  let pid = PeerId.init(peerId).valueOr:
    return err(error)
  await lib.switch.disconnect(pid)
  ok(true)

proc libp2pPeerInfo*(lib: LibP2P): Future[Result[PeerInfoResponse, string]] {.ffi.} =
  ## The node's own peer id and the addresses it listens on.
  let peerInfo = lib.switch.peerInfo
  if peerInfo.isNil():
    return err("switch peerInfo is nil")
  try:
    ok(PeerInfoResponse(peerId: $peerInfo.peerId, addrs: peerInfo.addrs.mapIt($it)))
  except LPError as e:
    err(e)

proc libp2pConnectedPeers*(
    lib: LibP2P, direction: PeerDirection
): Future[Result[PeersResponse, string]] {.ffi.} =
  ## Peer ids of the currently connected peers, restricted to `direction`.
  let dir =
    case direction
    of PeerDirection.Inbound: Direction.In
    of PeerDirection.Outbound: Direction.Out
  ok(PeersResponse(peerIds: lib.switch.connectedPeers(dir).mapIt($it)))

proc libp2pConnectedPeersAnyDirection*(
    lib: LibP2P
): Future[Result[PeersResponse, string]] {.ffi.} =
  ## Peer ids of every connected peer, inbound and outbound.
  ok(PeersResponse(peerIds: lib.switch.connectedPeers().mapIt($it)))

proc libp2pDial*(
    lib: LibP2P, req: DialRequest
): Future[Result[DialResponse, string]] {.ffi.} =
  ## Opens a stream to `peerId` speaking `proto`, returning its stream id.
  ## `timeoutMs <= 0` defers to libp2p's own dial timeout.
  let peerId = PeerId.init(req.peerId).valueOr:
    return err(error)
  let multiaddresses = parseMultiaddrs(req.multiaddrs).valueOr:
    return err(error)
  if req.forceDial and multiaddresses.len == 0:
    return err("forceDial requires multiaddrs")

  # The two dial overloads react differently when a stream fails to open. The
  # addrs overload closes the connection. The peer-id overload only raises. Use
  # the peer-id overload when there are no addrs, so a failure does not close a
  # connection the caller did not open.
  let dialing =
    if multiaddresses.len == 0:
      lib.switch.dial(peerId, req.proto)
    else:
      lib.switch.dial(peerId, multiaddresses, @[req.proto], req.forceDial)
  let stream =
    try:
      await dialing.wait(callTimeout(req.timeoutMs))
    except AsyncTimeoutError:
      return err("dial timeout")
    except DialFailedError as e:
      return err(e)
  ok(DialResponse(streamId: lib.streams.register(stream)))

proc libp2pDialCircuitRelay*(
    lib: LibP2P, req: DialCircuitRelayRequest
): Future[Result[DialResponse, string]] {.ffi.} =
  ## Opens a stream to `peerId` over the circuit-relay address `multiaddr`.
  ## `timeoutMs <= 0` defers to libp2p's own dial timeout.
  let dstPeerId = PeerId.init(req.peerId).valueOr:
    return err(error)
  let relayCircuitAddr = MultiAddress.init(req.multiaddr).valueOr:
    return err(error)
  let stream =
    try:
      await lib.switch.dial(dstPeerId, @[relayCircuitAddr], req.proto).wait(
        callTimeout(req.timeoutMs)
      )
    except AsyncTimeoutError:
      return err("dial timeout")
    except DialFailedError as e:
      return err(e)
  ok(DialResponse(streamId: lib.streams.register(stream)))

func validateReadLength(n: int64): Result[int, string] =
  ## Guards attacker-controlled read lengths before they size an allocation:
  ## rejects negatives and anything past the `MaxReadBytes` ceiling (64 MiB), which
  ## sits well below `int.high` even on 32-bit, so the `int(n)` narrowing is always safe.
  if n < 0:
    return err("invalid read length")
  if n > MaxReadBytes:
    return err("read length exceeds maximum")
  if n > int.high:
    return err("read length too large")
  ok(int(n))

proc libp2pStreamReadExactly*(
    lib: LibP2P, req: StreamReadExactlyRequest
): Future[Result[ReadResponse, string]] {.ffi.} =
  ## Reads exactly `numBytes` from the stream, capped at `MAX_READ_BYTES`.
  let stream = ?lib.streams.get(req.streamId)
  let expected = ?validateReadLength(req.numBytes)
  if expected == 0:
    return ok(ReadResponse(data: @[]))
  var buf = newSeqUninit[byte](expected)
  try:
    await stream.readExactly(addr buf[0], expected)
  except LPStreamError as e:
    return err(e)
  ok(ReadResponse(data: buf))

proc libp2pStreamReadLp*(
    lib: LibP2P, req: StreamReadLpRequest
): Future[Result[ReadResponse, string]] {.ffi.} =
  ## Reads one length-prefixed message, rejecting a prefix above `maxSize`.
  let stream = ?lib.streams.get(req.streamId)
  let maxSize = ?validateReadLength(req.maxSize)
  let data =
    try:
      await stream.readLp(maxSize)
    except LPStreamError as e:
      return err(e)
  ok(ReadResponse(data: data))

proc libp2pStreamWrite*(
    lib: LibP2P, req: StreamWriteRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Writes `data` to the stream as raw bytes.
  let stream = ?lib.streams.get(req.streamId)
  try:
    await stream.write(req.data)
  except LPStreamError as e:
    return err(e)
  ok(true)

proc libp2pStreamWriteLp*(
    lib: LibP2P, req: StreamWriteRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Writes `data` to the stream as one length-prefixed message.
  let stream = ?lib.streams.get(req.streamId)
  try:
    await stream.writeLp(req.data)
  except LPStreamError as e:
    return err(e)
  ok(true)

proc libp2pStreamClose*(
    lib: LibP2P, streamId: uint64
): Future[Result[bool, string]] {.ffi.} =
  ## Closes the stream's write side; the handle stays valid until released.
  let stream = ?lib.streams.get(streamId)
  await stream.close()
  ok(true)

proc libp2pStreamCloseWithEof*(
    lib: LibP2P, streamId: uint64
): Future[Result[bool, string]] {.ffi.} =
  ## Closes the stream and waits for the peer's EOF.
  let stream = ?lib.streams.get(streamId)
  await stream.closeWithEOF()
  ok(true)

proc libp2pStreamRelease*(
    lib: LibP2P, streamId: uint64
): Future[Result[bool, string]] {.ffi.} =
  ## Drops the stream handle, letting a custom-protocol handler finish.
  discard ?lib.streams.get(streamId)
  lib.streams.release(streamId)
  ok(true)

proc libp2pMountProtocol*(
    lib: LibP2P, proto: string
): Future[Result[bool, string]] {.ffi.} =
  ## Mounts a custom protocol; each inbound stream on it fires
  ## `on_incoming_stream` and stays open until the host releases the handle.
  if proto.len == 0:
    return err("proto is empty")
  if lib.switch.isNil():
    return err("libp2p switch is not initialized")

  let peerInfo = lib.switch.peerInfo
  if lib.customProtocols.hasKey(proto) or proto in peerInfo.protocols:
    return err(proto, "protocol already mounted")

  # Capture the registry ref, not `lib`: a closure over `lib` stored back into `lib.customProtocols` would cycle and leak under `--mm:refc`.
  let streams = lib.streams
  proc handle(
      stream: Stream, selectedProto: string
  ) {.async: (raises: [CancelledError]).} =
    let streamId = streams.register(stream)
    defer:
      streams.release(streamId)
    let releaseWaiter =
      Future[void].Raising([CancelledError]).init("cbind custom protocol release")
    streams.releaseWaiters[streamId] = releaseWaiter
    onIncomingStream(
      IncomingStreamEvent(
        proto: selectedProto, streamId: streamId, peerId: $stream.peerId
      )
    )
    await releaseWaiter

  let mountedProtocol = LPProtocol.new(codecs = @[proto], handler = handle)
  await mountedProtocol.start()

  try:
    lib.switch.mount(mountedProtocol)
  except LPError as e:
    await mountedProtocol.stop()
    return err(e)

  lib.customProtocols[proto] = mountedProtocol
  ok(true)

proc libp2pGossipsubPublish*(
    lib: LibP2P, req: PublishRequest
): Future[Result[PublishResponse, string]] {.ffi.} =
  ## Publishes `data` on `topic`, returning how many peers it went to.
  let gossipSub = lib.gossipSub.valueOr:
    return err("gossipsub not initialized")
  let peerCount = await gossipSub.publish(req.topic, req.data)
  ok(PublishResponse(peerCount: peerCount.int64))

proc libp2pGossipsubSubscribe*(
    lib: LibP2P, topic: string
): Future[Result[bool, string]] {.ffi.} =
  ## Subscribes to `topic`; messages arrive as `on_pubsub_message` events.
  let gossipSub = lib.gossipSub.valueOr:
    return err("gossipsub not initialized")
  if not lib.topicHandlers.hasKey(topic):
    let handler = proc(t: string, data: seq[byte]): Future[void] {.async.} =
      onPubsubMessage(PubsubMessageEvent(topic: t, data: data))
    lib.topicHandlers[topic] = handler
    gossipSub.subscribe(topic, handler)
  ok(true)

proc libp2pGossipsubUnsubscribe*(
    lib: LibP2P, topic: string
): Future[Result[bool, string]] {.ffi.} =
  ## Unsubscribes from `topic`. A topic that was never subscribed is a no-op.
  let gossipSub = lib.gossipSub.valueOr:
    return err("gossipsub not initialized")
  let handler = lib.topicHandlers.getOrDefault(topic, nil)
  if not handler.isNil():
    lib.topicHandlers.del(topic)
    gossipSub.unsubscribe(topic, handler)
  ok(true)

func toExtendedRecordEntry(record: ExtendedPeerRecord): ExtendedPeerRecordEntry =
  ExtendedPeerRecordEntry(
    peerId: $record.peerId,
    seqNo: record.seqNo,
    addrs: record.addresses.mapIt($it.address),
    services: record.services.mapIt(ServiceInfoEntry(id: it.id, data: it.data.get(@[]))),
  )

func toExtendedRecordsResponse(
    records: seq[ExtendedPeerRecord]
): ExtendedRecordsResponse =
  ExtendedRecordsResponse(records: records.mapIt(toExtendedRecordEntry(it)))

proc libp2pKadFindNode*(
    lib: LibP2P, peerId: string
): Future[Result[PeersResponse, string]] {.ffi.} =
  ## Walks the DHT for the peers closest to `peerId`.
  let kad = lib.kad.valueOr:
    return err("kad-dht not initialized")
  let target = PeerId.init(peerId).valueOr:
    return err(error)
  let peers =
    try:
      await kad.findNode(target.toKey())
    except LPError as e:
      return err(e)
  ok(PeersResponse(peerIds: peers.mapIt($it)))

proc libp2pKadWaitBootstrap*(
    lib: LibP2P, timeoutMs: int64
): Future[Result[bool, string]] {.ffi.} =
  ## Waits for the DHT bootstrap that `libp2p_ctx_start` launched; `timeoutMs <= 0`
  ## waits until it ends. A timeout leaves the bootstrap running. `true` means the
  ## bootstrap ended, also when it gave up on its own `bootstrapTimeout`.
  let kad = lib.kad.valueOr:
    return err("kad-dht not initialized")
  if not lib.running:
    return err("switch not started")
  if not await kad.waitBootstrap().withTimeout(callTimeout(timeoutMs)):
    return err("bootstrap wait timeout")
  if not kad.started:
    return err("switch stopped")
  ok(true)

proc libp2pKadPutValue*(
    lib: LibP2P, req: KadPutValueRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Stores `value` under `key` on the DHT nodes closest to it.
  let kad = lib.kad.valueOr:
    return err("kad-dht not initialized")
  let key = Key.fromBytes(req.key)
  let value = Value.fromBytes(req.value)
  (await kad.putValue(key, value)).isOkOr:
    return err(error)
  ok(true)

proc libp2pKadGetValue*(
    lib: LibP2P, req: KadGetValueRequest
): Future[Result[ReadResponse, string]] {.ffi.} =
  ## Looks `key` up on the DHT. `quorum` is how many agreeing records to
  ## require; pass a negative value for the default.
  let kad = lib.kad.valueOr:
    return err("kad-dht not initialized")
  if req.quorum == 0:
    return err("quorum must be greater than 0 (use a negative value for the default)")
  let quorum =
    if req.quorum < 0:
      Opt.none(int)
    else:
      Opt.some(req.quorum)
  let key = Key.fromBytes(req.key)
  let res =
    try:
      await kad.getValue(key, quorum)
    except LPError as e:
      return err(e)
  let entry = res.valueOr:
    return err(error)
  ok(ReadResponse(data: entry.value.toBytes()))

proc kadAndCid(lib: LibP2P, cid: string): Result[(KadDHT, Cid), string] =
  let kad = lib.kad.valueOr:
    return err("kad-dht not initialized")
  let c = Cid.init(cid).valueOr:
    return err(error, "invalid cid")
  ok((kad, c))

proc libp2pKadAddProvider*(
    lib: LibP2P, cid: string
): Future[Result[bool, string]] {.ffi.} =
  ## Announces this node as a provider of `cid`, once.
  let (kad, c) = kadAndCid(lib, cid).valueOr:
    return err(error)
  await kad.addProvider(c)
  ok(true)

proc libp2pKadStartProviding*(
    lib: LibP2P, cid: string
): Future[Result[bool, string]] {.ffi.} =
  ## Announces this node as a provider of `cid` and keeps re-announcing it.
  let (kad, c) = kadAndCid(lib, cid).valueOr:
    return err(error)
  await kad.startProviding(c)
  ok(true)

proc libp2pKadStopProviding*(
    lib: LibP2P, cid: string
): Future[Result[bool, string]] {.ffi.} =
  ## Stops re-announcing this node as a provider of `cid`.
  let (kad, c) = kadAndCid(lib, cid).valueOr:
    return err(error)
  kad.stopProviding(c)
  ok(true)

proc libp2pKadGetProviders*(
    lib: LibP2P, cid: string
): Future[Result[ProvidersResponse, string]] {.ffi.} =
  ## Finds the peers advertising themselves as providers of `cid`.
  let (kad, c) = kadAndCid(lib, cid).valueOr:
    return err(error)
  let providersSet =
    try:
      await kad.getProviders(c.toKey())
    except LPError as e:
      return err(e)

  var providers: seq[ProviderInfo]
  for provider in providersSet.toSeq():
    let providerId = provider.id.valueOr:
      continue
    let peerId = PeerId.init(providerId).valueOr:
      continue
    providers.add(ProviderInfo(peerId: $peerId, addrs: provider.addrs.mapIt($it)))
  ok(ProvidersResponse(providers: providers))

proc runningServiceDiscovery(lib: LibP2P): Result[ServiceDiscovery, string] =
  let kad = lib.kad.valueOr:
    return err("service discovery not initialized")
  if not (kad of ServiceDiscovery):
    return err("service discovery not mounted")
  # Before the switch runs there is no listen address and no signed peer record.
  if not lib.running:
    return err("switch not started; call libp2p_ctx_start first")
  ok(ServiceDiscovery(kad))

proc libp2pKadRandomRecords*(
    lib: LibP2P
): Future[Result[ExtendedRecordsResponse, string]] {.ffi.} =
  ## Extended peer records collected from a random DHT walk.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  let records = await disco.lookupRandom()
  ok(toExtendedRecordsResponse(records))

proc libp2pServiceDiscoStart*(lib: LibP2P): Future[Result[bool, string]] {.ffi.} =
  ## Resumes discovery after `libp2p_ctx_service_disco_stop`; `libp2p_ctx_start` already starts it.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  await disco.start()
  ok(true)

proc libp2pServiceDiscoStop*(lib: LibP2P): Future[Result[bool, string]] {.ffi.} =
  ## Stops the discovery loops while the switch keeps running.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  await disco.stop()
  ok(true)

proc libp2pServiceDiscoStartAdvertising*(
    lib: LibP2P, req: StartAdvertisingRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Advertises `serviceId` in this node's record, or publishes a non-empty
  ## `advertisement` (a signed XPR that must list `serviceId`) under its signer's key.
  ## A second call for the same `serviceId` replaces the advertisement.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)

  disco.startAdvertising(
    ServiceInfo(id: req.serviceId, data: Opt.some(req.serviceData)),
    Opt.noneWhenEmpty(req.advertisement),
  ).isOkOr:
    return err(error)

  ok(true)

proc libp2pServiceDiscoStopAdvertising*(
    lib: LibP2P, serviceId: string
): Future[Result[bool, string]] {.ffi.} =
  ## Stops advertising `serviceId`.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  await disco.stopAdvertising(serviceId)
  ok(true)

proc libp2pServiceDiscoRegisterInterest*(
    lib: LibP2P, serviceId: string
): Future[Result[bool, string]] {.ffi.} =
  ## Registers interest in `serviceId` so its providers are cached locally.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  discard disco.registerInterest(serviceId)
  ok(true)

proc libp2pServiceDiscoUnregisterInterest*(
    lib: LibP2P, serviceId: string
): Future[Result[bool, string]] {.ffi.} =
  ## Drops the interest previously registered for `serviceId`.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  disco.unregisterInterest(serviceId)
  ok(true)

proc libp2pServiceDiscoLookup*(
    lib: LibP2P, req: LookupRequest
): Future[Result[ExtendedRecordsResponse, string]] {.ffi.} =
  ## Looks up the extended peer records advertising `serviceId`.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  let service = ServiceInfo(id: req.serviceId, data: Opt.some(req.serviceData))
  let res = await disco.lookup(service)
  let ads = res.valueOr:
    return err(error)
  ok(toExtendedRecordsResponse(ads.mapIt(it.data)))

proc libp2pServiceDiscoRandomLookup*(
    lib: LibP2P
): Future[Result[ExtendedRecordsResponse, string]] {.ffi.} =
  ## Extended peer records from a random walk, whatever they advertise.
  let disco = runningServiceDiscovery(lib).valueOr:
    return err(error)
  let records = await disco.lookupRandom()
  ok(toExtendedRecordsResponse(records))

proc libp2pCreateXpr*(
    lib: LibP2P, req: CreateXprRequest
): Future[Result[seq[byte], string]] {.ffi.} =
  ## Signs and encodes an extended peer record for this node. Empty `addrs`
  ## means the switch's own addresses, `seqNo` 0 means "now".
  let peerInfo = lib.switch.peerInfo
  if peerInfo.isNil():
    return err("switch peerInfo is nil")

  var addresses = parseMultiaddrs(req.addrs).valueOr:
    return err(error)
  if addresses.len == 0:
    addresses = peerInfo.addrs

  let seqNo =
    if req.seqNo == 0:
      getTime().toUnix().uint64
    else:
      req.seqNo

  var services: seq[ServiceInfo]
  for s in req.services:
    services.add(ServiceInfo(id: s.id, data: Opt.some(s.data)))

  let peerRecord = ExtendedPeerRecord.init(peerInfo.peerId, addresses, seqNo, services)

  let xpr = SignedExtendedPeerRecord.build(peerInfo.privateKey, peerRecord).valueOr:
    return err(error)

  ok(xpr.encode())

proc libp2pDecodeXpr*(
    req: DecodeXprRequest
): Future[Result[ExtendedPeerRecordEntry, string]] {.ffiStatic.} =
  ## Decodes a signed extended peer record and verifies its signature.
  let sxpr = SignedExtendedPeerRecord.decode(req.encoded).valueOr:
    return err(error, "failed to decode signed extended peer record")

  sxpr.checkValid().isOkOr:
    return err(error, "invalid XPR signature")

  ok(toExtendedRecordEntry(sxpr.data))

proc libp2pCircuitRelayReserve*(
    lib: LibP2P, req: CircuitRelayReserveRequest
): Future[Result[ReservationResponse, string]] {.ffi.} =
  ## Reserves a slot on a circuit relay, returning the relayed addresses.
  let cl = lib.relayClient.valueOr:
    return err("relay client is not mounted (set circuitRelayClient=true in config)")

  let peerId = PeerId.init(req.relayPeerId).valueOr:
    return err(error)

  let multiaddresses = parseMultiaddrs(req.relayAddrs).valueOr:
    return err(error)

  let rsvp = (await cl.tryReserve(peerId, multiaddresses)).valueOr:
    return err(error, "reservation failed")

  ok(ReservationResponse(addrs: rsvp.addrs.mapIt($it), expireTime: rsvp.expire))

proc libp2pPeerstoreGetPeers*(
    lib: LibP2P
): Future[Result[PeersResponse, string]] {.ffi.} =
  ## Every peer id known to the peer store, connected or not.
  var peerIds: seq[string]
  try:
    for peerId in keys(lib.switch.peerStore[AddressBook].book):
      peerIds.add($peerId)
  except LPError as e:
    return err(e)
  ok(PeersResponse(peerIds: peerIds))

proc libp2pPeerstoreGetPeerInfo*(
    lib: LibP2P, peerId: string
): Future[Result[PeerStoreEntryResponse, string]] {.ffi.} =
  ## Everything the peer store holds for `peerId`; absent books come back empty.
  let pid = PeerId.init(peerId).valueOr:
    return err(error)
  let peerStore = lib.switch.peerStore
  try:
    var entry = PeerStoreEntryResponse(peerId: $pid)
    entry.addrs = peerStore[AddressBook][pid].mapIt($it)
    entry.protocols = peerStore[ProtoBook][pid]
    if peerStore[KeyBook].contains(pid):
      entry.publicKey = peerStore[KeyBook][pid].getBytes().valueOr:
        seq[byte].default
    entry.agentVersion = peerStore[AgentBook][pid]
    entry.protoVersion = peerStore[ProtoVersionBook][pid]
    ok(entry)
  except LPError as e:
    err(e)

proc libp2pPeerstoreAddPeer*(
    lib: LibP2P, req: AddPeerRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Adds `peerId` to the peer store, extending its addresses and protocols.
  let pid = PeerId.init(req.peerId).valueOr:
    return err(error)
  if req.addrs.len == 0:
    return err("at least one address is required")

  let addrs = parseMultiaddrs(req.addrs).valueOr:
    return err(error)

  let peerStore = lib.switch.peerStore
  peerStore[AddressBook].extend(pid, addrs)
  if req.protocols.len > 0:
    peerStore[ProtoBook].extend(pid, req.protocols)
  ok(true)

proc libp2pPeerstoreSetPeerAddresses*(
    lib: LibP2P, req: SetAddressesRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Replaces the peer store's addresses for `peerId`.
  let pid = PeerId.init(req.peerId).valueOr:
    return err(error)

  let addrs = parseMultiaddrs(req.addrs).valueOr:
    return err(error)

  lib.switch.peerStore[AddressBook][pid] = addrs
  ok(true)

proc libp2pPeerstoreSetPeerProtocols*(
    lib: LibP2P, req: SetProtocolsRequest
): Future[Result[bool, string]] {.ffi.} =
  ## Replaces the peer store's protocol list for `peerId`.
  let pid = PeerId.init(req.peerId).valueOr:
    return err(error)
  lib.switch.peerStore[ProtoBook][pid] = req.protocols
  ok(true)

proc libp2pPeerstoreDeletePeer*(
    lib: LibP2P, peerId: string
): Future[Result[bool, string]] {.ffi.} =
  ## Drops every peer-store entry for `peerId`.
  let pid = PeerId.init(peerId).valueOr:
    return err(error)
  lib.switch.peerStore.del(pid)
  ok(true)

proc libp2pCreateCid*(
    req: CreateCidRequest
): Future[Result[string, string]] {.ffiStatic.} =
  ## Builds a CID string from a multicodec, a multihash name and the data.
  ## `version` is `CID_VERSION_V0` or `CID_VERSION_V1`.
  let cidVer =
    case req.version
    of CidVersionV0:
      CIDv0
    of CidVersionV1:
      CIDv1
    else:
      return err("cid version must be 0 or 1")

  let mc = MultiCodec.codec(req.multicodec)
  if mc == InvalidMultiCodec:
    return err(req.multicodec, "invalid multicodec")

  let mh = MultiHash.digest(req.hash, req.data).valueOr:
    return err(error, "multihash error")

  let cid = Cid.init(cidVer, mc, mh).valueOr:
    return err(error, "cid init error")

  ok($cid)

proc libp2pNewPrivateKey*(
    req: NewPrivateKeyRequest
): Future[Result[seq[byte], string]] {.ffiStatic.} =
  ## Generates a private key. `scheme` is one of the
  ## `KEY_SCHEME_*` constants.
  if req.scheme < ord(low(PKScheme)) or req.scheme > ord(high(PKScheme)):
    return err("invalid key scheme")
  let scheme = PKScheme(req.scheme)

  let rng = newRng()
  let key = PrivateKey.random(scheme, rng).valueOr:
    return err(error, "could not generate private key")

  let keyData = key.getBytes().valueOr:
    return err(error, "could not get bytes for private key")

  ok(keyData)

type LabelPair = object
  name: string
  value: string

type MetricEntry = object
  name: string
  `type`: string
  help: string
  labels: seq[LabelPair]
  value: float64
  timestamp: int64

const UntypedMetricKind = "untyped"

proc parseMetricType(typeLine: string): string =
  ## `typeLine` is the collector's pre-formatted "# TYPE <name> <kind>\n";
  ## returns <kind>, or "untyped" when the line is empty or malformed.
  let tokens = typeLine.splitWhitespace()
  if tokens.len < 4:
    return UntypedMetricKind
  tokens[^1]

proc parseMetricHelp(helpLine: string): string =
  ## `helpLine` is the collector's pre-formatted "# HELP <name> <text>\n";
  ## returns <text> (which itself may contain whitespace), or "" when absent.
  const PrefixTokens = 3 # "#", "HELP", "<name>"
  let tokens = helpLine.splitWhitespace(PrefixTokens)
  if tokens.len <= PrefixTokens:
    return ""
  tokens[PrefixTokens].strip()

func toUnixMillis(t: Time): int64 =
  ## Milliseconds since the Unix epoch. `std/times` has no `toMilliseconds` on
  ## Nim 2.2.4, so build it from the second and nanosecond components.
  t.toUnix() * 1000 + t.nanosecond div 1_000_000

proc addMetricEntry(
    entries: ptr seq[MetricEntry],
    metricType: string,
    help: string,
    name: string,
    value: float64,
    labels, labelValues: openArray[string],
    timestamp: Time,
) {.gcsafe, raises: [].} =
  # Skip _created entries: OpenMetrics timestamp metadata, not measurements.
  if name.endsWith("_created"):
    return
  doAssert labels.len == labelValues.len, "metric label count mismatch"
  var labelPairs = newSeq[LabelPair](labels.len)
  for i in 0 ..< labels.len:
    labelPairs[i] = LabelPair(name: labels[i], value: labelValues[i])
  entries[].add MetricEntry(
    name: name,
    `type`: metricType,
    help: help,
    labels: labelPairs,
    value: value,
    timestamp: timestamp.toUnixMillis(),
  )

proc collectRegistryMetrics(registry: Registry): seq[MetricEntry] {.gcsafe.} =
  var entries: seq[MetricEntry]
  {.cast(gcsafe).}:
    withLock registry.lock:
      for collector in registry.collectors:
        let metricType = parseMetricType(collector.typ)
        let help = parseMetricHelp(collector.help)
        let entriesPtr = addr entries
        collector.collect(
          proc(
              name: string,
              value: float64,
              labels, labelValues: openArray[string],
              timestamp: Time,
          ) {.gcsafe, raises: [].} =
            addMetricEntry(
              entriesPtr, metricType, help, name, value, labels, labelValues, timestamp
            )
        )
  entries

proc libp2pCollectMetrics*(): Future[Result[string, string]] {.ffiStatic.} =
  ## A JSON snapshot of the Prometheus registry, one object per metric sample.
  var jsonText: string
  try:
    {.cast(gcsafe).}:
      jsonText = $collectRegistryMetrics(defaultRegistry).toJson()
  except CatchableError as e:
    return err(e, "failed to serialize metrics")
  ok(jsonText)

genBindings()
