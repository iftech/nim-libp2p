# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Config crossing the FFI boundary and its parsing, `include`d into
## `../libp2p.nim`.
##
## `Libp2pConfig` is the raw, wire-friendly shape the host fills in; `parse`
## validates it once and returns a `ParsedConfig` of ready-to-use Nim values, so
## the node builder never touches a raw string or ordinal again:
##
##   let cfg = ?config.parse()
##   ... cfg.privKey, cfg.transport, cfg.bootstrapNodes ...
##
## The `{.ffi.}` types share this module with `genBindings()` on purpose: nim-ffi
## reads the object fields straight from the AST, and an exported field would
## leak its `*` into the generated field name. `include` (not `import`) keeps the
## fields unexported and the emitted bindings clean.

type TransportType {.ffi.} = enum
  Quic = "quic"
  Tcp = "tcp"

type MuxerType {.ffi.} = enum
  Mplex = "mplex"
  Yamux = "yamux"

type ServiceDiscoveryMode {.ffi.} = enum
  Server = "server"
  Client = "client"

type BootstrapNode {.ffi.} = object
  peerId: string
  multiaddrs: seq[string]

type RateLimitConfig {.ffi.} = object
  ## Token bucket. Set both fields or neither; all zero disables the limit.
  bytes: int
  intervalMs: int64

type GossipsubConfig {.ffi.} = object
  mount: bool
  triggerSelf: bool ## Deliver locally published messages to self.
  maxMessageSize: int ## 0 uses the core default; capped at `MAX_GOSSIPSUB_MESSAGE_SIZE`.
  overheadRateLimit: RateLimitConfig ## Per-peer protocol-overhead budget, on ingress.
  disconnectPeerAboveRateLimit: bool
    ## False leaves the budget as a metric; nothing enforces it.

type Libp2pConfig {.ffi.} = object
  logLevel: int ## Chronicles runtime log level to apply before node construction.
  gossipsub: GossipsubConfig ## Mounting and ingress limits for GossipSub.
  mountKad: bool ## Mount the Kademlia DHT service.
  mountServiceDiscovery: bool ## Mount random-find based service discovery.
  serviceDiscoveryMode: ServiceDiscoveryMode
    ## A client queries the DHT but serves no requests and registers no adverts.
  serviceDiscoveryDisableXprPublishing: bool
    ## Keep this node's own signed peer record out of the DHT.
  dnsResolver: string ## DNS server address; empty uses the core defaults.
  addrs: seq[string] ## Listen multiaddresses for the switch.
  muxer: MuxerType ## Type of muxer used for TCP transports.
  transport: TransportType ## Type of transport for selecting TCP or QUIC.
  bootstrapNodes: seq[BootstrapNode]
    ## Peers to add to the peer store and Kad bootstrap set.
  privKey: seq[byte] ## Serialized private key; empty generates a fresh key.
  maxConnections: int
    ## Connection manager total limit; non-positive uses the core default.
  maxIn: int ## Incoming connection limit; non-positive uses the core default.
  maxOut: int ## Outgoing connection limit; non-positive uses the core default.
  maxConnsPerPeer: int ## Per-peer connection limit; non-positive uses the core default.
  circuitRelay: bool ## Mount the relay v2 server.
  circuitRelayClient: bool ## Enable the relay v2 client transport.
  autonat: bool ## Enable the legacy direct AutoNAT v1 service.
  autonatV2: bool ## Compatibility alias for NAT reachability probing with AutoNAT v2.
  autonatV2Server: bool ## Mount the AutoNAT v2 server.
  natPortMappingAuto: bool
    ## Enable gateway port mapping with automatic protocol selection.
  natPortMappingUpnp: bool ## Enable gateway port mapping restricted to UPnP-IGD.
  natPortMappingNatPmp: bool ## Enable gateway port mapping restricted to PCP/NAT-PMP.
  natExplicitIp: string
    ## Announce this external IP instead of discovering a gateway mapping.
  natDiscoveryTimeoutMs: int64
    ## Gateway discovery timeout for port mapping; <= 0 uses the core default.
  natMappingTimeoutMs: int64
    ## Gateway mapping request timeout; <= 0 uses the core default.
  natReachabilityV1: bool ## Enable NAT reachability probing with AutoNAT v1.
  natReachabilityV2: bool ## Enable NAT reachability probing with AutoNAT v2.
  natReachabilityScheduleIntervalMs: int64
    ## Reachability probe interval; <= 0 disables scheduling override.
  natHolePunching: bool ## Enable AutoNAT v1, AutoRelay, and DCUtR hole punching.
  natHolePunchingMaxNumRelays: int
    ## Relay reservation target for hole punching; <= 0 uses the core default.
  natHolePunchingScheduleIntervalMs: int64
    ## Hole-punch reachability probe interval; <= 0 disables scheduling override.

type ParsedGossipsub = object
  mount: bool
  triggerSelf: bool
  maxMessageSize: int
  overheadRateLimit: Opt[RateLimit]
  disconnectPeerAboveRateLimit: bool

type ParsedTransport = object
  ## The transport to build, plus the muxer it needs. A muxer is only used with
  ## TCP, so the variant makes "no muxer for QUIC" unrepresentable rather than
  ## carrying a meaningless default.
  case kind: TransportType
  of TransportType.Tcp:
    muxer: MuxerType
  of TransportType.Quic:
    discard

type ParsedConfig = object
  ## `Libp2pConfig` with every field validated and decoded once. Consumed by the
  ## node builder; carries no raw strings or ordinals.
  dnsServers: seq[TransportAddress]
  addrs: seq[MultiAddress]
  transport: ParsedTransport
  privKey: Opt[PrivateKey]
  bootstrapNodes: seq[(PeerId, seq[MultiAddress])]
  maxConnections: int
  maxIn: int
  maxOut: int
  maxConnsPerPeer: int
  circuitRelay: bool
  circuitRelayClient: bool
  autonat: bool
  nat: Opt[NATConfig]
  autonatV2Server: bool
  gossipsub: ParsedGossipsub
  mountKad: bool
  mountServiceDiscovery: bool
  serviceDiscoveryMode: ServiceDiscoveryMode
  serviceDiscoveryDisableXprPublishing: bool

proc parseMultiaddrs(raw: openArray[string]): Result[seq[MultiAddress], string] =
  var addrs: seq[MultiAddress]
  for a in raw:
    let ma = MultiAddress.init(a).valueOr:
      return err(error, fmt"invalid multiaddress '{a}'")
    addrs.add(ma)
  ok(addrs)

proc parseBootstrapNodes(
    nodes: openArray[BootstrapNode]
): Result[seq[(PeerId, seq[MultiAddress])], string] =
  var parsed: seq[(PeerId, seq[MultiAddress])]
  for node in nodes:
    let peerId = PeerId.init(node.peerId).valueOr:
      return err(error, "invalid bootstrap peer id")
    let addrs = ?parseMultiaddrs(node.multiaddrs)
    parsed.add((peerId, addrs))
  ok(parsed)

proc resolveDnsServers(dnsResolver: string): Result[seq[TransportAddress], string] =
  if dnsResolver.len == 0:
    return ok(DefaultDnsServers)
  try:
    ok(@[initTAddress(dnsResolver)])
  except TransportAddressError as e:
    err(e, "invalid dnsResolver address")

proc parsePrivateKey(raw: seq[byte]): Result[Opt[PrivateKey], string] =
  if raw.len == 0:
    return ok(Opt.none(PrivateKey))
  let key = PrivateKey.init(raw).valueOr:
    return err(error, "invalid private key")
  ok(Opt.some(key))

const
  MaxGossipsubMessageSize {.ffiConst.} = 64 * 1024 * 1024
    ## A peer can make us preallocate this much before a byte is validated.
  MaxOverheadRateLimitIntervalMs {.ffiConst.} = high(int64) div 1_000_000
    ## `chronos.milliseconds` scales to the nanoseconds a `Duration` holds.

func requireMount(cfg: GossipsubConfig): Result[void, string] =
  if cfg.mount:
    return ok()
  if cfg.maxMessageSize != 0 or cfg.overheadRateLimit.bytes != 0 or
      cfg.overheadRateLimit.intervalMs != 0 or cfg.disconnectPeerAboveRateLimit:
    return err("gossipsub limits require gossipsub.mount")
  ok()

func parseMaxMessageSize(size: int): Result[int, string] =
  if size < 0:
    return err("maxMessageSize must be 0 or greater")
  if size == 0:
    return ok(DefaultPubSubMaxMessageSize)
  if size > MaxGossipsubMessageSize:
    return err($MaxGossipsubMessageSize, "maxMessageSize exceeds the byte limit")
  ok(size)

func validateLimit(limit: RateLimitConfig): Result[void, string] =
  ## Rules of the wire shape only; `GossipSubParams.validateParameters` checks
  ## the limit itself.
  if limit.intervalMs > MaxOverheadRateLimitIntervalMs:
    return err(
      $MaxOverheadRateLimitIntervalMs, "overheadRateLimit.intervalMs exceeds the limit"
    )
  if limit.bytes == 0 and limit.intervalMs != 0:
    return err("overheadRateLimit.intervalMs requires overheadRateLimit.bytes")
  if limit.bytes != 0 and limit.intervalMs == 0:
    return err("overheadRateLimit.bytes requires overheadRateLimit.intervalMs")
  ok()

func parseRateLimit(limit: RateLimitConfig): Result[Opt[RateLimit], string] =
  ?validateLimit(limit)
  if limit.bytes == 0:
    return ok(Opt.none(RateLimit))
  ok(
    Opt.some(
      RateLimit(bytes: limit.bytes, interval: chronos.milliseconds(limit.intervalMs))
    )
  )

func parseGossipsub(cfg: GossipsubConfig): Result[ParsedGossipsub, string] =
  ?requireMount(cfg)
  ok(
    ParsedGossipsub(
      mount: cfg.mount,
      triggerSelf: cfg.triggerSelf,
      maxMessageSize: ?parseMaxMessageSize(cfg.maxMessageSize),
      overheadRateLimit: ?parseRateLimit(cfg.overheadRateLimit),
      disconnectPeerAboveRateLimit: cfg.disconnectPeerAboveRateLimit,
    )
  )

func parseTransportConfig(config: Libp2pConfig): ParsedTransport =
  # A muxer is only used with TCP, so a QUIC config's `muxer` is ignored.
  case config.transport
  of TransportType.Quic:
    ParsedTransport(kind: TransportType.Quic)
  of TransportType.Tcp:
    ParsedTransport(kind: TransportType.Tcp, muxer: config.muxer)

func countEnabled(values: varargs[bool]): int =
  for value in values:
    if value:
      result.inc

func optDurationMs(ms: int64): Opt[Duration] =
  if ms > 0:
    Opt.some(chronos.milliseconds(ms))
  else:
    Opt.none(Duration)

proc parsePortMappingConfig(
    config: Libp2pConfig
): Result[Opt[PortMappingConfig], string] =
  if not (
    config.natPortMappingAuto or config.natPortMappingUpnp or config.natPortMappingNatPmp or
    config.natExplicitIp.len > 0
  ):
    return ok(Opt.none(PortMappingConfig))

  let
    discoveryTimeout =
      if config.natDiscoveryTimeoutMs > 0:
        chronos.milliseconds(config.natDiscoveryTimeoutMs)
      else:
        DefaultDiscoveryTimeout
    mappingTimeout =
      if config.natMappingTimeoutMs > 0:
        chronos.milliseconds(config.natMappingTimeoutMs)
      else:
        DefaultMappingTimeout

  if config.natExplicitIp.len > 0:
    try:
      return ok(
        Opt.some(
          PortMappingConfig(
            mode: ExplicitIp, explicitIp: parseIpAddress(config.natExplicitIp)
          )
        )
      )
    except ValueError as e:
      return err(e, "invalid natExplicitIp")
  if config.natPortMappingUpnp:
    return ok(
      Opt.some(
        PortMappingConfig(
          mode: Upnp, discoveryTimeout: discoveryTimeout, mappingTimeout: mappingTimeout
        )
      )
    )
  if config.natPortMappingNatPmp:
    return ok(
      Opt.some(
        PortMappingConfig(
          mode: NatPmp,
          discoveryTimeout: discoveryTimeout,
          mappingTimeout: mappingTimeout,
        )
      )
    )
  ok(
    Opt.some(
      PortMappingConfig(
        mode: Auto, discoveryTimeout: discoveryTimeout, mappingTimeout: mappingTimeout
      )
    )
  )

proc parseReachabilityConfig(config: Libp2pConfig): Opt[ReachabilityConfig] =
  let scheduleInterval = optDurationMs(config.natReachabilityScheduleIntervalMs)
  if config.natReachabilityV1:
    return Opt.some(
      ReachabilityConfig(
        version: AutonatV1,
        scheduleInterval: scheduleInterval,
        v2ServiceConfig: Opt.none(AutonatV2ServiceConfig),
      )
    )
  if config.natReachabilityV2 or config.autonatV2:
    let v2ServiceConfig =
      if scheduleInterval.isSome():
        Opt.some(AutonatV2ServiceConfig.new(scheduleInterval = scheduleInterval))
      else:
        Opt.none(AutonatV2ServiceConfig)
    return Opt.some(
      ReachabilityConfig(
        version: AutonatV2,
        scheduleInterval: scheduleInterval,
        v2ServiceConfig: v2ServiceConfig,
      )
    )
  Opt.none(ReachabilityConfig)

proc parseHolePunchingConfig(config: Libp2pConfig): Opt[HolePunchingConfig] =
  if not config.natHolePunching:
    return Opt.none(HolePunchingConfig)
  Opt.some(
    HolePunchingConfig(
      maxNumRelays: max(1, config.natHolePunchingMaxNumRelays),
      onReservation: nil,
      scheduleInterval: optDurationMs(config.natHolePunchingScheduleIntervalMs),
    )
  )

proc validateNATConfig(config: Libp2pConfig): Result[void, string] =
  let
    portMappingModes = countEnabled(
      config.natPortMappingAuto,
      config.natPortMappingUpnp,
      config.natPortMappingNatPmp,
      config.natExplicitIp.len > 0,
    )
    wantsReachabilityV1 = config.natReachabilityV1
    wantsReachabilityV2 = config.natReachabilityV2 or config.autonatV2
    wantsReachability = wantsReachabilityV1 or wantsReachabilityV2

  if portMappingModes > 1:
    return err("NAT port mapping modes are mutually exclusive")
  if wantsReachabilityV1 and wantsReachabilityV2:
    return err("NAT reachability v1 and v2 are mutually exclusive")
  if wantsReachability and config.natHolePunching:
    return err(
      "NAT hole punching and reachability are mutually exclusive; " &
        "hole punching already runs AutoNAT v1"
    )
  if config.natReachabilityScheduleIntervalMs > 0 and not wantsReachability:
    return err(
      "natReachabilityScheduleIntervalMs requires natReachabilityV1, " &
        "natReachabilityV2, or autonatV2"
    )
  if not config.natHolePunching:
    if config.natHolePunchingMaxNumRelays > 0:
      return err("natHolePunchingMaxNumRelays requires natHolePunching")
    if config.natHolePunchingScheduleIntervalMs > 0:
      return err("natHolePunchingScheduleIntervalMs requires natHolePunching")
  ok()

proc parseNATConfig(config: Libp2pConfig): Result[Opt[NATConfig], string] =
  ?validateNATConfig(config)

  let nat = NATConfig(
    portMapping: ?parsePortMappingConfig(config),
    reachability: parseReachabilityConfig(config),
    holePunching: parseHolePunchingConfig(config),
  )

  if nat.portMapping.isNone() and nat.reachability.isNone() and nat.holePunching.isNone():
    ok(Opt.none(NATConfig))
  else:
    ok(Opt.some(nat))

func requireServiceDiscoveryMount(config: Libp2pConfig): Result[void, string] =
  if config.mountServiceDiscovery:
    return ok()
  if config.serviceDiscoveryMode != ServiceDiscoveryMode.Server or
      config.serviceDiscoveryDisableXprPublishing:
    return err("service discovery settings require mountServiceDiscovery")
  ok()

proc parse(config: Libp2pConfig): Result[ParsedConfig, string] =
  ?requireServiceDiscoveryMount(config)
  ok(
    ParsedConfig(
      dnsServers: ?resolveDnsServers(config.dnsResolver),
      addrs: ?parseMultiaddrs(config.addrs),
      transport: parseTransportConfig(config),
      privKey: ?parsePrivateKey(config.privKey),
      bootstrapNodes: ?parseBootstrapNodes(config.bootstrapNodes),
      maxConnections: config.maxConnections,
      maxIn: config.maxIn,
      maxOut: config.maxOut,
      maxConnsPerPeer: config.maxConnsPerPeer,
      circuitRelay: config.circuitRelay,
      circuitRelayClient: config.circuitRelayClient,
      autonat: config.autonat,
      nat: ?parseNATConfig(config),
      autonatV2Server: config.autonatV2Server,
      gossipsub: ?parseGossipsub(config.gossipsub),
      mountKad: config.mountKad,
      mountServiceDiscovery: config.mountServiceDiscovery,
      serviceDiscoveryMode: config.serviceDiscoveryMode,
      serviceDiscoveryDisableXprPublishing: config.serviceDiscoveryDisableXprPublishing,
    )
  )
