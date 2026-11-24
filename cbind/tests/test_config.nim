# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import ffi

import std/[strformat, net]
import chronos
import unittest2

import ../../libp2p
import ../../libp2p/services/natservice
import ../../libp2p/[multiaddress, peerid]
import ../../libp2p/crypto/crypto
import ../../libp2p/nameresolving/dnsresolver
import ../../libp2p/protocols/pubsub/gossipsub
import ../../libp2p/protocols/service_discovery/types
import ../../libp2p/protocols/connectivity/autonatv2/service

type ConfigTest = ref object

# `{.ffiConst.}` in config.nim refuses to compile without a declared library.
declareLibrary("configtest", ConfigTest)

include "../libp2p/config"

type Case[T] = object
  name: string
  input: T
  want: string

func accepts[T](name: string, input: T): Case[T] =
  Case[T](name: name, input: input)

func rejects[T](name: string, input: T, want: string): Case[T] =
  Case[T](name: name, input: input, want: want)

template checkCases[T](cases: openArray[Case[T]], parseProc: untyped) =
  for c in cases:
    checkpoint c.name
    let res = parseProc(c.input)
    if c.want.len == 0:
      check res.isOk()
    else:
      check res.isErr()
      if res.isErr():
        check res.error == c.want

func mounted(cfg: GossipsubConfig): GossipsubConfig =
  var mountedCfg = cfg
  mountedCfg.mount = true
  mountedCfg

suite "cbind config":
  test "parse: service discovery settings":
    const needsMount = "service discovery settings require serviceDiscovery.mount"
    let cases = [
      accepts("defaults", Libp2pConfig()),
      rejects(
        "client mode without mount",
        Libp2pConfig(
          serviceDiscovery: ServiceDiscoveryConfig(mode: ServiceDiscoveryMode.Client)
        ),
        needsMount,
      ),
      rejects(
        "disableXprPublishing without mount",
        Libp2pConfig(
          serviceDiscovery: ServiceDiscoveryConfig(disableXprPublishing: true)
        ),
        needsMount,
      ),
      accepts(
        "client mode with mount",
        Libp2pConfig(
          serviceDiscovery:
            ServiceDiscoveryConfig(mount: true, mode: ServiceDiscoveryMode.Client)
        ),
      ),
      accepts(
        "disableXprPublishing with mount",
        Libp2pConfig(
          serviceDiscovery:
            ServiceDiscoveryConfig(mount: true, disableXprPublishing: true)
        ),
      ),
      accepts(
        "fReturn at the limit",
        Libp2pConfig(
          serviceDiscovery: ServiceDiscoveryConfig(mount: true, fReturn: MaxFReturn)
        ),
      ),
      rejects(
        "fReturn above the limit",
        Libp2pConfig(
          serviceDiscovery: ServiceDiscoveryConfig(mount: true, fReturn: MaxFReturn + 1)
        ),
        "fReturn exceeds the limit of " & $MaxFReturn & " (" & $(MaxFReturn + 1) & ")",
      ),
    ]
    checkCases(cases, parse)

  test "parse: addrs, bootstrap nodes, keys and dns":
    const
      validPeerId = "12D3KooWB1b3qZxWJanuhtseF3DmPggHCtG36KZ9ixkqHtdKH9fh"
      noSlash = "ip4/127.0.0.1/tcp/0"
      noSlashErr = "multiaddress: Invalid MultiAddress, must start with `/`"
    let rng = newRng()
    let validKey = KeyPair.random(rng).get().seckey.getBytes().get()
    let cases = [
      accepts("valid addr", Libp2pConfig(addrs: @["/ip4/127.0.0.1/tcp/0"])),
      rejects(
        "addr without leading slash",
        Libp2pConfig(addrs: @["ip4/127.0.0.1/tcp/0"]),
        "invalid multiaddress 'ip4/127.0.0.1/tcp/0': " &
          "multiaddress: Invalid MultiAddress, must start with `/`",
      ),
      rejects(
        "bad bootstrap peer id",
        Libp2pConfig(bootstrapNodes: @[BootstrapNode(peerId: "nope", multiaddrs: @[])]),
        "invalid bootstrap peer id: peerid: incorrect PeerId string",
      ),
      rejects(
        "bad private key",
        Libp2pConfig(privKey: @[1'u8, 2, 3]),
        "invalid private key: KeyError",
      ),
      rejects(
        "dnsResolver without port",
        Libp2pConfig(dnsResolver: "1.1.1.1"),
        "invalid dnsResolver address: Format is <address>:<port>!",
      ),
      accepts("dnsResolver with port", Libp2pConfig(dnsResolver: "1.1.1.1:53")),
      accepts("valid private key", Libp2pConfig(privKey: validKey)),
      accepts(
        "bootstrap node with valid peer id and addr",
        Libp2pConfig(
          bootstrapNodes:
            @[BootstrapNode(peerId: validPeerId, multiaddrs: @["/ip4/127.0.0.1/tcp/1"])]
        ),
      ),
      accepts(
        "bootstrap node without addrs",
        Libp2pConfig(
          bootstrapNodes: @[BootstrapNode(peerId: validPeerId, multiaddrs: @[])]
        ),
      ),
      rejects(
        "bad bootstrap addr",
        Libp2pConfig(
          bootstrapNodes: @[BootstrapNode(peerId: validPeerId, multiaddrs: @[noSlash])]
        ),
        "invalid multiaddress '" & noSlash & "': " & noSlashErr,
      ),
      rejects(
        "bad addr after a valid one",
        Libp2pConfig(addrs: @["/ip4/127.0.0.1/tcp/0", noSlash]),
        "invalid multiaddress '" & noSlash & "': " & noSlashErr,
      ),
    ]
    checkCases(cases, parse)

  test "parseGossipsub: limits":
    const needsMount = "gossipsub limits require gossipsub.mount"
    let cases = [
      accepts("defaults", GossipsubConfig()),
      rejects(
        "maxMessageSize without mount", GossipsubConfig(maxMessageSize: 1), needsMount
      ),
      rejects(
        "rate limit bytes without mount",
        GossipsubConfig(overheadRateLimit: RateLimitConfig(bytes: 1)),
        needsMount,
      ),
      rejects(
        "rate limit interval without mount",
        GossipsubConfig(overheadRateLimit: RateLimitConfig(intervalMs: 1)),
        needsMount,
      ),
      rejects(
        "disconnectPeerAboveRateLimit without mount",
        GossipsubConfig(disconnectPeerAboveRateLimit: true),
        needsMount,
      ),
      rejects(
        "negative maxMessageSize",
        GossipsubConfig(maxMessageSize: -1).mounted(),
        "maxMessageSize must be 0 or greater",
      ),
      accepts("maxMessageSize of one", GossipsubConfig(maxMessageSize: 1).mounted()),
      accepts(
        "maxMessageSize at the limit",
        GossipsubConfig(maxMessageSize: MaxGossipsubMessageSize).mounted(),
      ),
      rejects(
        "maxMessageSize above the limit",
        GossipsubConfig(maxMessageSize: MaxGossipsubMessageSize + 1).mounted(),
        "maxMessageSize exceeds the limit of " & $MaxGossipsubMessageSize & " bytes (" &
          $(MaxGossipsubMessageSize + 1) & ")",
      ),
      rejects(
        "rate limit bytes only",
        GossipsubConfig(overheadRateLimit: RateLimitConfig(bytes: 1)).mounted(),
        "overheadRateLimit.bytes requires overheadRateLimit.intervalMs",
      ),
      rejects(
        "rate limit interval only",
        GossipsubConfig(overheadRateLimit: RateLimitConfig(intervalMs: 1)).mounted(),
        "overheadRateLimit.intervalMs requires overheadRateLimit.bytes",
      ),
      accepts(
        "rate limit interval at the limit",
        GossipsubConfig(
          overheadRateLimit:
            RateLimitConfig(bytes: 1, intervalMs: MaxOverheadRateLimitIntervalMs)
        ).mounted(),
      ),
      rejects(
        "rate limit interval above the limit",
        GossipsubConfig(
          overheadRateLimit:
            RateLimitConfig(bytes: 1, intervalMs: MaxOverheadRateLimitIntervalMs + 1)
        ).mounted(),
        "overheadRateLimit.intervalMs exceeds the limit of " &
          $MaxOverheadRateLimitIntervalMs & " (" & $(MaxOverheadRateLimitIntervalMs + 1) &
          ")",
      ),
      rejects(
        "rate limit interval above the limit without bytes",
        GossipsubConfig(
          overheadRateLimit:
            RateLimitConfig(intervalMs: MaxOverheadRateLimitIntervalMs + 1)
        ).mounted(),
        "overheadRateLimit.intervalMs exceeds the limit of " &
          $MaxOverheadRateLimitIntervalMs & " (" & $(MaxOverheadRateLimitIntervalMs + 1) &
          ")",
      ),
      rejects(
        "negative rate limit bytes without interval",
        GossipsubConfig(overheadRateLimit: RateLimitConfig(bytes: -1)).mounted(),
        "overheadRateLimit.bytes requires overheadRateLimit.intervalMs",
      ),
      rejects(
        "negative rate limit interval without bytes",
        GossipsubConfig(overheadRateLimit: RateLimitConfig(intervalMs: -1)).mounted(),
        "overheadRateLimit.intervalMs requires overheadRateLimit.bytes",
      ),
      accepts(
        "rate limit with both fields",
        GossipsubConfig(overheadRateLimit: RateLimitConfig(bytes: 1, intervalMs: 1)).mounted(),
      ),
      accepts(
        "mounted with triggerSelf and disconnect",
        GossipsubConfig(triggerSelf: true, disconnectPeerAboveRateLimit: true).mounted(),
      ),
    ]
    checkCases(cases, parseGossipsub)

  test "parseGossipsub: decoded values":
    let defaults = parseGossipsub(GossipsubConfig().mounted()).get()
    check:
      defaults.maxMessageSize == DefaultPubSubMaxMessageSize
      defaults.overheadRateLimit.isNone()

    let limited = parseGossipsub(
        GossipsubConfig(overheadRateLimit: RateLimitConfig(bytes: 10, intervalMs: 20)).mounted()
      )
      .get()
    check limited.overheadRateLimit ==
      Opt.some(RateLimit(bytes: 10, interval: chronos.milliseconds(20)))

  test "parseNATConfig: exclusive options":
    const
      exclusiveMappings = "NAT port mapping modes are mutually exclusive"
      exclusiveReachability = "NAT reachability v1 and v2 are mutually exclusive"
      exclusiveHolePunching =
        "NAT hole punching and reachability are mutually exclusive; " &
        "hole punching already runs AutoNAT v1"
    let cases = [
      accepts("defaults", Libp2pConfig()),
      rejects(
        "auto and upnp",
        Libp2pConfig(natPortMappingAuto: true, natPortMappingUpnp: true),
        exclusiveMappings,
      ),
      rejects(
        "natpmp and explicit ip",
        Libp2pConfig(natPortMappingNatPmp: true, natExplicitIp: "1.2.3.4"),
        exclusiveMappings,
      ),
      rejects(
        "reachability v1 and v2",
        Libp2pConfig(natReachabilityV1: true, natReachabilityV2: true),
        exclusiveReachability,
      ),
      rejects(
        "reachability v1 and autonatV2 alias",
        Libp2pConfig(natReachabilityV1: true, autonatV2: true),
        exclusiveReachability,
      ),
      rejects(
        "reachability and hole punching",
        Libp2pConfig(natReachabilityV2: true, natHolePunching: true),
        exclusiveHolePunching,
      ),
      rejects(
        "reachability interval without reachability",
        Libp2pConfig(natReachabilityScheduleIntervalMs: 1),
        "natReachabilityScheduleIntervalMs requires natReachabilityV1, " &
          "natReachabilityV2, or autonatV2",
      ),
      rejects(
        "relay count without hole punching",
        Libp2pConfig(natHolePunchingMaxNumRelays: 1),
        "natHolePunchingMaxNumRelays requires natHolePunching",
      ),
      rejects(
        "hole punching interval without hole punching",
        Libp2pConfig(natHolePunchingScheduleIntervalMs: 1),
        "natHolePunchingScheduleIntervalMs requires natHolePunching",
      ),
      rejects(
        "bad explicit ip",
        Libp2pConfig(natExplicitIp: "nope"),
        "invalid natExplicitIp: " &
          "Invalid IP Address. Address contains an invalid character",
      ),
      rejects(
        "upnp and natpmp",
        Libp2pConfig(natPortMappingUpnp: true, natPortMappingNatPmp: true),
        exclusiveMappings,
      ),
      rejects(
        "auto and explicit ip",
        Libp2pConfig(natPortMappingAuto: true, natExplicitIp: "1.2.3.4"),
        exclusiveMappings,
      ),
      rejects(
        "reachability v1 and hole punching",
        Libp2pConfig(natReachabilityV1: true, natHolePunching: true),
        exclusiveHolePunching,
      ),
      rejects(
        "autonatV2 alias and hole punching",
        Libp2pConfig(autonatV2: true, natHolePunching: true),
        exclusiveHolePunching,
      ),
      accepts("auto port mapping", Libp2pConfig(natPortMappingAuto: true)),
      accepts("upnp port mapping", Libp2pConfig(natPortMappingUpnp: true)),
      accepts("natpmp port mapping", Libp2pConfig(natPortMappingNatPmp: true)),
      accepts("explicit ipv4", Libp2pConfig(natExplicitIp: "1.2.3.4")),
      accepts("explicit ipv6", Libp2pConfig(natExplicitIp: "::1")),
      accepts(
        "port mapping with reachability",
        Libp2pConfig(natPortMappingAuto: true, natReachabilityV1: true),
      ),
      accepts("reachability v1", Libp2pConfig(natReachabilityV1: true)),
      accepts("reachability v2", Libp2pConfig(natReachabilityV2: true)),
      accepts("autonatV2 alias", Libp2pConfig(autonatV2: true)),
      accepts(
        "reachability v2 and autonatV2 alias",
        Libp2pConfig(natReachabilityV2: true, autonatV2: true),
      ),
      accepts(
        "reachability v1 with interval",
        Libp2pConfig(natReachabilityV1: true, natReachabilityScheduleIntervalMs: 1),
      ),
      accepts(
        "autonatV2 alias with interval",
        Libp2pConfig(autonatV2: true, natReachabilityScheduleIntervalMs: 1),
      ),
      accepts(
        "zero reachability interval without reachability",
        Libp2pConfig(natReachabilityScheduleIntervalMs: 0),
      ),
      accepts(
        "negative reachability interval without reachability",
        Libp2pConfig(natReachabilityScheduleIntervalMs: -1),
      ),
      accepts(
        "zero relay count without hole punching",
        Libp2pConfig(natHolePunchingMaxNumRelays: 0),
      ),
      accepts(
        "negative relay count without hole punching",
        Libp2pConfig(natHolePunchingMaxNumRelays: -1),
      ),
      accepts(
        "negative hole punching interval without hole punching",
        Libp2pConfig(natHolePunchingScheduleIntervalMs: -1),
      ),
      accepts("hole punching alone", Libp2pConfig(natHolePunching: true)),
      accepts(
        "hole punching with its options",
        Libp2pConfig(
          natHolePunching: true,
          natHolePunchingMaxNumRelays: 2,
          natHolePunchingScheduleIntervalMs: 1000,
        ),
      ),
    ]
    checkCases(cases, parseNATConfig)

  test "parseNATConfig: decoded values":
    check parseNATConfig(Libp2pConfig()).get().isNone()

    let clamped = parseNATConfig(
        Libp2pConfig(natHolePunching: true, natHolePunchingMaxNumRelays: 0)
      )
      .get()
      .get()
    check clamped.holePunching.get().maxNumRelays == 1

    let explicit = parseNATConfig(
        Libp2pConfig(natHolePunching: true, natHolePunchingMaxNumRelays: 5)
      )
      .get()
      .get()
    check explicit.holePunching.get().maxNumRelays == 5

    let v2 = parseNATConfig(
        Libp2pConfig(autonatV2: true, natReachabilityScheduleIntervalMs: 7)
      )
      .get()
      .get()
    check:
      v2.reachability.get().version == AutonatV2
      v2.reachability.get().scheduleInterval == Opt.some(chronos.milliseconds(7))
