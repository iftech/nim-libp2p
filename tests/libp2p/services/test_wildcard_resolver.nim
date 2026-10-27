# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, metrics
import
  ../../../libp2p/
    [builders, switch, services/wildcardresolverservice, multiaddress, multicodec]
import ../../tools/[unittest, multiaddress, switch_builder]

proc getAddressesMock(
    addrFamily: AddressFamily
): seq[InterfaceAddress] {.gcsafe, raises: [].} =
  try:
    if addrFamily == AddressFamily.IPv4:
      return @[
        InterfaceAddress.init(initTAddress("127.0.0.1:0"), 8),
        InterfaceAddress.init(initTAddress("192.168.1.22:0"), 24),
      ]
    else:
      return @[
        InterfaceAddress.init(initTAddress("::1:0"), 8),
        InterfaceAddress.init(initTAddress("fe80::1:0"), 64),
      ]
  except TransportAddressError as e:
    echo "Error: " & $e.msg
    fail()

proc createSwitch(addrs: seq[MultiAddress]): Switch =
  return makeStandardSwitchBuilder(addrs).withWildcardResolver(false).build()

proc startResolverSwitch(
    switch: Switch, service: WildcardAddressResolverService
) {.async.} =
  await switch.start()
  await service.start(switch)

proc stopResolverSwitch(
    switch: Switch, service: WildcardAddressResolverService
) {.async.} =
  try:
    await service.stop(switch)
  finally:
    await switch.stop()

suite "WildcardAddressResolverService":
  teardown:
    checkTrackers()

  asyncTest "WildcardAddressResolverService must resolve wildcard addresses and stop doing so when stopped":
    let svc =
      WildcardAddressResolverService.new(networkInterfaceProvider = getAddressesMock)
    let switch = createSwitch(
      @[ma("/ip4/127.0.0.1/tcp/0/"), ma("/ip4/0.0.0.0/tcp/0/"), ma("/ip6/::/tcp/0/")]
    )
    await startResolverSwitch(switch, svc)
    let tcpIp4Locahost = switch.peerInfo.addrs[0][multiCodec("tcp")].get
    let tcpIp4Wildcard = switch.peerInfo.addrs[1][multiCodec("tcp")].get
    let tcpIp6 = switch.peerInfo.addrs[3][multiCodec("tcp")].get # tcp port for ip6

    check switch.peerInfo.addrs ==
      @[
        ma("/ip4/127.0.0.1" & $tcpIp4Locahost),
        ma("/ip4/127.0.0.1" & $tcpIp4Wildcard),
        ma("/ip4/192.168.1.22" & $tcpIp4Wildcard),
        ma("/ip6/::1" & $tcpIp6),
        ma("/ip6/fe80::1" & $tcpIp6),
        # IPv6 dual stack
        ma("/ip4/127.0.0.1" & $tcpIp6),
        ma("/ip4/192.168.1.22" & $tcpIp6),
      ]
    await stopResolverSwitch(switch, svc)
    check switch.peerInfo.addrs ==
      @[
        ma("/ip4/127.0.0.1" & $tcpIp4Locahost),
        ma("/ip4/0.0.0.0" & $tcpIp4Wildcard),
        ma("/ip6/::" & $tcpIp6),
      ]
