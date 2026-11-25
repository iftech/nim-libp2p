# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ./unittest

when defined(macosx):
  import chronos/transports/osnet
  import ../../libp2p/services/mdns/socketoptions

  let MacosMulticastFlag* {.importc: "IFF_MULTICAST", header: "<net/if.h>".}: cuint

  iterator ipv4Addresses(iface: NetworkInterface): InterfaceAddress {.raises: [].} =
    for address in iface.addresses:
      if address.host.family == AddressFamily.IPv4:
        yield address

proc openMdnsTestSender(
    callback: DatagramCallback
): Future[DatagramTransport] {.async: (raises: [CancelledError, TransportError]).} =
  when not defined(macosx):
    return newDatagramTransport(callback, local = initTAddress("127.0.0.1:0"))
  else:
    # Bind the source and select multicast egress on the same interface.
    for iface in getInterfaces():
      if iface.state != StatusUp or iface.ifType == IfSoftwareLoopback or
          (iface.flags and uint64(MacosMulticastFlag)) == 0:
        continue
      for address in iface.ipv4Addresses():
        let sender =
          try:
            newDatagramTransport(callback, local = address.host)
          except TransportError:
            continue
        var selected = address.host.address_v4
        let status = setSocketOption(
          toSocketHandle(sender.fd), ipv4Protocol, ipv4MulticastInterface, selected
        )
        var usable = false
        try:
          if status == 0:
            # An interface can accept IP_MULTICAST_IF without a usable route.
            await sender.sendTo(initTAddress("224.0.0.251:5353"), @[0'u8])
            usable = true
            return sender
        except TransportOsError as exc:
          if exc.code.int notin [EHOSTUNREACH.int, ENETUNREACH.int, EADDRNOTAVAIL.int]:
            raise exc
        finally:
          if not usable:
            await noCancel sender.closeWait()
    return nil

template newMdnsTestSender*(callback: DatagramCallback): DatagramTransport =
  block:
    let sender =
      try:
        await openMdnsTestSender(callback)
      except TransportError as exc:
        raiseAssert "Failed to open mDNS test sender: " & exc.msg
    if sender.isNil:
      checkpoint "No usable IPv4 multicast route for the mDNS test sender"
      skip()
      return
    sender

template requireMdnsMulticastRoute*(callback: DatagramCallback) =
  when defined(macosx):
    block:
      let probe = newMdnsTestSender(callback)
      await noCancel probe.closeWait()
