# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos

when defined(macosx):
  import chronos/transports/osnet
  import ../../libp2p/services/mdns/socketoptions

  let MacosMulticastFlag* {.importc: "IFF_MULTICAST", header: "<net/if.h>".}: cuint

proc newMdnsTestSender*(callback: DatagramCallback): DatagramTransport =
  when defined(macosx):
    # Bind the source and select multicast egress on the same interface.
    for iface in getInterfaces():
      if iface.state != StatusUp or iface.ifType == IfSoftwareLoopback or
          (iface.flags and uint64(MacosMulticastFlag)) == 0:
        continue
      for address in iface.addresses:
        if address.host.family == AddressFamily.IPv4:
          let sender = newDatagramTransport(callback, local = address.host)
          var selected = address.host.address_v4
          let status = setSocketOption(
            toSocketHandle(sender.fd), ipv4Protocol, ipv4MulticastInterface, selected
          )
          if status == 0:
            return sender
          sender.close()
    raise
      newException(TransportError, "No usable IPv4 multicast interface for mDNS test")
  else:
    return newDatagramTransport(callback, local = initTAddress("127.0.0.1:0"))
