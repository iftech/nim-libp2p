# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, chronicles
import ../switch

export NetworkInterfaceProvider, getAddresses

logScope:
  topics = "libp2p wildcard-addresses"

type WildcardAddressResolverService* = ref object of Service
  ## Hands the `AddressManager` the interfaces it expands a wildcard listen
  ## address ("0.0.0.0" for IPv4, "::" for IPv6) onto.
  networkInterfaceProvider: NetworkInterfaceProvider

proc new*(
    T: typedesc[WildcardAddressResolverService],
    networkInterfaceProvider: NetworkInterfaceProvider = getAddresses,
): T =
  T(networkInterfaceProvider: networkInterfaceProvider)

method start*(
    self: WildcardAddressResolverService, switch: Switch
) {.async: (raises: [CancelledError, LPError]).} =
  switch.addressManager.networkInterfaceProvider = self.networkInterfaceProvider
  await switch.peerInfo.update()
  info "Wildcard address resolver service started"

method stop*(
    self: WildcardAddressResolverService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  info "Stopping WildcardAddressResolverService"
  switch.addressManager.networkInterfaceProvider = nil
  await switch.peerInfo.update()
