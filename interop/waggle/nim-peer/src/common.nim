# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/strutils
import chronos
import ../../../../libp2p/[builders, protocols/waggle]

type InteropPeer* = ref object
  peer*: PeerId
  switch*: Switch
  address: MultiAddress
  disconnected*: Future[void].Raising([CancelledError])
  onPeerLeft: PeerEventHandler

proc newInteropPeer*(address: string): InteropPeer =
  let
    parts = address.rsplit("/p2p/", maxsplit = 1)
    random = newRng()
    switch = SwitchBuilder
      .new()
      .withRng(random)
      .withAddress(MultiAddress.init("/ip4/127.0.0.1/tcp/0").get())
      .withTcpTransport()
      .withYamux()
      .withNoise()
      .build()
    client = InteropPeer(
      peer: PeerId.init(parts[1]).get(),
      address: MultiAddress.init(parts[0]).get(),
      switch: switch,
      disconnected: Future[void].Raising([CancelledError]).init(),
    )
  client.onPeerLeft = proc(
      remote: PeerId, event: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    if remote == client.peer and not client.disconnected.finished:
      client.disconnected.complete()

  switch.addPeerEventHandler(client.onPeerLeft, PeerEventKind.Left)
  client

proc mountWaggle*(
    client: InteropPeer, onEvent: WaggleEventHandler, config = WaggleConfig()
): Waggle =
  let waggle = Waggle.new(
    switch = client.switch, rng = client.switch.rng, onEvent = onEvent, config = config
  )
  client.switch.mount(waggle)
  waggle

proc connect*(client: InteropPeer) {.async.} =
  await client.switch.connect(client.peer, @[client.address])

proc stop*(client: InteropPeer) {.async.} =
  client.switch.removePeerEventHandler(client.onPeerLeft, PeerEventKind.Left)
  client.onPeerLeft = nil
  await client.switch.stop()
