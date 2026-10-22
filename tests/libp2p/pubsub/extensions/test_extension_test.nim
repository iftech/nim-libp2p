# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../../libp2p/peerid
import
  ../../../../libp2p/protocols/pubsub/
    [gossipsub/extension_test, gossipsub/extensions_types]
import ../../../tools/[unittest, crypto]

suite "GossipSub Extensions :: Test Extension":
  test "isSupported":
    let ext = TestExtension.new()
    check:
      ext.isSupported(PeerExtensions()) == false
      ext.isSupported(PeerExtensions(testExtension: true)) == true

  test "config validation":
    expect AssertionDefect:
      discard TestExtension.new(TestExtensionConfig())

  test "onNegotiated callback called":
    var negotiatedPeers: seq[PeerId]
    proc onNegotiatedCb(peer: PeerId) {.gcsafe, raises: [].} =
      negotiatedPeers.add(peer)

    let ext = TestExtension.new(TestExtensionConfig(onNegotiated: onNegotiatedCb))

    let peerId1 = PeerId.random()
    ext.onNegotiated(peerId1)
    check negotiatedPeers == @[peerId1]

    let peerId2 = PeerId.random()
    ext.onNegotiated(peerId2)
    check negotiatedPeers == @[peerId1, peerId2]
