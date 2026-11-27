# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../libp2p/peerid
import ./[unittest, crypto]

suite "PeerId testing tools":
  test "random returns a valid peer id":
    check PeerId.random().validate()

  test "random returns the requested number of valid peer ids":
    let peers = PeerId.random(3)
    check peers.len == 3
    for peer in peers:
      check peer.validate()

  test "random accepts an empty batch":
    check PeerId.random(0).len == 0
