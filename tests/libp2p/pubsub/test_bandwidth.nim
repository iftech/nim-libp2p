# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/math
import chronos
import ../../../libp2p/protocols/pubsub/gossipsub/bandwidth
import ../../tools/[unittest]

suite "GossipSub bandwidth":
  test "update stays finite when the message arrives within the same millisecond":
    var ema = ExponentialMovingAverage.init()
    ema.update(Moment.now(), 40 * 1024)

    check:
      ema.value().classify() notin {fcInf, fcNegInf, fcNan}
      ema.value() > 0

  test "calculateReceiveTimeMs does not divide by a zero data rate":
    check:
      calculateReceiveTimeMs(40 * 1024, 0) == calculateReceiveTimeMs(40 * 1024, 1)
