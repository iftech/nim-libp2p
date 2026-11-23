# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./[unittest, futures]

suite "Test future helpers":
  asyncTest "waitForCancellation stays pending and propagates cancellation":
    var cleanedUp = false
    proc wait() {.async: (raises: [CancelledError]).} =
      try:
        await waitForCancellation()
      finally:
        cleanedUp = true

    let pending = wait()
    await sleepAsync(1.milliseconds)
    check not pending.finished()
    await pending.cancelAndWait()
    check pending.cancelled()
    check cleanedUp

  asyncTest "allFuturesRaising propagates a cancelled child":
    let child = waitForCancellation()
    await child.cancelAndWait()
    expect CancelledError:
      await allFuturesRaising(child)
