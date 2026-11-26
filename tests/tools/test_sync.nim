# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ./[unittest, sync]

suite "WaitGroup":
  teardown:
    checkTrackers()

  asyncTest "negative count":
    expect AssertionDefect:
      discard newWaitGroup(-1)

  asyncTest "zero count - done() has no effect":
    let wg = newWaitGroup(0)
    check wg.wait().finished

    wg.done()
    check wg.wait().finished

  asyncTest "countdown to finish":
    let wg = newWaitGroup(3)

    wg.done()
    check not wg.wait().finished
    wg.done()
    check not wg.wait().finished
    wg.done()
    check wg.wait().finished

  asyncTest "async countdown to finish":
    const count = 30
    let wg = newWaitGroup(count)

    proc countDown() {.async.} =
      await sleepAsync(10.millis)
      wg.done()

    for i in 0 ..< count:
      asyncSpawn countDown()

    check not wg.wait().finished
    check await wg.wait().withTimeout(200.millis)

  asyncTest "wait with interval":
    let wg = newWaitGroup(1)
    expect AsyncTimeoutError:
      await wg.wait(10.millis)

  asyncTest "canceling wait() does not cancel underlying future":
    let wg = newWaitGroup(1)
    discard await wg.wait().withTimeout(1.millis)

    check not wg.wait().finished
