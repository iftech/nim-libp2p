# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

# MacOs has some nasty jitter when sleeping
# (up to 7 ms), so we skip test there
when not defined(macosx):
  import chronos
  import ../../../libp2p/utils/heartbeat
  import ../../tools/[unittest]

  suite "Heartbeat":
    asyncTest "simple heartbeat":
      var i = 0
      proc t() {.async.} =
        heartbeat "shouldn't see this", 50.milliseconds:
          i.inc()

      let start = Moment.now()
      let hb = t()
      checkUntilTimeoutCustom(5.seconds, 5.milliseconds):
        i >= 10
      let elapsed = Moment.now() - start
      await hb.cancelAndWait()

      # 10 ticks span 9 intervals; a stalled runner only makes this later
      check elapsed >= 400.milliseconds

    asyncTest "change heartbeat period on the fly":
      var i = 0
      proc t() {.async.} =
        var period = 30.milliseconds
        heartbeat "shouldn't see this", period:
          i.inc()
          if i >= 4:
            period = 75.milliseconds

      let start = Moment.now()
      let hb = t()
      checkUntilTimeoutCustom(5.seconds, 5.milliseconds):
        i >= 9
      let elapsed = Moment.now() - start
      await hb.cancelAndWait()

      # 9th tick is due at 465 ms, or at 240 ms if the period stays 30 ms
      check elapsed >= 450.milliseconds

    asyncTest "catch up on slow heartbeat":
      var i = 0
      proc t() {.async.} =
        heartbeat "this is normal", 30.milliseconds:
          if i < 3:
            await sleepAsync(150.milliseconds)
          i.inc()

      let hb = t()
      await sleepAsync(900.milliseconds)
      await hb.cancelAndWait()
      # 3x (150ms heartbeat + 30ms interval) = 540ms
      # 360ms remaining, / 30ms = 12x
      # total 15
      # allow extra slack for timer jitter/scheduling delays in CI
      check i in 13 .. 18

    asyncTest "heartbeat sleep first":
      var i = 0
      proc t() {.async.} =
        heartbeat "shouldn't see this", 500.milliseconds, true:
          i.inc()

      let hb = t()
      await sleepAsync(100.milliseconds)
      check i == 0

      await sleepAsync(500.milliseconds)
      await hb.cancelAndWait()
      check i == 1
