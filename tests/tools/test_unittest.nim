# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
from std/exitprocs import nil
import ./[unittest]

type
  TestException = object of CatchableError
  UnexpectedTestException = object of CatchableError

proc raiseTestException(msg: string) =
  raise newException(TestException, msg)

proc raiseUnexpectedTestException() =
  raise newException(UnexpectedTestException, "unexpected exception")

template generatedAsyncTimeoutTest(cleanupRan: untyped) =
  asyncTest "fails when the generated test exceeds the suite timeout":
    defer:
      cleanupRan = true
    await sleepAsync(100.milliseconds)

suite "exception message helpers":
  test "expectMsgContains accepts an exception message containing the expected text":
    expectMsgContains TestException, "expected text":
      raiseTestException("some expected text in the message")

  test "expectMsg accepts an exception message equal to the expected text":
    expectMsg TestException, "the expected text":
      raiseTestException("the expected text")

suite "exception message helpers - failed":
  var programResultBefore {.threadvar.}: int

  setup:
    programResultBefore = exitProcs.getProgramResult()

  teardown:
    require testStatusIMPL == TestStatus.Failed
    testStatusIMPL = TestStatus.OK
    if programResultBefore == QuitSuccess:
      # If before our test the program result was not success, leave it as failed.
      exitProcs.setProgramResult(QuitSuccess)

  test "expectMsgContains fails when no exception is thrown":
    expectMsgContains TestException, "expected text":
      discard

  test "expectMsgContains fails for an unexpected exception":
    expectMsgContains TestException, "expected text":
      raiseUnexpectedTestException()

  test "expectMsgContains fails when the message does not contain the expected text":
    expectMsgContains TestException, "expected text":
      raiseTestException("different text")

  test "expectMsg fails when no exception is thrown":
    expectMsg TestException, "expected text":
      discard

  test "expectMsg fails for an unexpected exception":
    expectMsg TestException, "expected text":
      raiseUnexpectedTestException()

  test "expectMsg fails when the message differs from the expected text":
    expectMsg TestException, "expected text":
      raiseTestException("different text")

suite "checkUntilTimeout helpers":
  asyncTest "checkUntilTimeout should pass if the condition is true":
    let a = 2
    let b = 2
    checkUntilTimeout:
      a == b

  asyncTest "checkUntilTimeout should pass if the conditions are true":
    let a = 2
    let b = 2
    checkUntilTimeout:
      a == b
      a == 2
      b == 2

  asyncTest "checkUntilTimeout should pass if condition becomes true after time":
    var a = 1
    let b = 2
    proc makeConditionTrueLater() {.async.} =
      await sleepAsync(50.milliseconds)
      a = 2

    asyncSpawn makeConditionTrueLater()
    checkUntilTimeout:
      a == b

  asyncTest "checkUntilTimeoutCustom should pass when the condition is true":
    let a = 2
    let b = 2
    checkUntilTimeoutCustom(2.seconds, 100.milliseconds):
      a == b

  asyncTest "checkUntilTimeoutCustom should pass when the conditions are true":
    let a = 2
    let b = 2
    checkUntilTimeoutCustom(5.seconds, 100.milliseconds):
      a == b
      a == 2
      b == 2

  asyncTest "checkUntilTimeoutCustom should pass if condition becomes true after time":
    var a = 1
    let b = 2
    proc makeConditionTrueLater() {.async.} =
      await sleepAsync(50.milliseconds)
      a = 2

    asyncSpawn makeConditionTrueLater()
    checkUntilTimeoutCustom(200.milliseconds, 10.milliseconds):
      a == b

suite "asyncTest suite timeout", timeout = 100.milliseconds:
  asyncTest "uses the suite timeout":
    await sleepAsync(10.milliseconds)

  asyncTest "allows a per-test timeout override", timeout = 1000.milliseconds:
    await sleepAsync(200.milliseconds)

suite "asyncTest suite timeout - failed", timeout = 50.milliseconds:
  var programResultBefore {.threadvar.}: int
  var cleanupRan {.threadvar.}: bool

  setup:
    programResultBefore = exitProcs.getProgramResult()
    cleanupRan = false

  teardown:
    check cleanupRan
    require testStatusIMPL == TestStatus.Failed
    testStatusIMPL = TestStatus.OK
    if programResultBefore == QuitSuccess:
      exitProcs.setProgramResult(QuitSuccess)

  generatedAsyncTimeoutTest(cleanupRan)

suite "checkUntilTimeout helpers - failed":
  var programResultBefore {.threadvar.}: int

  setup:
    programResultBefore = exitProcs.getProgramResult()

  teardown:
    require testStatusIMPL == TestStatus.Failed
    testStatusIMPL = TestStatus.OK
    if programResultBefore == QuitSuccess:
      # if before out test program result was not success, leave it as failed
      exitProcs.setProgramResult(QuitSuccess)

  asyncTest "checkUntilTimeoutCustom should timeout if condition is never true":
    checkUntilTimeoutCustom(100.milliseconds, 10.milliseconds):
      false

suite "checkUntilTimeout helpers with block":
  asyncTest "checkUntilTimeout should pass after few attempts":
    let a = 2
    var b = 0

    checkUntilTimeout:
      block:
        b.inc
        a == b

    # final check ensures that checkUntilTimeout is actually called
    check:
      a == b

  asyncTest "checkUntilTimeout should pass after few attempts: multi condition":
    let goal1 = 2
    let goal2 = 4
    var val1 = 0
    var val2 = 0

    checkUntilTimeout:
      block:
        val1.inc
        val2.inc
        val2.inc
        val1 == goal1 and val2 == goal2

    # final check ensures that checkUntilTimeout is actually called
    check:
      val1 == goal1
      val2 == goal2
