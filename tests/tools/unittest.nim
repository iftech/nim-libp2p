# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, unittest2, std/[macros, strutils]
import ./trackers

export checkTrackers # TODO: maybe consider importing it on demand?
export unittest2 except suite

const
  asyncTestTimeoutDefault* = 15.seconds
  asyncTestCleanupTimeout = 1.seconds

var
  suiteAsyncTestTimeout {.threadvar.}: Duration
  hasSuiteAsyncTestTimeout {.threadvar.}: bool

template withSuiteAsyncTestTimeout(timeout: untyped, body: untyped): untyped =
  let previousTimeout = suiteAsyncTestTimeout
  let hadPreviousTimeout = hasSuiteAsyncTestTimeout
  suiteAsyncTestTimeout = timeout
  hasSuiteAsyncTestTimeout = true
  defer:
    suiteAsyncTestTimeout = previousTimeout
    hasSuiteAsyncTestTimeout = hadPreviousTimeout
  body

## suite wraps unittest2.suite in a proc to avoid issue with too many global variables
## See https://github.com/nim-lang/Nim/issues/8500
template suite*(name: string, timeout: untyped, body: untyped): untyped =
  block:
    proc testSuite() =
      withSuiteAsyncTestTimeout(timeout):
        unittest2.suite name:
          body

    testSuite()

template suite*(name: string, body: untyped): untyped =
  block:
    proc testSuite() =
      withSuiteAsyncTestTimeout(asyncTestTimeoutDefault):
        unittest2.suite name:
          body

    testSuite()

template asyncTeardown*(body: untyped): untyped =
  teardown:
    waitFor(
      (
        proc() {.async.} =
          body
      )()
    )

template asyncSetup*(body: untyped): untyped =
  setup:
    waitFor(
      (
        proc() {.async.} =
          body
      )()
    )

template asyncTest*(name: string, body: untyped): untyped =
  asyncTest(
    name,
    if hasSuiteAsyncTestTimeout: suiteAsyncTestTimeout else: asyncTestTimeoutDefault,
    body,
  )

# `timeout` stays untyped: a typed overload semchecks every plain asyncTest body.
template asyncTest*(name: string, timeout: untyped, body: untyped): untyped =
  test name:
    let testFut = (
      proc() {.async.} =
        body
    )()
    try:
      waitFor testFut.wait(timeout)
    except AsyncTimeoutError as exc:
      checkpoint "[TEST TIMEOUT] Test body exceeded its configured timeout of " &
        $timeout & "."
      try:
        waitFor testFut.cancelAndWait().wait(asyncTestCleanupTimeout)
      except AsyncTimeoutError:
        checkpoint "[TIMEOUT] Timed out waiting for the test body to cancel."
      raise exc

template isErrOf*(res: untyped, T: typedesc): bool =
  res.isErr() and res.error of T

template isParentErrOf*(res: untyped, T: typedesc): bool =
  res.isErr() and res.error.parent of T

macro expectMsgContains*(exception: typed, msg: typed, body: untyped): untyped =
  ## Test that `body` raises `exception` and its message contains `msg`.
  runnableExamples:
    proc fails() =
      raise newException(ValueError, "invalid value: 42")

    expectMsgContains ValueError, "invalid value":
      fails()

  let lineInfo = newLit(body.lineInfo)
  let containsSym = bindSym("contains", brForceOpen)

  quote:
    try:
      `body`
      checkpoint(`lineInfo` & ": Expect Failed, no exception was thrown.")
      fail()
    except `exception` as exc:
      let expectedMsg = `msg`
      if not `containsSym`(exc.msg, expectedMsg):
        checkpoint(
          `lineInfo` & ": Expect Failed, expected message to contain \"" & expectedMsg &
            "\", got \"" & exc.msg & "\"."
        )
        fail()
    except CatchableError as exc:
      checkpoint(
        `lineInfo` & ": Expect Failed, unexpected " & $exc.name & " (" & exc.msg &
          ") was thrown.\n" & exc.getStackTrace()
      )
      fail()

macro expectMsg*(exception: typed, msg: typed, body: untyped): untyped =
  ## Test that `body` raises `exception` and its message equals `msg`.
  runnableExamples:
    proc fails() =
      raise newException(ValueError, "invalid value")

    expectMsg ValueError, "invalid value":
      fails()

  let lineInfo = newLit(body.lineInfo)

  quote:
    try:
      `body`
      checkpoint(`lineInfo` & ": Expect Failed, no exception was thrown.")
      fail()
    except `exception` as exc:
      let expectedMsg = `msg`
      if exc.msg != expectedMsg:
        checkpoint(
          `lineInfo` & ": Expect Failed, expected message \"" & expectedMsg &
            "\", got \"" & exc.msg & "\"."
        )
        fail()
    except CatchableError as exc:
      checkpoint(
        `lineInfo` & ": Expect Failed, unexpected " & $exc.name & " (" & exc.msg &
          ") was thrown.\n" & exc.getStackTrace()
      )
      fail()

proc buildAndExpr(n: NimNode): NimNode =
  # Helper proc to recursively build a combined boolean expression

  if n.kind == nnkStmtList and n.len > 0:
    var combinedExpr = n[0] # Start with the first expression
    for i in 1 ..< n.len:
      # Combine the current expression with the next using 'and'
      combinedExpr = newCall("and", combinedExpr, n[i])
    return combinedExpr
  else:
    return n

const
  checkTimeoutDefault: Duration = 5.seconds
  sleepIntervalDefault: Duration = 50.milliseconds

macro checkUntilTimeoutCustom*(
    timeout: Duration, sleepInterval: Duration, code: untyped
): untyped =
  ## Periodically checks a given condition until it is true or a timeout occurs.
  ##
  ## `code`: untyped - A condition expression that should eventually evaluate to true.
  ## `timeout`: Duration - The maximum duration to wait for the condition to be true.
  ##
  ## Examples:
  ##   ```nim
  ##   # Example 1:
  ##   asyncTest "checkUntilTimeoutCustom should pass if the condition is true":
  ##     let a = 2
  ##     let b = 2
  ##     checkUntilTimeoutCustom(2.seconds):
  ##       a == b
  ##
  ##   # Example 2: Multiple conditions
  ##   asyncTest "checkUntilTimeoutCustom should pass if the conditions are true":
  ##     let a = 2
  ##     let b = 2
  ##     checkUntilTimeoutCustom(5.seconds)::
  ##       a == b
  ##       a == 2
  ##       b == 1
  ##   ```

  # Build the combined expression
  let combinedBoolExpr = buildAndExpr(code)

  quote:
    proc checkExpiringInternal(): Future[void] {.gensym, async.} =
      let start = Moment.now()
      while true:
        if Moment.now() > (start + `timeout`):
          checkpoint(
            "[TIMEOUT] Timeout was reached and the conditions were not true. Check if the code is working as " &
              "expected or consider increasing the timeout param."
          )
          check `code`
          return
        else:
          if `combinedBoolExpr`:
            return
          else:
            await sleepAsync(`sleepInterval`)

    await checkExpiringInternal()

macro checkUntilTimeout*(code: untyped): untyped =
  ## Same as `checkUntilTimeoutCustom` but with a default timeout of 5s with 50ms interval.
  ##
  ## Examples:
  ##   ```nim
  ##   # Example 1:
  ##   asyncTest "checkUntilTimeout should pass if the condition is true":
  ##     let a = 2
  ##     let b = 2
  ##     checkUntilTimeout:
  ##       a == b
  ##
  ##   # Example 2: Multiple conditions
  ##   asyncTest "checkUntilTimeout should pass if the conditions are true":
  ##     let a = 2
  ##     let b = 2
  ##     checkUntilTimeout:
  ##       a == b
  ##       a == 2
  ##       b == 1
  ##   ```
  quote:
    checkUntilTimeoutCustom(checkTimeoutDefault, sleepIntervalDefault, `code`)

template finalCheckTrackers*(): untyped =
  # finalCheckTrackers is a utility used for performing a final tracker check 
  # outside the test suite. It should be called at the very end of a test file 
  # (typically containing a bundle of tests) to ensure that no tests have left 
  # any trackers open.

  unittest2.suite "Final checkTrackers":
    test "test":
      # checkTrackers must be executed within a suite or test. otherwise, 
      # its output won't appear on stdout.
      checkTrackers()
