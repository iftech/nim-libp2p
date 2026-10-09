# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/strformat
import ../../libp2p/[errors, results]
import ../tools/unittest

type DemoError = object of LPError

type DemoResult[T] = Result[T, LPResultError]

const
  NotEnoughMemory = "not enough memory"
  PeerGone = "peer gone"

proc reserve(missingMb: int): DemoResult[void] =
  if missingMb > 0:
    return err(fmt"missing: {missingMb}MB", NotEnoughMemory)
  ok()

proc errorOf(cause: string, detail: string): LPResultError =
  proc fail(): DemoResult[void] =
    err(detail, cause)

  fail().error

proc errorOf(cause: string): LPResultError =
  DemoResult[void].err(cause).error

suite "LPResultError":
  test "$ returns the message":
    check $errorOf("bad peer") == "bad peer"

  test "== compares the message with a string on either side":
    let e = errorOf("bad peer")
    check:
      e == "bad peer"
      "bad peer" == e
      e != "other"
      "other" != e

  test "chronicles prints the full message":
    let e = errorOf(NotEnoughMemory, newString(1000))
    check chroniclesFormatItIMPL(e) == $e

  test "err on the type wraps a string":
    let r = DemoResult[int].err("bad peer")
    check:
      r.isErr()
      r.error == "bad peer"

  test "err on the type works for a void value":
    let r = DemoResult[void].err("bad peer")
    check r.error == "bad peer"

  test "err on the type still takes an LPResultError":
    let r = DemoResult[int].err(errorOf("bad peer"))
    check r.error == "bad peer"

  test "bare err with a concatenation compiles in a proc":
    proc fail(name: string): DemoResult[int] =
      err("bad " & name)

    check fail("peer").error == "bad peer"

  test "return err compiles as an early exit":
    proc fail(early: bool): DemoResult[int] =
      if early:
        return err("early")
      ok(1)

    check:
      fail(true).error == "early"
      fail(false).get() == 1

  test "err on a var result sets the error":
    var r = DemoResult[int].ok(1)
    r.err("bad peer")
    check r.error == "bad peer"

  test "valueOrRaise raises the requested exception with the message":
    let r = DemoResult[int].err("bad peer")
    try:
      discard r.valueOrRaise(DemoError)
      raiseAssert "should not get here"
    except DemoError as e:
      check e.msg == "bad peer"

  test "onErrorRaise raises the requested exception with the message":
    let r = DemoResult[void].err("bad peer")
    try:
      r.onErrorRaise(DemoError)
      raiseAssert "should not get here"
    except DemoError as e:
      check e.msg == "bad peer"

  test "$ joins the cause and the detail":
    check:
      $errorOf(NotEnoughMemory) == "not enough memory"
      $errorOf(NotEnoughMemory, "missing: 2MB") == "not enough memory (missing: 2MB)"

  test "isOfError matches the cause and ignores the detail":
    check:
      reserve(2).isOfError(NotEnoughMemory)
      reserve(3).isOfError(NotEnoughMemory)
      reserve(2).error == "not enough memory (missing: 2MB)"
      not reserve(2).isOfError(PeerGone)
      not reserve(0).isOfError(NotEnoughMemory)

  test "isOfError matches an ad hoc string error by its text":
    let r = DemoResult[int].err("bad peer")
    check:
      r.isOfError("bad peer")
      not r.isOfError(NotEnoughMemory)

  test "wrapError chains the inner error under the outer one":
    let e = errorOf(NotEnoughMemory, "missing: 2MB").wrapError(PeerGone)
    check e == "peer gone: not enough memory (missing: 2MB)"

  test "wrapError keeps the chain of an already wrapped outer error":
    let e =
      errorOf(NotEnoughMemory).wrapError(errorOf(PeerGone).wrapError("start failed"))
    check e == "start failed: peer gone: not enough memory"

  test "an unset error renders as not set":
    var e: LPResultError
    check:
      $e == "<not set>"
      $errorOf("") == "<not set>"

  test "err with an inner error wraps it":
    proc connect(): DemoResult[int] =
      reserve(2).isOkOr:
        return err(error, PeerGone)
      ok(1)

    proc start(): DemoResult[int] =
      let conn = connect().valueOr:
        return err(error, "start failed")
      ok(conn)

    check start().error == "start failed: peer gone: not enough memory (missing: 2MB)"

  test "err with two strings sets the detail and the cause":
    proc parse(T: type): T =
      err("/ip4/1.2.3.4", "too few parts")

    check:
      parse(DemoResult[int]).error == "too few parts (/ip4/1.2.3.4)"
      parse(DemoResult[int]).isOfError("too few parts")
      parse(DemoResult[int]).error.detail == "/ip4/1.2.3.4"
      parse(Result[int, string]).error == "too few parts (/ip4/1.2.3.4)"

  test "err with an inner error puts the outer message first in a string error":
    proc connect(): Result[int, string] =
      reserve(2).isOkOr:
        return err(error, "reservation failed")
      ok(1)

    check connect().error == "reservation failed: not enough memory (missing: 2MB)"

  test "err with an exception wraps its message":
    proc parse(T: type): T =
      try:
        raise newException(ValueError, "bad digit")
      except ValueError as e:
        err(e, "parse failed")

    check:
      parse(DemoResult[int]).error == "parse failed: bad digit"
      parse(DemoResult[int]).isOfError("parse failed")
      parse(LPResult[int]).error == "parse failed: bad digit"
      parse(Result[int, string]).error == "parse failed: bad digit"

  test "err with an exception, cstring or LPResultError gives its message to a string error":
    proc fromException(): Result[int, string] =
      try:
        raise newException(ValueError, "bad digit")
      except ValueError as e:
        err(e)

    proc fromExceptionToError(): DemoResult[int] =
      try:
        raise newException(ValueError, "bad digit")
      except ValueError as e:
        err(e)

    proc keepsException(): Result[int, ref CatchableError] =
      try:
        raise newException(ValueError, "bad digit")
      except ValueError as e:
        err(e)

    proc fromCString(): Result[int, string] =
      err(cstring("bad peer"))

    proc fromCStringToError(): DemoResult[int] =
      err(cstring("bad peer"))

    proc keepsCString(): Result[int, cstring] =
      err(cstring("bad peer"))

    proc fromLPResultError(): Result[int, string] =
      err(errorOf(NotEnoughMemory, "missing: 2MB"))

    proc keepsLPResultError(): DemoResult[int] =
      err(errorOf(PeerGone))

    check:
      fromException().error == "bad digit"
      fromExceptionToError().error == "bad digit"
      keepsException().error.msg == "bad digit"
      fromCString().error == "bad peer"
      fromCStringToError().error == "bad peer"
      keepsCString().error == "bad peer"
      fromLPResultError().error == "not enough memory (missing: 2MB)"
      keepsLPResultError().isOfError(PeerGone)

  test "err with an inner error of another type wraps its text":
    type Stage = enum
      readStage

    proc fail(T: type): T =
      err(readStage, "send failed")

    check:
      fail(DemoResult[int]).error == "send failed: readStage"
      fail(DemoResult[int]).isOfError("send failed")
      fail(DemoResult[int]).isOfError("readStage")
      fail(Result[int, string]).error == "send failed: readStage"

  test "isOfError matches every error of the chain":
    let r =
      DemoResult[int].err(errorOf(NotEnoughMemory, "missing: 2MB").wrapError(PeerGone))
    check:
      r.isOfError(PeerGone)
      r.isOfError(NotEnoughMemory)
      not r.isOfError("missing: 2MB")
      not DemoResult[int].ok(1).isOfError(PeerGone)
