# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/strformat
import ../../libp2p/[errors, results]
import ../tools/unittest

type DemoError = object of LPError

type DemoResult[T] = Result[T, LPResultError]

let
  NotEnoughMemory = LPResultError.init("not enough memory")
  PeerGone = LPResultError.init("peer gone")

proc reserve(missingMb: int): DemoResult[void] =
  if missingMb > 0:
    return err(NotEnoughMemory.withDetail(fmt"missing: {missingMb}MB"))
  ok()

suite "LPResultError":
  test "$ returns the message":
    check $LPResultError.init("bad peer") == "bad peer"

  test "== compares the message with a string on either side":
    let e = LPResultError.init("bad peer")
    check:
      e == "bad peer"
      "bad peer" == e
      e != "other"
      "other" != e

  test "chronicles prints the full message":
    let e = NotEnoughMemory.withDetail(newString(1000))
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
    let r = DemoResult[int].err(LPResultError.init("bad peer"))
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
      $NotEnoughMemory == "not enough memory"
      $NotEnoughMemory.withDetail("missing: 2MB") == "not enough memory (missing: 2MB)"

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
      r.isOfError(LPResultError.init("bad peer"))
      not r.isOfError(NotEnoughMemory)

  test "wrapError chains the inner error under the outer one":
    let e = NotEnoughMemory.withDetail("missing: 2MB").wrapError(PeerGone)
    check e == "peer gone: not enough memory (missing: 2MB)"

  test "wrapError keeps the chain of an already wrapped outer error":
    let e = NotEnoughMemory.wrapError(PeerGone.wrapError("start failed"))
    check e == "start failed: peer gone: not enough memory"

  test "an unset error renders as not set":
    var e: LPResultError
    check:
      $e == "<not set>"
      $LPResultError.init("") == "<not set>"

  test "withDetail on the outer error keeps the inner error":
    let
      inner = NotEnoughMemory
      outer = inner.wrapError(PeerGone).withDetail("16U")
    check:
      outer == "peer gone (16U): not enough memory"
      outer.cause == PeerGone.cause
      outer.detail == "16U"

  test "err with an inner error wraps it":
    proc connect(): DemoResult[int] =
      reserve(2).isOkOr:
        return err(error, PeerGone)
      ok(1)

    proc start(): DemoResult[int] =
      let conn = connect().valueOr:
        return err(error, "start failed")
      ok(conn)

    check:
      start().error == "start failed: peer gone: not enough memory (missing: 2MB)"
      DemoResult[int].err(NotEnoughMemory, PeerGone).error ==
        "peer gone: not enough memory"

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

  test "err with an exception, enum or cstring gives its message to a string error":
    type Color = enum
      Red

    proc fromException(): LPResult[int] =
      try:
        raise newException(ValueError, "bad digit")
      except ValueError as e:
        err(e)

    proc fromEnum(): LPResult[int] =
      err(Red)

    proc fromCString(): LPResult[int] =
      err(cstring("bad peer"))

    proc keepsEnum(): Result[int, Color] =
      err(Red)

    check:
      fromException().error == "bad digit"
      fromEnum().error == "Red"
      fromCString().error == "bad peer"
      keepsEnum().error == Red

  test "isOfError matches every error of the chain":
    let r = DemoResult[int].err(NotEnoughMemory.withDetail("missing: 2MB"), PeerGone)
    check:
      r.isOfError(PeerGone)
      r.isOfError(NotEnoughMemory)
      r.isOfError("not enough memory")
      not r.isOfError("missing: 2MB")
      not DemoResult[int].ok(1).isOfError(PeerGone)
