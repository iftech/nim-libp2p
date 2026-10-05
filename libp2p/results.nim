# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/sequtils
import pkg/results
import chronicles

export results

{.push raises: [].}

# a ref keeps the error one pointer wide: refc corrupts Result[T, E] when T holds a RootObj and E has several GC fields
type LPResultError* = ref object
  cause*: string
  detail*: string
  wrapped: seq[LPResultError] # underlying errors, nearest first, each one unwrapped

type LPResult*[T] = Result[T, LPResultError]

func init*(T: type LPResultError, cause: string, detail = ""): T =
  T(cause: cause, detail: detail)

func withDetail*(e: LPResultError, detail: string): LPResultError =
  LPResultError(cause: e.cause, detail: detail, wrapped: e.wrapped)

func wrapError*(inner, outer: LPResultError): LPResultError =
  LPResultError(
    cause: outer.cause,
    detail: outer.detail,
    wrapped:
      outer.wrapped & @[LPResultError(cause: inner.cause, detail: inner.detail)] &
      inner.wrapped,
  )

func wrapError*(inner: LPResultError, outer: string): LPResultError =
  inner.wrapError(LPResultError.init(outer))

func `$`*(e: LPResultError): string =
  if e.isNil():
    return "<not set>"

  var msg = e.cause
  if e.detail.len > 0:
    msg.add(" (" & e.detail & ")")
  for inner in e.wrapped:
    msg.add(": " & $inner)
  if msg == "": "<not set>" else: msg

func `==`*(e: LPResultError, msg: string): bool =
  $e == msg

func `==`*(msg: string, e: LPResultError): bool =
  $e == msg

chronicles.formatIt(LPResultError):
  $it

func err*[T](R: type Result[T, LPResultError], cause: string): R =
  R.err(LPResultError.init(cause))

func err*[T](R: type Result[T, LPResultError], detail: string, cause: string): R =
  R.err(LPResultError.init(cause, detail))

func err*[T](
    R: type Result[T, LPResultError], inner: LPResultError, outer: LPResultError
): R =
  R.err(inner.wrapError(outer))

func err*[T](R: type Result[T, LPResultError], inner: LPResultError, outer: string): R =
  R.err(inner.wrapError(outer))

func err*[T](R: type Result[T, LPResultError], e: ref CatchableError, msg: string): R =
  R.err(LPResultError.init(e.msg).wrapError(msg))

func err*[T, E: not LPResultError](R: type Result[T, LPResultError], inner: E): R =
  R.err(LPResultError.init($inner))

func err*[T, E: not ref CatchableError](
    R: type Result[T, LPResultError], inner: E, outer: string
): R =
  R.err(LPResultError.init($inner).wrapError(outer))

func err*[T](R: type Result[T, string], detail: string, cause: string): R =
  R.err(cause & " (" & detail & ")")

func err*[T](R: type Result[T, string], e: ref CatchableError, msg: string): R =
  R.err(msg & ": " & e.msg)

func err*[T, E: not ref CatchableError](
    R: type Result[T, string], inner: E, outer: string
): R =
  R.err(outer & ": " & $inner)

template err*(detail: string, cause: string): auto =
  err(typeof(result), detail, cause)

template err*(inner: LPResultError, outer: LPResultError): auto =
  err(typeof(result), inner, outer)

template err*(inner: LPResultError, outer: string): auto =
  err(typeof(result), inner, outer)

template err*[E: not Result](inner: E, outer: string): auto =
  err(typeof(result), inner, outer)

template err*(e: ref CatchableError, msg: string): auto =
  err(typeof(result), e, msg)

template err*[X: CatchableError](e: ref X): auto =
  when typeof(result.error) is string | LPResultError:
    err(typeof(result), e.msg)
  else:
    err(typeof(result), e)

template err*(e: cstring): auto =
  when typeof(result.error) is string | LPResultError:
    err(typeof(result), $e)
  else:
    err(typeof(result), e)

template err*(e: LPResultError): auto =
  when typeof(result.error) is string:
    err(typeof(result), $e)
  else:
    err(typeof(result), e)

func hasCause(e: LPResultError, cause: string): bool =
  if e.isNil():
    return false

  e.cause == cause or e.wrapped.anyIt(it.cause == cause)

func isOfError*[T](r: Result[T, LPResultError], cause: string): bool =
  ## True when any error of the chain has `cause`.
  r.isErr() and r.error.hasCause(cause)

func isOfError*[T](r: Result[T, LPResultError], e: LPResultError): bool =
  r.isOfError(e.cause)

func toException*[E](e: E, X: typedesc): ref X =
  (ref X)(msg: $e)

func toException*[E](e: E, X: typedesc, msg: string): ref X =
  (ref X)(msg: msg & ": " & $e)

template valueOrRaise*[T: not void, E](r: Result[T, E], X: typedesc): T =
  ## Unwrap `r`, or raise `X` carrying the error message.
  r.valueOr:
    raise error.toException(X)

template onErrorRaise*[E](r: Result[void, E], X: typedesc) =
  ## Raise `X` carrying the error message when `r` is an error.
  r.isOkOr:
    raise error.toException(X)
