# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/sequtils
import pkg/results
import chronicles

export results

{.push raises: [].}

type LPResultError* = object
  cause*: string
  detail*: string
  wrapped: seq[LPResultError] # underlying errors, nearest first, each one unwrapped

type LPResult*[T] = Result[T, string]

func init*(T: type LPResultError, cause: string): T =
  T(cause: cause)

func withDetail*(e: LPResultError, detail: string): LPResultError =
  LPResultError(cause: e.cause, detail: detail, wrapped: e.wrapped)

func wrapError*(inner, outer: LPResultError): LPResultError =
  LPResultError(
    cause: outer.cause,
    detail: outer.detail,
    wrapped: @[LPResultError(cause: inner.cause, detail: inner.detail)] & inner.wrapped,
  )

func wrapError*(inner: LPResultError, outer: string): LPResultError =
  inner.wrapError(LPResultError.init(outer))

func `$`*(e: LPResultError): string =
  var msg = e.cause
  if e.detail.len > 0:
    msg.add(" (" & e.detail & ")")
  for inner in e.wrapped:
    msg.add(": " & $inner)
  msg

func `==`*(e: LPResultError, msg: string): bool =
  $e == msg

func `==`*(msg: string, e: LPResultError): bool =
  $e == msg

chronicles.formatIt(LPResultError):
  $it

func err*[T](R: type Result[T, LPResultError], msg: string): R =
  R.err(LPResultError.init(msg))

func err*[T](
    R: type Result[T, LPResultError],
    inner: LPResultError,
    outer: LPResultError | string,
): R =
  R.err(inner.wrapError(outer))

template err*(inner: LPResultError, outer: LPResultError | string): auto =
  err(typeof(result), inner, outer)

func err*[T](R: type Result[T, LPResultError], e: ref CatchableError, msg: string): R =
  R.err(LPResultError.init(e.msg), msg)

func err*[T](R: type Result[T, string], e: ref CatchableError, msg: string): R =
  R.err(msg & ": " & e.msg)

template err*(e: ref CatchableError, msg: string): auto =
  err(typeof(result), e, msg)

func hasCause(e: LPResultError, cause: string): bool =
  e.cause == cause or e.wrapped.anyIt(it.cause == cause)

func isOfError*[T](r: Result[T, LPResultError], cause: string): bool =
  ## True when any error of the chain has `cause`.
  r.isErr() and r.error.hasCause(cause)

func isOfError*[T](r: Result[T, LPResultError], e: LPResultError): bool =
  r.isOfError(e.cause)

func toException*[E](e: E, X: typedesc): ref X =
  (ref X)(msg: $e)

template valueOrRaise*[T: not void, E](r: Result[T, E], X: typedesc): T =
  ## Unwrap `r`, or raise `X` carrying the error message.
  r.valueOr:
    raise error.toException(X)

template onErrorRaise*[E](r: Result[void, E], X: typedesc) =
  ## Raise `X` carrying the error message when `r` is an error.
  r.isOkOr:
    raise error.toException(X)
