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

func init(T: type LPResultError, cause: string, detail = ""): T =
  T(cause: cause, detail: detail)

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

func toLPResultError[E](e: E): LPResultError =
  when E is LPResultError:
    e
  elif E is ref CatchableError:
    LPResultError.init(e.msg)
  else:
    LPResultError.init($e)

func err*[T, E: not LPResultError](R: type Result[T, LPResultError], inner: E): R =
  ## `?` calls this to turn a foreign error into an `LPResultError`.
  R.err(toLPResultError(inner))

template err*(detail: string, cause: string): auto =
  when typeof(result.error) is LPResultError:
    typeof(result).err(LPResultError.init(cause, detail))
  else:
    typeof(result).err(cause & " (" & detail & ")")

template err*[E: not Result](inner: E, outer: string): auto =
  when typeof(result.error) is LPResultError:
    typeof(result).err(toLPResultError(inner).wrapError(outer))
  else:
    typeof(result).err(outer & ": " & $toLPResultError(inner))

template err*[X: CatchableError](e: ref X): auto =
  when typeof(result.error) is LPResultError:
    typeof(result).err(LPResultError.init(e.msg))
  elif typeof(result.error) is string:
    typeof(result).err(e.msg)
  else:
    typeof(result).err(e)

template err*(e: cstring): auto =
  when typeof(result.error) is LPResultError:
    typeof(result).err(LPResultError.init($e))
  elif typeof(result.error) is string:
    typeof(result).err($e)
  else:
    typeof(result).err(e)

template err*(e: LPResultError): auto =
  when typeof(result.error) is string:
    typeof(result).err($e)
  else:
    typeof(result).err(e)

func hasCause(e: LPResultError, cause: string): bool =
  if e.isNil():
    return false

  e.cause == cause or e.wrapped.anyIt(it.cause == cause)

func isOfError*[T](r: Result[T, LPResultError], cause: string): bool =
  ## True when any error of the chain has `cause`.
  r.isErr() and r.error.hasCause(cause)

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
