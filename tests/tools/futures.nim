# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos/futures, chronos, sequtils

template waitForCancellation*(): untyped =
  ## Return a future that remains pending until it is cancelled.
  newAsyncEvent().wait()

proc allFuturesRaising*(
    args: varargs[FutureBase]
): Future[void].Raising([CatchableError]) =
  # This proc is only meant for use in tests / not suitable for general use.
  # Swallowing errors arbitrarily instead of aggregating them is bad design
  # It raises `CatchableError` instead of the union of the `futs` errors,
  # inflating the caller's `raises` list unnecessarily. `macro` could fix it.
  let futs = @args
  (
    proc() {.async: (raises: [CatchableError]).} =
      await allFutures(futs)
      var firstErr: ref CatchableError
      for fut in futs:
        if not fut.completed():
          let err = fut.error()
          if err of CancelledError:
            raise err
          if firstErr == nil:
            firstErr = err
      if firstErr != nil:
        raise firstErr
  )()

proc allFuturesRaising*[T](
    futs: varargs[Future[T]]
): Future[void].Raising([CatchableError]) =
  allFuturesRaising(futs.mapIt(FutureBase(it)))

proc allFuturesRaising*[T, E]( # https://github.com/nim-lang/Nim/issues/23432
    futs: varargs[InternalRaisesFuture[T, E]]
): Future[void].Raising([CatchableError]) =
  allFuturesRaising(futs.mapIt(FutureBase(it)))
