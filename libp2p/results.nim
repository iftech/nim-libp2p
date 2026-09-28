# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import pkg/results

export results

{.push raises: [].}

type LPResult*[T] = Result[T, string]

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
