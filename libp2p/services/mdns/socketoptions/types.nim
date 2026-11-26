# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/os
import results

type InterfaceBindingResult* = Result[bool, OSErrorCode]
  ## ok(true) means ingress is pinned; ok(false) means pinning is unavailable
  ## and receives must be filtered by the caller. An error is an OS failure.
