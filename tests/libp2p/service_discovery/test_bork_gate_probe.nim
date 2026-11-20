# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../tools/[unittest]

suite "Service Discovery gate probe":
  test "trivially passes":
    check 1 + 1 == 2
