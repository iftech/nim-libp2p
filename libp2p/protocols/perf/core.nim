# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## `Perf <https://github.com/libp2p/specs/blob/master/perf/perf.md>`_ protocol specification

import ../../protocodec

const
  PerfCodec* = ProtoCodec("/perf/1.0.0")
  PerfSize* = 65536
