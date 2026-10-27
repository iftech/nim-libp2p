# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

const
  ReconcileScenario* = "reconcile"
  TopologyScenario* = "topology"
  LifecycleScenario* = "lifecycle"
  PressureScenario* = "pressure"

  # Object ID prefixes agreed with rust-peer/src/main.rs.
  RustObjectPrefix* = byte 'R'
  NimObjectPrefix* = byte 'N'
