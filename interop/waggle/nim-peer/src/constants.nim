# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

const

  # Object ID prefixes agreed with rust-peer/src/main.rs.
  RustObjectPrefix* = byte 'R'
  NimObjectPrefix* = byte 'N'

  MetadataOnlyKind* = 0.byte
  PayloadKind* = 1.byte
  EmptyFieldsKind* = 2.byte
  FixtureKinds* = [MetadataOnlyKind, PayloadKind, EmptyFieldsKind]
