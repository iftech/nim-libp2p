# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Require a configured license header at the start of a source file.

import std/strutils
import compiler/ast
import lint

type HeaderSettings* = object
  license*: string

proc runLicenseHeader(
    source: string, ast: PNode, settings: HeaderSettings
): seq[Finding] =
  if not source.startsWith(settings.license):
    return @[Finding(line: 1, col: 0, msg: "missing or incorrect license header")]

let headers* = Linter()
let licenseHeader* = headers.addCheck(runLicenseHeader)
