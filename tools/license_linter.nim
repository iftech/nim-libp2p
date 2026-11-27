# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Require the project's license header at the start of a source file.

import std/strutils
import compiler/ast
import lint

type HeaderSettings* = object ## Trailing whitespace and CRLF are ignored.
  license*: string = """# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
"""

proc runLicenseHeader(
    source: string, ast: PNode, settings: HeaderSettings
): seq[Finding] =
  let lines = source.splitLines()
  let required = settings.license.strip(leading = false).splitLines()
  for index, line in required:
    let expected = line.strip(leading = false)
    if index >= lines.len or lines[index].strip(leading = false) != expected:
      result.add Finding(
        line: index + 1,
        col: 0,
        msg: "missing or incorrect license header; expected " & expected,
      )
      break

let headers* = Linter()
let licenseHeader* = headers.addCheck(runLicenseHeader)
