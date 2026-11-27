# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../code_style_linter

proc findingLines(source: string): seq[int] =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  var lines: seq[int]
  for finding in implicitResult.run(source, ast, ImplicitResultSettings()):
    lines.add(finding.line)
  lines

# Only the inner routine uses an implicit result.
doAssert findingLines(
  """proc outer() =
  proc inner(): int =
    result = 1
  discard inner()
"""
) == @[2]

# An explicit outer result must not hide the inner routine's implicit result.
doAssert findingLines(
  """proc outer(): int =
  var result: int
  proc inner(): int =
    result = 1
  result = inner()
"""
) == @[3]

# Each routine owns its own result, even when both use it implicitly.
doAssert findingLines(
  """proc outer(): int =
  proc inner(): int =
    result = 1
  result = inner()
"""
) == @[1, 2]

# An explicit inner result must not cause a hint on either routine.
doAssert findingLines(
  """proc outer(): int =
  proc inner(): int =
    var result: int
    result = 1
  inner()
"""
).len == 0
