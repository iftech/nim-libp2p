# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../code_style_linter

proc count(source: string): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  implicitResult.run(source, ast, ImplicitResultSettings()).len

for source in [
  "proc value(): int = result = 1", "func value(): int = inc result",
  "proc value(): int =\n  if ready: result = 1",
]:
  doAssert count(source) == 1, source
for source in [
  "proc value(): int = 1", "proc value(): int = return 1",
  "proc value(): int =\n  var result: int\n  result = 1",
]:
  doAssert count(source) == 0, source
