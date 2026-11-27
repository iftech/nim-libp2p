# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../check_until_timeout_linter

proc count(source: string): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  checkUntilTimeout.run(source, ast, CheckUntilTimeoutSettings()).len

for source in [
  "checkUntilTimeout:\n  ready", "checkUntilTimeout(ready)",
  "proc nested() =\n  checkUntilTimeout:\n    ready",
]:
  doAssert count(source) == 1, source
for source in ["await ready.wait()", "check ready", "let text = \"checkUntilTimeout\""]:
  doAssert count(source) == 0, source
