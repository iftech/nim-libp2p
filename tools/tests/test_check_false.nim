# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../unittest2_linter

proc count(source: string): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  checkFalse.run(source, ast, CheckFalseSettings()).len

for source in ["check false", "check(false)", "proc nested() = check false"]:
  doAssert count(source) == 1, source
for source in [
  "check true", "check value == false", "check not value", "let text = \"check false\""
]:
  doAssert count(source) == 0, source
