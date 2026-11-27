# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../completed_cancel_linter

proc count(source: string): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  completedCancel.run(source, ast, CompletedCancelSettings()).len

for source in [
  "if not fut.completed(): fut.cancel()", "if not completed(fut): cancel(fut)",
  "proc nested() =\n  if not fut.completed(): fut.cancel()",
]:
  doAssert count(source) == 1, source
for source in [
  "fut.cancel()", "if fut.completed(): fut.cancel()",
  "if not fut.completed():\n  fut.cancel()\n  echo 1",
  "if not fut.completed():\n  fut.cancel()\nelse:\n  discard",
  "if not fut.completed(): fut.close()",
]:
  doAssert count(source) == 0, source
