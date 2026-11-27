# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../todo_linter

proc count(source: string): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  todoWithIssue.run(source, ast, TodoSettings()).len

for source in [
  "# TODO fix this", "discard # todo fix this", "#[ TODO fix this ]#",
  "##[ TODO fix this ]##", "# TODO:0", "# TODO #12abc",
]:
  doAssert count(source) == 1, source
for source in [
  "# TODO:1234 fix this", "# TODO fix this #1234",
  "# TODO https://github.com/iftech/nim-libp2p/issues/1234",
  "let text = \"# TODO fix this\"", "let text = r\"# TODO fix this\"",
  "let text = \"\"\"# TODO fix this\"\"\"", "# todos are not markers", "let ch = '#'",
  "let number = 1'u8",
]:
  doAssert count(source) == 0, source
let source = "discard\n# TODO fix this\n"
let ast = parseString(source, newIdentCache(), newPartialConfigRef())
let findings = todoWithIssue.run(source, ast, TodoSettings())
doAssert findings.len == 1
doAssert findings[0].line == 2 and findings[0].col == 2
