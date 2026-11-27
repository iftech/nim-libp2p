# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../chronicles_linter

proc count(source: string): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  messageEndsWithPunctuation.run(source, ast, MessageSettings()).len

for source in ["info \"\"", "info \" \"", "info \"   \"", "info \"Ready\""]:
  doAssert count(source) == 0, source
for source in ["info \"Ready.\"", "info \"Ready!  \""]:
  doAssert count(source) == 1, source
