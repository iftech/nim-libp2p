# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../forbidden_call_linter

proc count(source: string, settings: ForbiddenCallSettings): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  forbiddenCall.run(source, ast, settings).len

let settings = ForbiddenCallSettings(minArgs: 1, literalOnly: true)
for source in [
  "await fut.withTimeout(5.seconds)", "await wait(fut, chronos.seconds(5))",
  "asyncSleep(100.millis)", "proc nested() = discard wait(fut, minutes(1))",
]:
  doAssert count(source, settings) == 1, source
for source in [
  "await event.wait()", "await fut.withTimeout(timeout)",
  "await wait(fut, config.timeout)", "discard unrelated(5.seconds)",
  "let text = \"withTimeout(5.seconds)\"",
]:
  doAssert count(source, settings) == 0, source
doAssert count("wait(fut, timeout)", ForbiddenCallSettings()) == 1
doAssert count("wait(fut, 5.seconds)", ForbiddenCallSettings(names: @["sleep"])) == 0
