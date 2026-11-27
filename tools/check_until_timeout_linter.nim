# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Prefer awaiting a signal over polling with checkUntilTimeout.

import compiler/ast
import lint

type CheckUntilTimeoutSettings* = object

proc runCheckUntilTimeout(
    source: string, ast: PNode, s: CheckUntilTimeoutSettings
): seq[Finding] =
  var stack = @[ast]
  while stack.len > 0:
    let node = stack.pop()
    if node == nil:
      continue
    if node.kind in {nkCall, nkCommand} and node.len > 0 and node[0].kind == nkIdent and
        node[0].ident.s == "checkUntilTimeout":
      result.add node.toFinding(
        "prefer awaiting the event directly; `checkUntilTimeout` polls and " &
          "hides what the test is actually waiting for"
      )
    if node.kind in {nkNone .. nkNilLit}:
      continue
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]

let polling* = Linter()
let checkUntilTimeout* = polling.addCheck(runCheckUntilTimeout)
