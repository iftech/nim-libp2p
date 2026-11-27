# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Report redundant completed guards around future cancellation.

import compiler/ast
import lint

type CompletedCancelSettings* = object

proc calleeName(node: PNode): string =
  if node.kind notin {nkCall, nkCommand} or node.len == 0:
    return ""
  let callee = node[0]
  if callee.kind == nkIdent:
    callee.ident.s
  elif callee.kind == nkDotExpr and callee.len == 2 and callee[1].kind == nkIdent:
    callee[1].ident.s
  else:
    ""

proc isCancelGuard(node: PNode): bool =
  if node.kind != nkIfStmt or node.len != 1:
    return false
  let branch = node[0]
  if branch.kind != nkElifBranch or branch.len != 2:
    return false
  let condition = branch[0]
  if condition.kind != nkPrefix or condition.len != 2 or condition[0].kind != nkIdent or
      condition[0].ident.s != "not" or calleeName(condition[1]) != "completed":
    return false
  let body = branch[1]
  if body.kind == nkStmtList:
    body.len == 1 and calleeName(body[0]) == "cancel"
  else:
    calleeName(body) == "cancel"

proc runCompletedCancel(
    source: string, ast: PNode, s: CompletedCancelSettings
): seq[Finding] =
  var stack = @[ast]
  while stack.len > 0:
    let node = stack.pop()
    if node == nil:
      continue
    if isCancelGuard(node):
      result.add node.toFinding(
        "`cancel` on a finished future is a no-op; drop the `completed` guard"
      )
    if node.kind in {nkNone .. nkNilLit}:
      continue
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]

let cancellation* = Linter()
let completedCancel* = cancellation.addCheck(runCompletedCancel)
