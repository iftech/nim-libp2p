# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Syntactic checks for literal timeouts chosen at the call site.

import compiler/ast
import lint

type ForbiddenCallSettings* = object
  names*: seq[string] = @["asyncSleep", "wait", "withTimeout"]
    ## Call names to report, including dot-call syntax.
  minArgs*: int = 0 ## Minimum number of explicit arguments; excludes `Event.wait()`.
  literalOnly*: bool = false
    ## Only report literal durations, not caller-supplied budgets.

proc isCall(node: PNode): bool =
  node.kind in {nkCall, nkCommand}

proc calleeName(node: PNode): string =
  if not isCall(node) or node.len == 0:
    return ""
  let callee = node[0]
  if callee.kind == nkIdent:
    callee.ident.s
  elif callee.kind == nkDotExpr and callee.len == 2 and callee[1].kind == nkIdent:
    callee[1].ident.s
  else:
    ""

proc isLiteralDuration(node: PNode): bool =
  const units = [
    "nanoseconds", "microseconds", "milliseconds", "seconds", "minutes", "hours",
    "nanosecond", "microsecond", "millisecond", "second", "minute", "hour", "millis",
  ]
  if node.kind == nkDotExpr and node.len == 2 and node[1].kind == nkIdent and
      node[1].ident.s in units:
    return node[0].kind in {nkIntLit .. nkUInt64Lit}
  if isCall(node) and node.len == 2 and node[1].kind in {nkIntLit .. nkUInt64Lit}:
    let callee = node[0]
    if callee.kind == nkIdent:
      return callee.ident.s in units
    if callee.kind == nkDotExpr and callee.len == 2 and callee[1].kind == nkIdent:
      return callee[1].ident.s in units
  false

iterator nodes(ast: PNode): PNode =
  var stack = @[ast]
  while stack.len > 0:
    let node = stack.pop()
    if node == nil:
      continue
    yield node
    if node.kind in {nkNone .. nkNilLit}:
      continue
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]

proc runForbiddenCall(
    source: string, ast: PNode, s: ForbiddenCallSettings
): seq[Finding] =
  for node in nodes(ast):
    let name = calleeName(node)
    if name.len == 0 or name notin s.names or node.len - 1 < s.minArgs:
      continue
    if s.literalOnly and not isLiteralDuration(node[^1]):
      continue
    result.add node.toFinding(
      "avoid `" & name & "`: a timeout chosen here hides the caller's " &
        "budget; pass a deadline in or let the caller bound the operation"
    )

let timeoutCalls* = Linter()
let forbiddenCall* = timeoutCalls.addCheck(runForbiddenCall)
