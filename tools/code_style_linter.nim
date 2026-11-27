# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Linter for code style rules that need only the parsed AST.

import compiler/ast

import lint

type ImplicitResultSettings* = object
  ## Settings for the check that `result` is declared before it is used.
  ##
  ## Nim declares `result` implicitly in every proc that returns a value, so
  ## a body that assigns to it without declaring it reads as if the variable
  ## came from nowhere. Declaring it — `var result: T` — makes the return
  ## value explicit at the top of the proc.

# --- AST helpers ----------------------------------------------------------

proc isRoutine(node: PNode): bool =
  node.kind in {
    nkProcDef, nkFuncDef, nkMethodDef, nkConverterDef, nkLambda, nkDo, nkMacroDef,
    nkTemplateDef, nkIteratorDef,
  }

proc isResult(node: PNode): bool =
  node.kind == nkIdent and node.ident.s == "result"

proc bindsResult(node: PNode): bool =
  case node.kind
  of nkPragmaExpr:
    node.len > 0 and bindsResult(node[0])
  of nkPostfix:
    node.len > 1 and bindsResult(node[1])
  of nkIdentDefs, nkVarTuple:
    for index in 0 ..< node.len - 2:
      if bindsResult(node[index]):
        return true
    false
  of nkConstDef:
    node.len > 0 and bindsResult(node[0])
  else:
    isResult(node)

proc declaresResult(node: PNode): bool =
  if node.kind notin {nkVarSection, nkLetSection, nkConstSection}:
    return false
  for definition in node.sons:
    if bindsResult(definition):
      return true
  false

proc usesResult(node: PNode, shadowed = false): bool =
  ## Nested routines own their result; block and loop bindings stay local.
  if node == nil or isRoutine(node):
    return false
  if isResult(node):
    return not shadowed
  if node.kind in {nkNone .. nkNilLit}:
    return false
  case node.kind
  of nkStmtList, nkStmtListExpr:
    var localResult = shadowed
    for child in node.sons:
      if declaresResult(child):
        localResult = true
    for child in node.sons:
      if usesResult(child, localResult):
        return true
  of nkDotExpr:
    return node.len > 0 and usesResult(node[0], shadowed)
  of nkExprEqExpr, nkExprColonExpr:
    return node.len > 1 and usesResult(node[1], shadowed)
  of nkIdentDefs, nkConstDef, nkVarTuple:
    # Declaration names are bindings, but their types/initializers are expressions.
    for index in max(0, node.len - 2) ..< node.len:
      if usesResult(node[index], shadowed):
        return true
  of nkForStmt, nkParForStmt:
    var loopResult = shadowed
    for index in 0 ..< node.len - 2:
      loopResult = loopResult or bindsResult(node[index])
    if usesResult(node[^2], shadowed) or usesResult(node[^1], loopResult):
      return true
  else:
    for child in node.sons:
      if usesResult(child, shadowed):
        return true
  false

proc hasResult(node: PNode): bool =
  # Templates and iterators do not have an implicit return-value variable.
  if node.kind in {nkTemplateDef, nkIteratorDef} or node.len <= 6:
    return false
  let params = node[3]
  params.kind == nkFormalParams and params.len > 0 and params[0].kind != nkEmpty and
    not (params[0].kind == nkIdent and params[0].ident.s == "void")

# --- checks ---------------------------------------------------------------

proc runImplicitResult(
    source: string, ast: PNode, s: ImplicitResultSettings
): seq[Finding] =
  ## Check each value-returning routine independently, including macros.
  var findings: seq[Finding]
  var stack = @[ast]
  while stack.len > 0:
    let node = stack.pop()
    if node == nil:
      continue
    if isRoutine(node) and hasResult(node) and usesResult(node[6]):
      findings.add(node.toFinding("do not use implicit `result` variable"))
    if node.kind in {nkNone .. nkNilLit}:
      continue
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]
  findings

# --- linter ---------------------------------------------------------------

let codeStyle* = Linter()

let implicitResult* = codeStyle.addCheck(runImplicitResult)
