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
  ## True for the routine definitions that can have a `result`.
  node.kind in {nkProcDef, nkFuncDef, nkMethodDef, nkConverterDef}

proc isResult(node: PNode): bool =
  node.kind == nkIdent and node.ident.s == "result"

proc declaresResult(node: PNode): bool =
  ## True when `node` is a `var`/`let`/`const` section declaring `result`.
  if node.kind notin {nkVarSection, nkLetSection, nkConstSection}:
    return false
  for def in node.sons:
    if def.kind in {nkIdentDefs, nkConstDef} and def.len > 0 and isResult(def[0]):
      return true
  false

proc usesResult(node: PNode): bool =
  ## True when `node` refers to or assigns to `result`.
  if node == nil:
    return false
  if isResult(node):
    return true
  if node.kind in {nkNone .. nkNilLit}:
    return false
  for child in node.sons:
    if usesResult(child):
      return true
  false

proc body(node: PNode): PNode =
  ## The body of a routine definition.
  if node.len > 6:
    node[6]
  else:
    nil

# --- checks ---------------------------------------------------------------

proc runImplicitResult(ast: PNode, s: ImplicitResultSettings): seq[Finding] =
  ## Reports a routine that uses `result` without declaring it.
  ##
  ## Routines are visited outermost first, and a routine's body is not
  ## searched for nested routines: a nested routine's `result` is its own.
  var stack = @[ast]
  while stack.len > 0:
    let node = stack.pop()
    if node == nil:
      continue
    if isRoutine(node):
      let routineBody = body(node)
      if routineBody != nil and not declaresResult(routineBody) and
          usesResult(routineBody):
        result.add(node.toFinding("do not use implicit `result` variable"))
      continue
    if node.kind in {nkNone .. nkNilLit}:
      continue
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]

# --- linter ---------------------------------------------------------------

let codeStyle* = Linter()

let implicitResult* = codeStyle.addCheck(runImplicitResult)
