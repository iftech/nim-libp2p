# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Linter for chronos usage.
##
## The checks here encode one policy: a timeout is a decision about how long an
## operation may take, and that decision belongs to the caller, not to the code
## that waits. A `withTimeout` or a `wait` buried in a helper picks a duration
## empirically, and the number is invisible at the call site that actually
## knows the budget.
##
## The checks are syntactic: they match call shapes in the parsed AST. A call is
## recognised by its name, so a local proc that happens to be called `wait` is
## reported too. That is the intended trade-off — the names are chronos' and
## shadowing them is the rarer case.

import compiler/ast

import lint

type
  ForbiddenCallSettings* = object ## Settings for the check that forbids calls by name.
    names*: seq[string] = @["asyncSleep", "wait", "withTimeout"]
      ## Call names to report. Matched against the callee's identifier, so
      ## `withTimeout(x)` and `x.withTimeout` are both caught.
    minArgs*: int = 0
      ## Fewest arguments a call must have to be reported. `wait` needs 1:
      ## `Event.wait()` takes no timeout and is not what this check is about,
      ## while `wait(fut, duration)` picks one.

  CompletedCancelSettings* = object
    ## Settings for the check that forbids guarding `cancel` with `completed`.
    ##
    ## `if not fut.completed(): fut.cancel()` reads as a safety measure but is
    ## not one: `cancel` on a finished future is a no-op, so the guard only
    ## adds a branch. The check reports the `if` statement.

# --- AST helpers ----------------------------------------------------------

proc isCall(node: PNode): bool =
  node.kind in {nkCall, nkCommand}

proc calleeName(node: PNode): string =
  ## The name a call goes through, or "" when it is not a plain identifier.
  ##
  ## Handles `f(x)` (`nkIdent` callee) and `x.f` (`nkDotExpr` callee, the
  ## `f` half).
  if not isCall(node) or node.len == 0:
    return ""
  let callee = node[0]
  if callee.kind == nkIdent:
    callee.ident.s
  elif callee.kind == nkDotExpr and callee.len == 2 and callee[1].kind == nkIdent:
    callee[1].ident.s
  else:
    ""

proc isNamedCall(node: PNode, name: string): bool =
  isCall(node) and calleeName(node) == name

proc isCompletedCall(node: PNode): bool =
  ## True for `x.completed()` and `completed(x)`.
  isNamedCall(node, "completed")

proc isCancelCall(node: PNode): bool =
  ## True for `x.cancel()` and `cancel(x)`.
  isNamedCall(node, "cancel")

proc isNotCompleted(node: PNode): bool =
  ## True for `not x.completed()`.
  node.kind == nkPrefix and node.len == 2 and node[0].kind == nkIdent and
    node[0].ident.s == "not" and isCompletedCall(node[1])

proc isCancelGuard(node: PNode): bool =
  ## True for `if not x.completed(): x.cancel()`.
  ##
  ## The condition must be `not <something>.completed()` and the body must be a
  ## single `cancel` call. Anything else in the body means the branch does more
  ## than the guard pretends to.
  if node.kind != nkIfStmt or node.len != 1:
    return false
  let branch = node[0]
  if branch.kind != nkElifBranch or branch.len != 2:
    return false
  if not isNotCompleted(branch[0]):
    return false
  let body = branch[1]
  if body.kind == nkStmtList:
    body.len == 1 and isCancelCall(body[0])
  else:
    isCancelCall(body)

iterator nodes(ast: PNode): PNode =
  ## Yields every node in the tree, at any depth.
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

# --- checks ---------------------------------------------------------------

proc runForbiddenCall(ast: PNode, s: ForbiddenCallSettings): seq[Finding] =
  for node in nodes(ast):
    let name = calleeName(node)
    if name.len > 0 and name in s.names and node.len - 1 >= s.minArgs:
      result.add(
        node.toFinding(
          "avoid `" & name & "`: a timeout chosen here hides the caller's " &
            "budget; pass a deadline in or let the caller bound the operation"
        )
      )

proc runCompletedCancel(ast: PNode, s: CompletedCancelSettings): seq[Finding] =
  for node in nodes(ast):
    if isCancelGuard(node):
      result.add(
        node.toFinding(
          "`cancel` on a finished future is a no-op; drop the `completed` guard"
        )
      )

# --- linter ---------------------------------------------------------------

let chronos* = Linter()

let forbiddenCall* = chronos.addCheck(runForbiddenCall)
let completedCancel* = chronos.addCheck(runCompletedCancel)
