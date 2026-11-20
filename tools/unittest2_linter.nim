# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Linter for unittest2 usage.
##
## The checks here encode one policy: a test that cannot fail is worse than no
## test, because it reports success. `check false` is the shape that happens
## when a test is stubbed out or a condition is temporarily disabled, and it
## stays in the suite silently passing.

import compiler/ast

import lint

type CheckFalseSettings* = object
  ## Settings for the check that forbids `check false`.
  ##
  ## `check false` is always a mistake: it either marks a test that was never
  ## finished or one whose condition was disabled to make it pass. A test
  ## that is meant to fail should say so with `raiseAssert` and a message
  ## explaining why.

# --- AST helpers ----------------------------------------------------------

proc isFalse(node: PNode): bool =
  node.kind == nkIdent and node.ident.s == "false"

proc isCheckFalse(node: PNode): bool =
  ## True for `check false` and `check(false)`.
  ##
  ## `check` is a template, so it parses as a command or a call with the
  ## condition as its first argument.
  node.kind in {nkCommand, nkCall} and node.len == 2 and node[0].kind == nkIdent and
    node[0].ident.s == "check" and isFalse(node[1])

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

proc runCheckFalse(ast: PNode, s: CheckFalseSettings): seq[Finding] =
  for node in nodes(ast):
    if isCheckFalse(node):
      result.add(
        node.toFinding(
          "`check false` never passes; use `raiseAssert` with an explanation, " &
            "or remove the test"
        )
      )

# --- linter ---------------------------------------------------------------

let unittest2* = Linter()

let checkFalse* = unittest2.addCheck(runCheckFalse)
