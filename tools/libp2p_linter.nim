# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Linter for nim-libp2p specific patterns.
##
## The checks here encode conventions of this codebase that no general linter
## can know about: a test helper that must be used instead of the raw call, and
## a test macro whose use usually means the test is waiting for something it
## should have been told about.

import compiler/ast

import lint

type
  PeerIdRandomSettings* = object
    ## Settings for the check that forbids `PeerId.random(rng)`.
    ##
    ## `tests/tools/crypto.nim` provides `PeerId.random()` and
    ## `PeerId.random(count)`, which draw from the shared test rng and unwrap
    ## the `Result` for you. Calling the library proc directly means threading
    ## an rng through the test and handling a `Result` that cannot fail in
    ## practice.

  CheckUntilTimeoutSettings* = object
    ## Settings for the check that reports `checkUntilTimeout`.
    ##
    ## The macro polls a condition until it holds or a timeout expires. It is
    ## the right tool when the test genuinely cannot know when the condition
    ## becomes true, but it is also the easy way out of a missing signal: a
    ## test that waits for a callback, a future, or a channel can usually be
    ## written to await it directly, which is both faster and deterministic.

# --- AST helpers ----------------------------------------------------------

proc isCall(node: PNode): bool =
  node.kind in {nkCall, nkCommand}

proc isRng(node: PNode): bool =
  ## True for the test rng: `rng()` and `rng`.
  if node.kind == nkIdent:
    return node.ident.s == "rng"
  isCall(node) and node.len == 1 and node[0].kind == nkIdent and
    node[0].ident.s == "rng"

proc isPeerIdRandomWithRng(node: PNode): bool =
  ## True for `PeerId.random(rng)` and `PeerId.random(count, rng)`.
  ##
  ## The callee is `PeerId.random` — a dot expression whose right half is
  ## `random` — and the last argument is the rng. The helper's overloads take
  ## no rng, so they are not reported.
  if not isCall(node) or node.len < 2:
    return false
  let callee = node[0]
  callee.kind == nkDotExpr and callee.len == 2 and callee[1].kind == nkIdent and
    callee[1].ident.s == "random" and callee[0].kind == nkIdent and
    callee[0].ident.s == "PeerId" and isRng(node[^1])

proc isCheckUntilTimeout(node: PNode): bool =
  ## True for `checkUntilTimeout:` and `checkUntilTimeout(...)`.
  ##
  ## The macro takes a block, so it parses as a command whose first argument is
  ## the block, or as a call with the same shape.
  isCall(node) and node.len > 0 and node[0].kind == nkIdent and
    node[0].ident.s == "checkUntilTimeout"

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

proc runPeerIdRandom(ast: PNode, s: PeerIdRandomSettings): seq[Finding] =
  for node in nodes(ast):
    if isPeerIdRandomWithRng(node):
      result.add(
        node.toFinding(
          "use the `PeerId.random()` test helper instead of `PeerId.random(rng)`"
        )
      )

proc runCheckUntilTimeout(ast: PNode, s: CheckUntilTimeoutSettings): seq[Finding] =
  for node in nodes(ast):
    if isCheckUntilTimeout(node):
      result.add(
        node.toFinding(
          "prefer awaiting the event directly; `checkUntilTimeout` polls and " &
            "hides what the test is actually waiting for"
        )
      )

# --- linter ---------------------------------------------------------------

let libp2p* = Linter()

let peerIdRandom* = libp2p.addCheck(runPeerIdRandom)
let checkUntilTimeout* = libp2p.addCheck(runCheckUntilTimeout)
