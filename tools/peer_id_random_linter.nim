# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Prefer the shared test RNG helpers over raw PeerId.random calls.

import compiler/ast
import lint

type PeerIdRandomSettings* = object

proc isRng(node: PNode): bool =
  if node.kind == nkIdent:
    return node.ident.s == "rng"
  node.kind in {nkCall, nkCommand} and node.len == 1 and node[0].kind == nkIdent and
    node[0].ident.s == "rng"

proc isPeerIdRandomWithRng(node: PNode): bool =
  if node.kind notin {nkCall, nkCommand} or node.len < 2:
    return false
  let callee = node[0]
  callee.kind == nkDotExpr and callee.len == 2 and callee[1].kind == nkIdent and
    callee[1].ident.s == "random" and callee[0].kind == nkIdent and
    callee[0].ident.s == "PeerId" and isRng(node[^1])

proc runPeerIdRandom(
    source: string, ast: PNode, s: PeerIdRandomSettings
): seq[Finding] =
  var stack = @[ast]
  while stack.len > 0:
    let node = stack.pop()
    if node == nil:
      continue
    if isPeerIdRandomWithRng(node):
      result.add node.toFinding(
        "use the `PeerId.random()` test helper without the RNG argument"
      )
    if node.kind in {nkNone .. nkNilLit}:
      continue
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]

let peerIds* = Linter()
let peerIdRandom* = peerIds.addCheck(runPeerIdRandom)
