# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Prefer shared test helpers over the public RNG-taking PeerId.random overloads.

import std/sets
import compiler/ast
import lint

type PeerIdRandomSettings* = object

proc isRng(typ: PType): bool =
  if typ.isNil:
    return false
  let resolved = typ.skipTypes({tyAlias, tyVar, tyLent, tySink})
  if resolved.isNil or resolved.sym.isNil or resolved.sym.name.s != "Rng":
    return false
  let module = resolved.sym.originatingModule
  not module.isNil and module.name.s == "rng"

proc runPeerIdRandom(
    source: string, ast: PNode, typed: PNode, s: PeerIdRandomSettings
): seq[Finding] =
  var findings: seq[Finding]
  var reported: HashSet[(int, int)]
  var stack = @[typed]
  while stack.len > 0:
    let node = stack.pop()
    if node.isNil:
      continue
    if node.kind in nkCallKinds and node.len > 1 and node[0].kind == nkSym:
      let callee = node[0].sym
      let module = callee.originatingModule
      if callee.name.s == "random" and not module.isNil and module.name.s == "peerid":
        for index in 1 ..< node.len:
          # Use the resolved overload's parameter type: an argument alias may
          # carry its own symbol even when its underlying type is Rng.
          if not callee.typ.isNil and index < callee.typ.len and isRng(
            callee.typ[index]
          ):
            let position = (int(node.info.line), int(node.info.col))
            if position notin reported:
              reported.incl position
              findings.add node.toFinding(
                "use the shared `PeerId.random` test helper without the RNG " &
                  "argument; keep the count argument for batches"
              )
            break
    if node.kind in {nkNone .. nkNilLit}:
      continue
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]
  findings

let peerIds* = Linter()
let peerIdRandom* = peerIds.addCheck(runPeerIdRandom)
