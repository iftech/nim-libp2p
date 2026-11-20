# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Check the values Chronicles actually passes to its output after expanding
## formatIt. This includes imported and generic formatters selected by Nim, but
## does not mistake Chronicles' identity fallback for a custom representation.
## Type-specific formatIt declarations in the import closure also count when
## their expansion preserves the input type. The generic identity fallback does
## not count. This checks representation policy, not redaction correctness.
##
## Coverage: directly written calls with literal messages and named/bare fields,
## using Chronicles' textline/textblock outputs. Disabled logs and uninstantiated
## generics cannot be checked. JSON output expands setProperty away and is not
## supported. The import-closure declaration fallback is not a visibility or
## overload-resolution check. Repeated message/field pairs share attribution.

import std/[sets, tables]
import compiler/[ast, types]
import lint

type LogPayloadSettings* = object

proc symbolName(node: PNode): string =
  case node.kind
  of nkSym: node.sym.name.s
  of nkIdent: node.ident.s
  else: ""

proc boundedType(typ: PType): bool =
  if typ.isNil:
    return false
  let resolved = typ.skipTypes({tyAlias, tyGenericInst, tyVar, tyLent, tySink, tyRange})
  if not resolved.isNil and resolved.kind == tyTuple:
    for i in 0 ..< resolved.len:
      if not boundedType(resolved[i]):
        return false
    return true
  not resolved.isNil and
    resolved.kind in {
      tyBool,
      tyChar,
      tyEnum,
      tyInt .. tyInt64,
      tyUInt .. tyUInt64,
      tyFloat .. tyFloat128,
      tyString,
      tyCstring,
    }

proc boundedCall(node: PNode): bool =
  ## Only the outer expression bounds a payload: len(x) is safe, but
  ## (len(x), x) and x & shortLog(y) still contain the raw payload.
  if node.kind in {nkHiddenStdConv, nkHiddenSubConv, nkHiddenDeref, nkHiddenAddr, nkPar} and
      node.len > 0:
    return boundedCall(node[^1])
  node.kind in nkCallKinds and node.len > 0 and
    symbolName(node[0]) in ["shortLog", "len"]

proc runBoundedLogPayloads(
    source: string, ast, typed: PNode, settings: LogPayloadSettings
): seq[Finding] =
  var
    formatterTypes: seq[PType]
    visitedModules: HashSet[int]
    findings: seq[Finding]
    reported: HashSet[(int, int, string)]
    sourceFields: seq[tuple[name, message: string, value: PNode]]
    recordMessages: Table[int, string]

  proc recordSymbol(node: PNode): PSym =
    var value = node
    while value.kind in {nkHiddenAddr, nkHiddenDeref} and value.len > 0:
      value = value[0]
    if value.kind == nkSym:
      result = value.sym

  proc collectFields(node: PNode) =
    if node.isNil:
      return
    if node.kind in {nkCall, nkCommand} and node.len > 1 and
        symbolName(node[0]) in
        ["trace", "debug", "info", "notice", "warn", "error", "fatal"]:
      if node[1].kind notin {nkStrLit .. nkTripleStrLit}:
        return
      for i in 2 ..< node.len:
        let field = node[i]
        if field.kind == nkExprEqExpr and field.len == 2:
          sourceFields.add (symbolName(field[0]), node[1].strVal, field[1])
        elif field.kind == nkIdent:
          sourceFields.add (symbolName(field), node[1].strVal, field)
    for child in node:
      collectFields(child)

  proc collectFormatters(node: PNode) =
    if node.isNil:
      return
    if node.kind == nkImportStmt:
      for child in node:
        if child.kind == nkSym and child.sym.kind == skModule and
            child.sym.id notin visitedModules:
          visitedModules.incl child.sym.id
          collectFormatters(child.sym.ast)
    if node.kind == nkTemplateDef:
      if node.len > bodyPos and node[namePos].kind == nkSym and
          symbolName(node[namePos]) == "chroniclesFormatItIMPL" and
          node[bodyPos].kind != nkEmpty:
        let signature = node[namePos].sym.typ
        if not signature.isNil and signature.len == 2 and not signature[1].isNil:
          let param = signature[1]
          # auto/type-class parameters are Chronicles' generic fallback, not
          # an intentional representation for a concrete type.
          if param.kind in {
            tyObject, tyDistinct, tyRef, tyPtr, tySequence, tyArray, tyTuple,
            tyGenericInst, tyEnum,
          }:
            formatterTypes.add param
      return
    for child in node:
      collectFormatters(child)

  proc hasFormatter(typ: PType): bool =
    for candidate in formatterTypes:
      if sameType(typ, candidate):
        return true

  proc inspect(node: PNode) =
    if node.isNil:
      return
    # Template bodies are uninstantiated. Their actual expansions are checked
    # at their call sites; imported/generated locations cannot be reported as
    # positions in the selected source file.
    if node.kind == nkTemplateDef:
      return
    if node.kind in nkCallKinds and node.len >= 5 and
        symbolName(node[0]) == "initLogRecord" and
        node[4].kind in {nkStrLit .. nkTripleStrLit}:
      let record = recordSymbol(node[1])
      if not record.isNil:
        recordMessages[record.id] = node[4].strVal
    if node.kind in nkCallKinds and node.len >= 4 and node[0].kind == nkSym and
        node[0].sym.name.s == "setProperty":
      let
        callee = node[0].sym
        module = callee.originatingModule
        field = node[2]
        value = node[3]
      # Restrict this to Chronicles output, not unrelated setProperty procs.
      if not module.isNil and
          module.name.s in ["textlines", "textblocks", "json_records"] and
          field.kind in {nkStrLit .. nkTripleStrLit} and not value.typ.isNil and
          value.typ.kind != tyError and not boundedType(value.typ) and
          not boundedCall(value) and not hasFormatter(value.typ):
        let record = recordSymbol(node[1])
        if not record.isNil and sfMainModule in record.originatingModule.flags and
            record.id in recordMessages:
          for original in sourceFields:
            if original.name == field.strVal and
                original.message == recordMessages[record.id]:
              let key = (
                int(original.value.info.line),
                int(original.value.info.col),
                field.strVal,
              )
              if key notin reported:
                reported.incl key
                findings.add original.value.toFinding(
                  "potentially unbounded log field `" & field.strVal &
                    "` must use shortLog or len, or implement formatIt"
                )
    for child in node:
      inspect(child)

  if not typed.isNil:
    collectFields(ast)
    collectFormatters(typed)
    inspect(typed)
  findings

let
  logPayloads* = Linter()
  boundedLogPayloads* = logPayloads.addCheck(runBoundedLogPayloads)
