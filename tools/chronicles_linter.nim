# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Linter for Chronicle log statements, following the rules nim-libp2p enforces
## with `tools/audit_logs.py`.
##
## Every rule that encodes project policy — which fields are payloads, which
## names stand in for exception text, which levels must stay payload-free, which
## short names are acceptable — is a setting with a default. The defaults match
## what libp2p uses today, so an unconfigured linter behaves like the script;
## a project with different conventions configures the check instead of forking
## the linter.
##
## The checks are the syntactic subset of the script: they need only the parsed
## AST. The script's rule "potentially unbounded fields must use `shortLog`"
## needs a value's *type*, which a parse-only AST does not carry. It is listed
## under "Not implemented" in the README.

import std/strutils

import compiler/ast

import lint/types

type
  MessageSettings* = object ## Settings shared by the message checks.
    trailingPunctuation*: set[char] = {'.', '!', '?'}
    allowTrailingPunctuation*: bool ## Accept `Some message.`.
    maxSentences*: Positive = 1

  FieldNameSettings* = object
    minLength*: int = 3 ## Shortest accepted field name.
    exceptions*: seq[string] =
      @["id", "ip"] ## Names accepted regardless of `minLength`.

  ExceptionSettings* = object ## Which fields must carry exception text.
    field*: string = "err" ## The field exception text is expected in.
    aliases*: seq[string] = @["description", "error", "message", "msg"]
      ## Fields that must not stand in for it.

  UnboundedSettings* = object
    ## Which fields may carry an unbounded payload, and what makes them safe.
    fields*: seq[string] = @[
      "data", "buffer", "payload", "encoded", "certificate", "ticket", "signature",
      "advertisement", "msg", "message", "request", "response", "record", "addresses",
      "addrs",
    ]
      ## Field names that conventionally carry byte arrays or unbounded
      ## protocol objects.
    escapes*: seq[string] = @["shortLog", "len"]
      ## Calls that make a value safe to log. `shortLog` bounds the value,
      ## `len` logs its element count instead. Any call form counts:
      ## `x.shortLog`, `shortLog(x)`, `x.len`, `len(x)`.
    basicTypes*: seq[string] = @[
      "bool", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16",
      "uint32", "uint64", "float", "float32", "float64", "char", "string", "cstring",
    ]
      ## Type names that are safe to log as they are. A value whose type is
      ## visible in the source — a literal, or a conversion such as `int(x)` —
      ## is accepted when its type is listed here. Values whose type is only
      ## known after semantic analysis are not covered.

  PayloadSettings* = object
    ## Which log levels must not carry payloads, and which fields carry them.
    levels*: seq[string] = @["warn", "error"]
      ## Levels that must stay payload-free, e.g.
      ## `["warn", "error"]`. Matched against the level name
      ## in the source, so it needs no enum.
    fields*: seq[string] = @[
      "msg", "message", "buffer", "record", "reply", "response", "rpcMsg", "data",
      "encoded", "certificate", "ticket", "key",
    ] ## Field names that carry a payload.

# --- AST helpers ----------------------------------------------------------

proc isLogCall(node: PNode): bool =
  ## True for both chronicles call shapes:
  ##   `info "message", field = value`  (nkCommand)
  ##   `info("message", field = value)` (nkCall)
  node.kind in {nkCommand, nkCall} and node.len > 0 and node[0].kind == nkIdent and
    node[0].ident.s in ["trace", "debug", "info", "notice", "warn", "error", "fatal"]

proc levelName(node: PNode): string =
  node[0].ident.s

proc messageNode(call: PNode): PNode =
  ## The literal event message, or nil when it is not a string literal.
  if call.len > 1 and call[1].kind in {nkStrLit .. nkTripleStrLit}:
    call[1]
  else:
    nil

iterator logCalls(ast: PNode): PNode =
  ## Yields every chronicles log statement in the tree, at any depth.
  ##
  ## Uses an explicit stack rather than recursion: log statements are common and
  ## deeply nested in real code, and a plain recursive walk over a large tree is
  ## needlessly hard on the stack.
  var stack = @[ast]
  while stack.len > 0:
    let node = stack.pop()
    if node == nil:
      continue
    if isLogCall(node):
      yield node
      # A log statement contains no nested log statements.
      continue
    # `len` is only valid for non-leaf nodes; leaves have no children.
    for i in countdown(node.safeLen - 1, 0):
      stack.add node[i]

iterator logFields(call: PNode): tuple[name: string, value: PNode, named: bool] =
  ## Yields the fields of a log call: `name = value` pairs and bare (positional)
  ## selectors such as the `peerId` in `trace "message", peerId`.
  for i in 2 ..< call.len:
    let arg = call[i]
    case arg.kind
    of nkExprEqExpr:
      if arg[0].kind == nkIdent:
        yield (arg[0].ident.s, arg[1], true)
      else:
        yield (arg[0].strVal, arg[1], false)
    of nkIdent:
      yield (arg.ident.s, arg, false)
    else:
      discard

proc callsAny(node: PNode, names: seq[string]): bool =
  ## True when `node` contains a call to one of `names`, in either form:
  ## `shortLog(x)` or `x.shortLog`.
  if node == nil:
    return false
  case node.kind
  of nkCall, nkCommand:
    if node.len > 0 and node[0].kind == nkIdent and node[0].ident.s in names:
      return true
  of nkDotExpr:
    if node.len == 2 and node[1].kind == nkIdent and node[1].ident.s in names:
      return true
  else:
    discard
  if node.kind in {nkNone .. nkNilLit}:
    return false
  for child in node.sons:
    if callsAny(child, names):
      return true

proc isExceptionText(value: PNode): bool =
  ## Detects `getCurrentExceptionMsg()` and `<something>.msg`.
  if value.kind == nkCall and value.len > 0 and value[0].kind == nkIdent and
      value[0].ident.s == "getCurrentExceptionMsg":
    return true
  value.kind == nkDotExpr and value.len == 2 and value[1].kind == nkIdent and
    value[1].ident.s == "msg"

# --- checks ---------------------------------------------------------------

proc runMessageEndsWithPunctuation(ast: PNode, s: MessageSettings): seq[Finding] =
  if s.allowTrailingPunctuation:
    return
  for call in logCalls(ast):
    let node = messageNode(call)
    if node != nil and node.strVal.strip()[^1] in s.trailingPunctuation:
      result.add finding(node, "log message must not end with forbidden punctuation")

proc runMessageMaxSentences(ast: PNode, s: MessageSettings): seq[Finding] =
  for call in logCalls(ast):
    let node = messageNode(call)
    if node == nil:
      continue
    let msg = node.strVal
    var sentenceCount = 1 # if the message is not empty, there is at least one sentence

    for i in 0 ..< msg.high:
      if msg[i] in s.trailingPunctuation and msg[i + 1] in Whitespace:
        inc sentenceCount

      if sentenceCount > s.maxSentences:
        result.add finding(
          node,
          "log message must contain no more than " & $s.maxSentences & " sentences",
        )
        break

proc runFieldNameLength(ast: PNode, s: FieldNameSettings): seq[Finding] =
  for call in logCalls(ast):
    for field in logFields(call):
      if field.name.len < s.minLength and field.name notin s.exceptions:
        let kind = if field.named: "field" else: "bare field"
        result.add finding(
          field.value,
          kind & " '" & field.name & "' is too short (needs to be at least " &
            $s.minLength & " characters long)",
        )

proc runErrForException(ast: PNode, s: ExceptionSettings): seq[Finding] =
  for call in logCalls(ast):
    for f in logFields(call):
      if f.name in s.aliases and isExceptionText(f.value):
        result.add finding(
          f.value,
          "use `" & s.field & "` for exception text instead of `" & f.name & "`",
        )

proc runNoPayloadWhenElevated(ast: PNode, s: PayloadSettings): seq[Finding] =
  for call in logCalls(ast):
    if levelName(call) notin s.levels:
      continue
    for f in logFields(call):
      if f.name in s.fields:
        result.add finding(
          f.value, "elevated log contains payload field `" & f.name & "`"
        )

proc literalType(value: PNode): string =
  ## The type name of a literal, or "" when the value is not a literal.
  case value.kind
  of nkIntLit .. nkInt64Lit: "int"
  of nkUIntLit .. nkUInt64Lit: "uint"
  of nkFloatLit .. nkFloat128Lit: "float"
  of nkStrLit, nkRStrLit, nkTripleStrLit: "string"
  of nkCharLit: "char"
  else: ""

proc convertedType(value: PNode): string =
  ## The target type of a conversion such as `int(x)`, or "" when the value is
  ## not a conversion.
  if value.kind == nkCall and value.len == 2 and value[0].kind == nkIdent:
    return value[0].ident.s
  ""

proc isBasicType(value: PNode, basicTypes: seq[string]): bool =
  ## True when the value's type is visible in the source and is a basic type.
  ## `true` and `false` parse as identifiers, so they are handled explicitly.
  if value.kind == nkIdent and value.ident.s in ["true", "false"]:
    return "bool" in basicTypes
  let name =
    if literalType(value).len > 0:
      literalType(value)
    else:
      convertedType(value)
  name.len > 0 and name in basicTypes

proc runUnboundedFields(ast: PNode, s: UnboundedSettings): seq[Finding] =
  ## Flags fields that conventionally carry unbounded payloads unless the value
  ## is bounded.
  ##
  ## The rule, as nim-libp2p states it:
  ##
  ## - a `seq[T]` must never be logged raw: it needs a `chronicles.formatIt`
  ##   for that sequence type, a `shortLog` call, or `.len`
  ## - any other type needs a `chronicles.formatIt` for that type
  ## - basic types (bool, int, float, string, enums) are always fine
  ##
  ## Only the value-side half is checkable without type information: a value
  ## that calls an escape, takes `.len`, or is visibly a basic type is accepted.
  ## Whether the value's type has a `formatIt` cannot be decided from a
  ## parse-only tree, so a value that relies on one is reported here. That is
  ## why this check is configured as a hint.
  for call in logCalls(ast):
    for f in logFields(call):
      if f.name notin s.fields:
        continue
      if callsAny(f.value, s.escapes) or isBasicType(f.value, s.basicTypes):
        continue
      result.add finding(
        f.value,
        "potentially unbounded log field `" & f.name & "` must use " &
          s.escapes.join(" or "),
      )

# --- linter ---------------------------------------------------------------

let chronicles* = newLinter("chronicles")

let messageEndsWithPunctuation* =
  chronicles.check("messageEndsWithPunctuation", runMessageEndsWithPunctuation)
let messageMaxSentences* =
  chronicles.check("messageMaxSentences", runMessageMaxSentences)
let fieldNameLength* = chronicles.check("fieldNameLength", runFieldNameLength)
let errForException* = chronicles.check("errForException", runErrForException)
let noPayloadWhenElevated* =
  chronicles.check("noPayloadWhenElevated", runNoPayloadWhenElevated)
let unboundedFields* = chronicles.check("unboundedFields", runUnboundedFields)
