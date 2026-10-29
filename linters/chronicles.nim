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
  MessageSettings* = object
    ## Settings shared by the message checks.
    allowTrailingPeriod*: bool ## Accept `Some message.`.

  FieldNameSettings* = object
    minLength*: int ## Shortest accepted field name.
    exceptions*: seq[string] ## Names accepted regardless of `minLength`.

  ExceptionSettings* = object
    ## Which fields must carry exception text.
    field*: string ## The field exception text is expected in.
    aliases*: seq[string] ## Fields that must not stand in for it.

  PayloadSettings* = object
    ## Which log levels must not carry payloads, and which fields carry them.
    levels*: seq[string] ## Levels that must stay payload-free, e.g.
                         ## `["warn", "error"]`. Matched against the level name
                         ## in the source, so it needs no enum.
    fields*: seq[string] ## Field names that carry a payload.

# Settings used when a check is configured without a `settings:` block. These
# are the values `audit_logs.py` enforces, and the only place defaults live: a
# setting that is present always wins, so an empty list means "none", not
# "use the default".
const
  defaultFieldNameSettings* = FieldNameSettings(
    minLength: 3, exceptions: @["id", "ip"]
  )
  defaultExceptionSettings* = ExceptionSettings(
    field: "err", aliases: @["description", "error", "message", "msg"]
  )
  defaultPayloadSettings* = PayloadSettings(
    levels: @["warn", "error"],
    fields: @[
      "msg", "message", "buffer", "record", "reply", "response", "rpcMsg",
      "data", "encoded", "certificate", "ticket", "key",
    ],
  )

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

proc isExceptionText(value: PNode): bool =
  ## Detects `getCurrentExceptionMsg()` and `<something>.msg`.
  if value.kind == nkCall and value.len > 0 and value[0].kind == nkIdent and
      value[0].ident.s == "getCurrentExceptionMsg":
    return true
  value.kind == nkDotExpr and value.len == 2 and value[1].kind == nkIdent and
    value[1].ident.s == "msg"

# --- checks ---------------------------------------------------------------

proc runMessageEndsWithPeriod(ast: PNode, s: MessageSettings): seq[Finding] =
  if s.allowTrailingPeriod:
    return
  for call in logCalls(ast):
    let node = messageNode(call)
    if node != nil and node.strVal.endsWith("."):
      result.add finding(node, "log message must not end with a full stop")

proc runMessageOneSentence(ast: PNode, s: MessageSettings): seq[Finding] =
  for call in logCalls(ast):
    let node = messageNode(call)
    if node == nil:
      continue
    let msg = node.strVal
    # A period, at least one whitespace character, then a capital letter starts
    # a new sentence: "First sentence. Second sentence". This mirrors the
    # `\.\s+(?=[A-Z])` pattern used by the Python audit.
    var i = 0
    while i < msg.len - 1:
      if msg[i] == '.':
        var j = i + 1
        while j < msg.len and msg[j] in {' ', '\t', '\n', '\r'}:
          inc j
        if j > i + 1 and j < msg.len and msg[j] in {'A' .. 'Z'}:
          result.add finding(node, "log message must contain one sentence")
          break
      inc i

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
          f.value,
          "elevated log contains payload field `" & f.name & "`",
        )

# --- linter ---------------------------------------------------------------

let chronicles* = newLinter("chronicles")

let messageEndsWithPeriod* = chronicles.check(
  "messageEndsWithPeriod", runMessageEndsWithPeriod
)
let messageOneSentence* = chronicles.check("messageOneSentence", runMessageOneSentence)
let fieldNameLength* = chronicles.check(
  "fieldNameLength", runFieldNameLength, defaultFieldNameSettings
)
let errForException* = chronicles.check(
  "errForException", runErrForException, defaultExceptionSettings
)
let noPayloadWhenElevated* = chronicles.check(
  "noPayloadWhenElevated", runNoPayloadWhenElevated, defaultPayloadSettings
)
