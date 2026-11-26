# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Source-comment policies: issue-linked TODOs and the project's license header.

import std/strutils
import compiler/ast
import lint

type
  TodoSettings* = object
    ## Settings for TODO comments, which must reference an issue on the same line.

  HeaderSettings* = object
    ## Required opening header; trailing whitespace and CRLF are ignored.
    license*: string = """# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
"""

proc commentMask(source: string): string =
  ## Keep comment characters and line endings at their original byte positions.
  ## Unlike the parsed AST, this includes ordinary and trailing comments.
  result = newString(source.len)
  var index = 0
  while index < source.len:
    if source[index] in {'\r', '\n'}:
      result[index] = source[index]
      inc index
    elif source[index] == '#':
      if source.continuesWith("#[", index) or source.continuesWith("##[", index):
        var endings: seq[string]
        while index < source.len:
          let opening =
            if source.continuesWith("##[", index):
              "##["
            elif source.continuesWith("#[", index):
              "#["
            else:
              ""
          if opening.len > 0:
            endings.add(if opening == "##[": "]##" else: "]#")
            for ch in opening:
              result[index] = ch
              inc index
          elif endings.len > 0 and source.continuesWith(endings[^1], index):
            let ending = endings.pop()
            for ch in ending:
              result[index] = ch
              inc index
            if endings.len == 0:
              break
          else:
            result[index] = source[index]
            inc index
      else:
        while index < source.len and source[index] notin {'\r', '\n'}:
          result[index] = source[index]
          inc index
    elif source[index] == '"':
      let triple = source.continuesWith("\"\"\"", index)
      let raw = index > 0 and source[index - 1] in IdentChars
      inc(index, if triple: 3 else: 1)
      while index < source.len:
        if triple and source.continuesWith("\"\"\"", index):
          inc(index, 3)
          break
        elif not triple and source[index] == '"':
          if raw and source.continuesWith("\"\"", index):
            inc(index, 2)
          else:
            inc index
            break
        elif not triple and not raw and source[index] == '\\':
          inc(index, 2)
        else:
          if source[index] in {'\r', '\n'}:
            result[index] = source[index]
          inc index
    elif source[index] == '\'' and index + 2 < source.len and
        (source[index + 2] == '\'' or source[index + 1] == '\\'):
      # A numeric suffix (1'u8) is not a character literal.
      inc index
      while index < source.len:
        if source[index] == '\\':
          inc(index, 2)
        elif source[index] == '\'':
          inc index
          break
        else:
          inc index
    elif source[index] == '`':
      inc index
      while index < source.len and source[index] != '`':
        inc index
      if index < source.len:
        inc index
    else:
      inc index

proc issueNumber(text: string, start: int): bool =
  var index = start
  var positive = false
  while index < text.len and text[index] in Digits:
    positive = positive or text[index] != '0'
    inc index
  index > start and positive and (index == text.len or text[index] notin IdentChars)

proc hasIssue(text: string): bool =
  let suffix = text.strip()
  if suffix.startsWith(":"):
    var index = 1
    while index < suffix.len and suffix[index] in Whitespace:
      inc index
    if issueNumber(suffix, index):
      return true
  for index in 0 ..< suffix.len:
    if suffix[index] == '#' and issueNumber(suffix, index + 1):
      return true
    if suffix.continuesWith("/issues/", index) and issueNumber(suffix, index + 8):
      return true

proc runTodoWithIssue(
    source: string, ast: PNode, settings: TodoSettings
): seq[Finding] =
  let lines = commentMask(source).splitLines()
  for lineIndex, line in lines:
    let lower = line.toLowerAscii()
    var start = 0
    while start < lower.len:
      let column = lower.find("todo", start)
      if column < 0:
        break
      let ending = column + 4
      if (column == 0 or lower[column - 1] notin IdentChars) and
          (ending == lower.len or lower[ending] notin IdentChars) and
          not hasIssue(line[ending .. ^1]):
        result.add Finding(
          line: lineIndex + 1,
          col: column,
          msg: "TODO comment must reference an issue (e.g. TODO:1234)",
        )
      start = ending

proc runLicenseHeader(
    source: string, ast: PNode, settings: HeaderSettings
): seq[Finding] =
  let lines = source.splitLines()
  let required = settings.license.strip(leading = false).splitLines()
  for index, line in required:
    let expected = line.strip(leading = false)
    if index >= lines.len or lines[index].strip(leading = false) != expected:
      result.add Finding(
        line: index + 1,
        col: 0,
        msg: "missing or incorrect license header; expected " & expected,
      )
      break

let
  comments* = Linter()
  todoWithIssue* = comments.addCheck(runTodoWithIssue)
  licenseHeader* = comments.addCheck(runLicenseHeader)
